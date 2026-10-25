# Concurrency

## One anonymizer, shared

Build one at module scope and use it from every request. That is the shape
nearly every web application takes, and it is safe:

```python
anonymizer = Anonymizer(level="strict")   # module scope


@app.post("/ask")
async def ask(question: str) -> str:
    safe, vault = anonymizer.anonymize(question)
    reply = await provider.complete(safe)
    return anonymizer.restore(reply, vault)
```

Nothing about an operation is stored on the anonymizer. The format and the
token numbering both live on the vault, and the vault belongs to the caller —
which is what makes sharing the anonymizer sound.

It was not always. The format chosen for an operation used to be kept on the
instance, so a second caller could overwrite it between the first caller's
write and its use. The first caller then minted tokens in the second caller's
delimiters while its own vault recorded the format it had asked for, and the
numbering restarted — so `!|EMAIL_1|!` could stand for two different values
and restoring returned whichever was written last.

## One vault, shared

Also safe, and a reasonable thing to do: `anonymize_into` exists to
accumulate, which is what a multi-turn conversation needs.

```python
vault = Vault()
for turn in turns:                 # even concurrently
    safe = anonymizer.anonymize_into(turn, vault)
```

The vault allocates tokens under its own lock, so reading the counter and
writing the mapping are one atomic step. Without that, two callers both read
index 5, both minted token 6, and the second write replaced the first — while
the first caller's text still said token 6.

**But sharing a vault between *unrelated* callers is a privacy mistake, not
just a concurrency one.** Everything in a vault is visible to everyone
holding it. One vault per conversation, not one per process.

## asyncio

Safe, and worth knowing why rather than trusting a test: this library
contains no `await`. A coroutine yields only at an await, so `anonymize()`
runs to completion before any other coroutine resumes. There is no
interleaving to protect against.

```python
await asyncio.gather(*(handle(n) for n in range(200)))   # fine
```

`asyncio.to_thread` and a thread-pool executor hand the work to real threads,
which puts the threaded case back — and that is what the locks are for.

## Several nodes

Nothing is shared between processes, so nothing can collide. The only
question is whether the vault needs to travel:

| Shape | Needs a store? |
| --- | --- |
| anonymize → provider → restore, one handler | **no** |
| many nodes behind a load balancer, each handling whole requests | **no** |
| a multi-turn conversation keeping one token per person | yes |
| anonymize on one node, restore on another | yes |
| a queue, where the worker is a different process | yes |

See [stores](stores.md), including what happens when the vault is missing.

## Several processes

A vault is an ordinary Python object, so it travels when serialized:

```python
with ProcessPoolExecutor() as pool:
    safe, vault = pool.submit(work, text).result()   # pickles fine
```

Adding the lock briefly broke this — a lock cannot be pickled, which killed
every pickle-based route including a process pool and any task queue using
it. The lock is excluded from the pickled state and a fresh one is made on
unpickle, because a lock means nothing across a process boundary.

For anything that crosses a machine, use `Vault.as_dict()` and JSON rather
than pickle. A pickled payload is executable on load.

## What is not safe

**Mutating a policy while it is in use.** `Anonymizer` is immutable after
construction, so there is nothing to mutate — build a second one instead of
reconfiguring the first.

**Sharing a vault between unrelated requests.** Not a thread-safety problem;
a privacy one.

**Assuming a token means anything without its vault.** Two vaults mint the
same strings unless you use `Vault.scoped()`. Never merge two vaults.

## How this is tested

`tests/concurrency/` runs six threads through 300 rounds each and asserts
four invariants: every vault agrees with its own format, nothing is lost on
restore, no output carries another caller's value, and no token stands for
two values. Reintroducing either original bug fails them.
