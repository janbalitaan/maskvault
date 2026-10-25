# Stores

## The common case needs no store

A vault is returned to you rather than held by the anonymizer, which is what
makes the ordinary shape need nothing at all:

```python
def answer(question: str) -> str:
    safe, vault = anonymizer.anonymize(question)   # a local variable
    reply = provider.complete(safe)
    return anonymizer.restore(reply, vault)        # the same local
```

Anonymize, call the provider and restore in one request handler, and the
vault never leaves it. Scale that to any number of nodes and nothing crosses,
because nothing is shared.

**Adding a store here makes it less private, not more.** A stored vault is
plaintext somewhere it was not before.

## When you do need one

- a multi-turn conversation where one person should keep one token
- anonymizing on one node and restoring on another
- a queue, where the worker is a different process

```python
from maskvault.ciphers import FernetCipher
from maskvault.stores import (
    DatabaseVaultStore,
    MemoryVaultStore,
    SerializedVaultStore,
)

MemoryVaultStore()                                       # one process
SerializedVaultStore(backend, FernetCipher.from_env())    # Redis, Valkey, ...
DatabaseVaultStore(connection, FernetCipher.from_env())   # PostgreSQL, MySQL
```

All three take the same four methods: `save`, `load`, `delete`, `in`.

## What happens without the vault

Worth knowing, because the two outcomes are not equally bad.

**Node 2 has no vault.** The token stays visible. Wrong, but obviously
wrong, and `leaked()` reports it:

```python
anonymizer.leaked(reply, Vault())   # ['!|EMAIL_1|!']
```

**Node 2 has its own unrelated vault.** Both vaults independently minted the
identical string, so node 1's token is found in node 2's vault and resolves
to *someone else's value*. A wrong answer rather than a missing one, and
`leaked()` sees nothing because the token really is there.

`Vault.scoped()` makes the second impossible — a random marker in every
label, so two vaults cannot mint the same token:

```python
vault = Vault.scoped()      # tokens look like !|EMAIL_GUTK_1|!
```

Off by default, because a longer token is one a model is more likely to
reformat. Worth it when restoring happens in a different process.

## A key-value backend is about ten lines

Which is why none of them is a dependency here:

```python
class RedisBackend:
    def __init__(self, client):
        self._client = client

    def get(self, key):
        return self._client.get(key)

    def set(self, key, value, ttl_seconds):
        self._client.set(key, value, ex=int(ttl_seconds))

    def delete(self, key):
        self._client.delete(key)
```

Memcached, DynamoDB and a two-column table are the same shape. Bytes rather
than `str`, because that is what these stores natively hold — handing them a
`str` means guessing an encoding somewhere, and the guess stays invisible
until a non-ASCII value arrives.

## A database is different in two ways

```python
store = DatabaseVaultStore(connection, cipher, paramstyle="format")
store.create_table()      # once, at deploy
```

**No native expiry.** The lifetime is a column, filtered on every read and
reclaimed by `purge()` — which something has to call: a cron, a startup hook,
a periodic task. An unswept table of vaults is a growing pile of plaintext,
and that is the one failure a database store has which a cache does not.

**`paramstyle` is explicit.** `"qmark"` for sqlite3 and oracledb, `"format"`
for psycopg and the MySQL drivers — the PEP 249 names. Not detected
automatically, because `paramstyle` is a module attribute rather than a
connection one, and guessing from a class name breaks on a wrapper or a pool.

A table name cannot be a bound parameter, so it is interpolated — and
validated against `^[A-Za-z_][A-Za-z0-9_]*$` rather than trusted. Every
*value* is bound.

## The lifetime is yours

Entries expire after fifteen minutes unless you say otherwise, because a
vault's lifetime is the window in which its values are exposed.

```python
DatabaseVaultStore(connection, cipher, ttl_seconds=0)     # no expiry
DatabaseVaultStore(connection, cipher, ttl_seconds=3600)  # an hour
```

**Zero means no expiry**, handing retention to you. That is the point of
using a database rather than a cache: retention there is already somebody's
job — a nightly job, a partition drop, a policy the DBA owns — and a library
second-guessing it is a library fighting the deployment.

A negative value raises rather than being read as zero. A TTL is usually
computed, and one that came out negative is a bug worth hearing about, not a
silent switch to keeping plaintext forever.

## Keys are yours to choose, and the choice matters

A key shared between two unrelated requests hands one caller's values to
another. A conversation id or a request id is right; a user id usually is
not, because one user has more than one conversation.

```python
SerializedVaultStore(backend, cipher, prefix="acme:masked:")
```

The prefix namespaces vaults within a shared keyspace. Overridable, because
a deployment with its own convention should not have to fight this one.

## Logging what you chose

```python
store.describe()
# "vault store: fernet (AES-128-CBC with an HMAC-SHA256 tag), entries expire after 900s"
# "vault store: plaintext (not encrypted), entries do not expire; retention is yours to manage"
```

Worth logging at startup. "plaintext" in a production log is the kind of
thing someone notices.

## Serializing a vault yourself

If you would rather not use a store at all:

```python
payload = json.dumps(vault.as_dict())      # to a response, a queue, a cookie
vault = Vault.from_dict(json.loads(payload))
```

Lossless — the values, the destroyed labels, the scope and the format's own
patterns. A payload with no `values` raises rather than loading as an empty
vault, because an empty one restores nothing and looks identical to a vault
whose values were all absent.

JSON rather than pickle. A pickled payload is executable on load, so a store
an attacker can write becomes code execution in every process that reads it.

## How you know a token restores to the right value

A token is an index into **one** vault, not a global name. Two independent
vaults both mint `EMAIL_1`, so restoring with the wrong one returns another
caller's value — and it returns it *silently*, because the lookup succeeded.
`leaked()` sees nothing to report. That is the most dangerous failure this
library can have: not an error, a plausible wrong answer.

Three things prevent it, and only the first is a guarantee.

**Keep the vault with the request that produced it.** This is the actual
correctness argument. The vault *is* the identity of that conversation; the
marker below is a safety net under a mistake, not a replacement for pairing
them correctly.

**Derive the marker from an id you already have unique.**

```python
vault = Vault.for_key(conversation_id)
store.save(conversation_id, vault)
```

Uniqueness is then inherited from your own id space rather than drawn from a
hat. The marker is deterministic, so a retry or a second node reaches the
same answer, and loading the wrong conversation's vault is caught because the
marker is a function of the id you asked for.

**Or take a random marker.** `Vault.scoped()` draws twelve letters. This is
probabilistic — it is never 100%:

| vaults in flight | 12 letters | 16 | 20 | 24 |
| --- | --- | --- | --- | --- |
| 1,000,000 | 5.2e-06 | 1.1e-11 | 2.5e-17 | 5.5e-23 |
| 5,000,000 | 1.3e-04 | 2.9e-10 | 6.3e-16 | 1.4e-21 |

At five million concurrent vaults, twelve letters give about one chance in
7,600 that *some* pair shares a marker — and a shared marker only matters if
those two vaults are also mixed up. `Vault.scoped(letters=20)` costs eight
more characters per token and puts it at 6e-16, below the rate at which a
cosmic ray flips a bit in the machine doing the work.

**An unscoped `Vault()` offers none of this.** `anonymize()` returns one, so
it is the default — right for a single-process round trip where the vault
never leaves the function, wrong the moment a vault is stored, queued or
passed between nodes. Use `for_key` or `scoped` there.

## How long a vault lives, and how to end it early

A vault holds the originals in plaintext — that is its job — so how long it
lives is how long that data exists. `restore()` does **not** empty it, on
purpose: a multi-turn conversation needs the same tokens to mean the same
people on the next turn. So retention is governed by the TTL, and everything
else is an option on top.

| Lever | Scope | When it acts |
| --- | --- | --- |
| `ttl_seconds` | every store | the default, 900s; `0` means never |
| `store.delete(key)` | one vault | immediately |
| `store.purge()` | expired entries | when you call it |
| `store.clear()` | everything in memory | immediately |
| `vault.wipe(older_than=…)` | values past that age | immediately; default 900s, `0` for all |

**The TTL is the real control.** Fifteen minutes by default, because a
request-and-reply cycle is seconds and a conversation is minutes. Set it to
your own retention policy, or to `0` to turn this library's expiry off
entirely and leave retention to the job that already owns it — a nightly
sweep, a partition drop, a DBA's policy. Zero means *no expiry*, not
immediate expiry, throughout.

**`purge()` has to be called by something.** A cache expires entries itself,
so `SerializedVaultStore` over Redis or Memcached needs nothing. A database
has no native expiry, so `DatabaseVaultStore.purge()` is what reclaims
expired rows, from a cron, a startup hook or a periodic task. An unswept
table of vaults is a growing pile of plaintext nobody is using.

**`vault.wipe()` forgets by age, not all at once.** A long conversation keeps
needing its recent values while the ones from twenty turns ago are finished,
and an all-or-nothing wipe would force a choice between leaving plaintext
around and breaking a request still in flight:

```python
vault.wipe()                  # anything older than 15 minutes
vault.wipe(older_than=60)     # anything older than a minute
vault.wipe(older_than=0)      # everything, finished or not
```

The default matches the store TTL, so a vault in memory and a vault in a
cache age out together rather than one outliving the other by accident.

For the single-turn flow, where the vault is finished the moment the reply is
restored, say so explicitly:

```python
restored = anonymizer.restore(reply, vault)
vault.wipe(older_than=0)          # the object in hand
store.delete(conversation_id)     # and the stored copy
```

The ages travel with the vault, so a wipe after a trip through Redis or a
table still forgets the right things. A vault written by a version that did
not record them treats its values as **new** rather than old: keeping data a
few minutes too long is a smaller fault than forgetting what a live request
needs.

Both, because they are separate copies — wiping the object does not reach the
store, and deleting from the store does not reach the object.

After a wipe the tokens resolve to nothing rather than to something wrong,
`leaked()` reports them, and `summary()` still describes what the request
replaced. An audit line written after disposal would otherwise read "nothing
replaced" for a request that handled somebody's data.

The counters deliberately survive, so a token minted later cannot reuse
`EMAIL_1` and resolve to a different person.

**It is not a secure erase.** Python strings are immutable and the
interpreter may hold copies the process cannot reach, so `wipe()` removes the
reference, not every byte. For a stronger guarantee the value must not reach
this process at all.
