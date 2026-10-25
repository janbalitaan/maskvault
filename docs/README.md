# maskvault documentation

Replace confidential values with tokens, pass the text through anything,
restore the originals afterwards.

```python
from maskvault import Anonymizer

anonymizer = Anonymizer()
safe, vault = anonymizer.anonymize("email alice@acme.com about the invoice")
# "email !|EMAIL_1|! about the invoice"

reply = provider.complete(safe)
answer = anonymizer.restore(reply, vault)
```

The provider never sees the address. Your reader still gets a correct answer.

## Start here

| Page | What it covers |
| --- | --- |
| [Getting started](getting-started.md) | Install, a first round trip, wiring it in. Ten minutes. |
| [Levels](levels.md) | The four strictness levels and what each adds. |
| [Detection](detection.md) | What is found, how, and what each match costs you. |
| [Whitelisting](whitelisting.md) | Nine mechanisms for taking back control. |
| [Token formats](token-formats.md) | Delimiters, collisions, and why the default is what it is. |
| [Structured data](structured-data.md) | Dicts, lists and JSON rather than one string. |
| [Stores](stores.md) | Moving a vault between requests, processes and nodes. |
| [Encryption](encryption.md) | Who encrypts, who holds the key. |
| [Concurrency](concurrency.md) | One anonymizer, many callers. Threads, asyncio, nodes. |
| [Command line](cli.md) | Cleaning a file or a pipe before it goes anywhere. |
| [API reference](api.md) | Every public name, with signatures. |
| [Security](security.md) | What this protects, and what it does not. |
| [Limitations](limitations.md) | Stated plainly, so you can judge the fit. |

## The shape of it

```
Anonymizer ─┬─> anonymize()  ──> (safe text, Vault)
            │                         │
            │     Detector ───────────┤  what to look for
            │     Whitelist ──────────┤  what to leave alone
            │     TokenFormat ────────┘  how a token is written
            │
            └─> restore(text, vault) ──> the original values back
```

Four pieces, each with one job:

- **`Anonymizer`** applies a policy to text. It holds no per-operation state,
  so one instance is safe to share across concurrent callers.
- **`Vault`** maps tokens back to values. It is returned to you, not held —
  which is what makes the common case need no storage at all.
- **A `Detector`** says what to look for and what happens to a match:
  tokenized and restored, or destroyed and never returned.
- **A `Whitelist`** says what to leave alone, because that judgement is the
  one this library cannot make for you.

## Two actions, and the distinction matters

| | What happens | Example |
| --- | --- | --- |
| **reversible** | replaced with a token, restored afterwards | an address, a phone number, an employer |
| **destroy** | replaced with a notice, never restored | a password, an API key, a card number |

A credential that came back would mean the library had handed it to a
provider and then handed it onward. If one appears, something upstream has
gone wrong, and quietly restoring it would hide that.

## Design commitments

These do not change between versions:

1. **Default deny.** Within a level, every detector runs unless the whitelist
   says otherwise. The value that leaks is the one nobody thought to
   configure.
2. **A destroyed value never returns.** Not by a setting, not by a flag.
3. **Nothing is logged that carries a value.** `Vault.summary()` and
   `describe_policy()` are safe; `explain()` and `preview()` are not, and say
   so.
4. **No required dependencies.** A privacy filter that pulls in a dependency
   tree is one nobody can audit.
