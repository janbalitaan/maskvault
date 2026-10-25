# maskvault

Reversible anonymization with a vault. Replace confidential values with
tokens, pass the text through anything, restore the originals afterwards.

[![PyPI](https://img.shields.io/pypi/v/maskvault)](https://pypi.org/project/maskvault/)
[![Python](https://img.shields.io/pypi/pyversions/maskvault)](https://pypi.org/project/maskvault/)
[![CI](https://github.com/janbalitaan/maskvault/actions/workflows/ci.yaml/badge.svg)](https://github.com/janbalitaan/maskvault/actions/workflows/ci.yaml)
[![License](https://img.shields.io/pypi/l/maskvault)](https://github.com/janbalitaan/maskvault/blob/main/LICENSE)

```python
from maskvault import Anonymizer, Level

anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})

safe, vault = anonymizer.anonymize("I work at Acme Corp, email me@acme.com")
# safe -> "I work at !|ORG_1|!, email !|EMAIL_1|!"

result = send_somewhere(safe)          # a model, a log, a vendor, a dataset
final = anonymizer.restore(result, vault)   # the real values come back
```

It is not tied to any one destination. The same mechanism serves a prompt sent
to a provider, a log line shipped to a vendor, a dataset handed to a
contractor, a bug report pasted into a tracker, or a support transcript
reviewed by a third party.

## Documentation

Full documentation is in [`docs/`](https://github.com/janbalitaan/maskvault/blob/main/docs/README.md):

| Page | |
| --- | --- |
| [Getting started](https://github.com/janbalitaan/maskvault/blob/main/docs/getting-started.md) | Install, a first round trip, wiring it in |
| [Levels](https://github.com/janbalitaan/maskvault/blob/main/docs/levels.md) | The four strictness levels |
| [Detection](https://github.com/janbalitaan/maskvault/blob/main/docs/detection.md) | What is found, and how |
| [Whitelisting](https://github.com/janbalitaan/maskvault/blob/main/docs/whitelisting.md) | Nine mechanisms for taking control back |
| [Token formats](https://github.com/janbalitaan/maskvault/blob/main/docs/token-formats.md) | Delimiters, collisions, the default |
| [Structured data](https://github.com/janbalitaan/maskvault/blob/main/docs/structured-data.md) | Dicts, lists and JSON |
| [Stores](https://github.com/janbalitaan/maskvault/blob/main/docs/stores.md) | Moving a vault between processes and nodes |
| [Encryption](https://github.com/janbalitaan/maskvault/blob/main/docs/encryption.md) | Who encrypts, who holds the key |
| [Concurrency](https://github.com/janbalitaan/maskvault/blob/main/docs/concurrency.md) | One anonymizer, many callers |
| [Command line](https://github.com/janbalitaan/maskvault/blob/main/docs/cli.md) | Cleaning a file or a pipe |
| [API reference](https://github.com/janbalitaan/maskvault/blob/main/docs/api.md) | Every public name |
| [Security](https://github.com/janbalitaan/maskvault/blob/main/docs/security.md) | What this protects, and what it does not |
| [Limitations](https://github.com/janbalitaan/maskvault/blob/main/docs/limitations.md) | Stated plainly |

Security reports go through
[SECURITY.md](https://github.com/janbalitaan/maskvault/blob/main/SECURITY.md) rather than an issue.

## Install

```bash
pip install maskvault
```

Python 3.10+. **No dependencies**, so it runs in a serverless function, in CI,
in a build step, or on a Raspberry Pi with no model download and no install
step.

---

## The two-way distinction

Most tools in this space do one thing: they remove. maskvault separates two
cases that need opposite handling.

**Reversible** — identifying but legitimate. An employer, a phone number, a
salary, a health condition. Replaced with a token, restored afterwards. The
third party never sees it; your user still gets a correct answer.

**Destroyed** — must never arrive and must never come back. An API key, a
private key, a card number, a connection string. Replaced with a notice and
*not* restored, because if one of these appeared, something went wrong
upstream and quietly putting it back would hide the mistake.

```python
safe, vault = anonymizer.anonymize("key sk-abc123… and I work at Acme Corp")
# "key [an API key was removed before sending] and I work at !|ORG_1|!"
vault.destroyed   # ["api_key"]
```

So an exact round trip holds **only when nothing was destroyed**. That is the
intended behavior, not a limitation to work around.

## Strictness levels

```python
Anonymizer(level=Level.MINIMAL)    # credentials only
Anonymizer(level=Level.STANDARD)   # + contact details, identifiers (default)
Anonymizer(level=Level.STRICT)     # + GDPR Article 9 special categories
Anonymizer(level=Level.PARANOID)   # + a lower entropy bar
```

`STRICT` adds vocabularies for health, religion, politics, identity, origin
and criminal or financial history — the categories European law treats as
needing explicit consent, which has held up well as a description of what
people do not want shared. It is the right level when the subject is a person
and the wrong level for a codebase, because "black" is in the origin
vocabulary and also half the CSS ever written.

## Control

Nothing is allowed through by default. Every mechanism for allowing something:

```python
Anonymizer(
    level=Level.STRICT,
    whitelist={
        "labels":     ["url", "age"],            # turn a detector off
        "categories": ["identity"],              # turn a category off
        "values":     ["Python", "FastAPI"],     # exact strings
        "words":      ["black", "native"],       # word-bounded
        "contains":   ["github.com"],            # substring
        "prefixes":   ["https://mysite.dev/"],
        "suffixes":   ["@mycompany.com"],
        "domains":    ["mycompany.com"],         # emails and URLs, subdomains too
        "patterns":   [r"^EMP-\d{4}$"],          # regex
    },
)
```

Plus `predicate=` for arbitrary logic, which has no JSON form by design — a
config file should not be able to introduce executable code.

Two curated starting lists are included: `COMMON_SAFE_VALUES` (public
technology names) and `TECHNICAL_HOMONYMS` (words in the sensitive
vocabularies that are also ordinary technical vocabulary).

## Configure from what you actually see

Guessing a whitelist up front is the wrong way round. Run real input through
it and read the findings:

```python
print(anonymizer.preview(text))
```

```
9 findings at level strict:
  reversible  AGE                I am 34
  reversible  STREET_ADDRESS     42 Rizal Street
  reversible  SALARY             earn $95,000 a year
  reversible  HEALTH             diabetes
  reversible  RELIGION           Catholic
  allowed     URL                https://github.com/me
  destroy     AWS_ACCESS_KEY     AKIAIOSFODNN7EXAMPLE
8 would be replaced, 1 allowed through
```

`explain()` returns the same as structured `Finding` objects.
`suggest_whitelist()` turns it into a config draft to edit down.

`preview()` prints real values, so it is for a terminal, not a log. For a log
there is `vault.summary()`, which counts by kind and contains no values:

```
"1 age, 2 health, 1 salary, 1 street_address, 1 destroyed"
```

## Moving a vault between processes

The common case needs nothing. Anonymize, call the provider and restore in
one request handler, and the vault is a local variable that never leaves it:

```python
safe, vault = anonymizer.anonymize(question)
reply = provider.complete(safe)
answer = anonymizer.restore(reply, vault)
```

Scale that to any number of nodes and nothing crosses, because nothing is
shared. **Adding a store here makes it less private, not more.**

A store is for when the vault has to outlive the request — a multi-turn
conversation where one person should keep one token, anonymizing on one node
and restoring on another, or a queue where the worker is a different process.

```python
from maskvault.ciphers import FernetCipher
from maskvault.stores import MemoryVaultStore, SerializedVaultStore

MemoryVaultStore()                                      # one process
SerializedVaultStore(backend, FernetCipher.from_env())   # Redis, Valkey, ...
DatabaseVaultStore(connection, FernetCipher.from_env())  # PostgreSQL, MySQL
```

A key-value backend is about ten lines, which is why none of them is a
dependency here:

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

### Encryption is not optional, and not defaulted either

A stored vault holds every original value. It usually goes somewhere with
wider access than the application — a shared cache, a table, a backup of
either — while the key stays in the application. Those are different trust
domains, which is what makes encrypting here worth doing.

So a store refuses to be built without a cipher. There is no secure default
to fall back to: a key cannot be invented, because a random one per process
would leave the node that restores unable to decrypt what the node that
anonymized wrote. And defaulting to plaintext would mean a store that looks
encrypted to anyone who did not read the signature.

```bash
pip install 'maskvault[encryption]'
```

```python
key = FernetCipher.generate_key()   # once, at deployment, kept somewhere safe
cipher = FernetCipher(key)          # or FernetCipher.from_env()
```

Opting out is a thing you have to type, so that it shows in review:

```python
SerializedVaultStore(backend, PlaintextCipher())   # faster, and visible
```

`store.describe()` returns a line safe to log at startup. "plaintext" in a
production log is the kind of thing someone notices; a silent default never
would be.

### Who does the encrypting

maskvault performs it and implements none of it. The only cipher here
delegates to `cryptography`'s Fernet — an audited implementation — and this
package contains no cryptographic primitive of its own.

The key is yours throughout. Where it lives, how it rotates, and whether it
ever reaches the process at all are your decisions, and the key never appears
in anything this library writes: not a repr, not `describe()`, not the vault,
not the stored bytes.

If you would rather own the whole operation, implement `VaultCipher`. A KMS,
an HSM or a Vault transit backend all fit, and none of them require importing
anything from here:

```python
class KmsCipher:
    def __init__(self, client, key_id):
        self._client, self._key_id = client, key_id

    def encrypt(self, plaintext):
        return self._client.encrypt(
            KeyId=self._key_id, Plaintext=plaintext
        )["CiphertextBlob"]

    def decrypt(self, ciphertext):
        return self._client.decrypt(CiphertextBlob=ciphertext)["Plaintext"]

    @property
    def describes(self):
        return f"aws kms, key {self._key_id}"
```

That key never reaches your process, and `store.describe()` reports
`aws kms, key alias/prod` so the choice is visible in a startup log.

### The lifetime is yours, with a default if you want one

Entries expire after fifteen minutes unless you say otherwise, because a
vault's lifetime is the window in which its values are exposed.

**`ttl_seconds=0` means no expiry**, which hands retention to you. That is
the point of using a database rather than a cache: retention there is already
somebody's job — a nightly job, a partition drop, a policy the DBA owns — and
a library second-guessing it is a library fighting the deployment.

```python
DatabaseVaultStore(connection, cipher, ttl_seconds=0)     # yours to manage
DatabaseVaultStore(connection, cipher, ttl_seconds=3600)  # an hour
```

A negative value raises rather than being read as zero. A TTL is usually
computed, and one that came out negative is a bug worth hearing about — not a
silent switch to keeping plaintext forever.

A database has no expiry of its own, so `purge()` has to be called by
something when a TTL is set. With `ttl_seconds=0` there is nothing for it to
do, and `describe()` stops asking for it.

And key by something two callers cannot share. A conversation id or a request
id is right; a user id usually is not, because one user has more than one
conversation, and a shared key hands one caller's values to another.

## The token format is yours

The default is `!|LABEL_1|!`. Two collisions can break a token and only one
is detectable.

**With the input.** The text already contains the delimiter, so a replacement
nests inside it or a real occurrence is mistaken for a token. This one is
handled automatically: the format is chosen per operation by trying each
candidate until one is absent from the text, and the choice is recorded in
the vault so restoring needs no bookkeeping from you.

```python
safe, vault = anonymizer.anonymize("a note mentioning !|EXISTING|!")
vault.token_format.name   # "pipe_brackets", since the default was taken
```

**With wherever the output goes.** The input is clean, but the *result* is
pasted into a wiki, rendered as Markdown, or fed to a template engine — where
the token means something. Selection cannot help, because it sees the text it
is given and knows nothing about the destination. Only the default can
protect against this, by being a pair nothing claims.

So the default was picked by testing each candidate against what people
actually paste into a model:

| | claimed by |
| --- | --- |
| `!|X|!` | **nothing** — the default |
| `[\|X\|]` | Haskell and Idris quasi-quotation. Rare, more legible, so it is second |
| `@@X@@` | unified diff hunk headers, `@@ -1,5 +1,5 @@` |
| `[[X]]` | wikilinks — Obsidian, Roam, Logseq, MediaWiki, Dendron, Foam |
| `[!X!]` | GitHub alerts, `> [!NOTE]`. And `[![` is a linked image — the badge syntax at the top of most READMEs |
| `{{X}}` | templates — Jinja, Handlebars, Mustache, Vue, Angular, Liquid |
| `{\|X\|}` | MediaWiki tables, and LaTeX |
| `<<X>>` | AsciiDoc cross-references |
| `%%X%%` | Obsidian comments, SQL `LIKE`, `printf` |
| `((X))` | Roam block references |
| `(\|X\|)` | Haskell idiom brackets, the Elixir and OCaml pipe operator |
| `<\|X\|>` | a model's own special tokens — the one pair to never use |

What the default does **not** fix: a model that reformats a token breaks
restoring whatever the delimiters are, and `!|EMAIL_1|` is rejected exactly as
`@@EMAIL_1@` was. [`leaked()`](#detecting-a-mangled-token) is what reports
that, and no choice of delimiter removes the need for it.

Ask for brackets by name when you control the whole pipeline and want the
most model-legible form:

```python
Anonymizer(token_format="brackets")   # -> [[ORG_1]]
```

Pin one when you need it stable, by name or outright:

```python
Anonymizer(token_format="pipe_bang")

Anonymizer(token_format=TokenFormat(
    name="mine",
    opening="<%|",
    closing="|%>",
    label_pattern=r"[a-z_]+",
    label_case="lower",
))   # -> <%|org_1|%>
```

Or supply your own candidate list, and auto-selection chooses from yours
rather than the built-ins:

```python
Anonymizer(format_candidates=(my_first_choice, my_fallback))
```

`random_format()` generates unguessable delimiters per call. That removes any
possibility of collision, and raises the cost of text forging a token that
`restore()` would expand — unpredictable, which is weaker than secret, but
useful when the text passes through something that processes untrusted input.

A format is validated at construction: it must match its own output. A format
that cannot would lose every value at restore time with no error, so it is
refused immediately instead:

```python
TokenFormat(name="bad", opening="[[", closing="]]", label_pattern=r"\d+")
# ValueError: token format 'bad' cannot match its own output ('[[LABEL_1]]')
```

Formats round-trip through `format_from_dict` / `as_dict`, so one can live in
a config file.

## When a token comes back damaged

A model may mangle a token. `leaked()` reports any that survive restoration,
so you can fall back rather than show `[[ORG_2]]` to a user:

```python
if anonymizer.leaked(reply, vault):
    return deterministic_answer()
```

An invented token such as `[[ORG_9]]` is deliberately left visible rather than
resolved to something unrelated — a visible oddity beats a silent wrong answer
about someone's employer.

---

## Limitations

Read this section before trusting the library with anything that matters. A
privacy tool that oversells itself is worse than no privacy tool, because it
replaces caution with false confidence.

### It cannot find a name it was not told about

There is no NLP here. maskvault will not find "Maria Santos" in free text
unless you list it in `terms`. Microsoft Presidio will, using a named-entity
model, and for unstructured text about unknown people that is a genuine and
large advantage over this library.

Use `terms` for the names you know. If you need to anonymize text about people
whose names you do not know in advance, use Presidio, or run both.

### The sensitive vocabularies are word lists, not understanding

`STRICT` matches terms from curated lists. That means:

- **It misses what is not listed.** A condition, faith or affiliation nobody
  added will pass straight through. The health list has ~107 entries; medicine
  has tens of thousands of terms.
- **It matches innocent uses.** "black", "native", "union", "strike",
  "terminal", "partner" and "default" all appear in these lists for good
  reasons and all have ordinary technical meanings. `TECHNICAL_HOMONYMS`
  exists because of this, and it is a mitigation, not a fix.
- **It cannot read negation or context.** "I do not have diabetes" and "my
  work on diabetes research" are both matched.

### It is English-centric and Western-format-centric

The vocabularies are English. The national-ID pattern is a US SSN shape.
Street suffixes, postcodes and phone conventions lean US, UK and Philippine.
Text in another language, or identifiers in another country's format, are
largely unprotected unless you supply your own detectors.

This is the most valuable place to contribute, and the easiest.

### Entropy detection has a floor and a ceiling

The entropy net catches secrets whose format nobody anticipated, but:

- A secret from a **narrow alphabet** scores low. An AWS access key id is
  uppercase and digits only, measures 3.68 bits, and falls under the base64
  threshold — which is why there is also an explicit AWS pattern. An unknown
  vendor with a similarly narrow format will be missed.
- A **short** secret cannot be judged. Below the minimum length entropy is
  too noisy to act on, so a six-character password is invisible to this layer.
  `Level.PARANOID` lowers the bar and widens the alphabet to catch punctuated
  passwords, at the cost of more false positives.
- A **passphrase** is not caught. Entropy is measured per character, so
  "correct horse battery staple" scores like the ordinary words it is made of
  even though it is a strong secret. Nothing here will find it.
- Entropy is only one of four conditions, and not the strongest. Per-character
  entropy cannot tell a short varied English phrase from a generated string —
  "the quick brown fox jumps" scores above 4 bits. The absence of whitespace
  does more separating work than the entropy figure does, which also means a
  secret containing a space is invisible to this layer.
- It will **flag things that are not secrets** — a long opaque identifier, a
  hash in a URL path. Known-safe shapes (UUIDs, git SHAs, version strings) are
  excluded, but that list is not complete.

### Regexes over-match and under-match

The failure mode to watch for is a **partial** match: a pattern that claims
part of a value and leaves the rest in the output. Half a phone number is
still a phone number, so this is worse than no match at all.

It happens when a pattern tries to encode a value's grammar. A phone number
expressed as groups of digits backtracks — the greedy middle consumes the
trailing digits, the engine retries from a later position, and the result
covers only the middle of the number. The phone detector therefore finds
candidates with a loose pattern and validates them in code, which is the
approach to follow for anything whose shape is not genuinely regular.

### Tokens can degrade the result

A model reading `[[ORG_1]]` may write worse prose, ask what the token means,
or refuse. Tokens are chosen to survive quoting and reformatting, and
`leaked()` tells you when one did not, but the trade is real: more privacy,
somewhat less fluency.

### The vault is in-process memory

It is not encrypted, not persisted, and not shared between processes. Restore
has to happen where anonymization happened, or you have to pass the vault
yourself — and if you pass it over a network you have moved the problem rather
than solved it.

### Structured data

Dicts, lists and JSON are walked rather than flattened, so the structure
survives:

```python
from maskvault import anonymize_data, restore_data

safe, vault = anonymize_data({"user": {"email": "me@acme.com"}}, anonymizer)
# {"user": {"email": "!|EMAIL_1|!"}}

restore_data(safe, anonymizer, vault)   # the original, exactly
```

One vault covers the whole structure, so a value appearing in two places gets
one token. Keys are left alone by default, because a key is schema rather than
data and replacing it would make the output unparseable — pass
`include_keys=True` when a key is itself sensitive. Numbers are left alone for
the same reason, with `stringify_numbers=True` to opt in. `skip_keys` passes
named fields through untouched, for an id or timestamp something downstream
matches on.

### No format preservation

`[[PHONE_1]]` does not look like a phone number. Anything downstream that
validates the shape of its input will reject it. Format-preserving
tokenization is a reasonable feature request and is not implemented.

### It is not compliance

GDPR Article 9 is used here as an organizing principle for *what to look
for*. Using this library does not make a system GDPR, HIPAA or PCI compliant.
Compliance is about lawful basis, retention, contracts, access control and
disclosure — most of which are organizational, and none of which a regex can
establish.

### First match wins

Detectors run in a fixed order and the first to match a span claims it.
Specific formats are ordered before generic ones for this reason, but nested
or overlapping sensitive values may not be handled the way you expect. Check
with `explain()`.

---

## How this compares

| | maskvault | Presidio | scrubadub | detect-secrets |
| --- | --- | --- | --- | --- |
| Dependencies | **0** | 31 + NLP models | 8 | 4 |
| Reversible | **first-class vault** | via encryption | no | no |
| Credentials destroyed, not tokenized | **yes** | no | no | n/a (one-way) |
| Secret scanning | entropy + ~20 formats | limited | no | **its whole focus** |
| Finds unknown person names | **no** | **yes (NER)** | partial | no |
| Special-category vocabularies | **yes** | no | no | no |
| Allowlist mechanisms | **9 + predicate** | per-recognizer | limited | regex allowlist |
| Inspect before trusting | **preview/explain** | analyzer results | no | audit mode |
| Non-English | **weak** | **strong** | weak | n/a |

**Pick Presidio** if you need to find names and entities in text about people
you do not know in advance, or need strong non-English support, and can carry
the install weight.

**Pick detect-secrets** if you only want to stop credentials reaching a repo.

**Pick maskvault** if you need the values *back*, want no dependencies, and
want credentials and personal data handled differently from one another.

They compose: Presidio for entity discovery, maskvault for the reversible
vault and the credential rules.

---

## Contributing

The limitations above are a roadmap, and most of them are fixed by adding
data rather than changing design. Contributions are very welcome, and these
are the ones that help most:

**New locales.** A national ID format, phone convention, postcode shape or
address pattern for a country that is not covered. This is the highest-value
contribution and needs no knowledge of the internals.

**Vocabulary for another language.** The special categories are English-only.
Any language added makes the `STRICT` level meaningfully more useful.

**A missed credential format.** A vendor whose token shape is not in
`VENDOR_CREDENTIALS`. These are quick to add and immediately valuable.

**A false positive you hit.** A real one, with the input that caused it, is
worth more than a hypothetical. Add it as a test.

Each detector needs a test in **both** directions — something it must catch
and something it must leave alone. A detector with only positive tests tends
to be the one that over-matches in someone else's data.

```bash
git clone https://github.com/janbalitaan/maskvault
cd maskvault
uv sync
uv run pytest
uv run ruff check src tests
uv run ty check src
```

See `CONTRIBUTING.md` for the detector contract and how to add one.

## License

MIT
