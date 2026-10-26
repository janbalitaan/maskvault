# Limitations

Stated plainly, because a privacy tool that overstates itself is worse than
one that does less. Each of these is a reasonable thing to send a pull
request about.

## Detection is a check against carelessness

Four families of detector catch what they recognize: published credential
formats, personal identifiers with a shape, vocabulary terms, and the entropy
net for randomness nobody anticipated.

What goes through: a value with no recognizable shape under no recognizable
key. A credential split across two fields. One base64-encoded or assembled at
runtime. A vendor whose format is not in the list. A name, unless you name it
in `terms`.

`explain()` on real input is the way to find out what your text actually
contains, and `suggest_whitelist()` turns that reading into config.

## It does not encrypt a value in memory

A resolved value is plaintext in process memory, like any other string. To
decrypt you would need the key, and the key would live in the same process —
so an attacker who can read your memory reads both.

Wiping is no better. A `str` is immutable and cannot be overwritten, and
holding values in a `bytearray` fails on first use:

```python
secret = bytearray(b"the-password")
connect(secret.decode())            # an immutable str copy, out of reach
secret[:] = b"\x00" * len(secret)   # wipes one copy of several
```

If a value must not be readable by whatever can read your process, that needs
an HSM, an enclave, or a service that holds the key and performs the
operation for you.

What *is* worth encrypting is a stored vault, where the key stays in your
application and the ciphertext goes elsewhere. See
[encryption](encryption.md).

## A reply that returns only some of the values

Three values go out, the reply mentions two. That is ordinary — a reply need
not repeat everything it was given — so nothing is wrong and `leaked()` stays
quiet. Whether it is *acceptable* is your call, not this library's: a
summarizer mentioning two of three contacts is fine, a form-filler returning
two of three fields is a failure.

Both questions are answerable, and the pair is what separates the cases:

```python
resolved = anonymizer.resolved(reply, vault)     # came back intact
leftover = anonymizer.leaked(reply, vault)       # came back broken
```

| resolved | leaked | meaning |
| --- | --- | --- |
| 3 of 3 | 0 | everything came back |
| 2 of 3 | 0 | one was not mentioned — usually fine |
| 2 of 3 | 1 | one was mangled — the reply has lost a value |

The middle and bottom rows have the same `resolved` count, which is why
`leaked()` is not optional: it is the only thing that tells an omission from
a loss.

A destroyed value has no token, so it appears in neither list. There is
nothing for a reply to return.

## A model that reformats a token breaks restoring

No delimiter choice fixes this. `!|EMAIL_1|` is rejected exactly as
`@@EMAIL_1@` was — neither is silently restored, which is the important
part, but neither comes back either.

```python
if leftover := anonymizer.leaked(answer, vault):
    return fallback()
```

That check is not optional in a production path.

## Some values are genuinely ambiguous

Over-masking costs as much as under-masking. A value replaced by a token is a
value the model cannot reason about, so a log line whose byte count became
`!|PHONE_1|!` is a question the assistant can no longer answer — and the
reader has no idea why.

Measured against twenty sentences of ordinary engineering prose, one is still
touched at every level:

```
"Room 221B has 14 chairs and seats 42 people."   ->   UNIT_NUMBER
```

`Room 221B` in an address *is* a unit number. In that sentence it is a
meeting room. No pattern separates them, because the difference is meaning
rather than shape. The same holds for a bare ten-digit integer: `1073741824`
is a gibibyte and also the length of a phone number.

Where it matters, say so:

```python
Anonymizer(whitelist={"patterns": [r"\bRoom \w+ has\b", r"\d+ bytes\b"]})
```

Four others were fixed rather than documented, because they were defects and
not ambiguity: a bare seven-digit integer read as a phone number, an ISBN
read as one, `policy allows 3 retries` read as a policy number, and
`Policy No: 9988776655` labelled PHONE — protected, but under a label a
caller whitelisting `policy_number` would never reach.

## Vocabulary detection produces false positives

The special categories are word lists, because there is no *shape* to a
religion. So "trans", "cis", "strike", "chronic", "mi" and "dl" all match
something they should not in a technical sentence.

`TECHNICAL_HOMONYMS` blunts the common ones, and `STRICT` is opt-in rather
than the default for this reason. Beyond that it is your whitelist's job, and
`suggest_whitelist()` is how to build one from real text rather than guesses.

## Overlapping detectors mean the label is a choice

The first detector to claim a span wins. An IP address is also a punctuated
digit run; a Stripe key is also a high-entropy blob. The order is chosen so
the more specific one wins, but it means:

- whitelisting one `label` can leave a looser detector claiming the value
- `values` is compared against the whole match, which may be wider than you
  expect

[Whitelisting](whitelisting.md) covers both, and `explain()` shows which span
was claimed.

## A vault is as sensitive as the input

It maps tokens back to original values. Storing one moves the exposure rather
than removing it; logging one undoes the whole exercise. `summary()` is the
part that is safe to write down.

And a token means nothing without its vault. Two vaults mint the same strings
unless you use `Vault.scoped()`, so never merge two and never persist tokens
without the vault that explains them.

## Numbers and bytes are left alone

A number has no delimiters to tokenize into, and coercing it would change the
type of data passing through. `stringify_numbers=True` opts in.

`bytes` is skipped entirely — it is a `Sequence`, and walking one would turn a
blob into a list of integers.

## Depth is capped, not detected

A structure 64 levels deep stops being walked rather than raising. A cycle is
not detected; the cap is what stops the recursion, because cycle detection at
every node costs more than it saves.

## Terms are literal and word-bounded

`terms={"employer": ["Initech"]}` matches `Initech`, not `Initech Inc` as a
unit and not `initech.com` as a whole. For anything with structure, write a
`Detector` with a pattern.

## Only one language's worth of vocabulary

The special-category word lists are English. A detector built from
`SpecialCategories.category_detector(category, terms)` takes any vocabulary
you supply, but the shipped lists will not catch a disclosure in another
language.

## It is not a DLP product

No scanning of files at rest, no policy server, no audit trail, no
classification taxonomy. It anonymizes text you hand it, in-process, and
hands the mapping back to you. Everything else is yours to build.

## An unserialized connection loses operations

`DatabaseVaultStore(..., serialize=False)` with a driver that is not
thread-safe loses operations under contention — measured on sqlite3 with one
connection and sixteen threads, about a third of them, as raised errors,
missed rows and unresolved tokens.

None of them came back as another caller's value, because the scope marker
stops a token resolving in the wrong vault. But "fails loudly" is the most
that can be promised there, and the default exists so you do not have to
rely on it.
