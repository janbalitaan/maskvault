# Levels

The main dial. Each level is a set of detectors, and a higher one is a
superset of the one below plus a lower bar for guessing.

```python
from maskvault import Anonymizer, Level

Anonymizer(level=Level.STANDARD)   # the default
Anonymizer(level="strict")         # a string works too
```

| Level | Detectors | Destroys | Restores | Adds over the one below |
| --- | --- | --- | --- | --- |
| `MINIMAL` | 19 | 19 | 0 | — credentials only |
| `STANDARD` | 41 | 19 | 22 | contact details, identifiers, structured personal data |
| `STRICT` | 47 | 19 | 28 | the GDPR Article 9 special categories |
| `PARANOID` | 47 | 19 | 28 | a lower entropy bar and a wider alphabet |

What each one is for:

## `MINIMAL` — credentials only

Nineteen detectors, all destructive: vendor API keys, private keys, password
assignments, card numbers, connection strings, auth headers, and the entropy
net for secrets whose format nobody anticipated.

Nothing is tokenized, so nothing is restored. Right when the text is already
yours to send and the only question is whether a credential slipped into it —
a log line, a stack trace, a support dump.

```python
Anonymizer(level=Level.MINIMAL).anonymize(
    "GET /users 200 in 42ms token=sk_live_NOTAREALKEYEXAMPLE"
)
# "GET /users 200 in 42ms token=[a Stripe key was removed before sending]"
```

## `STANDARD` — the default

Adds twenty-two reversible detectors: email, phone, URLs, IP and MAC
addresses, national IDs, passports, IBANs, dates of birth, street addresses,
postal codes, coordinates, licences, tax IDs, bank and policy numbers,
employee IDs, salaries, social handles, ages.

The level to reach for when text is going to a provider and coming back. The
values are replaced and restored, so your reader sees a correct answer while
the provider sees tokens.

## `STRICT` — the special categories

Adds the six GDPR Article 9 groupings: health, religion, politics, identity,
origin, plus criminal and financial history. These are vocabulary-driven
rather than pattern-driven, because there is no *shape* to a religion — only
a list of words.

```python
Anonymizer(level=Level.STRICT).anonymize("I was treated for diabetes last year")
# "I was treated for !|HEALTH_1|! last year"
```

That makes them the most likely to produce a false positive, which is what
[whitelisting](whitelisting.md) and `TECHNICAL_HOMONYMS` exist for — "trans",
"strike", "cis" and "chronic" all mean something else in a technical
sentence.

## `PARANOID` — a lower bar

The same detectors as `STRICT`, with the entropy net tuned to fire more
easily: a shorter minimum candidate, a relaxed threshold, and symbols in the
alphabet so a punctuated password is caught.

More real secrets, more false positives. That is the trade the level exists
to make, and it is the right one when the cost of a miss is high and a human
reviews the output.

```python
Anonymizer(level=Level.PARANOID).anonymize("the password is Tr0ub4dour&3-horse")
# "the password is [a value that looked like a secret was removed before sending]"
```

## Seeing what a level includes

```python
from maskvault import Levels

[detector.label for detector in Levels.detectors_for("strict")]
```

Or from the shell, grouped by what happens to a match:

```bash
maskvault policy --level strict
```

## Composing your own

A level is a convenience, not a constraint. Pass detectors directly when you
want a set of your own:

```python
from maskvault import Anonymizer, Registry

Anonymizer(detectors=Registry.all_detectors(include_entropy=False))
```

Or add to a level with `terms`, for the things no pattern can find — an
employer, a client, a project name:

```python
Anonymizer(terms={"employer": ["Initech"], "client": ["Acme Corp"]})
```

Terms run before every detector, because a literal you named should win over
a generic pattern. They are reversible and appear in `explain()` like
anything else.
