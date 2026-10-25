# Whitelisting

Strictness is only usable if you can take it back. Nine mechanisms, checked
in this order, plus a predicate for whatever is left.

| | Matches | Example |
| --- | --- | --- |
| `labels` | turns a whole detector off | `{"url", "age"}` |
| `categories` | turns a special category off | `{"health"}` |
| `values` | the whole match, case-insensitive | `{"Python", "FastAPI"}` |
| `words` | a single word, word-bounded | `{"black", "native"}` |
| `contains` | the substring anywhere in the match | `{"github.com"}` |
| `prefixes` | the match starts with this | `{"https://mysite.dev/"}` |
| `suffixes` | the match ends with this | `{"@mycompany.com"}` |
| `domains` | an email or URL on this domain | `{"mycompany.com"}` |
| `patterns` | regexes | `[r"^EMP-\d{4}$"]` |
| `predicate` | any callable — Python only | `lambda v: v.startswith("ok")` |

```python
from maskvault import Anonymizer

Anonymizer(whitelist={
    "labels": ["url"],
    "domains": ["mycompany.com"],
    "values": ["Python", "FastAPI"],
})
```

## Nothing is allowed by default

Deciding what is harmless is the one judgement this library cannot make, so
it makes none: within a level, every detector runs unless you say otherwise.
The value that leaks is the one nobody thought to configure.

Which would make configuring it a guessing game, so it is not:

```python
anonymizer = Anonymizer(level="strict")
draft = anonymizer.suggest_whitelist(real_input)
```

```json
{
  "values": ["alice@acme.com", "Python", "FastAPI"],
  "labels": [],
  "note": "a draft: remove anything that should stay protected"
}
```

Run real input through it, read the list, delete anything that should stay
protected, and keep the rest as config. `suggest_whitelist` omits destroyed
values by default — suggesting a credential for the allowlist is the one
suggestion it must not make.

## A label turns a detector off, not a value on

Worth knowing rather than discovering. `labels` removes a detector entirely,
so a value two detectors could claim is then taken by the other:

```python
Anonymizer(whitelist={"labels": ["ip_address"]}).anonymize("from 10.42.7.19")
# "from !|PHONE_1|!"      an IP is also a punctuated digit run
```

When you want a *value* kept whatever matches it, say so:

```python
Anonymizer(whitelist={"values": ["10.42.7.19"]})       # exactly this
Anonymizer(whitelist={"patterns": [r"10\.\d+\.\d+\.\d+"]})   # this shape
```

## `values` is the whole match, which is not always the value

A detector can claim more text than you expect. The entropy net takes the
whole assignment, so an exact entry for the key alone does not match it:

```python
KEY = "sk_live_NOTAREALKEYEXAMPLE"

Anonymizer(whitelist={"values": [KEY]}).anonymize(f"key={KEY}")
# still removed — the entropy candidate was "key=sk_live_..."

Anonymizer(whitelist={"contains": [KEY]}).anonymize(f"key={KEY}")
# kept
```

`contains` or `patterns` is the answer when another detector may take a wider
span. `explain()` shows you which span was claimed.

## A key that will not be read raises

A typo in a whitelist key used to be ignored, which left you debugging why a
value was still replaced with no way to see the key was never looked at:

```python
Anonymizer(whitelist={"regexes": [r"x"]})
# WhitelistError: unrecognized whitelist key: 'regexes' (did you mean
# 'patterns'?). Recognized keys are: categories, contains, domains, labels,
# patterns, prefixes, suffixes, values, words
```

The suggestion is mapped rather than guessed by string distance, which would
have pointed at `prefixes` — a different mechanism entirely.

Two keys are special:

- **`note`**, `comment` and `_comment` are accepted and carry no policy, so a
  JSON config can explain itself. JSON has no comments, and
  `suggest_whitelist` emits a note.
- **`predicate`** is refused with its reason: it takes a callable, and a
  config file should not be able to introduce executable code. Pass it to
  `Whitelist(predicate=...)` in Python.

## A predicate, for whatever is left

```python
from maskvault import Anonymizer, Whitelist

Anonymizer(whitelist=Whitelist(
    predicate=lambda value: value.endswith("@mycompany.com"),
))
```

No JSON form, deliberately. Everything else here is data.

## Starting from the common cases

```python
from maskvault import COMMON_SAFE_VALUES, Whitelist

Whitelist(values=set(COMMON_SAFE_VALUES))
```

Languages, frameworks, cloud providers and tools — the things a CV or a
support ticket mentions constantly and which identify nobody. Worth reading
before adopting; it is a starting point, not a policy.

## Merging

```python
platform = Whitelist(labels={"url"})
team = Whitelist(domains={"acme.com"})
Anonymizer(whitelist=platform.merge(team))
```

For a policy assembled from more than one place — a platform default and a
team addition.
