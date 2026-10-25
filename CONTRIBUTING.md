# Contributing to maskvault

The library's coverage is mostly data, not design, so adding a detector or a
vocabulary is the normal way to improve it and needs no familiarity with the
internals.

## Adding a detector

A detector is one dataclass:

```python
from maskvault.detectors import Action, Detector
import re

Detector(
    label="my_country_national_id",
    pattern=re.compile(r"\b\d{3}-\d{4}-\d{6}\b"),
    action=Action.REVERSIBLE,
)
```

`label` becomes the token name, so `my_country_national_id` produces
`[[MY_COUNTRY_NATIONAL_ID_1]]`. Keep it lowercase with underscores.

`action` is the decision that matters:

- `Action.REVERSIBLE` — identifying but legitimate. Tokenized and restored.
- `Action.DESTROY` — a credential. Replaced with a `notice` and never
  restored. Use this only for things that should never have been in the text.

### When a pattern is not enough

Some values are not really regular expressions. A phone number is "a run of
digits that is phone-shaped", and encoding that grammar in one pattern
invites backtracking: the greedy part consumes too much, the engine retries
from a later position, and the match ends up covering only the middle of the
value. Half a phone number left in the output is worse than no match at all.

So a detector can carry a validator: match generously, decide in code.

```python
def is_my_id_shaped(candidate: str) -> bool:
    digits = sum(character.isdigit() for character in candidate)
    return digits == 13 and not candidate.startswith("0")

Detector(
    label="my_country_national_id",
    pattern=re.compile(r"(?<![\w.])[\d-]{13,17}(?![\w.])"),
    action=Action.REVERSIBLE,
    validate=is_my_id_shaped,
)
```

Prefer this over a clever pattern. It is easier to read, easier to test, and
does not backtrack.

### Ordering

Detectors run in order and the first match claims the span. Put specific
formats before generic ones — otherwise a vendor key is claimed by the
generic entropy net and loses its label.

## Adding a vocabulary

`src/maskvault/personal.py` holds the special categories as frozensets. To
add a language, add a set and register it:

```python
HEALTH_TERMS_ES: frozenset[str] = frozenset({
    "diabetes", "cáncer", "embarazo", ...
})

SPECIAL_CATEGORIES["health_es"] = HEALTH_TERMS_ES
```

Terms are matched case-insensitively with word boundaries, longest first, so
multi-word terms work and short terms do not match inside longer words.

**Check for homonyms.** Before adding a term, consider whether it has an
ordinary meaning in technical text. If it does, add it to
`TECHNICAL_HOMONYMS` in `whitelist.py` as well, so developers running
`STRICT` over code are not ambushed by it.

## Tests

Every detector needs tests in **both** directions:

```python
def test_it_catches_a_real_one(self):
    safe, vault = anonymizer.anonymize("my id is 123-4567-890123")
    assert "123-4567-890123" not in safe

def test_it_leaves_this_alone(self):
    safe, _ = anonymizer.anonymize("version 1.2.3 released 2024-06-01")
    assert "2024-06-01" in safe
```

The second test is the important one. A detector with only positive tests is
the one that over-matches in someone else's data.

For anything that replaces a span, also assert **nothing partial is left**:

```python
assert not re.findall(r"\d{3,}", safe)
```

That single assertion catches the most common detector defect: a match that
covers part of a value and leaves the rest behind.

## Running the checks

```bash
uv sync
uv run pytest
uv run ruff check src tests
uv run ty check src
```

All three must pass. Conventions the linter enforces, so you do not have to
remember them: absolute imports only, no relative imports, imports at the top
of the file, and a docstring on every public class and method.

## Things to discuss before building

Open an issue first for these, because they change the shape of the library:

- **Format-preserving tokens**, so `[[PHONE_1]]` looks like a phone number.
  Wanted, but it interacts with uniqueness and restoration.
- **Deterministic tokens** via HMAC, so the same value yields the same token
  across processes without sharing a vault.
- **Structured input** — anonymizing dicts, JSON and dataframes recursively
  rather than only strings.
- **An optional NLP backend** for name detection. The zero-dependency core is
  deliberate, so this would have to be an extra.

## What will not be merged

- A dependency in the core package. Zero dependencies is the point; optional
  extras are the mechanism for anything heavier.
- A detector with no negative test.
- A claim of compliance with any regulation.
