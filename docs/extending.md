# Extending without waiting for a release

A pattern in a library is a liability on someone else's release cycle. A
vendor changes a key format. A region writes phone numbers differently. A
detector fires on something harmless in your codebase and nowhere else. A
word list is English and your users are not.

None of those should mean opening an issue and waiting, so none of them do.

## Adjust a shipped set by label

```python
from maskvault import Anonymizer, Levels, Level

detectors = Levels.detectors_for(
    Level.STANDARD,
    replace={"aws_access_key": my_better_pattern},   # it is out of date
    without=("age", "salary"),                       # noise in this codebase
    add=(my_extra_check,),                           # nothing would know this
    add_first=(my_internal_id,),                     # and it has to win
    extra_terms={"health": ["long covid"]},          # a word the list misses
)
anonymizer = Anonymizer(detectors=detectors)
```

Four operations, one call. `Registry.all_detectors` takes the first three too.

**A replacement keeps its position.** The shipped ordering is a correctness
guarantee — specific before generic, destructive before reversible, entropy
last — so a replacement takes the slot of what it replaced rather than going
on the end.

**`add` appends; `add_first` prepends.** Appending is right for a detector
catching what the shipped ones missed. It is wrong for one that has to *win*
a span a shipped detector would claim, and an internal identifier is exactly
that — `EMP-004212` is a punctuated digit run, so the phone detector takes it
unless something runs earlier:

```python
Levels.detectors_for(Level.STANDARD, add=(mine,))        # see EMP-!|PHONE_1|!
Levels.detectors_for(Level.STANDARD, add_first=(mine,))  # see !|INTERNAL_ID_1|!
```

**By label, not by index.** The order of a shipped list is an implementation
detail, and code pinned to a position in it breaks on an upgrade.

**A label that is not there raises.** The usual cause is a typo or a label a
version renamed, and silently doing nothing would leave you believing a
replacement was in effect while the original was still running:

```
DetectorError: without names a detector that is not in this set:
aws_acces_key. Available labels are: age, api_key, aws_access_key, ...
```

## Replace a pattern

The patterns are importable, so a replacement can build on one rather than
start from nothing:

```python
import re
from maskvault import Action, Detector
from maskvault.patterns import AWS_ACCESS_KEY   # 41 named patterns

better = Detector(
    label="aws_access_key",
    pattern=re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    action=Action.DESTROY,
    notice="[an AWS key was removed]",
)
```

A keyword-led pattern should capture only the value, so the token does not
swallow the keyword:

```python
Detector(
    label="session",
    pattern=re.compile(r"session=(\S+)"),
    action=Action.DESTROY,
    group=1,
)
```

A `group` the pattern does not have is refused at construction, because
falling back to the whole match would look like the detector working.

## Tune the phone bounds

Seven to fifteen digits covers the ITU E.164 range and most national
formats. A four-digit short code and a six-digit internal extension are both
real and both outside it:

```python
from maskvault import Action, Detector, PhoneShape
from maskvault.patterns import PHONE

regional = Detector(
    label="phone",
    pattern=PHONE,
    action=Action.REVERSIBLE,
    validate=PhoneShape.bounded(6, 12),
)
Levels.detectors_for(Level.STANDARD, replace={"phone": regional})
```

`bounded` keeps the date-and-time exclusion the validator exists for, so a
timestamp is still not read as a phone number.

## Tune the entropy bars

```python
from maskvault import EntropyDetector, EntropyThresholds, Levels, Level

# A repository full of hex digests, where the default bar misfires.
detector = EntropyDetector.build(thresholds=EntropyThresholds(hex=2.5))
Levels.detectors_for(Level.STANDARD, replace={"high_entropy": detector})
```

One bar per alphabet, because the maximum differs: hex tops out at 4 bits per
character, base64 at 6, an unconstrained alphabet higher still. A single
number would be too strict for hex or too loose for the rest.

`EntropyThresholds().relaxed_by(0.5)` lowers all of them together, which is
what `PARANOID` does. A negative bar or `minimum_classes=0` is refused —
both would accept everything of the right shape.

## Extend a vocabulary

```python
from maskvault import SpecialCategories

SpecialCategories.vocabularies({"health": ["long covid", "neuropathy"]})
SpecialCategories.vocabularies({"salud": ["hipertensión"]})   # a new category
```

A name already shipped is **extended**, not replaced. A caller adding one
term almost never means "and discard the other hundred", and the version that
silently did would be a privacy regression dressed as a convenience.

To replace a vocabulary outright, pass your own set to `category_detector`:

```python
SpecialCategories.category_detector("health", frozenset({"neuropathy"}))
```

Terms are lower-cased, because matching is case-insensitive and a capitalized
entry would look like it worked while matching nothing extra.

### `extra_terms` is not `terms`

Two options take word lists and they do different jobs:

| | |
| --- | --- |
| `Anonymizer(terms=...)` | literals **you** name, with **your** label, always on |
| `extra_terms=...` | adds to a **shipped special-category** vocabulary, which only runs at `STRICT` and above |

```python
# "Initech" is my client's name. Replace it, label it CLIENT, at every level.
Anonymizer(terms={"client": ["Initech"]})

# "long covid" is a health condition the shipped list misses. Treat it the
# way the other hundred health terms are treated — so only at STRICT.
Levels.detectors_for(Level.STRICT, extra_terms={"health": ["long covid"]})
```

Reaching for `extra_terms` to hide a company name does nothing at `STANDARD`,
which is the default. That is the mistake the similar names invite.

## What is deliberately not adjustable

**The shipped mappings are read-only.** `SPECIAL_CATEGORIES`,
`FORMATS_BY_NAME`, `KEY_ALIASES` and `REFUSED_KEYS` are `MappingProxyType`.
Assigning to one would change behaviour for every user in the process,
including a library that never asked — and in a library whose job is to not
miss things, detection turning itself off is the worst available failure. Every
one of them has an extension path that does not involve mutation.

**The order within a shipped set.** It is a correctness guarantee rather than
a preference, and `replace` exists so you never need to reorder to change a
pattern.

**That a destroyed value never returns.** Not by a setting, not by a flag.

## Where to put your configuration

A policy is code. It belongs beside your application, not in user input:

```python
# app/anonymizing.py
DETECTORS = Levels.detectors_for(
    Level.STRICT,
    replace={"phone": REGIONAL_PHONE},
    without=("age",),
    extra_terms={"health": LOCAL_HEALTH_TERMS},
)
ANONYMIZER = Anonymizer(detectors=DETECTORS, whitelist=WHITELIST)
```

One module, imported where it is needed, and `describe_policy()` logs what it
decided at startup.
