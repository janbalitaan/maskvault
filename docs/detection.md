# Detection

Four families of detector, and the order they run in is correctness rather
than preference.

## The two actions

| | What happens | When |
| --- | --- | --- |
| `REVERSIBLE` | replaced with a token, restored afterwards | identifying but legitimate |
| `DESTROY` | replaced with a notice, never restored | must not be sent, must not come back |

A destroyed value coming back would mean this library handed a credential to
a provider and then handed it onward. The notice is there so you can see it
happened.

## Vendor credentials — by published format

Issuers publish the shape of their credentials, which makes these the one
kind of secret recognizable from the value alone. Nineteen of them: AWS
access and secret keys, Slack, Stripe, Twilio, SendGrid, npm, PyPI and
HashiCorp tokens, JWTs, SSH public keys, connection strings with embedded
credentials, Basic and Bearer headers, environment assignments.

All destructive, because a credential that came back is the failure this
library exists to prevent.

## The entropy net — for what nobody published

A detector list catches the formats it knows. It misses a session cookie, a
database password, a signed URL, a token from a vendor nobody has heard of.
What those share is *randomness*, and Shannon entropy measures it.

But entropy alone is a weaker signal than it looks. "the quick brown fox
jumps" scores above 4 bits simply because it barely repeats a character — so
entropy is one of four conditions:

| Condition | Why |
| --- | --- |
| one token | no whitespace. Prose is words; a secret is one run of characters — and this separates more than the entropy figure does |
| long enough | below 20 characters entropy is too noisy to act on |
| random enough | above the threshold for the candidate's alphabet (hex, base64, mixed) |
| varied enough | a secret usually mixes cases, digits or symbols |

Each alone produces false positives. Together they are precise, and the tests
pin both directions.

```python
from maskvault import Entropy

Entropy.classify("aB3dE5fG7hJ9kL1mN3pQ5rS7")
# EntropyVerdict(is_secret=True, entropy=4.33, alphabet='base64', ...)

Entropy.classify("abcdefghijklmnopqrstuvwxyz")
# EntropyVerdict(is_secret=False, reason='fewer than 2 character classes', ...)
```

`find_secrets()` returns only confirmed secrets — the name is the contract.
`classify()` is what explains a candidate either way, which is the method to
use when adjusting a threshold.

## Personal identifiers — by shape

National IDs, passports, IBANs, IP and MAC addresses, dates of birth, street
addresses, postal codes, coordinates, licences, plates, tax IDs, bank and
policy numbers, employee IDs, salaries, social handles, ages.

Reversible: a model may legitimately need to reason about an address or a
salary band, and your reader needs the real one back.

## Special categories — by vocabulary

At `STRICT` and above. Health, religion, politics, identity, origin, criminal
and financial history — the GDPR Article 9 groupings.

Vocabulary-driven, because there is no shape to a religion. That makes them
the most false-positive-prone, which `TECHNICAL_HOMONYMS` exists to blunt:

```python
from maskvault import TECHNICAL_HOMONYMS
# "trans", "cis", "strike", "chronic", "mi", "dl", "x" ...
```

Each of those means something else in a technical sentence, so they are
excluded from vocabulary matching by default.

## Order is correctness, not preference

The first detector to claim a span wins, so the order decides the label — and
sometimes the action.

```
vendor credentials      destroy   a known format wins over everything
destructive general     destroy   api_key, private_key, passwords, cards
precise identifiers     reverse   ip_address before phone: an IP is also a
                                  punctuated digit run
contact details         reverse   email before social_handle: an address is
                                  unambiguous, a handle is "a platform name
                                  followed by something"
structured personal     reverse
special categories      reverse   at STRICT and above
the entropy net         destroy   last, so a known format is labelled rather
                                  than destroyed as an anonymous blob
```

Getting this wrong is subtle. `ip_address` used to run *after* `phone`, so
`10.42.7.19` was labelled `PHONE` — the value survived, but a caller
whitelisting `ip_address` found it had no effect.

## Adding your own

```python
import re
from maskvault import Action, Anonymizer, Detector

internal_id = Detector(
    label="internal_id",
    pattern=re.compile(r"\bEMP-\d{6}\b"),
    action=Action.REVERSIBLE,
)

Anonymizer(detectors=(*Registry.all_detectors(), internal_id))
```

A keyword-led pattern should capture only the value, so the token does not
swallow the keyword:

```python
Detector(
    label="session",
    pattern=re.compile(r"session=(\S+)"),
    action=Action.DESTROY,
    group=1,      # replace the capture, not the whole match
)
```

A group that does not exist is refused at construction. Falling back to the
whole match would look like the detector working while the token silently
covered the keyword too.

## When a pattern has to stay loose

The phone pattern matches any punctuated digit run and decides in code,
because a regex strict enough for every international format is strict enough
to backtrack badly — and a backtracking match covers only the middle of a
number, which is worse than no match at all.

```python
Detector(..., validate=PhoneShape.looks_like_a_phone_number)
```

The cost is that the validator has to reject everything else shaped like a
digit run. A timestamp is the common one: `2026-10-25 14:02:11` has ten
digits, and an anchored date check only rejects a date standing alone.
