"""Reversible anonymization with a vault.

Replace confidential values with tokens, pass the text through anything,
restore the originals afterwards. The destination is not the library's
business: it serves a prompt sent to a model, a log line shipped to a vendor,
a dataset handed to a contractor, a bug report pasted into a tracker, or a
support transcript read by a third party.

    from maskvault import Anonymizer, Level

    anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})

    safe, vault = anonymizer.anonymize("I work at Acme Corp, me@acme.com")
    # "I work at [[ORG_1]], [[EMAIL_1]]"

    result = send_somewhere(safe)
    final = anonymizer.restore(result, vault)

Two kinds of value, handled in opposite ways:

**Reversible** — identifying but legitimate. An employer, a phone number, a
salary, a health condition. Tokenized, then restored, so the third party never
sees it and your reader still gets a correct answer.

**Destroyed** — must never arrive and must never come back. An API key, a
private key, a card number, a connection string. Replaced with a notice and
not restored, because its presence means something went wrong upstream and
restoring it would hide the mistake.

An exact round trip therefore holds only when nothing was destroyed.

Strictness is a choice made once, with `Level`, and `Whitelist` lets anything
back through — by label, category, exact value, word, substring, prefix,
suffix, domain, regex, or an arbitrary predicate. Nothing is allowed by
default, and `Anonymizer.preview()` reports what would be replaced so a
policy can be built from real input rather than guesswork.

No dependencies, which is deliberate: a privacy filter nobody can audit is
not much of a privacy filter.
"""

from maskvault.anonymizer import TOKEN_TEMPLATE, Anonymizer
from maskvault.detectors import (
    DEFAULT_DETECTORS,
    PERSONAL_DATA,
    PHONE_MAX_DIGITS,
    PHONE_MIN_DIGITS,
    VENDOR_CREDENTIALS,
    all_detectors,
    entropy_detector,
    is_phone_shaped,
)
from maskvault.entropy import classify, find_secrets, shannon_entropy
from maskvault.levels import detectors_for
from maskvault.models import (
    COMMON_SAFE_VALUES,
    TECHNICAL_HOMONYMS,
    TOKEN_PATTERN,
    Action,
    Detector,
    EntropyVerdict,
    Finding,
    Level,
    Vault,
    Whitelist,
)
from maskvault.personal import (
    SPECIAL_CATEGORIES,
    STRUCTURED_PERSONAL,
    special_category_detectors,
)

__all__ = [
    "COMMON_SAFE_VALUES",
    "DEFAULT_DETECTORS",
    "PERSONAL_DATA",
    "PHONE_MAX_DIGITS",
    "PHONE_MIN_DIGITS",
    "SPECIAL_CATEGORIES",
    "STRUCTURED_PERSONAL",
    "TECHNICAL_HOMONYMS",
    "TOKEN_PATTERN",
    "TOKEN_TEMPLATE",
    "VENDOR_CREDENTIALS",
    "Action",
    "Anonymizer",
    "Detector",
    "EntropyVerdict",
    "Finding",
    "Level",
    "Vault",
    "Whitelist",
    "__version__",
    "all_detectors",
    "classify",
    "detectors_for",
    "entropy_detector",
    "find_secrets",
    "is_phone_shaped",
    "shannon_entropy",
    "special_category_detectors",
]
__version__ = "0.1.0"
