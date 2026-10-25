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

from maskvault.anonymizer import Anonymizer
from maskvault.constants import PHONE_MAX_DIGITS, PHONE_MIN_DIGITS, TOKEN_TEMPLATE
from maskvault.detectors import (
    DEFAULT_DETECTORS,
    PERSONAL_DATA,
    VENDOR_CREDENTIALS,
    EntropyDetector,
    PhoneShape,
    Registry,
)
from maskvault.entropy import Entropy
from maskvault.formats import DEFAULT_FORMATS, TokenFormats
from maskvault.levels import Levels
from maskvault.models import (
    Action,
    Detector,
    EntropyVerdict,
    Finding,
    Level,
    TokenFormat,
    Vault,
    Whitelist,
)
from maskvault.patterns import TOKEN as TOKEN_PATTERN
from maskvault.personal import STRUCTURED_PERSONAL, SpecialCategories
from maskvault.structured import anonymize_data, restore_data
from maskvault.vocabularies import (
    COMMON_SAFE_VALUES,
    SPECIAL_CATEGORIES,
    TECHNICAL_HOMONYMS,
)

__all__ = [
    "COMMON_SAFE_VALUES",
    "DEFAULT_DETECTORS",
    "DEFAULT_FORMATS",
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
    "Entropy",
    "EntropyDetector",
    "EntropyVerdict",
    "Finding",
    "Level",
    "Levels",
    "PhoneShape",
    "Registry",
    "SpecialCategories",
    "TokenFormat",
    "TokenFormats",
    "Vault",
    "Whitelist",
    "__version__",
    "anonymize_data",
    "restore_data",
]
__version__ = "0.1.0"
