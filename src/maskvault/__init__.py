"""Reversibly replace private values before a prompt leaves your process.

Redaction is one-way: it removes a value and the value is gone. This is
reversible. A value is replaced with a token before the prompt is sent, and
the token is replaced with the original in the answer that comes back — so the
provider never sees it, and your user still gets a correct answer.

    from maskvault import Anonymizer

    anonymizer = Anonymizer(terms={"ORG": ["Acme Corp"], "CLIENT": ["Initech"]})
    safe, vault = anonymizer.anonymize(prompt)
    reply = call_your_model(safe)          # provider sees [[ORG_1]]
    answer = anonymizer.restore(reply, vault)   # user sees Acme Corp

Credentials are treated differently: an API key, a private key, a password
assignment or a card number is destroyed rather than tokenized, and never
restored. If one of those appears in a prompt, something went wrong upstream
and quietly putting it back would hide the mistake.

No dependencies. A privacy filter that pulls in a dependency tree is a privacy
filter nobody can audit.
"""

from maskvault.anonymizer import (
    TOKEN_PATTERN,
    TOKEN_TEMPLATE,
    Anonymizer,
    Finding,
    Vault,
)
from maskvault.detectors import (
    DEFAULT_DETECTORS,
    PHONE_MAX_DIGITS,
    PHONE_MIN_DIGITS,
    Action,
    Detector,
    is_phone_shaped,
)
from maskvault.levels import Level, detectors_for
from maskvault.personal import SPECIAL_CATEGORIES, STRUCTURED_PERSONAL
from maskvault.whitelist import COMMON_SAFE_VALUES, TECHNICAL_HOMONYMS, Whitelist

__all__ = [
    "COMMON_SAFE_VALUES",
    "DEFAULT_DETECTORS",
    "PHONE_MAX_DIGITS",
    "PHONE_MIN_DIGITS",
    "SPECIAL_CATEGORIES",
    "STRUCTURED_PERSONAL",
    "TECHNICAL_HOMONYMS",
    "TOKEN_PATTERN",
    "TOKEN_TEMPLATE",
    "Action",
    "Anonymizer",
    "Detector",
    "Finding",
    "Level",
    "Vault",
    "Whitelist",
    "__version__",
    "detectors_for",
    "is_phone_shaped",
]
__version__ = "0.1.0"
