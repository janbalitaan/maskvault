"""Every tunable number in one place.

These are the values someone adjusts when the library is too aggressive or
not aggressive enough. Scattered through the modules that use them they are
effectively undiscoverable; collected here they can be read, reviewed and
changed as a set.

What is deliberately *not* here: the private regexes each function uses to do
its own job. `_ISO_DATE` in the phone validator and `_HEX` in the entropy
classifier are implementation detail for one function, and moving them away
from that function would make both harder to read. A constant earns a place
in this file by being something a user might want to change.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Token format
# ---------------------------------------------------------------------------

# The default placeholder shape. Delimiters are chosen per operation by
# models.token_format, because no delimiter is safe in every markup language,
# so these two are the fallback for code holding no format of its own.
# Not a credential, despite the name — bandit flags anything called TOKEN.
TOKEN_TEMPLATE = "[[{label}_{index}]]"  # noqa: S105
TOKEN_REGEX = r"\[\[([A-Z_]+)_(\d+)\]\]"  # noqa: S105


# ---------------------------------------------------------------------------
# Phone numbers
# ---------------------------------------------------------------------------

# E.164 sets the upper bound. The lower bound excludes short numbers that are
# far more often quantities than phone numbers.
PHONE_MIN_DIGITS = 7
PHONE_MAX_DIGITS = 15


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

# Below this length, entropy is too noisy to act on.
ENTROPY_MIN_LENGTH = 20

# Shannon entropy in bits per character, above which a candidate is treated
# as a secret. Thresholds differ by alphabet because a smaller alphabet caps
# the achievable entropy: hex can only reach log2(16) = 4.0, so demanding 4.5
# of it would never match.
HEX_THRESHOLD = 3.0
BASE64_THRESHOLD = 4.0
MIXED_THRESHOLD = 3.5

# A secret almost always draws on more than one character class. Prose and
# snake_case identifiers draw on one.
MIN_CHARACTER_CLASSES = 2

# The alphabet for candidate tokens. Punctuation is excluded so a run of
# prose is not read as one long candidate.
TOKEN_ALPHABET = r"A-Za-z0-9+/=_\-"  # noqa: S105

# A password is a different shape: short, and containing punctuation. With the
# token alphabet it splits at the first symbol, so the relaxed mode widens to
# any non-space character — at the cost of matching more non-secrets.
PASSWORD_ALPHABET = r"\S"  # noqa: S105

# What the PARANOID level changes: a shorter candidate and a lower bar.
PARANOID_MIN_LENGTH = 16
PARANOID_RELAX_BY = 0.5


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

# Stripped from both ends before an allowlist comparison, because a detector
# may hand over a value with sentence punctuation attached.
TRAILING_PUNCTUATION = " .,;:!?\"'()[]{}<>"
