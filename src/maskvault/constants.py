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

from collections.abc import Mapping
from types import MappingProxyType

# ---------------------------------------------------------------------------
# Token format
# ---------------------------------------------------------------------------

# The default placeholder shape. Delimiters are chosen per operation by
# models.token_format, because no delimiter is safe in every markup language,
# so these two are the fallback for code holding no format of its own.
# Not a credential, despite the name — bandit flags anything called TOKEN.
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


# ---------------------------------------------------------------------------
# Structured data
# ---------------------------------------------------------------------------

# How deep to walk a nested structure. A structure referencing itself would
# otherwise recurse forever, and a depth cap is cheaper than checking every
# node for a cycle.
MAX_STRUCTURE_DEPTH = 64

# How much of a structure's text to read before choosing a token format. The
# format only has to avoid colliding with delimiters already in the text, and
# a few kilobytes is a representative sample of any structure — walking a
# large one in full would cost more than the choice is worth.
SAMPLE_LIMIT = 4096

# Names a developer plausibly reaches for, mapped to the real key. String
# similarity alone suggests "prefixes" for "regexes", which sends someone to
# the wrong mechanism — so the cases where distance misleads are listed.
KEY_ALIASES: Mapping[str, str] = MappingProxyType(
    {
        "regex": "patterns",
        "regexes": "patterns",
        "regexps": "patterns",
        "pattern": "patterns",
        "label": "labels",
        "value": "values",
        "word": "words",
        "domain": "domains",
        "category": "categories",
        "categorys": "categories",
        "allow": "values",
        "allowlist": "values",
        "exact": "values",
        "substring": "contains",
        "substrings": "contains",
        "startswith": "prefixes",
        "endswith": "suffixes",
    }
)

# Keys a config file may carry that are read but hold no policy. `note` is
# here because `suggest_whitelist` emits one and its output is documented as
# usable as config — and because JSON has no comments, so a config file has
# nowhere else to explain itself.
IGNORED_KEYS = frozenset({"note", "notes", "comment", "_comment", "description"})

# Keys that are recognized and deliberately refused, with the reason. A
# generic "unrecognized key" would send someone looking for a typo when the
# real answer is that the mechanism does not exist in JSON on purpose.
REFUSED_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "predicate": (
            "a predicate takes a callable, and a config file should not be able "
            "to introduce executable code. Pass it to Whitelist(predicate=...) "
            "in Python instead"
        ),
    }
)

# The whitelist keys a config file may use. `predicate` is absent on purpose:
# it takes a callable, and a config file should not be able to introduce
# executable code. Kept here so the set a reader sees and the set the code
# checks are the same one.
JSON_KEYS = frozenset(
    {
        "labels",
        "categories",
        "values",
        "words",
        "contains",
        "prefixes",
        "suffixes",
        "domains",
        "patterns",
    }
)

# How many letters go into a scoped vault's marker. Letters rather than hex
# digits, because the scope is part of the label and the default label pattern
# accepts only `[A-Z_]`. Four letters gives 456,976 values: enough that two
# vaults in one deployment will not collide, short enough that the token stays
# something a model copies back without reformatting it.
# Letters in a scoped vault's marker. The marker is what makes a vault mix-up
# visible, so its collision resistance bounds that safety directly, and the
# birthday bound governs: with n vaults in flight the chance two share a
# marker is about 1 - exp(-n^2 / 2 * 26^letters).
#
#   letters   1,000 vaults   1,000,000 vaults
#         4         66%             ~1
#         8        4e-6            90.9%
#        12       2e-14          0.0005%
#        16      1e-22           1.1e-11
#
# Twelve is the default: negligible at a million, and thirteen characters per
# token rather than seventeen. A system larger than that raises `letters`, and
# one that already has a unique id per conversation should use
# `Vault.for_key()` instead, where uniqueness is inherited rather than hoped
# for.
SCOPE_LETTERS = 12

# How long a stored vault lives by default. A vault holds plaintext originals,
# so its lifetime is the window in which they are exposed — long enough for a
# provider call and a follow-up, short enough that a forgotten entry does not
# sit in memory for the life of the process.
VAULT_TTL_SECONDS = 15 * 60
