"""Finding secrets that announce themselves only by looking random.

A detector list catches the formats it knows. It misses a session cookie, a
database password, a signed URL, a token from a vendor nobody has heard of —
anything whose shape was not anticipated.

What all of those share is *randomness*, and Shannon entropy measures it. But
per-character entropy is a weaker signal than it first appears: a short,
varied phrase such as "the quick brown fox jumps" scores above 4 bits simply
because it barely repeats a character. Entropy alone would call that a secret.

So entropy is only one of four conditions, and the others carry real weight:

    one token        no whitespace — prose is a sequence of words, a secret
                     is a single run of characters, and this does more
                     separating work than the entropy figure does
    long enough      below the minimum, entropy is too noisy to act on
    random enough    above the threshold for the candidate's alphabet
    varied enough    a secret usually mixes cases, digits or symbols

Each condition on its own produces false positives. Together they are
precise, and the tests pin both directions — real secrets caught, prose and
identifiers left alone.
"""

from __future__ import annotations

import math
import re

from maskvault.models.entropy_verdict import EntropyVerdict

# Below this, entropy is too noisy to judge.
MIN_LENGTH = 20

# Shannon entropy in bits per character. Thresholds differ by alphabet
# because a smaller alphabet caps the achievable entropy: hex can only reach
# log2(16) = 4.0, so demanding 4.5 of it would never match.
HEX_THRESHOLD = 3.0
BASE64_THRESHOLD = 4.0
MIXED_THRESHOLD = 3.5

# A secret almost always draws on more than one character class. Prose and
# snake_case identifiers draw on one.
MIN_CHARACTER_CLASSES = 2

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")


# Candidate tokens: long unbroken runs that could be a secret. Split on
# whitespace and the punctuation that surrounds values in real text.
# The default alphabet covers token-shaped secrets: API keys, hex digests,
# base64 blobs. It excludes punctuation on purpose, so a run of prose is not
# read as one long candidate.
TOKEN_ALPHABET = r"A-Za-z0-9+/=_\-"  # noqa: S105

# A password is a different shape. It is short, it contains punctuation, and
# with the token alphabet it splits at the first symbol — "k3yMaterial9xQ!zP"
# becomes two fragments, neither long enough to judge. This alphabet keeps it
# whole, at the cost of matching more non-secrets, which is why only the
# relaxed mode uses it.
PASSWORD_ALPHABET = r"\S"  # noqa: S105


def candidate_pattern(
    min_length: int = MIN_LENGTH, include_symbols: bool = False
) -> re.Pattern[str]:
    """Candidate tokens of at least `min_length` characters.

    `include_symbols` widens the alphabet to any non-space character, which
    keeps a punctuated password in one piece.
    """
    alphabet = PASSWORD_ALPHABET if include_symbols else TOKEN_ALPHABET
    return re.compile(rf"[{alphabet}]{{{max(min_length, 8)},}}")


CANDIDATE = candidate_pattern()

# Shapes that are long and random-looking but are not secrets. Checked before
# entropy, because each would otherwise be a confident false positive.
_KNOWN_SAFE = (
    # A UUID identifies something; it is not a credential on its own.
    re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    ),
    # A git commit SHA.
    re.compile(r"^[0-9a-f]{40}$"),
    # Semantic-version-ish and date-ish runs.
    re.compile(r"^[\d._-]+$"),
)


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character.

    The standard measure: sum over distinct characters of -p*log2(p), where p
    is that character's frequency in the string.
    """
    if not text:
        return 0.0
    length = len(text)
    counts: dict[str, int] = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def character_classes(text: str) -> int:
    """How many of lower, upper, digit and symbol appear."""
    return sum(
        (
            any(character.islower() for character in text),
            any(character.isupper() for character in text),
            any(character.isdigit() for character in text),
            any(not character.isalnum() for character in text),
        )
    )


def classify(
    candidate: str, relax_by: float = 0.0, min_length: int = MIN_LENGTH
) -> EntropyVerdict:
    """Decide whether a single token looks like a secret.

    `relax_by` lowers each threshold, trading false positives for coverage.
    """
    classes = character_classes(candidate)
    entropy = shannon_entropy(candidate)
    min_length = max(min_length, 8)

    # Whitespace means this is prose, not a token. Checked first because it
    # is the strongest signal available: entropy cannot tell a varied English
    # phrase from a generated string, and this can.
    if candidate != candidate.strip() or any(character.isspace() for character in candidate):
        return EntropyVerdict(
            candidate, entropy, classes, "prose", False, "contains whitespace, so not a token"
        )

    if len(candidate) < min_length:
        return EntropyVerdict(candidate, entropy, classes, "short", False, "too short to judge")

    for safe in _KNOWN_SAFE:
        if safe.match(candidate):
            return EntropyVerdict(
                candidate, entropy, classes, "known", False, "a known non-secret shape"
            )

    if _HEX.match(candidate):
        alphabet, threshold = "hex", HEX_THRESHOLD - relax_by
    elif _BASE64ISH.match(candidate):
        alphabet, threshold = "base64", BASE64_THRESHOLD - relax_by
    else:
        alphabet, threshold = "mixed", MIXED_THRESHOLD - relax_by

    if entropy < threshold:
        return EntropyVerdict(
            candidate,
            entropy,
            classes,
            alphabet,
            False,
            f"entropy {entropy:.2f} below {threshold} for {alphabet}",
        )

    # Hex is single-class by definition, so the diversity rule cannot apply.
    if alphabet != "hex" and classes < MIN_CHARACTER_CLASSES:
        return EntropyVerdict(
            candidate,
            entropy,
            classes,
            alphabet,
            False,
            f"only {classes} character class",
        )

    return EntropyVerdict(
        candidate,
        entropy,
        classes,
        alphabet,
        True,
        f"entropy {entropy:.2f} over {threshold} for {alphabet}",
    )


def find_secrets(text: str) -> list[EntropyVerdict]:
    """Every token in the text that looks like a secret."""
    seen: set[str] = set()
    verdicts = []
    for match in CANDIDATE.finditer(text):
        candidate = match.group(0)
        if candidate in seen:
            continue
        seen.add(candidate)
        verdict = classify(candidate)
        if verdict.is_secret:
            verdicts.append(verdict)
    return verdicts


def looks_like_a_secret(
    candidate: str, relax_by: float = 0.0, min_length: int = MIN_LENGTH
) -> bool:
    """Whether a token should be treated as a secret. Used as a Detector validator."""
    return classify(candidate, relax_by=relax_by, min_length=min_length).is_secret
