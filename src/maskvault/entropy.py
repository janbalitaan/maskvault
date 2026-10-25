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

import re

from maskvault.constants import (
    ENTROPY_MIN_LENGTH,
    PASSWORD_ALPHABET,
    TOKEN_ALPHABET,
)
from maskvault.models.entropy_thresholds import EntropyThresholds
from maskvault.models.entropy_verdict import EntropyVerdict
from maskvault.utils.text import TextMetrics

_HEX = re.compile(r"^[0-9a-fA-F]+$")
_BASE64ISH = re.compile(r"^[A-Za-z0-9+/_\-]+={0,2}$")


# Candidate tokens: long unbroken runs that could be a secret. Split on
# whitespace and the punctuation that surrounds values in real text.


class Entropy:
    """Measures how much a candidate looks generated rather than written.

    Static methods throughout: there is no state to carry, and the four
    conditions above are a calculation rather than a configuration. Grouping
    them names the subject, so a reader looking for "how does this decide
    something is random" has one place to go.
    """

    @staticmethod
    def candidate_pattern(
        min_length: int = ENTROPY_MIN_LENGTH, include_symbols: bool = False
    ) -> re.Pattern[str]:
        """Candidate tokens of at least `min_length` characters.

        `include_symbols` widens the alphabet to any non-space character, which
        keeps a punctuated password in one piece.
        """
        alphabet = PASSWORD_ALPHABET if include_symbols else TOKEN_ALPHABET
        return re.compile(rf"[{alphabet}]{{{max(min_length, 8)},}}")

    # Shapes that are long and random-looking but are not secrets. Checked before
    # entropy, because each would otherwise be a confident false positive.
    # Values that measure as random but are known not to be secrets.
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

    @staticmethod
    def classify(
        candidate: str,
        relax_by: float = 0.0,
        min_length: int = ENTROPY_MIN_LENGTH,
        thresholds: EntropyThresholds | None = None,
    ) -> EntropyVerdict:
        """Decide whether a single token looks like a secret.

        `relax_by` lowers each bar together, trading false positives for
        coverage. `thresholds` sets them individually, for tuning against one
        codebase's actual traffic — see `EntropyThresholds`. Passing both
        applies `relax_by` on top of the given bars.
        """
        bars = thresholds or EntropyThresholds()
        if relax_by:
            bars = EntropyThresholds(
                hex=max(bars.hex - relax_by, 0.0),
                base64=max(bars.base64 - relax_by, 0.0),
                mixed=max(bars.mixed - relax_by, 0.0),
                minimum_classes=bars.minimum_classes,
            )
        classes = TextMetrics.character_classes(candidate)
        entropy = TextMetrics.shannon_entropy(candidate)
        min_length = max(min_length, 8)

        # Whitespace means this is prose, not a token. Checked first because it
        # is the strongest signal available: entropy cannot tell a varied English
        # phrase from a generated string, and this can.
        if TextMetrics.contains_whitespace(candidate):
            return EntropyVerdict(
                candidate,
                entropy,
                classes,
                "prose",
                False,
                "contains whitespace, so not a token",
            )

        if len(candidate) < min_length:
            return EntropyVerdict(
                candidate, entropy, classes, "short", False, "too short to judge"
            )

        for safe in Entropy._KNOWN_SAFE:
            if safe.match(candidate):
                return EntropyVerdict(
                    candidate, entropy, classes, "known", False, "a known non-secret shape"
                )

        if _HEX.match(candidate):
            alphabet = "hex"
        elif _BASE64ISH.match(candidate):
            alphabet = "base64"
        else:
            alphabet = "mixed"
        threshold = bars.for_alphabet(alphabet)

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
        if alphabet != "hex" and classes < bars.minimum_classes:
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

    @staticmethod
    def find_secrets(text: str) -> list[EntropyVerdict]:
        """Every token in the text that looks like a secret."""
        seen: set[str] = set()
        verdicts = []
        for match in CANDIDATE.finditer(text):
            candidate = match.group(0)
            if candidate in seen:
                continue
            seen.add(candidate)
            verdict = Entropy.classify(candidate)
            if verdict.is_secret:
                verdicts.append(verdict)
        return verdicts

    @staticmethod
    def looks_like_a_secret(
        candidate: str,
        relax_by: float = 0.0,
        min_length: int = ENTROPY_MIN_LENGTH,
        thresholds: EntropyThresholds | None = None,
    ) -> bool:
        """Whether a token should be treated as a secret. Used as a Detector validator."""
        return Entropy.classify(
            candidate,
            relax_by=relax_by,
            min_length=min_length,
            thresholds=thresholds,
        ).is_secret

    # The measurement functions moved to utils.text when the domain logic and the
    # arithmetic were separated. Kept as names here because they are public API.
    shannon_entropy = TextMetrics.shannon_entropy
    character_classes = TextMetrics.character_classes


# Built once at import, because the default candidate pattern never varies and
# compiling it per call showed up in a profile.
CANDIDATE = Entropy.candidate_pattern()
