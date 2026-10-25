"""Measuring a string, without interpreting it."""

from __future__ import annotations

import math


class TextMetrics:
    """Measurements over a string.

    Static methods rather than instance ones: these are calculations with no
    state, and requiring a caller to construct something before reaching a
    pure function buys nothing. The class is here to group them under one
    name, so a reader looking for "how is entropy measured" has one place to
    look.
    """

    @staticmethod
    def shannon_entropy(text: str) -> float:
        """Bits of entropy per character.

        The standard measure: the sum over distinct characters of
        -p*log2(p), where p is that character's frequency in the string.

        Worth knowing what this does *not* tell you. A short varied phrase
        scores like a generated string — "the quick brown fox jumps" is over
        4 bits — because it barely repeats a character. Entropy separates
        repetitive text from varied text, not prose from secrets.
        """
        if not text:
            return 0.0
        length = len(text)
        counts: dict[str, int] = {}
        for character in text:
            counts[character] = counts.get(character, 0) + 1
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    @staticmethod
    def character_classes(text: str) -> int:
        """How many of lower, upper, digit and symbol appear.

        A generated secret usually draws on more than one. Prose and
        snake_case identifiers draw on one.
        """
        return sum(
            (
                any(character.islower() for character in text),
                any(character.isupper() for character in text),
                any(character.isdigit() for character in text),
                any(not character.isalnum() for character in text),
            )
        )

    @staticmethod
    def contains_whitespace(text: str) -> bool:
        """Whether a string is more than one token.

        Used where the distinction matters more than any measurement does:
        prose is a sequence of words, a secret is a single run of characters,
        and that separates them more reliably than entropy.
        """
        return text != text.strip() or any(character.isspace() for character in text)
