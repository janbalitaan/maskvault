"""Writing a number as letters."""

from __future__ import annotations

import string


class LetterCode:
    """Base-26 encoding into uppercase letters.

    Letters rather than digits or hex everywhere a scope marker is built,
    because the marker goes into the token *label* and the default
    `label_pattern` is `[A-Z_]+`. A hex marker like `C8A0` contains digits,
    so a scoped token stopped matching its own vault's pattern — restoring
    still worked, being a dictionary lookup, but `leaked()` went blind to the
    token it exists to report.
    """

    ALPHABET = string.ascii_uppercase
    BASE = len(ALPHABET)

    @staticmethod
    def encode(number: int, letters: int) -> str:
        """Render a non-negative integer as exactly `letters` letters.

        Wraps rather than widening, so a marker's width is fixed and a
        token's shape does not change after a few hundred million of them.
        Wrapping is safe where it is used because the random prefix, not the
        counter, is what separates one process from another.
        """
        rendered = []
        for _ in range(letters):
            number, index = divmod(number, LetterCode.BASE)
            rendered.append(LetterCode.ALPHABET[index])
        return "".join(rendered)

    @staticmethod
    def capacity(letters: int) -> int:
        """How many distinct values this many letters can hold."""
        return LetterCode.BASE**letters
