"""Reading the input a command operates on."""

from __future__ import annotations

from pathlib import Path
import sys

from maskvault.exceptions.base import MaskvaultError


class InputReader:
    """Reads text from a file or from standard input.

    Standard input matters more than it looks: the whole point of this tool is
    to clean something before it goes somewhere else, and that is usually a
    pipe — `kubectl logs ... | maskvault anonymize`. Requiring a file first
    would mean writing the sensitive thing to disk on the way.
    """

    @staticmethod
    def read(path: Path | None) -> str:
        """Return the text to work on, from `path` or standard input."""
        if path is None:
            return sys.stdin.read()
        try:
            return path.read_text(encoding="utf-8")
        except OSError as error:
            raise MaskvaultError(f"cannot read {path}: {error.strerror}") from error

    @staticmethod
    def describe(path: Path | None) -> str:
        """Name the input, for a message."""
        return str(path) if path else "standard input"
