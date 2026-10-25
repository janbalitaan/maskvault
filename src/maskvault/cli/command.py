"""What every command needs, in one place."""

from __future__ import annotations

from pathlib import Path
import sys
from typing import TextIO

from maskvault.cli.exit_codes import ExitCode
from maskvault.exceptions import MaskvaultError


class Command:
    """Streams, failure reporting and output, shared by the subcommands.

    Three things were written out in each command and are easy to let drift:

        the streams        `out or sys.stdout` in four places
        the failure path   the same except-print-return in three
        the newline rule   exactly one trailing newline, in two

    The newline rule is the one that matters most. `anonymize` and `restore`
    write text a caller will pipe into a file or another process, so a missing
    or doubled newline is a visible defect — and a rule implemented twice is
    one that eventually disagrees with itself.

    `path` is optional because `policy` reads nothing: it reports on the
    library rather than on input.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        self._path = path
        self._out = out or sys.stdout
        self._err = err or sys.stderr

    def _fail(self, error: MaskvaultError) -> ExitCode:
        """Report an error on stderr and return the status to exit with.

        Every command fails the same way, and `USAGE` rather than a generic
        error because a `MaskvaultError` here means the input or the arguments
        were wrong — not that the library broke.
        """
        print(f"error: {error}", file=self._err)
        return ExitCode.USAGE

    def _emit(self, text: str) -> None:
        """Write text to stdout with exactly one trailing newline.

        A caller redirecting stdout to a file gets the text and nothing else,
        whether or not the input ended in a newline.
        """
        print(text, end="" if text.endswith("\n") else "\n", file=self._out)

    def _note(self, message: str) -> None:
        """Write a message to stderr.

        Summaries and warnings go here so that redirecting stdout captures
        the text alone.
        """
        print(message, file=self._err)
