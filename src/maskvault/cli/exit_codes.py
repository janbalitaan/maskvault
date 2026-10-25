"""What this program's exit status means.

Named rather than written as literals, because a pipeline branches on them and
a bare number in a shell script is a number nobody can look up.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """The status this program exits with.

    Three values, and the distinction between the last two is what a pipeline
    needs: text that holds something sensitive is a different event from a
    command that could not run at all.
    """

    # Nothing sensitive was found, or the operation completed.
    OK = 0

    # Something sensitive was found. For `explain`, which exists to be a gate.
    FOUND = 1

    # The command itself could not run: no such file, bad arguments, a vault
    # that will not parse. Distinct from FOUND so a pipeline can tell "your
    # text has a secret in it" from "this tool was used wrongly".
    USAGE = 2
