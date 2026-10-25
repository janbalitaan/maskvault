"""Printing what a strictness level actually detects."""

from __future__ import annotations

import sys
from typing import TextIO

from maskvault.anonymizer import Anonymizer
from maskvault.cli.exit_codes import ExitCode
from maskvault.levels import Levels
from maskvault.models.action import Action
from maskvault.models.level import Level


class PolicyCommand:
    """Lists the detectors a level includes, and what each one does.

    The level is the main dial a caller turns, and "what does STRICT actually
    add" is a question the name alone cannot answer. Printing it beats reading
    the source, and beats discovering the answer from a value that was or was
    not replaced.
    """

    def __init__(
        self,
        level: str | None = None,
        *,
        out: TextIO | None = None,
    ) -> None:
        self._level = level
        self._out = out or sys.stdout

    def run(self) -> ExitCode:
        """Print the policy and return the status to exit with."""
        levels = [self._level] if self._level else [member.value for member in Level]
        for name in levels:
            self._describe(name)
        return ExitCode.OK

    def _describe(self, name: str) -> None:
        """Print one level's detectors, grouped by what happens to a match."""
        detectors = Levels.detectors_for(name)
        destroyed = [d.label for d in detectors if d.action is Action.DESTROY]
        reversible = [d.label for d in detectors if d.action is Action.REVERSIBLE]
        print(f"{name}: {len(detectors)} detectors", file=self._out)
        print(f"  destroyed   ({len(destroyed)}): {', '.join(destroyed)}", file=self._out)
        print(
            f"  reversible  ({len(reversible)}): {', '.join(reversible)}",
            file=self._out,
        )
        print(f"  {Anonymizer(level=name).describe_policy()}", file=self._out)
        print(file=self._out)
