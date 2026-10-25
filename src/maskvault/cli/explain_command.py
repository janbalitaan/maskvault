"""Reporting what is sensitive in some text, without revealing it."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from maskvault.anonymizer import Anonymizer
from maskvault.cli.command import Command
from maskvault.cli.exit_codes import ExitCode
from maskvault.cli.reader import InputReader
from maskvault.exceptions.base import MaskvaultError
from maskvault.models.action import Action
from maskvault.models.finding import Finding
from maskvault.models.level import Level


class ExplainCommand(Command):
    """Reports what would be replaced, and exits non-zero if anything would.

    The command to reach for before pasting a log into a chat window or
    attaching it to a ticket. It answers "is there anything in here I should
    not be sharing" without the answer itself being a thing you should not
    share.

    **No value is ever printed.** `Finding.value` holds the real matched text,
    so this reports the label, the action and the position and nothing else.
    A tool that printed the secret it found to warn you about the secret it
    found would be worse than useless — it would put the value into your
    terminal scrollback and your CI log.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        level: str = Level.STANDARD.value,
        as_json: bool = False,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        super().__init__(path, out=out, err=err)
        self._level = level
        self._as_json = as_json

    def run(self) -> ExitCode:
        """Report the findings and return the status to exit with."""
        try:
            text = InputReader.read(self._path)
            findings = Anonymizer(level=self._level).explain(text)
        except MaskvaultError as error:
            return self._fail(error)

        replaced = [finding for finding in findings if finding.replaced]
        if self._as_json:
            self._report_json(replaced)
        else:
            self._report_text(replaced)
        return ExitCode.FOUND if replaced else ExitCode.OK

    def _report_text(self, findings: list[Finding]) -> None:
        """Print for a person deciding whether to share something."""
        if not findings:
            print(
                f"{InputReader.describe(self._path)}: nothing sensitive found",
                file=self._out,
            )
            return
        width = max(len(finding.label) for finding in findings)
        for finding in findings:
            print(
                f"  {finding.label:{width}}  {finding.action.value:10}"
                f"  at {finding.start}-{finding.end}",
                file=self._out,
            )
        print(file=self._out)
        print(self._summary(findings), file=self._out)

    def _report_json(self, findings: list[Finding]) -> None:
        """Print for a tool consuming the result."""
        print(
            json.dumps(
                {
                    "source": InputReader.describe(self._path),
                    "level": self._level,
                    "found": len(findings),
                    "destroyed": sum(finding.action is Action.DESTROY for finding in findings),
                    "findings": [
                        {
                            "label": finding.label,
                            "action": finding.action.value,
                            "start": finding.start,
                            "end": finding.end,
                            # Deliberately no value. See the class docstring.
                            "length": finding.end - finding.start,
                        }
                        for finding in findings
                    ],
                },
                indent=2,
            ),
            file=self._out,
        )

    @staticmethod
    def _summary(findings: list[Finding]) -> str:
        """One line counting what was found, by label."""
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.label] = counts.get(finding.label, 0) + 1
        parts = [f"{count} {label}" for label, count in sorted(counts.items())]
        return f"{len(findings)} findings: {', '.join(parts)}"
