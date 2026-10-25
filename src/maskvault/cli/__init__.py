"""The command line, for cleaning something before it goes somewhere else.

The library is for a program that calls a provider. This is for the moment
before that: a log you are about to paste into a chat window, a config you are
about to attach to a ticket, a dump you are about to send to support.

    maskvault explain app.log              is there anything in here?
    maskvault anonymize app.log            print it with the values replaced
    kubectl logs pod | maskvault anonymize the same, from a pipe
    maskvault policy                       what each level detects

Reading from standard input is the common case rather than a convenience: the
point is to clean something on its way somewhere, and requiring a file first
would mean writing the sensitive thing to disk on the way past.

Exit status is the interface for `explain`: 0 means nothing sensitive, 1 means
something was found, 2 means the command could not run. The last two are
separate so a pipeline can tell "your text has a secret in it" from "this tool
was used wrongly".
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from maskvault.cli.anonymize_command import AnonymizeCommand
from maskvault.cli.exit_codes import ExitCode
from maskvault.cli.explain_command import ExplainCommand
from maskvault.cli.policy_command import PolicyCommand
from maskvault.cli.restore_command import RestoreCommand
from maskvault.models.level import Level

__all__ = [
    "AnonymizeCommand",
    "ExitCode",
    "ExplainCommand",
    "PolicyCommand",
    "RestoreCommand",
    "build_parser",
    "main",
    "run",
]

LEVELS = [member.value for member in Level]


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser, separately so it can be tested on its own."""
    parser = argparse.ArgumentParser(
        prog="maskvault",
        description="Replace confidential values before text leaves your machine.",
        epilog=("exit status:  0 nothing sensitive   1 something found   2 could not run"),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    explain = commands.add_parser(
        "explain",
        help="report what is sensitive, revealing none of it",
        description=(
            "Lists what would be replaced, by label and position. Prints no "
            "values, so it is safe to run in CI and safe to read over a "
            "shoulder. Exits 1 if anything was found."
        ),
    )
    _add_common(explain)
    explain.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )

    anonymize = commands.add_parser(
        "anonymize",
        help="print the text with sensitive values replaced",
        description=(
            "Writes the cleaned text to standard output. With --vault, also "
            "writes the originals so the result can be restored later."
        ),
    )
    _add_common(anonymize)
    anonymize.add_argument(
        "--vault",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "where to write the originals, created readable only by you. "
            "Without it the replacements cannot be undone, which is the right "
            "default when you just want a clean copy"
        ),
    )

    restore = commands.add_parser(
        "restore",
        help="put the original values back, using a vault",
        description=(
            "Reverses `anonymize`. Destroyed values are never restored, and "
            "tokens that could not be matched are reported rather than left "
            "silently in place."
        ),
    )
    restore.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=None,
        help="file to read. Standard input when omitted",
    )
    restore.add_argument(
        "--vault", type=Path, required=True, metavar="FILE", help="the vault to use"
    )

    policy = commands.add_parser(
        "policy",
        help="print what each strictness level detects",
        description=(
            "Lists the detectors a level includes and what happens to each "
            "match, so the dial is readable rather than something to infer."
        ),
    )
    policy.add_argument(
        "--level", choices=LEVELS, default=None, help="one level instead of all of them"
    )
    return parser


def _add_common(parser: argparse.ArgumentParser) -> None:
    """Add the arguments shared by the commands that read and analyze text."""
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=None,
        help="file to read. Standard input when omitted",
    )
    parser.add_argument(
        "--level",
        choices=LEVELS,
        default=Level.STANDARD.value,
        help=f"how much to look for (default: {Level.STANDARD.value})",
    )


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the command, and return an exit status."""
    arguments = build_parser().parse_args(argv)

    if arguments.command == "policy":
        return int(PolicyCommand(arguments.level).run())
    if arguments.command == "restore":
        return int(RestoreCommand(arguments.input, vault_path=arguments.vault).run())
    if arguments.command == "anonymize":
        return int(
            AnonymizeCommand(
                arguments.input, level=arguments.level, vault_path=arguments.vault
            ).run()
        )
    return int(
        ExplainCommand(arguments.input, level=arguments.level, as_json=arguments.as_json).run()
    )


def run() -> None:
    """Run as a console script, exiting rather than returning."""
    sys.exit(main())
