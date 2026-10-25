"""Replacing the sensitive parts of some text, reversibly."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from maskvault.anonymizer import Anonymizer
from maskvault.cli.command import Command
from maskvault.cli.exit_codes import ExitCode
from maskvault.cli.reader import InputReader
from maskvault.exceptions.base import MaskvaultError
from maskvault.models.level import Level
from maskvault.models.vault import Vault


class AnonymizeCommand(Command):
    """Prints the anonymized text, and writes the vault beside it.

    The vault is what makes this reversible, and it holds the original values
    — so where it goes is a decision, not a detail. Without `--vault` the
    replacements cannot be undone, which is the right default for "clean this
    log before I paste it somewhere": there is nothing to restore and nothing
    to leak.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        level: str = Level.STANDARD.value,
        vault_path: Path | None = None,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        super().__init__(path, out=out, err=err)
        self._level = level
        self._vault_path = vault_path

    def run(self) -> ExitCode:
        """Anonymize, print, and return the status to exit with."""
        try:
            text = InputReader.read(self._path)
            safe, vault = Anonymizer(level=self._level).anonymize(text)
            if self._vault_path is not None:
                self._write_vault(vault)
        except MaskvaultError as error:
            return self._fail(error)

        self._emit(safe)
        self._note(f"[{vault.summary()}]")
        return ExitCode.OK

    def _write_vault(self, vault: Vault) -> None:
        """Write the vault, readable only by its owner.

        It holds every original value, so it is as sensitive as the input was.
        Created with 0600 rather than the umask default, because the whole
        point of the exercise was to stop these values being readable.

        Serialized through `Vault.as_dict` rather than by hand. The
        hand-written version here dropped the scope and the format's own
        patterns, so a scoped vault could not be restored from its own file
        and a custom format came back with the wrong label pattern.
        """
        path = self._vault_path
        if path is None:  # pragma: no cover - guarded by the caller
            return
        try:
            serialized = json.dumps(vault.as_dict(), indent=2)
            path.write_text(serialized, encoding="utf-8")
            path.chmod(0o600)
        except OSError as error:
            raise MaskvaultError(
                f"cannot write the vault to {path}: {error.strerror}"
            ) from error
