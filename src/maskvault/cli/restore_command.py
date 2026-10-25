"""Putting the original values back, from a vault."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TextIO

from maskvault.anonymizer import Anonymizer
from maskvault.cli.command import Command
from maskvault.cli.exit_codes import ExitCode
from maskvault.cli.reader import InputReader
from maskvault.exceptions import VaultError
from maskvault.exceptions.base import MaskvaultError
from maskvault.models.vault import Vault


class RestoreCommand(Command):
    """Restores text from a vault written by `anonymize`.

    Reports tokens it could not restore rather than leaving them silently in
    place. A model that reformatted a token leaves one behind, and the reader
    of the restored text would otherwise see `@@EMAIL_1@@` and have no idea
    why.

    Destroyed values are never restored, by design — if a password was
    removed, putting it back is the one thing this must not do.
    """

    def __init__(
        self,
        path: Path | None = None,
        *,
        vault_path: Path,
        out: TextIO | None = None,
        err: TextIO | None = None,
    ) -> None:
        super().__init__(path, out=out, err=err)
        self._vault_path = vault_path

    def run(self) -> ExitCode:
        """Restore, print, and return the status to exit with."""
        try:
            text = InputReader.read(self._path)
            vault = self._read_vault()
            anonymizer = Anonymizer()
            restored = anonymizer.restore(text, vault)
            leftover = anonymizer.leaked(restored, vault)
        except MaskvaultError as error:
            return self._fail(error)

        self._emit(restored)
        if leftover:
            print(
                f"[{len(leftover)} token(s) could not be restored: "
                f"{', '.join(sorted(set(leftover)))}]",
                file=self._err,
            )
        if vault.destroyed:
            print(
                f"[{len(vault.destroyed)} destroyed value(s) were not restored, "
                "which is deliberate]",
                file=self._err,
            )
        return ExitCode.OK

    def _read_vault(self) -> Vault:
        """Load the vault, or explain why it cannot be used."""
        try:
            data = json.loads(self._vault_path.read_text(encoding="utf-8"))
        except OSError as error:
            raise MaskvaultError(
                f"cannot read the vault at {self._vault_path}: {error.strerror}"
            ) from error
        except json.JSONDecodeError as error:
            raise MaskvaultError(
                f"the vault at {self._vault_path} is not valid JSON: {error}"
            ) from error

        try:
            return Vault.from_dict(data)
        except VaultError as error:
            raise MaskvaultError(
                f"{error} Was it written by `maskvault anonymize --vault`?"
            ) from error
