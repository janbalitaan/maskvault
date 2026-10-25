"""Putting the original values back, from a vault."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import TextIO

from maskvault.anonymizer import Anonymizer
from maskvault.cli.exit_codes import ExitCode
from maskvault.cli.reader import InputReader
from maskvault.exceptions.base import MaskvaultError
from maskvault.models.token_format import TokenFormat
from maskvault.models.vault import Vault


class RestoreCommand:
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
        self._path = path
        self._vault_path = vault_path
        self._out = out or sys.stdout
        self._err = err or sys.stderr

    def run(self) -> ExitCode:
        """Restore, print, and return the status to exit with."""
        try:
            text = InputReader.read(self._path)
            vault = self._read_vault()
            anonymizer = Anonymizer()
            restored = anonymizer.restore(text, vault)
            leftover = anonymizer.leaked(restored, vault)
        except MaskvaultError as error:
            print(f"error: {error}", file=self._err)
            return ExitCode.USAGE

        print(restored, end="" if restored.endswith("\n") else "\n", file=self._out)
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

        if not isinstance(data, dict) or "values" not in data:
            raise MaskvaultError(
                f"the file at {self._vault_path} is not a vault — it has no "
                '"values". Was it written by `maskvault anonymize --vault`?'
            )
        stored = data.get("token_format") or {}
        token_format = (
            TokenFormat(
                name=str(stored.get("name", "custom")),
                opening=str(stored["opening"]),
                closing=str(stored["closing"]),
            )
            if stored.get("opening") and stored.get("closing")
            else TokenFormat.default()
        )
        return Vault(
            values=dict(data["values"]),
            destroyed=list(data.get("destroyed") or []),
            token_format=token_format,
        )
