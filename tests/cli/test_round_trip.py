"""Anonymizing and restoring from the shell, which is the whole workflow.

The vault is what makes it reversible, and it holds every original value — so
these check both that the round trip works and that the vault is written as
carefully as the input deserved.
"""

from __future__ import annotations

import json
import stat

import pytest

from maskvault.cli import ExitCode, main

ORIGINAL = "write to jan.doe@acme.com or call +63 917 555 1234\n"


@pytest.fixture
def source(tmp_path):
    path = tmp_path / "message.txt"
    path.write_text(ORIGINAL)
    return path


class TestAnonymizeCommand:
    def test_it_exits_zero(self, source):
        assert main(["anonymize", str(source)]) == ExitCode.OK

    def test_the_values_are_gone_from_the_output(self, source, capsys):
        main(["anonymize", str(source)])
        printed = capsys.readouterr().out
        assert "jan.doe@acme.com" not in printed
        assert "+63 917 555 1234" not in printed

    def test_the_text_around_them_survives(self, source, capsys):
        main(["anonymize", str(source)])
        printed = capsys.readouterr().out
        assert printed.startswith("write to ")
        assert " or call " in printed

    def test_the_summary_goes_to_stderr(self, source, capsys):
        """So redirecting stdout to a file captures the text alone."""
        main(["anonymize", str(source)])
        captured = capsys.readouterr()
        assert "[" in captured.err
        assert "[" not in captured.out.split("\n")[0].replace("@@", "")

    def test_without_a_vault_nothing_is_written(self, source, tmp_path):
        main(["anonymize", str(source)])
        assert list(tmp_path.glob("*.json")) == []

    def test_a_missing_file_exits_two(self, tmp_path, capsys):
        assert main(["anonymize", str(tmp_path / "nope.txt")]) == ExitCode.USAGE
        assert "error:" in capsys.readouterr().err


class TestTheVault:
    def test_it_is_written_when_asked(self, source, tmp_path):
        vault = tmp_path / "vault.json"
        main(["anonymize", str(source), "--vault", str(vault)])
        assert vault.is_file()
        assert "values" in json.loads(vault.read_text())

    def test_it_is_readable_only_by_its_owner(self, source, tmp_path):
        """It holds every original value, so it is as sensitive as the input.
        The umask default would often make it group-readable, which would
        undo the point of the exercise."""
        vault = tmp_path / "vault.json"
        main(["anonymize", str(source), "--vault", str(vault)])
        mode = stat.S_IMODE(vault.stat().st_mode)
        assert mode == 0o600

    def test_it_holds_the_originals(self, source, tmp_path):
        vault = tmp_path / "vault.json"
        main(["anonymize", str(source), "--vault", str(vault)])
        assert "jan.doe@acme.com" in vault.read_text()

    def test_an_unwritable_path_exits_two(self, source, tmp_path, capsys):
        vault = tmp_path / "no-such-directory" / "vault.json"
        assert main(["anonymize", str(source), "--vault", str(vault)]) == ExitCode.USAGE
        assert "cannot write the vault" in capsys.readouterr().err


class TestRestoreCommand:
    def test_the_round_trip_returns_the_original(self, source, tmp_path, capsys):
        vault = tmp_path / "vault.json"
        main(["anonymize", str(source), "--vault", str(vault)])
        safe = capsys.readouterr().out
        masked = tmp_path / "masked.txt"
        masked.write_text(safe)

        assert main(["restore", str(masked), "--vault", str(vault)]) == ExitCode.OK
        assert capsys.readouterr().out == ORIGINAL

    def test_a_missing_vault_exits_two(self, source, tmp_path, capsys):
        assert main(["restore", str(source), "--vault", str(tmp_path / "no.json")]) == (
            ExitCode.USAGE
        )
        assert "cannot read the vault" in capsys.readouterr().err

    def test_a_vault_that_is_not_json_exits_two(self, source, tmp_path, capsys):
        vault = tmp_path / "vault.json"
        vault.write_text("{not json")
        assert main(["restore", str(source), "--vault", str(vault)]) == ExitCode.USAGE
        assert "not valid JSON" in capsys.readouterr().err

    def test_a_file_that_is_not_a_vault_says_so(self, source, tmp_path, capsys):
        """Pointing it at the wrong JSON file is an easy mistake, and "no
        values" is more useful than a KeyError."""
        vault = tmp_path / "vault.json"
        vault.write_text('{"something": "else"}')
        assert main(["restore", str(source), "--vault", str(vault)]) == ExitCode.USAGE
        message = capsys.readouterr().err
        assert "not a vault" in message
        # And it still points at the command that writes one.
        assert "maskvault anonymize --vault" in message

    def test_an_unrestorable_token_is_reported(self, tmp_path, capsys):
        """A model that reformatted a token leaves one behind, and the reader
        would otherwise see !|EMAIL_1|! with no explanation."""
        vault = tmp_path / "vault.json"
        vault.write_text(json.dumps({"values": {"!|EMAIL_1|!": "me@acme.com"}}))
        masked = tmp_path / "masked.txt"
        masked.write_text("write to !|EMAIL_1|! and !|EMAIL_9|!\n")
        main(["restore", str(masked), "--vault", str(vault)])
        captured = capsys.readouterr()
        assert "me@acme.com" in captured.out
        assert "could not be restored" in captured.err

    def test_destroyed_values_are_not_restored(self, tmp_path, capsys):
        """The one thing restore must never do."""
        vault = tmp_path / "vault.json"
        vault.write_text(json.dumps({"values": {}, "destroyed": ["a password was removed"]}))
        masked = tmp_path / "masked.txt"
        masked.write_text("the key was [removed]\n")
        main(["restore", str(masked), "--vault", str(vault)])
        captured = capsys.readouterr()
        assert "were not restored" in captured.err
        assert "which is deliberate" in captured.err
