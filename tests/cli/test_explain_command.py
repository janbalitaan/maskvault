"""Reporting what is sensitive without revealing any of it.

The discipline that matters most here: `Finding.value` holds the real matched
text, so a command that printed it would put the secret into the terminal
scrollback and the CI log of whoever ran the check.
"""

from __future__ import annotations

import json

import pytest

from maskvault.cli import ExitCode, main

SECRET_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
LOG = (
    "2026-10-25 14:02:11 INFO request from 10.42.7.19 user=jan.doe@acme.com\n"
    f"2026-10-25 14:02:12 ERROR stripe failed key={SECRET_KEY}\n"
)


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "app.log"
    path.write_text(LOG)
    return path


class TestExplainCommand:
    def test_it_exits_one_when_something_is_found(self, log):
        """The exit status is the interface: this is meant to be a gate."""
        assert main(["explain", str(log)]) == ExitCode.FOUND

    def test_it_exits_zero_on_clean_text(self, tmp_path):
        path = tmp_path / "clean.txt"
        path.write_text("nothing interesting here at all\n")
        assert main(["explain", str(path)]) == ExitCode.OK

    def test_a_missing_file_exits_two(self, tmp_path, capsys):
        """Separate from FOUND, so a pipeline can tell a secret from misuse."""
        assert main(["explain", str(tmp_path / "nope.log")]) == ExitCode.USAGE
        assert "error:" in capsys.readouterr().err

    def test_it_names_what_it_found(self, log, capsys):
        main(["explain", str(log)])
        printed = capsys.readouterr().out
        assert "EMAIL" in printed
        assert "STRIPE_KEY" in printed

    def test_it_never_prints_a_value(self, log, capsys):
        """The whole point: a tool that printed the secret it found to warn
        you about the secret it found would be worse than useless."""
        main(["explain", str(log)])
        printed = capsys.readouterr()
        assert SECRET_KEY not in printed.out
        assert SECRET_KEY not in printed.err
        assert "jan.doe@acme.com" not in printed.out

    def test_it_reports_positions(self, log, capsys):
        main(["explain", str(log)])
        assert " at " in capsys.readouterr().out

    def test_it_counts_by_label(self, log, capsys):
        main(["explain", str(log)])
        assert "findings:" in capsys.readouterr().out

    def test_a_clean_file_says_so(self, tmp_path, capsys):
        path = tmp_path / "clean.txt"
        path.write_text("nothing interesting here at all\n")
        main(["explain", str(path)])
        assert "nothing sensitive found" in capsys.readouterr().out

    def test_the_level_changes_what_is_found(self, tmp_path):
        """MINIMAL looks only for credentials, so prose about health is not
        reported; STRICT adds the special categories."""
        path = tmp_path / "health.txt"
        path.write_text("I was treated for diabetes last year\n")
        assert main(["explain", str(path), "--level", "minimal"]) == ExitCode.OK
        assert main(["explain", str(path), "--level", "strict"]) == ExitCode.FOUND

    def test_it_reads_standard_input(self, monkeypatch, capsys):
        """The common case: cleaning something on its way through a pipe."""
        monkeypatch.setattr("sys.stdin", _FakeStdin(LOG))
        assert main(["explain"]) == ExitCode.FOUND
        assert "STRIPE_KEY" in capsys.readouterr().out


class TestExplainJson:
    def test_it_is_valid_json(self, log, capsys):
        main(["explain", str(log), "--json"])
        json.loads(capsys.readouterr().out)

    def test_it_carries_each_finding(self, log, capsys):
        main(["explain", str(log), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["found"] == len(payload["findings"])
        assert payload["found"] > 0

    def test_it_counts_the_destroyed(self, log, capsys):
        main(["explain", str(log), "--json"])
        assert json.loads(capsys.readouterr().out)["destroyed"] >= 1

    def test_it_reports_the_level(self, log, capsys):
        main(["explain", str(log), "--json", "--level", "strict"])
        assert json.loads(capsys.readouterr().out)["level"] == "strict"

    def test_it_carries_a_length_but_no_value(self, log, capsys):
        """A length is useful and reveals nothing worth protecting."""
        main(["explain", str(log), "--json"])
        out = capsys.readouterr().out
        assert SECRET_KEY not in out
        assert all("value" not in f for f in json.loads(out)["findings"])
        assert all(f["length"] > 0 for f in json.loads(out)["findings"])


class _FakeStdin:
    """Just enough of a stream for the reader to read."""

    def __init__(self, text: str) -> None:
        self._text = text

    def read(self) -> str:
        return self._text
