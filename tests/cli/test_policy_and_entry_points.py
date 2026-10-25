"""Printing the policy, and the two ways the tool is invoked."""

from __future__ import annotations

import subprocess
import sys

import pytest

from maskvault.cli import ExitCode, build_parser, main, run
from maskvault.models.level import Level


class TestPolicyCommand:
    def test_it_exits_zero(self):
        assert main(["policy"]) == ExitCode.OK

    def test_it_lists_every_level_by_default(self, capsys):
        main(["policy"])
        printed = capsys.readouterr().out
        for level in Level:
            assert level.value in printed

    def test_one_level_can_be_asked_for(self, capsys):
        main(["policy", "--level", "minimal"])
        printed = capsys.readouterr().out
        assert "minimal" in printed
        assert "paranoid" not in printed

    def test_it_separates_destroyed_from_reversible(self, capsys):
        """The distinction that matters more than any individual pattern."""
        main(["policy", "--level", "standard"])
        printed = capsys.readouterr().out
        assert "destroyed" in printed
        assert "reversible" in printed

    def test_strict_adds_more_than_standard(self, capsys):
        main(["policy", "--level", "standard"])
        standard = capsys.readouterr().out
        main(["policy", "--level", "strict"])
        strict = capsys.readouterr().out
        assert len(strict) > len(standard)

    def test_an_unknown_level_is_refused_by_the_parser(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["policy", "--level", "nonsense"])


class TestEntryPoints:
    def test_run_exits_rather_than_returning(self, monkeypatch, tmp_path):
        """A console script's return value is ignored, so it has to exit."""
        monkeypatch.setattr(sys, "argv", ["maskvault", "explain", str(tmp_path / "x")])
        with pytest.raises(SystemExit) as caught:
            run()
        assert caught.value.code == ExitCode.USAGE

    def test_python_dash_m_works(self):
        """Often the only way to reach it inside a container."""
        finished = subprocess.run(
            [sys.executable, "-m", "maskvault", "policy", "--level", "minimal"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert finished.returncode == ExitCode.OK
        assert "minimal" in finished.stdout

    def test_a_command_is_required(self):
        with pytest.raises(SystemExit):
            build_parser().parse_args([])

    def test_help_lists_every_command(self, capsys):
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--help"])
        printed = capsys.readouterr().out
        for command in ("explain", "anonymize", "restore", "policy"):
            assert command in printed

    def test_the_epilog_explains_the_exit_status(self, capsys):
        """It is the interface a pipeline uses, so it belongs in --help."""
        with pytest.raises(SystemExit):
            build_parser().parse_args(["--help"])
        assert "exit status" in capsys.readouterr().out

    def test_restore_requires_a_vault(self):
        """There is nothing to restore from without one."""
        with pytest.raises(SystemExit):
            build_parser().parse_args(["restore", "file.txt"])
