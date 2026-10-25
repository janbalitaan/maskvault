"""Every example has to actually run.

An example that stopped working is worse than no example: it is the first
thing a new reader tries, and it fails in a way that looks like their
mistake rather than ours. Running them in the suite means a change that
breaks one fails CI.

Each runs in a subprocess, because an example is a script — importing it
would not catch a failure in module-level code, which is most of what an
example is.
"""

from __future__ import annotations

from importlib.util import find_spec
from pathlib import Path
import re
import subprocess
import sys

import pytest

EXAMPLES = sorted((Path(__file__).resolve().parents[2] / "examples").glob("*.py"))


def skip_if_extra_is_missing(example: Path) -> None:
    """Skip an example whose optional extra is not installed.

    An example that needs one says so in its own docstring — `06_a_store.py`
    opens with `pip install 'maskvault[encryption]'`. Reading that rather
    than keeping a list here means a new example carrying the same note is
    handled without anyone remembering to update this file.
    """
    source = example.read_text()
    for extra, module in (("encryption", "cryptography"),):
        if f"maskvault[{extra}]" in source and find_spec(module) is None:
            pytest.skip(f"{example.name} needs the {extra} extra")


class TestEveryExampleRuns:
    def test_the_directory_is_not_empty(self):
        assert EXAMPLES, "no examples found"

    @pytest.mark.parametrize("example", EXAMPLES, ids=lambda item: item.name)
    def test_it_exits_cleanly(self, example):
        skip_if_extra_is_missing(example)
        finished = subprocess.run(
            [sys.executable, str(example)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert finished.returncode == 0, finished.stderr

    @pytest.mark.parametrize("example", EXAMPLES, ids=lambda item: item.name)
    def test_it_prints_something(self, example):
        skip_if_extra_is_missing(example)
        """An example that runs silently teaches nothing."""
        finished = subprocess.run(
            [sys.executable, str(example)], capture_output=True, text=True, check=False
        )
        assert finished.stdout.strip()

    @pytest.mark.parametrize("example", EXAMPLES, ids=lambda item: item.name)
    def test_it_says_how_to_run_it(self, example):
        """The first question a reader has."""
        assert "python examples/" in example.read_text()


class TestTheIndexIsAccurate:
    @staticmethod
    def _index() -> str:
        return (EXAMPLES[0].parent / "README.md").read_text()

    def test_every_example_is_listed(self):
        for example in EXAMPLES:
            assert example.name in self._index(), f"{example.name} is not listed"

    def test_nothing_is_listed_that_does_not_exist(self):

        names = {example.name for example in EXAMPLES}
        for listed in re.findall(r"`(\d\d_[\w]+\.py)`", self._index()):
            assert listed in names, f"{listed} is listed but missing"


class TestNoExampleLeaksAValue:
    """They print real values on purpose — that is how you see what was
    found. But none should print one it claimed to have protected."""

    @pytest.mark.parametrize("example", EXAMPLES, ids=lambda item: item.name)
    def test_an_anonymized_line_carries_no_address(self, example):
        finished = subprocess.run(
            [sys.executable, str(example)], capture_output=True, text=True, check=False
        )
        for line in finished.stdout.splitlines():
            if "!|EMAIL_" in line:
                assert "alice@acme.com" not in line, (
                    f"{example.name} printed a token and the value on one line"
                )
