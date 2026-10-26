"""The version is written in two places, and they have to agree.

`pyproject.toml` carries it for the build and `__init__.py` carries it for
`maskvault.__version__`. Nothing made them match, so a release could ship a
wheel labelled 0.2.0 whose module still said 0.1.0.

That matters here more than it usually would. PyPI permanently reserves a
filename once uploaded — deleting the release does not free it — so a wrong
version cannot be corrected in place. It has to be caught before the upload,
which is what this is.
"""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path
import re

import maskvault

ROOT = Path(__file__).resolve().parents[2]


class TestTheVersionIsStatedOnce:
    @staticmethod
    def _declared() -> str:
        """The version in pyproject.toml, read without a TOML parser.

        tomllib arrived in 3.11 and this project supports 3.10, so the line
        is matched directly rather than adding a dependency for one field.
        """
        text = (ROOT / "pyproject.toml").read_text()
        match = re.search(r'^version = "([^"]+)"', text, re.M)
        assert match, "pyproject.toml should declare a version"
        return match.group(1)

    def test_the_module_agrees_with_the_project(self):
        assert maskvault.__version__ == self._declared()

    def test_the_installed_distribution_agrees_too(self):
        """Catches a stale editable install as well as a typo."""
        assert version("maskvault") == self._declared()

    def test_the_changelog_has_an_entry_for_it(self):
        """A release with no changelog entry is one nobody can read about."""
        changelog = (ROOT / "CHANGELOG.md").read_text()
        assert f"## [{self._declared()}]" in changelog

    def test_the_changelog_entry_is_dated(self):
        """`## [0.1.0] — 2026-10-26`, not an undated heading."""
        changelog = (ROOT / "CHANGELOG.md").read_text()
        heading = re.search(
            rf"^## \[{re.escape(self._declared())}\] — (\d{{4}}-\d{{2}}-\d{{2}})$",
            changelog,
            re.M,
        )
        assert heading, "the released version needs a dated changelog heading"
