"""The README badges have to say what the package actually is.

The PyPI-sourced badges — `pypi/pyversions`, `pypi/l` — render "package or
version not found" until the package is published, so a reader of an
unpublished repository sees three broken badges where the information was
available all along.

Static badges render immediately and can drift instead, which is what these
tests are for: the claim in the README is checked against the metadata.
"""

from __future__ import annotations

from importlib.metadata import metadata
from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parents[2]
README = (ROOT / "README.md").read_text()


def badge(label: str) -> str:
    """The value half of a static shields.io badge, URL-decoded."""
    match = re.search(rf"img\.shields\.io/badge/{label}-([^-]+)-\w+\)", README)
    assert match, f"no static {label} badge in the README"
    return match.group(1).replace("%20", " ").replace("%7C", "|")


class TestTheBadgesMatchTheMetadata:
    def test_the_python_badge_lists_the_supported_versions(self):
        """Drift is the cost of a static badge, so it is checked."""
        classifiers = metadata("maskvault").get_all("Classifier") or []
        supported = sorted(
            line.rsplit(" :: ", 1)[-1]
            for line in classifiers
            if line.startswith("Programming Language :: Python :: 3.")
        )
        claimed = sorted(part.strip() for part in badge("python").split("|"))
        assert claimed == supported

    def test_the_license_badge_matches(self):
        declared = metadata("maskvault").get("License-Expression") or metadata("maskvault").get(
            "License"
        )
        assert badge("license") == declared

    def test_the_lowest_version_matches_requires_python(self):
        """The badge's first entry and `requires-python` are two statements
        of the same fact."""
        requires = metadata("maskvault").get("Requires-Python")
        lowest = sorted(part.strip() for part in badge("python").split("|"))[0]
        assert lowest in requires


class TestTheBadgesPointSomewhereUseful:
    @pytest.mark.parametrize(
        ("label", "destination"),
        [("python", "pyproject.toml"), ("license", "LICENSE")],
    )
    def test_a_static_badge_links_to_its_source(self, label, destination):
        """A badge nobody can verify is decoration. These link to the file
        that makes the claim true."""
        match = re.search(
            rf"\[!\[[^\]]*\]\(https://img\.shields\.io/badge/{label}[^)]*\)\]\(([^)]+)\)",
            README,
        )
        assert match, f"the {label} badge has no link"
        assert destination in match.group(1)

    def test_the_ci_badge_names_a_workflow_that_exists(self):
        match = re.search(r"actions/workflows/([\w.]+)/badge\.svg", README)
        assert match, "no CI badge in the README"
        assert (ROOT / ".github" / "workflows" / match.group(1)).is_file()

    def test_the_pypi_badge_points_at_the_right_project(self):
        """This one stays PyPI-sourced: showing the published version is the
        whole job, and "not found" before publication is accurate."""
        assert "img.shields.io/pypi/v/maskvault" in README
        assert "pypi.org/project/maskvault/" in README

    def test_no_badge_reads_its_value_from_an_unpublished_package(self):
        """`pypi/pyversions` and `pypi/l` render "package or version not
        found" until publication, which is three broken badges for
        information the repository already has."""
        for broken in ("pypi/pyversions", "pypi/l/", "pypi/license"):
            assert broken not in README, f"{broken} renders empty until published"
