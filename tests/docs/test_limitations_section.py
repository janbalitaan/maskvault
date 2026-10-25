"""The limitations are claims too, and a reader relies on them being"""

from __future__ import annotations

from importlib.metadata import requires
from pathlib import Path

from maskvault import Anonymizer, Level
from maskvault.entropy import Entropy


class TestLimitationsSection:
    """The limitations are claims too, and a reader relies on them being
    accurate in both directions."""

    def test_it_cannot_find_an_unlisted_name(self):
        """README: 'will not find "Maria Santos" unless you list it'."""
        safe, _ = Anonymizer(level=Level.STRICT).anonymize("I spoke with Maria Santos")
        assert "Maria Santos" in safe

    def test_an_unlisted_condition_passes_through(self):
        """README: 'misses what is not listed'."""
        safe, _ = Anonymizer(level=Level.STRICT).anonymize("I have sarcoidosis")
        assert "sarcoidosis" in safe

    def test_a_passphrase_is_not_caught(self):
        """README: 'correct horse battery staple scores like ordinary words'."""
        safe, _ = Anonymizer(level=Level.PARANOID).anonymize(
            "my passphrase is correct horse battery staple"
        )
        assert "correct horse battery staple" in safe

    def test_the_aws_key_entropy_figure(self):
        """README cites 3.68 bits for an AWS access key id."""
        assert round(Entropy.shannon_entropy("AKIAIOSFODNN7EXAMPLE"), 2) == 3.68

    def test_the_quick_brown_fox_figure(self):
        """README: 'the quick brown fox jumps scores above 4 bits'."""
        assert Entropy.shannon_entropy("the quick brown fox jumps") > 4.0

    def test_it_has_no_required_dependencies(self):
        """README: 'No dependencies'. The packaged metadata has to agree.

        Every requirement must be gated behind an extra, so `pip install
        maskvault` pulls in nothing. The encryption extra adds `cryptography`
        for callers who store a vault — which the common case never does.

        Read from the installed distribution rather than from pyproject.toml,
        because what a user gets is the metadata, and because tomllib is only
        in the standard library from 3.11 while this package supports 3.10.
        """
        unconditional = [
            requirement
            for requirement in requires("maskvault") or []
            if "extra ==" not in requirement
        ]
        assert unconditional == []

    def test_every_extra_is_declared_in_the_readme(self):
        """An extra nobody documents is one nobody installs."""
        extras = {
            requirement.split("extra == ")[1].strip("'\" ")
            for requirement in requires("maskvault") or []
            if "extra ==" in requirement
        }
        readme = (Path(__file__).resolve().parents[2] / "README.md").read_text()
        for extra in extras:
            # The install line, not just the word: "encryption" appears in a
            # comparison table, which passed this test while the extra itself
            # was undocumented.
            assert f"maskvault[{extra}]" in readme, (
                f"the {extra!r} extra has no install line in the README"
            )
