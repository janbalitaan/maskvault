"""The limitations are claims too, and a reader relies on them being"""

from __future__ import annotations

from maskvault import Anonymizer, Level, shannon_entropy


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
        assert round(shannon_entropy("AKIAIOSFODNN7EXAMPLE"), 2) == 3.68

    def test_the_quick_brown_fox_figure(self):
        """README: 'the quick brown fox jumps scores above 4 bits'."""
        assert shannon_entropy("the quick brown fox jumps") > 4.0
