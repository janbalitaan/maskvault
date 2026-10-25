"""TestValues."""

from __future__ import annotations

from maskvault import Anonymizer


class TestValues:
    def test_an_exact_value_passes_through(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        safe, _ = anonymizer.anonymize("write to me@example.com")
        assert "me@example.com" in safe

    def test_case_does_not_matter(self):
        anonymizer = Anonymizer(whitelist={"values": ["ME@EXAMPLE.COM"]})
        safe, _ = anonymizer.anonymize("write to me@example.com")
        assert "me@example.com" in safe

    def test_a_different_value_is_still_replaced(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        safe, _ = anonymizer.anonymize("write to other@example.com")
        assert "other@example.com" not in safe

    def test_trailing_punctuation_does_not_defeat_a_value(self):
        """A detector may hand over the match with sentence punctuation
        attached, which an exact entry would otherwise fail to match."""
        anonymizer = Anonymizer(whitelist={"values": ["https://example.com/me"]})
        safe, _ = anonymizer.anonymize("see https://example.com/me, then go")
        assert "https://example.com/me" in safe
