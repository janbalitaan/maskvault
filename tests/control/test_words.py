"""TestWords."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestWords:
    def test_a_word_passes_through(self):
        anonymizer = Anonymizer(level=Level.STRICT, whitelist={"words": ["black"]})
        safe, _ = anonymizer.anonymize("the black formatter")
        assert "black" in safe

    def test_a_word_entry_does_not_allow_a_longer_match(self):
        anonymizer = Anonymizer(level=Level.STRICT, whitelist={"words": ["bi"]})
        safe, _ = anonymizer.anonymize("I am bisexual")
        assert "bisexual" not in safe
