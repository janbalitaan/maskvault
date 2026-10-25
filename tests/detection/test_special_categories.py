"""TestSpecialCategories."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.personal import special_category_detectors
from maskvault.vocabularies import SPECIAL_CATEGORIES


@pytest.fixture
def strict() -> Anonymizer:
    return Anonymizer(level=Level.STRICT)


class TestSpecialCategories:
    @pytest.mark.parametrize("category", list(SPECIAL_CATEGORIES))
    def test_every_category_has_a_detector(self, category):
        labels = {detector.label for detector in special_category_detectors()}
        assert category in labels

    @pytest.mark.parametrize(
        "text,term",
        [
            ("I was diagnosed with diabetes", "diabetes"),
            ("I am a practicing Catholic", "Catholic"),
            ("I am a union member", "union member"),
            ("I came out as gay in 2015", "gay"),
            ("I am on an H1B visa", "visa"),
            ("I filed for bankruptcy", "bankruptcy"),
        ],
    )
    def test_a_listed_term_is_replaced(self, strict, text, term):
        safe, _ = strict.anonymize(text)
        assert term.lower() not in safe.lower()

    def test_a_longer_term_wins(self, strict):
        """'heart attack' must not be matched as 'heart' with 'attack' left."""
        safe, _ = strict.anonymize("I had a heart attack")
        assert "attack" not in safe

    def test_the_surrounding_sentence_stays_usable(self, strict):
        """Tokenizing the term rather than the sentence keeps the text
        meaningful to whatever reads it next."""
        safe, _ = strict.anonymize("I was diagnosed with diabetes in 2019")
        assert "in 2019" in safe

    def test_a_term_restores(self, strict):
        text = "I am a practicing Catholic"
        safe, vault = strict.anonymize(text)
        assert strict.restore(safe, vault) == text

    def test_an_unlisted_condition_passes_through(self, strict):
        """A vocabulary is a floor, not a guarantee. Stated here so the
        limitation is visible in the suite rather than only in the README."""
        safe, _ = strict.anonymize("I have been diagnosed with sarcoidosis")
        assert "sarcoidosis" in safe
