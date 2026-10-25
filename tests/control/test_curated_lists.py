"""TestCuratedLists."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.vocabularies import COMMON_SAFE_VALUES, TECHNICAL_HOMONYMS


class TestCuratedLists:
    @pytest.mark.parametrize("name", ["python", "fastapi", "postgresql", "kubernetes"])
    def test_common_safe_values_covers_the_obvious(self, name):
        assert name in COMMON_SAFE_VALUES

    @pytest.mark.parametrize("word", ["black", "native", "union", "terminal"])
    def test_homonyms_lists_words_with_technical_meanings(self, word):
        assert word in TECHNICAL_HOMONYMS

    def test_the_curated_lists_work_as_a_whitelist(self):
        anonymizer = Anonymizer(
            level=Level.STRICT,
            whitelist={
                "words": sorted(TECHNICAL_HOMONYMS),
                "values": sorted(COMMON_SAFE_VALUES),
            },
        )
        safe, _ = anonymizer.anonymize("I use black and Python on a native terminal")
        for word in ("black", "Python", "native", "terminal"):
            assert word in safe
