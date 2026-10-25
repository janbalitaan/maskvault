"""TestNoNesting."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestNoNesting:
    def test_a_value_inside_a_wikilink_does_not_nest(self, anonymizer):
        safe, _ = anonymizer.anonymize("See [[Acme Corp]] today")
        assert "[[[[" not in safe
        assert "]]]]" not in safe

    def test_the_surrounding_wikilink_survives(self, anonymizer):
        text = "See [[Meeting Notes]] and Acme Corp"
        safe, _ = anonymizer.anonymize(text)
        assert "[[Meeting Notes]]" in safe

    def test_the_round_trip_is_still_exact(self, anonymizer):
        text = "See [[Meeting Notes]]. I work at Acme Corp, mail me@acme.com"
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) == text
