"""TestPinnedFormats."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.models.token_format import TokenFormat


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestPinnedFormats:
    def test_a_format_can_be_pinned_by_name(self):
        anonymizer = Anonymizer(token_format="pipe_bang", terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("I work at Acme")
        assert "!|ORG_1|!" in safe

    def test_a_pinned_format_is_used_even_when_it_collides(self):
        """Pinning means the caller has taken responsibility for the choice."""
        anonymizer = Anonymizer(token_format="brackets", terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("see [[Notes]], I work at Acme")
        assert "[[ORG_1]]" in safe

    def test_a_custom_format_works(self):
        custom = TokenFormat(name="braces", opening="{{", closing="}}")
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        safe, vault = anonymizer.anonymize("I work at Acme")
        assert "{{ORG_1}}" in safe
        assert anonymizer.restore(safe, vault) == "I work at Acme"

    def test_an_unpinned_anonymizer_reports_no_fixed_format(self, anonymizer):
        assert anonymizer.token_format is None
