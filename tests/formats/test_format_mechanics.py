"""TestFormatMechanics."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.formats import AT_SIGNS, DEFAULT_FORMATS


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestFormatMechanics:
    def test_the_pattern_matches_what_the_template_writes(self):
        for token_format in DEFAULT_FORMATS:
            rendered = token_format.render("HEALTH", 3)
            assert token_format.pattern.fullmatch(rendered)

    def test_a_vault_carries_its_format(self, anonymizer):
        _, vault = anonymizer.anonymize("see [[Notes]] at Acme Corp")
        assert vault.token_format is AT_SIGNS

    def test_the_summary_still_counts_by_kind(self, anonymizer):
        """Counting reads tokens back, so it has to use the vault's format."""
        _, vault = anonymizer.anonymize("see [[Notes]], Acme Corp, me@acme.com")
        summary = vault.summary()
        assert "org" in summary
        assert "email" in summary
