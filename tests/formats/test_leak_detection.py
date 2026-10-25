"""TestLeakDetection."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestLeakDetection:
    def test_a_wikilink_shaped_like_a_token_is_not_a_leak(self, anonymizer):
        """A link to a page called API_2 has the exact shape of a token, so
        leak detection has to judge against the format actually used."""
        _, vault = anonymizer.anonymize("See [[Notes]] at Acme Corp")
        assert anonymizer.leaked("text with [[API_2]] in it", vault) == []

    def test_a_genuinely_mangled_token_is_still_reported(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme Corp")
        forged = vault.token_format.render("ORG", 9)
        assert anonymizer.leaked(f"I work at {forged}", vault) == [forged]
