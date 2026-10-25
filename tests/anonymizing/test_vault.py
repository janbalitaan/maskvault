"""TestVault."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(terms={"ORG": ["Acme Corporation", "Acme", "Initech"]})


class TestVault:
    def test_the_summary_contains_no_values(self, anonymizer):
        """The summary is meant for logs, so it must be safe to write down."""
        _, vault = anonymizer.anonymize("Acme, a@b.com, +63 917 555 1234")
        summary = vault.summary()
        for secret in ("Acme", "a@b.com", "917"):
            assert secret not in summary

    def test_the_summary_counts_by_kind(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme and Initech")
        assert "2 org" in vault.summary()

    def test_an_empty_vault_says_so(self, anonymizer):
        _, vault = anonymizer.anonymize("nothing sensitive here at all")
        assert vault.summary() == "nothing replaced"

    def test_replaced_counts_tokens(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme and a@b.com")
        assert vault.replaced == 2
