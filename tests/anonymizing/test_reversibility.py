"""TestReversibility."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(terms={"ORG": ["Acme Corporation", "Acme", "Initech"]})


class TestReversibility:
    def test_a_round_trip_returns_the_original(self, anonymizer):
        text = "I work at Acme Corporation. Email me at a@b.com or +63 917 555 1234."
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) == text

    def test_the_same_value_gets_the_same_token(self, anonymizer):
        """One value, one token — so a model can tell two mentions are one thing.

        Token numbering follows term length, not appearance, because longer
        terms are matched first. The test asserts the invariant rather than
        the numbering.
        """
        safe, vault = anonymizer.anonymize("Acme and Acme again, plus Initech")
        token_for_acme = next(t for t, v in vault.values.items() if v == "Acme")
        assert safe.count(token_for_acme) == 2
        assert len({t for t, v in vault.values.items() if v in {"Acme", "Initech"}}) == 2

    def test_longer_terms_win(self, anonymizer):
        """'Acme Corporation' must not be matched as 'Acme' + 'Corporation'."""
        safe, _ = anonymizer.anonymize("I work at Acme Corporation")
        assert "Corporation" not in safe

    def test_term_matching_ignores_case(self, anonymizer):
        safe, _ = anonymizer.anonymize("i work at acme corporation")
        assert "acme" not in safe.lower()

    def test_unknown_tokens_are_left_visible(self, anonymizer):
        """A model that invents a token must not resolve to something wrong.

        A visible oddity beats a silent wrong answer about someone's employer.
        """
        _, vault = anonymizer.anonymize("Acme")
        forged = vault.token_format.render("ORG", 9)
        assert anonymizer.restore(f"I work at {forged}", vault) == f"I work at {forged}"

    def test_leaked_reports_unmatched_tokens(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme")
        forged = vault.token_format.render("ORG", 9)
        real = vault.token_format.render("ORG", 1)
        assert anonymizer.leaked(f"at {forged} now", vault) == [forged]
        assert anonymizer.leaked(f"at {real} now", vault) == []
