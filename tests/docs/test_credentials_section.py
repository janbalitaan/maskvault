"""TestCredentialsSection."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestCredentialsSection:
    def test_the_destroyed_notice_and_vault_entry(self):
        """README shows the notice text and `vault.destroyed == ["api_key"]`."""
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize(
            "key sk-abcdefghijklmnopqrstuvwxyz1234 and I work at Acme Corp"
        )
        assert "[an API key was removed before sending]" in safe
        assert vault.destroyed == ["api_key"]
        assert vault.token_format.render("ORG", 1) in safe

    def test_a_destroyed_value_breaks_the_round_trip(self):
        """README: 'an exact round trip holds only when nothing was destroyed'."""
        anonymizer = Anonymizer(level=Level.STRICT)
        text = "key sk-abcdefghijklmnopqrstuvwxyz1234"
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) != text
