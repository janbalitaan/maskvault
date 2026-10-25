"""TestCredentialsAreDestroyed."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(terms={"ORG": ["Acme Corporation", "Acme", "Initech"]})


class TestCredentialsAreDestroyed:
    @pytest.mark.parametrize(
        "secret",
        [
            "sk-abcdefghijklmnopqrstuvwxyz1234",
            "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ1234567",
            "gsk_abcdefghijklmnopqrstuvwxyz12",
            "ghp_abcdefghijklmnopqrstuvwxyz12",
            "glpat-abcdefghijklmnopqrst",
        ],
    )
    def test_api_keys_never_reach_the_prompt(self, anonymizer, secret):
        safe, vault = anonymizer.anonymize(f"my key is {secret}")
        assert secret not in safe
        assert "api_key" in vault.destroyed

    def test_a_destroyed_value_is_never_restored(self, anonymizer):
        """Putting a key back would hide the fact that one was sent at all."""
        secret = "sk-abcdefghijklmnopqrstuvwxyz1234"
        safe, vault = anonymizer.anonymize(f"key {secret}")
        assert secret not in anonymizer.restore(safe, vault)

    def test_password_assignments_are_destroyed(self, anonymizer):
        safe, vault = anonymizer.anonymize("password=hunter2trustno1 and go")
        assert "hunter2trustno1" not in safe
        assert "password_assignment" in vault.destroyed

    def test_private_keys_are_destroyed(self, anonymizer):
        block = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"
        safe, vault = anonymizer.anonymize(f"here: {block}")
        assert "BEGIN RSA PRIVATE KEY" not in safe
        assert "private_key" in vault.destroyed

    def test_card_numbers_are_destroyed(self, anonymizer):
        safe, vault = anonymizer.anonymize("card 4111 1111 1111 1111 expires soon")
        assert "4111" not in safe
        assert "card_number" in vault.destroyed
