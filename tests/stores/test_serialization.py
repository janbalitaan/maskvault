"""A vault has to survive the trip, losing nothing.

This is the whole mechanism behind restoring on another node: there is no
magic, the vault is the data and it has to travel. So what matters is that
every field restoring depends on survives — and the two that a hand-rolled
version drops are exactly the two that fail silently.
"""

from __future__ import annotations

import json

import pytest

from maskvault import Anonymizer
from maskvault.exceptions import VaultError
from maskvault.models.token_format import TokenFormat
from maskvault.models.vault import Vault

CUSTOM = TokenFormat(
    name="mine",
    opening="<%|",
    closing="|%>",
    label_pattern=r"[a-z_]+",
    label_case="lower",
)


class TestARoundTripLosesNothing:
    def test_a_plain_vault(self):
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        assert Vault.from_dict(vault.as_dict()) == vault

    def test_the_values_come_back(self):
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")
        carried = Vault.from_dict(vault.as_dict())
        assert anonymizer.restore(safe, carried) == "email alice@acme.com"

    def test_destroyed_labels_survive(self):
        """So the other node can report that something was removed and will
        not be coming back."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("key=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc")
        assert Vault.from_dict(vault.as_dict()).destroyed == vault.destroyed

    def test_a_custom_format_survives_in_full(self):
        """The CLI's hand-rolled version kept only name, opening and closing,
        so a custom label pattern came back as the default — and `leaked()`
        then matched none of its own tokens."""
        anonymizer = Anonymizer(token_format=CUSTOM)
        safe, vault = anonymizer.anonymize("email bob@acme.com")
        carried = Vault.from_dict(vault.as_dict())
        assert carried.token_format == CUSTOM
        assert carried.pattern.search(safe)
        assert anonymizer.restore(safe, carried) == "email bob@acme.com"

    def test_a_scope_survives(self):
        """Also dropped by the hand-rolled version, which meant a scoped
        vault could not be restored from its own file."""
        anonymizer = Anonymizer()
        vault = Vault.scoped()
        safe = anonymizer.anonymize_into("email carol@acme.com", vault)
        carried = Vault.from_dict(vault.as_dict())
        assert carried.scope == vault.scope
        assert anonymizer.restore(safe, carried) == "email carol@acme.com"

    def test_it_is_json_serializable(self):
        """Not pickle: a pickled payload executes on load, so a store an
        attacker can write would be code execution in every reader."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        assert Vault.from_dict(json.loads(json.dumps(vault.as_dict()))) == vault

    def test_accumulating_continues_after_a_trip(self):
        """The numbering has to resume, or the second node overwrites the
        first node's tokens."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email first@acme.com")
        carried = Vault.from_dict(vault.as_dict())
        anonymizer.anonymize_into("email second@acme.com", carried)
        assert len(carried.snapshot()) == 2


class TestLoadingSomethingThatIsNotAVault:
    def test_a_payload_with_no_values_is_refused(self):
        """Returning an empty vault would look identical to a vault whose
        values were all absent, so a wiring mistake would surface as every
        token coming back unrestored."""
        with pytest.raises(VaultError, match="not a vault"):
            Vault.from_dict({"something": "else"})

    def test_a_non_dict_is_refused(self):
        with pytest.raises(VaultError):
            Vault.from_dict([1, 2, 3])

    def test_the_message_says_how_a_vault_is_made(self):
        with pytest.raises(VaultError) as caught:
            Vault.from_dict({})
        assert "as_dict" in str(caught.value)

    def test_a_vault_from_an_older_version_still_loads(self):
        """Missing destroyed, scope or token_format: tolerated, because a
        payload written before those existed should not become unreadable."""
        vault = Vault.from_dict({"values": {"!|EMAIL_1|!": "me@acme.com"}})
        assert vault.snapshot() == {"!|EMAIL_1|!": "me@acme.com"}
        assert vault.destroyed == []
        assert vault.scope == ""
