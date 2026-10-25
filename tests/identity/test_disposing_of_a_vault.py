"""A vault outlives its use unless something ends it.

`restore()` does not empty the vault, on purpose: a multi-turn conversation
needs the same tokens to mean the same people on the next turn. The
consequence is that a vault holds plaintext for as long as it exists — in
memory until it is collected, in a store until its TTL or an explicit delete.

So disposal is the caller's to perform, and `wipe()` is how.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Vault
from maskvault.stores import MemoryVaultStore

TEXT = "Email alice@acme.com or call +63 917 555 1234"


@pytest.fixture
def filled() -> tuple[Anonymizer, Vault, str]:
    anonymizer = Anonymizer()
    vault = Vault.for_key("conversation-1")
    payload = anonymizer.anonymize_into(TEXT, vault)
    return anonymizer, vault, payload


class TestRestoreLeavesTheVaultIntact:
    """Documented because a reader may assume otherwise."""

    def test_the_values_are_still_there(self, filled):
        anonymizer, vault, payload = filled
        anonymizer.restore(payload, vault)
        assert len(vault.values) == 2

    def test_restoring_twice_works(self, filled):
        """What a multi-turn conversation depends on."""
        anonymizer, vault, payload = filled
        assert anonymizer.restore(payload, vault) == TEXT
        assert anonymizer.restore(payload, vault) == TEXT


class TestWipeEmptiesIt:
    def test_it_reports_how_many_went(self, filled):
        _, vault, _ = filled
        assert vault.wipe() == 2

    def test_the_values_are_gone(self, filled):
        _, vault, _ = filled
        vault.wipe()
        assert vault.values == {}

    def test_wiping_twice_removes_nothing_the_second_time(self, filled):
        _, vault, _ = filled
        vault.wipe()
        assert vault.wipe() == 0

    def test_wiped_says_so(self, filled):
        _, vault, _ = filled
        assert not vault.wiped
        vault.wipe()
        assert vault.wiped

    def test_a_vault_that_never_held_anything_is_not_wiped(self):
        """Distinct from having been emptied."""
        assert not Vault().wiped


class TestAfterAWipeNothingResolves:
    def test_restore_resolves_nothing(self, filled):
        anonymizer, vault, payload = filled
        vault.wipe()
        assert anonymizer.restore(payload, vault) == payload

    def test_the_tokens_are_left_in_place(self, filled):
        """Not substituted for something wrong, and not silently dropped."""
        anonymizer, vault, payload = filled
        vault.wipe()
        assert "!|" in anonymizer.restore(payload, vault)

    def test_leaked_reports_them(self, filled):
        """Loud. A caller restoring against a wiped vault has a bug, and the
        reply is missing values it should have had."""
        anonymizer, vault, payload = filled
        vault.wipe()
        assert len(anonymizer.leaked(payload, vault)) == 2

    def test_resolved_is_empty(self, filled):
        anonymizer, vault, payload = filled
        vault.wipe()
        assert anonymizer.resolved(payload, vault) == []


class TestTheCountersSurviveAWipe:
    """So a token minted later cannot resolve to the wrong person."""

    def test_a_new_token_does_not_reuse_an_old_index(self, filled):
        anonymizer, vault, _ = filled
        vault.wipe()
        again = anonymizer.anonymize_into("Email bob@other.com", vault)
        assert "_2|!" in again

    def test_an_old_token_does_not_resolve_to_the_new_value(self, filled):
        """The failure this prevents: `EMAIL_1` from before the wipe coming
        back as the person who arrived after it."""
        anonymizer, vault, payload = filled
        vault.wipe()
        anonymizer.anonymize_into("Email bob@other.com", vault)
        assert "bob@other.com" not in anonymizer.restore(payload, vault)


class TestTheAuditLineSurvivesAWipe:
    """An audit written after disposal must not read "nothing replaced" for
    a request that handled somebody's data."""

    def test_the_summary_still_describes_the_request(self, filled):
        _, vault, _ = filled
        before = vault.summary()
        vault.wipe()
        assert vault.summary() == before

    def test_it_counts_the_kinds(self, filled):
        _, vault, _ = filled
        vault.wipe()
        assert "1 email" in vault.summary()
        assert "1 phone" in vault.summary()

    def test_it_holds_no_values(self, filled):
        _, vault, _ = filled
        vault.wipe()
        summary = vault.summary()
        assert "alice@acme.com" not in summary
        assert "917" not in summary

    def test_the_scope_marker_is_not_in_it(self, filled):
        """Counters are keyed by label-and-scope; a summary should say
        "email", not "email_qrmzvbdlkpwa"."""
        _, vault, _ = filled
        assert vault.scope.lower() not in vault.summary()

    def test_a_destroyed_value_is_still_counted(self):
        anonymizer = Anonymizer()
        vault = Vault.for_key("c")
        anonymizer.anonymize_into("key sk-" + "a" * 40, vault)
        vault.wipe()
        assert "destroyed" in vault.summary()


class TestDisposalFromAStore:
    def test_delete_removes_it(self):
        """The other half: wiping the object does not empty the store."""
        anonymizer = Anonymizer()
        vault = Vault.for_key("c1")
        anonymizer.anonymize_into(TEXT, vault)
        store = MemoryVaultStore()
        store.save("c1", vault)

        vault.wipe()
        assert store.load("c1") is not None, "the stored copy is separate"

        store.delete("c1")
        assert store.load("c1") is None
