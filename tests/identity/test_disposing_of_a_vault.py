"""A vault outlives its use unless something ends it.

`restore()` does not empty the vault, on purpose: a multi-turn conversation
needs the same tokens to mean the same people on the next turn. The
consequence is that a vault holds plaintext for as long as it exists — in
memory until it is collected, in a store until its TTL or an explicit delete.

So disposal is the caller's to perform, and `wipe()` is how — **selectively
by age**, so forgetting what a conversation has finished with does not take
the values a request still in flight depends on. `older_than=0` forgets
everything, for the single-turn case where nothing is needed again.
"""

from __future__ import annotations

import pickle

import pytest

from maskvault import Anonymizer, Vault
from maskvault.constants import VAULT_TTL_SECONDS, WIPE_AFTER_SECONDS
from maskvault.exceptions import VaultError
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
    """`older_than=0` forgets everything, finished or not."""

    def test_it_reports_how_many_went(self, filled):
        _, vault, _ = filled
        assert vault.wipe(older_than=0) == 2

    def test_the_values_are_gone(self, filled):
        _, vault, _ = filled
        vault.wipe(older_than=0)
        assert vault.values == {}

    def test_wiping_twice_removes_nothing_the_second_time(self, filled):
        _, vault, _ = filled
        vault.wipe(older_than=0)
        assert vault.wipe(older_than=0) == 0

    def test_wiped_says_so(self, filled):
        _, vault, _ = filled
        assert not vault.wiped
        vault.wipe(older_than=0)
        assert vault.wiped

    def test_a_vault_that_never_held_anything_is_not_wiped(self):
        """Distinct from having been emptied."""
        assert not Vault().wiped


class TestAfterAWipeNothingResolves:
    def test_restore_resolves_nothing(self, filled):
        anonymizer, vault, payload = filled
        vault.wipe(older_than=0)
        assert anonymizer.restore(payload, vault) == payload

    def test_the_tokens_are_left_in_place(self, filled):
        """Not substituted for something wrong, and not silently dropped."""
        anonymizer, vault, payload = filled
        vault.wipe(older_than=0)
        assert "!|" in anonymizer.restore(payload, vault)

    def test_leaked_reports_them(self, filled):
        """Loud. A caller restoring against a wiped vault has a bug, and the
        reply is missing values it should have had."""
        anonymizer, vault, payload = filled
        vault.wipe(older_than=0)
        assert len(anonymizer.leaked(payload, vault)) == 2

    def test_resolved_is_empty(self, filled):
        anonymizer, vault, payload = filled
        vault.wipe(older_than=0)
        assert anonymizer.resolved(payload, vault) == []


class TestTheCountersSurviveAWipe:
    """So a token minted later cannot resolve to the wrong person."""

    def test_a_new_token_does_not_reuse_an_old_index(self, filled):
        anonymizer, vault, _ = filled
        vault.wipe(older_than=0)
        again = anonymizer.anonymize_into("Email bob@other.com", vault)
        assert "_2|!" in again

    def test_an_old_token_does_not_resolve_to_the_new_value(self, filled):
        """The failure this prevents: `EMAIL_1` from before the wipe coming
        back as the person who arrived after it."""
        anonymizer, vault, payload = filled
        vault.wipe(older_than=0)
        anonymizer.anonymize_into("Email bob@other.com", vault)
        assert "bob@other.com" not in anonymizer.restore(payload, vault)


class TestTheAuditLineSurvivesAWipe:
    """An audit written after disposal must not read "nothing replaced" for
    a request that handled somebody's data."""

    def test_the_summary_still_describes_the_request(self, filled):
        _, vault, _ = filled
        before = vault.summary()
        vault.wipe(older_than=0)
        assert vault.summary() == before

    def test_it_counts_the_kinds(self, filled):
        _, vault, _ = filled
        vault.wipe(older_than=0)
        assert "1 email" in vault.summary()
        assert "1 phone" in vault.summary()

    def test_it_holds_no_values(self, filled):
        _, vault, _ = filled
        vault.wipe(older_than=0)
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
        vault.wipe(older_than=0)
        assert "destroyed" in vault.summary()


class TestDisposalFromAStore:
    def test_delete_removes_it(self):
        """The other half: wiping the object does not empty the store."""
        anonymizer = Anonymizer()
        vault = Vault.for_key("c1")
        anonymizer.anonymize_into(TEXT, vault)
        store = MemoryVaultStore()
        store.save("c1", vault)

        vault.wipe(older_than=0)
        assert store.load("c1") is not None, "the stored copy is separate"

        store.delete("c1")
        assert store.load("c1") is None


class TestWipeIsSelectiveByAge:
    """The point of the age: forgetting the old without breaking the new.

    A long conversation keeps needing its recent values while the ones from
    twenty turns ago are finished. An all-or-nothing wipe forces a choice
    between keeping plaintext around and breaking a request in flight.
    """

    @staticmethod
    def aged(vault: Vault, token: str, seconds: float) -> None:
        """Pretend a token was minted `seconds` ago."""
        vault._minted_at[token] -= seconds

    def test_the_old_value_goes_and_the_new_one_stays(self, filled):
        _, vault, _ = filled
        first = sorted(vault.values)[0]
        self.aged(vault, first, 20 * 60)
        assert vault.wipe() == 1
        assert len(vault.values) == 1
        assert first not in vault.values

    def test_nothing_recent_is_touched_by_default(self, filled):
        _, vault, _ = filled
        assert vault.wipe() == 0
        assert len(vault.values) == 2

    def test_the_threshold_can_be_lowered(self, filled):
        _, vault, _ = filled
        self.aged(vault, sorted(vault.values)[0], 90)
        assert vault.wipe(older_than=60) == 1

    def test_the_threshold_can_be_raised(self, filled):
        """A caller keeping a long conversation alive."""
        _, vault, _ = filled
        self.aged(vault, sorted(vault.values)[0], 20 * 60)
        assert vault.wipe(older_than=60 * 60) == 0

    def test_zero_forgets_everything(self, filled):
        _, vault, _ = filled
        assert vault.wipe(older_than=0) == 2

    def test_a_negative_threshold_is_refused(self, filled):
        _, vault, _ = filled
        with pytest.raises(VaultError, match="cannot be negative"):
            vault.wipe(older_than=-1)

    def test_the_default_matches_the_store_ttl(self):
        """So a vault in memory and a vault in a cache age out together
        rather than one outliving the other by accident."""
        assert WIPE_AFTER_SECONDS == VAULT_TTL_SECONDS

    def test_a_surviving_value_still_restores(self, filled):
        """The whole point — the newer request is unaffected."""
        anonymizer, vault, payload = filled
        self.aged(vault, sorted(vault.values)[0], 20 * 60)
        vault.wipe()
        restored = anonymizer.restore(payload, vault)
        assert "+63 917 555 1234" in restored or "alice@acme.com" in restored


class TestAgesSurviveTheStore:
    """A vault crosses process boundaries, so its ages have to travel.

    They were recorded with `time.monotonic()` first, whose origin differs in
    every process — so a revived vault saw every value as infinitely old and
    wiped all of them, which is precisely the direction that breaks a request
    in flight.
    """

    def test_a_round_trip_preserves_the_ages(self, filled):
        _, vault, _ = filled
        first = sorted(vault.values)[0]
        vault._minted_at[first] -= 20 * 60
        revived = Vault.from_dict(vault.as_dict())
        assert revived.wipe() == 1
        assert len(revived.values) == 1

    def test_a_fresh_vault_survives_a_round_trip_intact(self, filled):
        _, vault, _ = filled
        revived = Vault.from_dict(vault.as_dict())
        assert revived.wipe() == 0
        assert len(revived.values) == 2

    def test_the_times_are_in_the_serialized_form(self, filled):
        _, vault, _ = filled
        assert set(vault.as_dict()["minted_at"]) == set(vault.values)

    def test_a_vault_with_no_recorded_times_is_treated_as_new(self):
        """A vault written by an older version. Keeping too long costs
        minutes of exposure; forgetting too much breaks a live request."""
        legacy = {"values": {"!|EMAIL_1|!": "carol@acme.com"}, "destroyed": []}
        vault = Vault.from_dict(legacy)
        assert vault.wipe() == 0
        assert vault.wipe(older_than=0) == 1

    def test_pickling_preserves_the_ages_too(self, filled):
        _, vault, _ = filled
        vault._minted_at[sorted(vault.values)[0]] -= 20 * 60
        revived = pickle.loads(pickle.dumps(vault))
        assert revived.wipe() == 1
