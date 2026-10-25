"""Knowing that a token restores to the value it was minted for.

A token is an index into one vault, not a global name. Two independent
vaults both mint `EMAIL_1` for different addresses, so restoring with the
wrong vault returns another caller's value — silently, because the lookup
succeeds. That is the most dangerous failure this library can have: not an
error, a plausible wrong answer.

What prevents it, in order of strength:

    the pairing   keep the vault with the request that produced it. This is
                  the actual guarantee; everything below is a safety net
                  under a mistake.
    for_key       derive the marker from an id you already have unique, so
                  distinct conversations cannot produce the same marker
                  except on a digest collision.
    scoped        a random marker, so two vaults are very unlikely to agree.
    unscoped      no protection at all. Tokens collide by construction.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Vault
from maskvault.exceptions import VaultError

ALICE = "Email alice@acme.com"
BOB = "Email bob@other.com"


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer()


class TestAnUnscopedVaultCollides:
    """Documented so nobody mistakes the default for a guarantee."""

    def test_two_vaults_mint_the_same_token(self, anonymizer):
        alice, _ = anonymizer.anonymize(ALICE)
        bob, _ = anonymizer.anonymize(BOB)
        assert alice == bob

    def test_the_wrong_vault_silently_returns_another_value(self, anonymizer):
        """The reason `scoped` and `for_key` exist."""
        alice, _ = anonymizer.anonymize(ALICE)
        _, bob_vault = anonymizer.anonymize(BOB)
        assert anonymizer.restore(alice, bob_vault) == BOB

    def test_and_leaked_cannot_see_the_mistake(self, anonymizer):
        """The token resolved, so nothing is left for `leaked` to report."""
        alice, _ = anonymizer.anonymize(ALICE)
        _, bob_vault = anonymizer.anonymize(BOB)
        assert anonymizer.leaked(alice, bob_vault) == []


class TestAScopedVaultIsCaught:
    def test_two_scoped_vaults_do_not_collide(self, anonymizer):
        alice = anonymizer.anonymize_into(ALICE, Vault.scoped())
        bob = anonymizer.anonymize_into(BOB, Vault.scoped())
        assert alice != bob

    def test_the_wrong_vault_restores_nothing(self, anonymizer):
        """Left as it was, rather than swapped for someone else's value."""
        alice_vault, bob_vault = Vault.scoped(), Vault.scoped()
        alice = anonymizer.anonymize_into(ALICE, alice_vault)
        anonymizer.anonymize_into(BOB, bob_vault)
        assert anonymizer.restore(alice, bob_vault) == alice

    def test_and_leaked_reports_it(self, anonymizer):
        alice_vault, bob_vault = Vault.scoped(), Vault.scoped()
        alice = anonymizer.anonymize_into(ALICE, alice_vault)
        anonymizer.anonymize_into(BOB, bob_vault)
        assert anonymizer.leaked(alice, bob_vault)

    def test_the_right_vault_still_works(self, anonymizer):
        vault = Vault.scoped()
        alice = anonymizer.anonymize_into(ALICE, vault)
        assert anonymizer.restore(alice, vault) == ALICE


class TestADerivedMarkerIsDeterministic:
    def test_the_same_key_gives_the_same_marker(self):
        """So a retry, a replay or a second node agree."""
        assert Vault.for_key("conversation-42").scope == Vault.for_key("conversation-42").scope

    def test_different_keys_give_different_markers(self):
        assert Vault.for_key("conversation-42").scope != Vault.for_key("conversation-43").scope

    def test_the_marker_does_not_reveal_the_key(self):
        """A session id is often a user identifier, and the marker goes into
        every token in the payload."""
        marker = Vault.for_key("user-jan@acme.com-session-1").scope
        assert "JAN" not in marker or "ACME" not in marker

    def test_the_marker_is_letters_only(self):
        """A digit would stop a scoped token matching its own vault's
        pattern, which is what `leaked` relies on."""
        assert Vault.for_key("anything").scope.isalpha()
        assert Vault.for_key("anything").scope.isupper()

    def test_an_empty_key_is_refused(self):
        with pytest.raises(VaultError, match="non-empty key"):
            Vault.for_key("")

    def test_zero_letters_is_refused(self):
        with pytest.raises(VaultError, match="at least one letter"):
            Vault.for_key("session", letters=0)

    def test_loading_the_wrong_conversation_is_caught(self, anonymizer):
        """The marker is a function of the id asked for, so a mix-up shows."""
        right = Vault.for_key("session-1")
        wrong = Vault.for_key("session-2")
        payload = anonymizer.anonymize_into(ALICE, right)
        assert anonymizer.restore(payload, wrong) == payload
        assert anonymizer.leaked(payload, wrong)


class TestAWideMarkerDoesNotTripTheEntropyNet:
    """A regression guard, for a bug a widening introduced.

    The entropy detector's candidate pattern stops at the delimiters, so what
    reached it was the bare `EMAIL_QRMZVB_1` core. With a twelve-letter random
    scope that core measured as a high-entropy secret and the token was
    *destroyed* — the value lost for good and the vault left holding a token
    no longer present in the text. At twelve letters it happened to 11% of
    tokens, at sixteen to 39%, and only sometimes, depending on the draw.
    """

    TEXT = "Email carol@acme.com or call +63 917 555 1234 at 10.42.7.19"

    @pytest.mark.parametrize("letters", [1, 4, 8, 12, 16, 24, 32])
    def test_a_round_trip_holds_at_any_marker_width(self, anonymizer, letters):
        vault = Vault.scoped(letters=letters)
        payload = anonymizer.anonymize_into(self.TEXT, vault)
        assert anonymizer.restore(payload, vault) == self.TEXT

    @pytest.mark.parametrize("letters", [12, 16, 24])
    def test_no_notice_replaces_a_reversible_token(self, anonymizer, letters):
        """A destroyed token shows up as a notice in the payload."""
        vault = Vault.scoped(letters=letters)
        payload = anonymizer.anonymize_into(self.TEXT, vault)
        assert "was removed before sending" not in payload

    def test_a_derived_marker_survives_too(self, anonymizer):
        vault = Vault.for_key("conversation-42")
        payload = anonymizer.anonymize_into(self.TEXT, vault)
        assert anonymizer.restore(payload, vault) == self.TEXT

    def test_repeated_draws_all_round_trip(self, anonymizer):
        """The bug was intermittent, so one sample proves nothing."""
        for _ in range(200):
            vault = Vault.scoped()
            payload = anonymizer.anonymize_into(self.TEXT, vault)
            assert anonymizer.restore(payload, vault) == self.TEXT

    def test_a_real_secret_is_still_destroyed(self, anonymizer):
        """The guard must not have become a hole: a genuine high-entropy
        value that merely looks token-shaped is still judged on its own."""
        payload, _ = anonymizer.anonymize("token xK9mQ2vL8pR4tN6wY3zB7cH5")
        assert "xK9mQ2vL8pR4tN6wY3zB7cH5" not in payload


class TestMarkersAreUniqueAtScale:
    def test_fifty_thousand_random_markers_are_distinct(self):
        markers = {Vault._new_scope() for _ in range(50_000)}
        assert len(markers) == 50_000

    def test_fifty_thousand_derived_markers_are_distinct(self):
        markers = {Vault._derive_scope(f"conversation-{n}") for n in range(50_000)}
        assert len(markers) == 50_000


class TestARandomMarkerWidthIsValidated:
    def test_zero_letters_is_refused(self):
        """`Vault()` is how you ask for no marker; zero width would be a
        scoped vault whose marker distinguishes nothing."""
        with pytest.raises(VaultError, match="at least one letter"):
            Vault.scoped(letters=0)

    def test_a_negative_width_is_refused(self):
        with pytest.raises(VaultError, match="at least one letter"):
            Vault.scoped(letters=-1)

    def test_one_letter_is_allowed(self):
        """Weak, but a deliberate choice rather than an error."""
        assert len(Vault.scoped(letters=1).scope) == 1
