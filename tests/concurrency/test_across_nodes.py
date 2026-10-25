"""Anonymizing on one node and restoring on another.

The deployment question this answers: a request is anonymized on API node 1,
and the provider's reply is restored on node 2. There are three outcomes and
they are not equally bad.

**The vault travels with the work.** Correct, and what the library is built
for — the vault is returned to the caller rather than held, so it can be
pickled, serialized or kept in a store keyed to the request.

**Node 2 has no vault.** The token stays visible. Wrong, but obviously wrong,
and `leaked()` reports it.

**Node 2 has its own unrelated vault.** This is the dangerous one. Both
vaults independently minted the identical string, so node 1's token is found
in node 2's vault and resolves to *someone else's value*. A wrong answer, not
a missing one, and `leaked()` sees nothing because the token really is there.

`Vault.scoped()` is the answer to the third: a random marker in every label,
so two vaults cannot mint the same token and the mismatch degrades to the
second case.
"""

from __future__ import annotations

import pickle

from maskvault import Anonymizer
from maskvault.models.vault import Vault

ALICE = "email alice@acme.com about the invoice"


class TestTheVaultTravelsWithTheWork:
    def test_restoring_on_another_node_works(self):
        """What the library is built for: the vault is the caller's to move."""
        node1 = Anonymizer()
        safe, vault = node1.anonymize(ALICE)

        # Over the wire, a queue, or a store.
        carried_safe, carried_vault = pickle.loads(pickle.dumps((safe, vault)))

        node2 = Anonymizer()
        assert node2.restore(carried_safe, carried_vault) == ALICE

    def test_the_two_nodes_need_no_shared_configuration(self):
        """Node 2 does not have to be told which format was used — the vault
        carries it, which is why restoring never needs to be configured."""
        node1 = Anonymizer(token_format="brackets")
        safe, vault = node1.anonymize(ALICE)
        node2 = Anonymizer()  # a different default
        assert node2.restore(safe, vault) == ALICE


class TestNodeTwoHasNoVault:
    def test_the_token_stays_visible(self):
        node1 = Anonymizer()
        _, vault = node1.anonymize(ALICE)
        token = next(iter(vault.snapshot()))
        reply = f"I will contact {token} today."

        node2 = Anonymizer()
        assert token in node2.restore(reply, Vault())

    def test_leaked_reports_it(self):
        """So a caller can fail loudly rather than return a token to a user."""
        node1 = Anonymizer()
        _, vault = node1.anonymize(ALICE)
        token = next(iter(vault.snapshot()))
        node2 = Anonymizer()
        # With the vault node 2 actually has — the empty one — the token is
        # reported. This is the case a deployment can detect and fail on.
        assert node2.leaked(f"contact {token}", Vault()) == [token]
        # Handed node 1's vault it reports nothing, because that vault
        # restores the token. `leaked` restores before it looks.
        assert node2.leaked(f"contact {token}", vault) == []


class TestNodeTwoHasItsOwnVault:
    def test_an_unscoped_token_resolves_to_the_wrong_value(self):
        """The failure this whole module exists to document. Both vaults mint
        the identical string, so node 1's token is found in node 2's vault."""
        node1 = Anonymizer(token_format="pipe_bang")
        _, vault1 = node1.anonymize("email alice@acme.com")
        token = next(iter(vault1.snapshot()))

        node2 = Anonymizer(token_format="pipe_bang")
        vault2 = Vault()
        node2.anonymize_into("email bob@other.com", vault2)

        wrong = node2.restore(f"I contacted {token}", vault2)
        assert "bob@other.com" in wrong
        assert "alice@acme.com" not in wrong
        # And nothing reports a problem, which is what makes it dangerous.
        assert node2.leaked(wrong, vault2) == []

    def test_a_scoped_token_does_not(self):
        """With a scope the tokens cannot collide, so the wrong vault leaves
        the token visible instead of resolving it to someone else."""
        node1 = Anonymizer()
        vault1 = Vault.scoped()
        node1.anonymize_into("email alice@acme.com", vault1)
        token = next(iter(vault1.snapshot()))

        node2 = Anonymizer()
        vault2 = Vault.scoped()
        node2.anonymize_into("email bob@other.com", vault2)

        result = node2.restore(f"I contacted {token}", vault2)
        assert "bob@other.com" not in result
        assert "alice@acme.com" not in result
        assert token in result

    def test_and_leaked_reports_the_mismatch(self):
        """The silent wrong answer becomes a detectable one."""
        node1 = Anonymizer()
        vault1 = Vault.scoped()
        node1.anonymize_into("email alice@acme.com", vault1)
        token = next(iter(vault1.snapshot()))

        node2 = Anonymizer()
        vault2 = Vault.scoped()
        node2.anonymize_into("email bob@other.com", vault2)
        # Same delimiters, so node 2's pattern sees the foreign token — and
        # restoring does not consume it, because the scope differs.
        assert node2.leaked(f"I contacted {token}", vault2) == [token]


class TestScopedVaults:
    def test_a_scope_appears_in_the_token(self):
        vault = Vault.scoped()
        token = vault.mint("EMAIL", "me@acme.com")
        assert vault.scope in token

    def test_two_scoped_vaults_differ(self):
        assert Vault.scoped().scope != Vault.scoped().scope

    def test_a_scoped_vault_still_round_trips(self):
        anonymizer = Anonymizer()
        vault = Vault.scoped()
        safe = anonymizer.anonymize_into(ALICE, vault)
        assert anonymizer.restore(safe, vault) == ALICE

    def test_a_repeated_value_still_keeps_one_token(self):
        anonymizer = Anonymizer()
        vault = Vault.scoped()
        anonymizer.anonymize_into("email alice@acme.com", vault)
        anonymizer.anonymize_into("email alice@acme.com again", vault)
        assert len(vault.snapshot()) == 1

    def test_numbering_still_advances(self):
        anonymizer = Anonymizer()
        vault = Vault.scoped()
        anonymizer.anonymize_into("email a@acme.com and b@acme.com", vault)
        assert len(vault.snapshot()) == 2

    def test_a_scoped_vault_survives_pickling(self):
        """It has to, or it cannot reach the other node in the first place."""
        vault = Vault.scoped()
        anonymizer = Anonymizer()
        safe = anonymizer.anonymize_into(ALICE, vault)
        carried = pickle.loads(pickle.dumps(vault))
        assert carried.scope == vault.scope
        assert anonymizer.restore(safe, carried) == ALICE

    def test_a_custom_format_can_be_scoped(self):
        vault = Vault.scoped()
        assert vault.token_format is not None

    def test_the_default_is_unscoped(self):
        """Off by default: it makes tokens longer, and a longer token is one
        a model is more likely to reformat. Worth it when restoring happens
        elsewhere, not otherwise."""
        assert Vault().scope == ""
