"""Pushing anonymized text to a model and restoring its reply.

The use case the library exists for, and the one with the most ways to fail
quietly. A model is not a function: it reformats placeholders, wraps them in
Markdown, breaks them over lines, invents ones that were never minted. None
of that is a bug in the model — it is prose generation — so the library has
to notice.

Restoring is a literal replacement, so an altered token simply is not
replaced. What matters is that `leaked()` says so, because a reply that
silently lost a value is worse than one that visibly failed.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer
from maskvault.models.vault import Vault


@pytest.fixture
def exchange():
    """A question sent to a model, with the vault that goes with it."""
    anonymizer = Anonymizer()
    safe, vault = anonymizer.anonymize("reply to alice@acme.com, cc bob@acme.com")
    return anonymizer, safe, vault


class TestAModelThatBehaves:
    def test_a_verbatim_echo_restores(self, exchange):
        anonymizer, _, vault = exchange
        reply = f"I will email {next(iter(vault.snapshot()))} today."
        assert "alice@acme.com" in anonymizer.restore(reply, vault)

    def test_and_reports_nothing_leaked(self, exchange):
        anonymizer, _, vault = exchange
        reply = f"I will email {next(iter(vault.snapshot()))} today."
        assert anonymizer.leaked(reply, vault) == []

    def test_markdown_around_a_token_is_fine(self, exchange):
        """Bold and code fences do not touch the token itself."""
        anonymizer, _, vault = exchange
        token = next(iter(vault.snapshot()))
        for reply in (f"**{token}**", f"`{token}`", f"```\nto: {token}\n```"):
            assert "alice@acme.com" in anonymizer.restore(reply, vault)
            assert anonymizer.leaked(reply, vault) == []

    def test_a_repeated_token_restores_every_time(self, exchange):
        anonymizer, _, vault = exchange
        token = next(iter(vault.snapshot()))
        restored = anonymizer.restore(f"{token} and {token}", vault)
        assert restored.count("alice@acme.com") == 2

    def test_a_reply_mentioning_nothing_is_clean(self, exchange):
        """Not every reply quotes a token, and that is not a failure."""
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("I have sent the message.", vault) == []


class TestAModelThatAltersTheToken:
    """Each of these used to pass silently: the value was gone from the reply
    and `leaked()` reported nothing."""

    @pytest.mark.parametrize(
        ("behaviour", "reply"),
        [
            ("inner spaces", "I will email !| EMAIL_1 |! today."),
            ("delimiters dropped", "I will email EMAIL_1 today."),
            ("delimiters swapped", "I will email [EMAIL_1] today."),
            ("label lower-cased", "I will email !|email_1|! today."),
            ("broken over a line", "I will email !|EMAIL\n_1|! today."),
            ("underscore spaced", "I will email !|EMAIL _ 1|! today."),
        ],
    )
    def test_it_is_reported(self, exchange, behaviour, reply):
        anonymizer, _, vault = exchange
        assert anonymizer.leaked(reply, vault) == ["EMAIL_1"]

    @pytest.mark.parametrize(
        "reply",
        [
            "I will email !| EMAIL_1 |! today.",
            "I will email EMAIL_1 today.",
            "I will email [EMAIL_1] today.",
        ],
    )
    def test_the_value_really_is_missing(self, exchange, reply):
        """Which is why reporting it matters: the caller cannot show this."""
        anonymizer, _, vault = exchange
        assert "alice@acme.com" not in anonymizer.restore(reply, vault)


class TestAModelThatInventsAToken:
    def test_a_well_formed_unknown_token_is_reported(self, exchange):
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("I will email !|EMAIL_9|! today.", vault) == ["!|EMAIL_9|!"]

    def test_it_is_not_resolved_to_something_unrelated(self, exchange):
        """A visible oddity beats a silently wrong answer."""
        anonymizer, _, vault = exchange
        restored = anonymizer.restore("email !|EMAIL_9|!", vault)
        assert "!|EMAIL_9|!" in restored
        assert "alice@acme.com" not in restored

    def test_an_unrelated_label_is_not_reported(self, exchange):
        """Only labels this vault actually minted."""
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("see PHONE_1 in the spec", vault) == []


class TestItOverReportsOnPurpose:
    """The deliberate trade. A false positive costs a fallback on a request
    that was fine; a false negative costs a value silently missing from an
    answer somebody acts on."""

    def test_a_column_named_like_a_token_is_flagged(self, exchange):
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("the EMAIL_1 column in users", vault) == ["EMAIL_1"]

    def test_ordinary_prose_about_email_is_not(self, exchange):
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("I sent the email 1 hour ago", vault) == []

    def test_an_index_this_vault_never_minted_is_not(self, exchange):
        anonymizer, _, vault = exchange
        assert anonymizer.leaked("EMAIL_42 is not here", vault) == []

    def test_an_empty_vault_still_reports_a_well_formed_token(self, exchange):
        """It cannot restore the token, so the token genuinely is unrestored.

        The bare core is not reported, because an empty vault minted nothing
        and there is no core to look for — which is the right asymmetry:
        a well-formed token is evidence on its own, a bare label is only
        evidence relative to what this vault issued.
        """
        anonymizer, _, _ = exchange
        assert anonymizer.leaked("EMAIL_1 and !|EMAIL_1|!", Vault()) == ["!|EMAIL_1|!"]


class TestAMultiTurnChat:
    def test_one_vault_across_turns_keeps_one_token_per_person(self):
        """So the model can be told two turns refer to the same person."""
        anonymizer = Anonymizer()
        vault = Vault()
        first = anonymizer.anonymize_into("who is alice@acme.com?", vault)
        second = anonymizer.anonymize_into("email alice@acme.com again", vault)
        assert len(vault.snapshot()) == 1
        token = next(iter(vault.snapshot()))
        assert token in first
        assert token in second

    def test_a_reply_referring_to_an_earlier_turn_restores(self):
        anonymizer = Anonymizer()
        vault = Vault()
        anonymizer.anonymize_into("who is alice@acme.com?", vault)
        anonymizer.anonymize_into("and bob@acme.com?", vault)
        token = sorted(vault.snapshot())[0]
        restored = anonymizer.restore(f"as I said, {token} is the owner", vault)
        assert "@acme.com" in restored

    def test_the_wrong_turns_vault_is_caught(self):
        """A fresh vault per turn breaks a reply quoting an earlier token,
        and that has to be visible rather than silent."""
        anonymizer = Anonymizer()
        _, first_vault = anonymizer.anonymize("who is alice@acme.com?")
        token = next(iter(first_vault.snapshot()))

        # The wrong vault reports it, so the caller can fall back.
        assert anonymizer.leaked(f"{token} is the owner", Vault()) == [token]

        # The right vault restores it.
        assert "alice@acme.com" in anonymizer.restore(f"{token} is the owner", first_vault)


class TestAVaultWithAForeignToken:
    """A vault loaded from a store may hold a key written in a different
    format. Looking for its core would mean parsing a token this format
    cannot read, so it is skipped rather than guessed at."""

    def test_an_unparseable_key_is_skipped(self):
        anonymizer = Anonymizer()
        vault = Vault(values={"not-a-token": "me@acme.com", "!|EMAIL_1|!": "a@b.com"})
        # Only the parseable token contributes a core to look for.
        assert anonymizer.leaked("EMAIL_1 survived", vault) == ["EMAIL_1"]

    def test_a_vault_of_only_foreign_keys_reports_nothing(self):
        anonymizer = Anonymizer()
        vault = Vault(values={"not-a-token": "me@acme.com"})
        assert anonymizer.leaked("nothing token-shaped here", vault) == []

    def test_restoring_still_works_for_the_foreign_key(self):
        """It is a literal replacement, so a key this format cannot parse is
        still substituted."""
        anonymizer = Anonymizer()
        vault = Vault(values={"not-a-token": "me@acme.com"})
        assert anonymizer.restore("see not-a-token", vault) == "see me@acme.com"
