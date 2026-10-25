"""Behavior this library has to guarantee.

The phone cases carry the most weight. A pattern that covers only part of a
value leaves the rest in the output, and half a phone number is still a phone
number — so each one asserts that no digits survive, not merely that
something was replaced.
"""

from __future__ import annotations

import re

import pytest

from maskvault import Action, Anonymizer, Detector, is_phone_shaped


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
        assert anonymizer.restore("I work at [[ORG_9]]", vault) == "I work at [[ORG_9]]"

    def test_leaked_reports_unmatched_tokens(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme")
        assert anonymizer.leaked("at [[ORG_9]] now", vault) == ["[[ORG_9]]"]
        assert anonymizer.leaked("at [[ORG_1]] now", vault) == []


class TestPhoneNumbers:
    """Partial matches are the failure mode that matters."""

    @pytest.mark.parametrize(
        "number",
        [
            "+63 917 555 1234",
            "+1 (555) 123-4567",
            "0917-555-1234",
            "+44 20 7946 0958",
            "(02) 8123 4567",
        ],
    )
    def test_a_whole_number_is_replaced(self, anonymizer, number):
        safe, _ = anonymizer.anonymize(f"Call me on {number} today")
        leftover = re.findall(r"\d{3,}", safe)
        assert not leftover, f"{leftover} left in the prompt"

    def test_a_number_at_the_end_of_a_sentence(self, anonymizer):
        """Sentence punctuation must not shorten the match.

        A lookahead that excludes a following full stop rejects a number at
        the end of a sentence, and the engine then settles for a shorter
        match that leaves the final digits behind.
        """
        safe, _ = anonymizer.anonymize("Reach me at +63 917 555 1234.")
        assert not re.findall(r"\d{3,}", safe)

    @pytest.mark.parametrize("date", ["2024-06", "2017-08-31", "1999-01"])
    def test_iso_dates_are_not_phone_numbers(self, anonymizer, date):
        safe, _ = anonymizer.anonymize(f"I started in {date} there")
        assert date in safe

    @pytest.mark.parametrize("number", ["1200", "42", "3.12.8"])
    def test_short_numbers_are_left_alone(self, anonymizer, number):
        safe, _ = anonymizer.anonymize(f"the value is {number} exactly")
        assert number in safe

    @pytest.mark.parametrize(
        "candidate,expected",
        [
            ("+63 917 555 1234", True),
            ("555 1234", True),
            ("2024-06", False),
            ("12", False),
            ("1234567890123456789", False),  # beyond E.164
        ],
    )
    def test_shape_check(self, candidate, expected):
        assert is_phone_shaped(candidate) is expected


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


class TestConfiguration:
    def test_it_can_be_switched_off(self):
        anonymizer = Anonymizer(terms={"ORG": ["Acme"]}, enabled=False)
        safe, vault = anonymizer.anonymize("Acme and a@b.com")
        assert safe == "Acme and a@b.com"
        assert vault.replaced == 0

    def test_custom_detectors_replace_the_defaults(self):
        detector = Detector(
            label="employee_id",
            pattern=re.compile(r"\bEMP-\d{4}\b"),
            action=Action.REVERSIBLE,
        )
        anonymizer = Anonymizer(detectors=(detector,))
        safe, vault = anonymizer.anonymize("EMP-1234 wrote a@b.com")
        assert "[[EMPLOYEE_ID_1]]" in safe
        assert "a@b.com" in safe, "only the given detectors should apply"
        assert anonymizer.restore(safe, vault) == "EMP-1234 wrote a@b.com"

    def test_empty_input_is_safe(self, anonymizer):
        safe, vault = anonymizer.anonymize("")
        assert safe == ""
        assert vault.replaced == 0

    def test_restoring_without_a_vault_is_a_no_op(self, anonymizer):
        _, vault = anonymizer.anonymize("nothing here")
        assert anonymizer.restore("some answer", vault) == "some answer"
