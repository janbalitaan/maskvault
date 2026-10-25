"""The vault's reporting, and a token format's own round trip."""

from __future__ import annotations

import pytest

from maskvault import DEFAULT_FORMATS, Anonymizer, Level
from maskvault.exceptions import TokenFormatError
from maskvault.models.token_format import TokenFormat
from maskvault.models.vault import Vault


class TestVaultSummary:
    """Safe to log, so it is the thing an application actually records."""

    def test_an_empty_vault_says_nothing_was_replaced(self):
        assert Vault().summary() == "nothing replaced"

    def test_it_counts_the_destroyed_separately(self):
        """A destroyed value is not coming back, which is a different event
        from one that was tokenized."""
        _, vault = Anonymizer().anonymize("key=sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc")
        assert "destroyed" in vault.summary()

    def test_it_counts_reversible_replacements_by_kind(self):
        _, vault = Anonymizer().anonymize("write to me@acme.com and you@acme.com")
        assert "email" in vault.summary()

    def test_it_carries_no_values(self):
        """The reason it exists: this is what gets logged."""
        _, vault = Anonymizer().anonymize("write to me@acme.com")
        assert "me@acme.com" not in vault.summary()

    def test_replaced_counts_the_tokens(self):
        _, vault = Anonymizer().anonymize("write to me@acme.com and you@acme.com")
        assert vault.replaced == 2


class TestTokenFormatRoundTrip:
    def test_a_format_can_read_back_its_own_output(self):
        """Validated at construction, because a format that cannot is one
        whose tokens can never be restored."""
        token_format = TokenFormat(name="pipes", opening="||", closing="||")
        rendered = token_format.render("EMAIL", 1)
        assert token_format.pattern.match(rendered)

    def test_the_example_shows_what_a_token_looks_like(self):
        token_format = TokenFormat(name="pipes", opening="||", closing="||")
        assert token_format.example == "||LABEL_1||"

    def test_a_regex_metacharacter_delimiter_is_escaped(self):
        """Parentheses are a grouping construct, so an unescaped delimiter
        would compile into something that matches nothing like a token."""
        token_format = TokenFormat(name="parens", opening="(", closing=")")
        assert token_format.pattern.match(token_format.render("EMAIL", 1))

    def test_a_format_with_no_delimiter_is_refused(self):
        """Without one, a token is not distinguishable from prose."""
        with pytest.raises(TokenFormatError, match="opening and a closing"):
            TokenFormat(name="broken", opening="", closing=">")

    def test_a_label_case_the_pattern_disagrees_with_is_refused(self):
        """The two are validated together, so they cannot drift apart and
        lose every value at restore time."""
        with pytest.raises(TokenFormatError, match="cannot match its own output"):
            TokenFormat(
                name="mismatched",
                opening="<",
                closing=">",
                label_pattern=r"[a-z]+",
                label_case="keep",
            )

    def test_an_unknown_label_case_is_refused(self):
        with pytest.raises(TokenFormatError, match="label_case"):
            TokenFormat(name="odd", opening="<", closing=">", label_case="sideways")

    def test_label_case_is_applied_by_label_for_not_render(self):
        """`render` writes what it is given; casing is a separate step, so a
        caller who already cased a label does not get it cased twice."""
        lower = TokenFormat(
            name="lower",
            opening="<",
            closing=">",
            label_pattern=r"[a-z]+",
            label_case="lower",
        )
        assert lower.render("EMAIL", 1) == "<EMAIL_1>"
        assert lower.render(lower.label_for("EMAIL"), 1) == "<email_1>"

    def test_the_example_matches_what_a_real_token_looks_like(self):
        """It advertised `<LABEL_1>` for a format whose tokens were actually
        `<label_1>` — the one thing an example must not do."""
        lower = TokenFormat(
            name="lower",
            opening="<",
            closing=">",
            label_pattern=r"[a-z]+",
            label_case="lower",
        )
        assert lower.example == "<label_1>"
        assert lower.pattern.fullmatch(lower.example)

    def test_every_default_format_advertises_a_matchable_example(self):

        for token_format in DEFAULT_FORMATS:
            assert token_format.pattern.fullmatch(token_format.example)


class TestParanoidReachesFurther:
    """The level exists to make a specific trade: more false positives for
    fewer misses."""

    def test_it_catches_a_punctuated_password_standard_misses(self):
        text = "the password is Tr0ub4dour&3-horse"
        standard, _ = Anonymizer(level=Level.STANDARD).anonymize(text)
        paranoid, _ = Anonymizer(level=Level.PARANOID).anonymize(text)
        assert len(paranoid) != len(standard) or paranoid != standard


class TestVaultSummaryEdges:
    def test_a_token_that_does_not_match_the_format_is_skipped(self):
        """A vault loaded from disk may carry a key written by a different
        format. Counting it under the wrong label would be worse than
        leaving it out of the summary."""
        vault = Vault(values={"not-a-token": "value"})
        assert vault.summary() == "nothing replaced"

    def test_destroyed_alone_still_summarizes(self):
        vault = Vault(destroyed=["api_key"])
        assert "1 destroyed" in vault.summary()
