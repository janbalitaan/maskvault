"""Placeholder delimiters must not collide with the markup around them.

Double square brackets are the most legible choice for a language model and
also wikilink syntax in Obsidian, Roam, Logseq and MediaWiki. These tests pin
both halves of that trade: the legible format is used when it is safe, and
something else is used when it is not.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.models.token_format import (
    ANGLES,
    AT_SIGNS,
    BRACKETS,
    DEFAULT_FORMATS,
    MATH_BRACKETS,
    TokenFormat,
    choose_format,
    format_from_dict,
    random_format,
)


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestFormatSelection:
    def test_plain_text_gets_the_most_legible_format(self):
        assert choose_format("ordinary prose about work") is BRACKETS

    def test_wikilinks_force_a_different_format(self):
        assert choose_format("see [[Meeting Notes]]") is AT_SIGNS

    def test_each_collision_falls_through(self):
        assert choose_format("[[a]] and @@b@@") is ANGLES
        assert choose_format("[[a]] @@b@@ <<c>>") is MATH_BRACKETS

    def test_it_never_returns_nothing(self):
        """Even text containing every delimiter gets a format."""
        hostile = "[[a]] @@b@@ <<c>> ⟦d⟧"
        assert choose_format(hostile) is DEFAULT_FORMATS[-1]

    def test_only_the_opening_delimiter_decides(self):
        """A stray closing delimiter is harmless on its own, and rejecting it
        would switch formats more often than necessary."""
        assert choose_format("a closing ]] alone") is BRACKETS


class TestNoNesting:
    def test_a_value_inside_a_wikilink_does_not_nest(self, anonymizer):
        safe, _ = anonymizer.anonymize("See [[Acme Corp]] today")
        assert "[[[[" not in safe
        assert "]]]]" not in safe

    def test_the_surrounding_wikilink_survives(self, anonymizer):
        text = "See [[Meeting Notes]] and Acme Corp"
        safe, _ = anonymizer.anonymize(text)
        assert "[[Meeting Notes]]" in safe

    def test_the_round_trip_is_still_exact(self, anonymizer):
        text = "See [[Meeting Notes]]. I work at Acme Corp, mail me@acme.com"
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) == text


class TestLeakDetection:
    def test_a_wikilink_shaped_like_a_token_is_not_a_leak(self, anonymizer):
        """A link to a page called API_2 has the exact shape of a token, so
        leak detection has to judge against the format actually used."""
        _, vault = anonymizer.anonymize("See [[Notes]] at Acme Corp")
        assert anonymizer.leaked("text with [[API_2]] in it", vault) == []

    def test_a_genuinely_mangled_token_is_still_reported(self, anonymizer):
        _, vault = anonymizer.anonymize("Acme Corp")
        assert anonymizer.leaked("I work at [[ORG_9]]", vault) == ["[[ORG_9]]"]


class TestPinnedFormats:
    def test_a_format_can_be_pinned_by_name(self):
        anonymizer = Anonymizer(token_format="at_signs", terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("I work at Acme")
        assert "@@ORG_1@@" in safe

    def test_a_pinned_format_is_used_even_when_it_collides(self):
        """Pinning means the caller has taken responsibility for the choice."""
        anonymizer = Anonymizer(token_format="brackets", terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("see [[Notes]], I work at Acme")
        assert "[[ORG_1]]" in safe

    def test_a_custom_format_works(self):
        custom = TokenFormat(name="braces", opening="{{", closing="}}")
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        safe, vault = anonymizer.anonymize("I work at Acme")
        assert "{{ORG_1}}" in safe
        assert anonymizer.restore(safe, vault) == "I work at Acme"

    def test_an_unpinned_anonymizer_reports_no_fixed_format(self, anonymizer):
        assert anonymizer.token_format is None


class TestFormatMechanics:
    def test_the_pattern_matches_what_the_template_writes(self):
        for token_format in DEFAULT_FORMATS:
            rendered = token_format.render("HEALTH", 3)
            assert token_format.pattern.fullmatch(rendered)

    def test_a_vault_carries_its_format(self, anonymizer):
        _, vault = anonymizer.anonymize("see [[Notes]] at Acme Corp")
        assert vault.token_format is AT_SIGNS

    def test_the_summary_still_counts_by_kind(self, anonymizer):
        """Counting reads tokens back, so it has to use the vault's format."""
        _, vault = anonymizer.anonymize("see [[Notes]], Acme Corp, me@acme.com")
        summary = vault.summary()
        assert "org" in summary
        assert "email" in summary


class TestCustomFormats:
    """A caller owns the format. The library's job is to stop them shipping a
    broken one, not to limit what they can choose."""

    def test_a_fully_custom_format_round_trips(self):
        custom = TokenFormat(name="mine", opening="<%|", closing="|%>")
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        text = "I work at Acme"
        safe, vault = anonymizer.anonymize(text)
        assert "<%|ORG_1|%>" in safe
        assert anonymizer.restore(safe, vault) == text

    def test_lowercase_labels_work_end_to_end(self):
        custom = TokenFormat(
            name="lower",
            opening="{{",
            closing="}}",
            label_pattern=r"[a-z_]+",
            label_case="lower",
        )
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        safe, vault = anonymizer.anonymize("I work at Acme")
        assert "{{org_1}}" in safe
        assert anonymizer.restore(safe, vault) == "I work at Acme"

    def test_a_caller_supplies_their_own_candidates(self):
        mine = TokenFormat(name="mine", opening="<%|", closing="|%>")
        anonymizer = Anonymizer(format_candidates=(mine,), terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("see [[Notes]], I work at Acme")
        assert "<%|ORG_1|%>" in safe

    def test_candidates_are_reported(self):
        mine = TokenFormat(name="mine", opening="<%|", closing="|%>")
        assert Anonymizer(format_candidates=(mine,)).format_candidates == (mine,)

    def test_a_random_format_is_unguessable_and_works(self):
        anonymizer = Anonymizer(token_format=random_format(), terms={"ORG": ["Acme"]})
        text = "I work at Acme"
        safe, vault = anonymizer.anonymize(text)
        assert "Acme" not in safe
        assert anonymizer.restore(safe, vault) == text

    def test_two_random_formats_differ(self):
        assert random_format().opening != random_format().opening

    def test_a_format_round_trips_through_config(self):
        custom = TokenFormat(
            name="mine",
            opening="<%|",
            closing="|%>",
            label_pattern=r"[a-z_]+",
            label_case="lower",
        )
        assert format_from_dict(custom.as_dict()) == custom

    def test_label_case_and_label_pattern_are_validated_together(self):
        """They can only drift apart once, at construction, rather than
        silently at restore time."""
        with pytest.raises(ValueError, match="cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_case="lower")

    def test_config_without_required_keys_is_rejected(self):
        with pytest.raises(ValueError, match="opening"):
            format_from_dict({"name": "incomplete"})


class TestBrokenFormatsAreRefused:
    """A format whose pattern does not match its own output would lose every
    value at restore time, with no error. So it is refused at construction."""

    def test_a_missing_delimiter_is_refused(self):
        with pytest.raises(ValueError, match="delimiter"):
            TokenFormat(name="bad", opening="[[", closing="")

    def test_a_pattern_that_cannot_match_its_output_is_refused(self):
        with pytest.raises(ValueError, match="cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern=r"\d+")

    def test_an_uncompilable_pattern_is_refused(self):
        with pytest.raises(ValueError, match="does not compile"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern="[unclosed")

    def test_an_unknown_label_case_is_refused(self):
        with pytest.raises(ValueError, match="label_case"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_case="title")

    def test_choosing_from_no_candidates_is_refused(self):
        with pytest.raises(ValueError, match="at least one"):
            choose_format("text", ())

    def test_every_built_in_format_is_valid(self):
        """The validation applies to the library's own formats too."""
        for token_format in DEFAULT_FORMATS:
            assert token_format.pattern.fullmatch(token_format.render("LABEL", 1))
