"""A whitelist key that will not be read has to say so.

Silently ignoring one leaves a developer debugging why their value was still
replaced, with no way to see that the key was never looked at. The failure is
safe — an unapplied whitelist means more anonymization, not less — but it is
still a configuration that does not do what it says.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Whitelist
from maskvault.exceptions import WhitelistError


class TestUnknownKeysAreRefused:
    def test_an_unknown_key_raises(self):
        with pytest.raises(WhitelistError, match="unrecognized whitelist key"):
            Whitelist.from_dict({"regexes": ["x"]})

    def test_the_message_lists_every_recognized_key(self):
        with pytest.raises(WhitelistError) as caught:
            Whitelist.from_dict({"nonsense": ["x"]})
        for key in ("labels", "values", "patterns", "domains"):
            assert key in str(caught.value)

    def test_several_unknown_keys_are_all_named(self):
        with pytest.raises(WhitelistError) as caught:
            Whitelist.from_dict({"regexes": [], "nope": []})
        assert "regexes" in str(caught.value)
        assert "nope" in str(caught.value)

    def test_the_anonymizer_refuses_it_too(self):
        """The constructor takes a dict, so it is the same door."""
        with pytest.raises(WhitelistError):
            Anonymizer(whitelist={"regexes": ["x"]})

    def test_a_valid_whitelist_is_unaffected(self):
        whitelist = Whitelist.from_dict({"labels": ["url"], "values": ["Python"]})
        assert whitelist.allows_label("url")

    def test_an_empty_dict_is_fine(self):
        assert Whitelist.from_dict({}) is not None

    def test_none_is_fine(self):
        assert Whitelist.from_dict(None) is not None


class TestTheSuggestionPointsSomewhereUseful:
    """String distance alone suggests "prefixes" for "regexes", which sends
    someone to the wrong mechanism entirely."""

    @pytest.mark.parametrize(
        ("typo", "expected"),
        [
            ("regexes", "patterns"),
            ("regex", "patterns"),
            ("label", "labels"),
            ("value", "values"),
            ("allowlist", "values"),
            ("substring", "contains"),
            ("startswith", "prefixes"),
            ("endswith", "suffixes"),
        ],
    )
    def test_a_plausible_wrong_name_suggests_the_real_one(self, typo, expected):
        with pytest.raises(WhitelistError) as caught:
            Whitelist.from_dict({typo: []})
        assert f"did you mean '{expected}'" in str(caught.value)

    def test_an_unguessable_key_suggests_nothing(self):
        with pytest.raises(WhitelistError) as caught:
            Whitelist.from_dict({"zzz": []})
        assert "did you mean" not in str(caught.value)


class TestKeysThatAreReadButHoldNoPolicy:
    """`suggest_whitelist` emits a note, and its output is documented as
    usable as config — so a note has to be accepted. JSON has no comments,
    which leaves a config file nowhere else to explain itself."""

    def test_a_note_is_accepted(self):
        assert Whitelist.from_dict({"values": ["x"], "note": "why"}) is not None

    def test_the_suggestion_output_round_trips(self):
        """The regression this guards: the library's own output stopped being
        accepted by its own loader."""
        draft = Anonymizer().suggest_whitelist("write to me@acme.com about Python")
        assert Whitelist.from_dict(draft) is not None

    def test_a_comment_is_accepted(self):
        assert Whitelist.from_dict({"_comment": "set by the platform team"}) is not None

    def test_a_note_carries_no_policy(self):
        """It must not accidentally allow anything."""
        whitelist = Whitelist.from_dict({"note": "labels"})
        assert not whitelist.allows_label("labels")


class TestWhitelistEdges:
    def test_an_empty_value_is_allowed(self):
        """Nothing to protect, and replacing it would produce a token
        standing for nothing."""
        assert Whitelist.from_dict({}).allows_value("")
        assert Whitelist.from_dict({}).allows_value("   ")

    def test_a_pattern_that_will_not_compile_is_refused(self):
        """At construction, naming the pattern — not at match time, when the
        caller has no idea which entry was wrong."""
        with pytest.raises(WhitelistError, match="does not compile"):
            Whitelist.from_dict({"patterns": ["[unclosed"]})

    def test_the_description_mentions_a_predicate(self):
        """`describe()` is logged at startup, so it has to account for the one
        mechanism that has no JSON form."""
        whitelist = Whitelist(predicate=lambda value: value.startswith("ok"))
        assert "predicate" in whitelist.describe()

    def test_a_predicate_decides_what_is_left(self):
        whitelist = Whitelist(predicate=lambda value: value.endswith("@acme.com"))
        assert whitelist.allows_value("me@acme.com")
        assert not whitelist.allows_value("me@elsewhere.com")
