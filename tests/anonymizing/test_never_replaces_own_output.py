"""A detector must never claim text an earlier detector inserted.

Detectors run one after another over progressively replaced text, so a later
one sees the tokens and notices the earlier ones left behind. At PARANOID — a
lower entropy bar and symbols in the alphabet — `@@IP_ADDRESS_1@@` measures as
a high-entropy value.

The consequence was not cosmetic. A destroyed token loses the original
permanently and leaves a vault whose tokens no longer appear in the text, so
restoring could never work and nothing said why.
"""

from __future__ import annotations

import re

import pytest

from maskvault import Anonymizer, Level, TokenFormats, anonymize_data, restore_data
from maskvault.models.action import Action
from maskvault.models.detector import Detector

STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
TEXT = f"request from 10.42.7.19 user=jan.doe@acme.com key={STRIPE_KEY}"

LEVELS = list(Level)


class TestEveryTokenSurvives:
    @pytest.mark.parametrize("level", LEVELS, ids=lambda item: item.value)
    def test_every_minted_token_is_present_in_the_output(self, level):
        """The invariant that was broken: a vault entry whose token is absent
        from the text is unrestorable, and silently so."""
        anonymizer = Anonymizer(level=level)
        safe, vault = anonymizer.anonymize(TEXT)
        for token in vault.values:
            assert token in safe, f"{token} was minted and then destroyed"

    @pytest.mark.parametrize("level", LEVELS, ids=lambda item: item.value)
    def test_the_round_trip_returns_the_original_values(self, level):
        anonymizer = Anonymizer(level=level)
        safe, vault = anonymizer.anonymize(TEXT)
        restored = anonymizer.restore(safe, vault)
        for original in vault.values.values():
            assert original in restored

    @pytest.mark.parametrize("level", LEVELS, ids=lambda item: item.value)
    def test_nothing_is_left_unrestorable(self, level):
        anonymizer = Anonymizer(level=level)
        safe, vault = anonymizer.anonymize(TEXT)
        assert anonymizer.leaked(anonymizer.restore(safe, vault), vault) == []

    def test_paranoid_replaces_no_more_tokens_than_standard(self):
        """It should reach further into the *text*, not into its own work."""
        standard = Anonymizer(level=Level.STANDARD).anonymize(TEXT)[1]
        paranoid = Anonymizer(level=Level.PARANOID).anonymize(TEXT)[1]
        assert len(paranoid.destroyed) == len(standard.destroyed)


class TestNoticesAreLeftAlone:
    def test_a_notice_is_not_destroyed_again(self):
        """A notice is the only prose this library inserts, and a second pass
        over it would nest one notice inside another."""
        anonymizer = Anonymizer(level=Level.PARANOID)
        safe, _ = anonymizer.anonymize(f"key={STRIPE_KEY}")
        assert safe.count("[") == 1

    def test_text_that_already_contains_a_notice_is_tolerated(self):
        """Anonymizing output that has been through this once already."""
        anonymizer = Anonymizer(level=Level.PARANOID)
        once, _ = anonymizer.anonymize(f"key={STRIPE_KEY}")
        twice, vault = anonymizer.anonymize(once)
        assert twice == once
        assert vault.destroyed == []


class TestAcrossAStructure:
    def test_a_structure_round_trips_at_paranoid(self):
        """Walking a structure replaces field by field under one vault, so
        the same hazard applies to every leaf after the first."""
        anonymizer = Anonymizer(level=Level.PARANOID)
        original = {
            "client": {"ip": "10.42.7.19", "email": "jan.doe@acme.com"},
            "note": "see the log",
        }
        safe, vault = anonymize_data(original, anonymizer)
        assert restore_data(safe, anonymizer, vault) == original


class TestWithACustomFormat:
    def test_a_custom_format_is_protected_too(self):
        """The guard asks the active format, so it covers a caller's own
        delimiters rather than only the default."""
        anonymizer = Anonymizer(level=Level.PARANOID, token_format=TokenFormats.random_format())
        safe, vault = anonymizer.anonymize(TEXT)
        for token in vault.values:
            assert token in safe


class TestTheGuardItself:
    def test_an_empty_candidate_is_not_own_output(self):
        """A detector with an optional capture group can hand over nothing,
        and the guard is asked before the emptiness check."""
        assert not Anonymizer()._is_own_output("")

    def test_a_token_is_recognized(self):
        anonymizer = Anonymizer()
        anonymizer.anonymize("write to me@acme.com")
        assert anonymizer._is_own_output("@@EMAIL_1@@")

    def test_text_containing_a_token_is_recognized(self):
        """The case a fullmatch missed: the candidate is wider than the token."""
        anonymizer = Anonymizer()
        anonymizer.anonymize("write to me@acme.com")
        assert anonymizer._is_own_output("user=@@EMAIL_1@@")

    def test_ordinary_text_is_not(self):
        assert not Anonymizer()._is_own_output("write to me@acme.com")

    def test_a_reversible_detector_also_leaves_a_token_alone(self):
        """The guard sits in both paths, and a caller's own detector is how a
        real caller reaches the reversible one. A caller *term* cannot: terms
        are compiled word-bounded, and "@@" has no word boundary before it.

        The format has to be pinned too. Left to choose, the anonymizer picks
        delimiters the text does not already use, so a token from an earlier
        pass would not match the active format at all — a second line of
        defense rather than a reason to drop the first, since a caller who
        pins a format loses it.
        """
        once, _ = Anonymizer(token_format="at_signs").anonymize("write to me@acme.com")
        assert "@@EMAIL_1@@" in once

        greedy = Detector(
            label="anything", pattern=re.compile(r"\S+"), action=Action.REVERSIBLE
        )
        second = Anonymizer(token_format="at_signs", detectors=(greedy,))
        safe, again = second.anonymize(once)
        assert "@@EMAIL_1@@" in safe
        assert "@@EMAIL_1@@" not in again.values.values()

    def test_choosing_a_format_also_avoids_the_collision(self):
        """The other defense: delimiters already in the text are avoided, so
        a second pass does not see its own tokens as candidates."""
        once, _ = Anonymizer(token_format="at_signs").anonymize("write to me@acme.com")
        _, again = Anonymizer().anonymize(once)
        assert again.values == {}
