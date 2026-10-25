"""Adding to the word lists, which is the first thing people want.

The shipped vocabularies are English and general. A medical deployment, a
legal one, or anything not in English needs its own terms — so extending has
to be a supported operation rather than something to work out from the
source.

Two properties matter more than the convenience. A name already shipped is
*extended* rather than replaced, because a caller adding one term almost
never means "and discard the other hundred". And the shipped mapping is
read-only, because a library deeper in the stack assigning to it would
silently disable a category for every user in the process.
"""

from __future__ import annotations

import pytest

from maskvault import (
    SPECIAL_CATEGORIES,
    Anonymizer,
    Level,
    Levels,
    SpecialCategories,
)


def anonymizer_with(extra=None, categories=None) -> Anonymizer:
    """A STANDARD anonymizer plus the special categories, extended."""
    return Anonymizer(
        detectors=(
            *Levels.detectors_for(Level.STANDARD),
            *SpecialCategories.special_category_detectors(categories=categories, extra=extra),
        )
    )


class TestTheShippedMappingIsReadOnly:
    def test_assigning_to_it_raises(self):
        """A plain dict here meant a caller could silently disable a
        category for every user in the process."""
        with pytest.raises(TypeError):
            SPECIAL_CATEGORIES["health"] = frozenset()

    def test_deleting_from_it_raises(self):
        with pytest.raises(TypeError):
            del SPECIAL_CATEGORIES["health"]

    def test_the_sets_inside_are_frozen_too(self):
        with pytest.raises(AttributeError):
            SPECIAL_CATEGORIES["health"].add("whatever")

    def test_it_is_still_readable(self):
        """Read-only, not inaccessible — a caller inspecting what ships is a
        reasonable thing to do."""
        assert "diabetes" in SPECIAL_CATEGORIES["health"]
        assert len(SPECIAL_CATEGORIES) == 6


class TestExtendingAShippedCategory:
    def test_a_new_term_is_matched(self):
        """`neuropathy` is deliberately not in the shipped health list."""
        safe, _ = anonymizer_with({"health": ["neuropathy"]}).anonymize("I have neuropathy")
        assert "neuropathy" not in safe

    def test_the_shipped_terms_survive(self):
        """The property that matters: adding one term must not discard the
        hundred that were already there."""
        extended = SpecialCategories.vocabularies({"health": ["neuropathy"]})
        assert "diabetes" in extended["health"]
        assert len(extended["health"]) == len(SPECIAL_CATEGORIES["health"]) + 1

    def test_both_old_and_new_terms_match_together(self):
        safe, vault = anonymizer_with({"health": ["neuropathy"]}).anonymize(
            "I have neuropathy and diabetes"
        )
        assert "neuropathy" not in safe
        assert "diabetes" not in safe
        assert vault.replaced == 2

    def test_a_multi_word_term_works(self):
        safe, _ = anonymizer_with({"health": ["long covid"]}).anonymize(
            "recovering from long covid"
        )
        assert "long covid" not in safe

    def test_extending_does_not_touch_the_shipped_mapping(self):
        """The merge is a copy. Otherwise one caller's extension would reach
        every other caller in the process."""
        before = len(SPECIAL_CATEGORIES["health"])
        SpecialCategories.vocabularies({"health": ["neuropathy"]})
        assert len(SPECIAL_CATEGORIES["health"]) == before


class TestANewCategory:
    def test_it_gets_its_own_label(self):
        labels = [
            detector.label
            for detector in SpecialCategories.special_category_detectors(
                extra={"project": ["atlas"]}
            )
        ]
        assert "project" in labels

    def test_its_terms_are_matched_under_that_label(self):
        safe, vault = anonymizer_with({"project": ["atlas"]}).anonymize(
            "shipping atlas next week"
        )
        assert "atlas" not in safe
        assert any("PROJECT" in token for token in vault.snapshot())

    def test_it_round_trips(self):
        anonymizer = anonymizer_with({"project": ["atlas"]})
        safe, vault = anonymizer.anonymize("shipping atlas next week")
        assert anonymizer.restore(safe, vault) == "shipping atlas next week"

    def test_a_non_english_vocabulary_works(self):
        """The shipped lists are English, which is a stated limitation
        rather than a design choice."""
        safe, _ = anonymizer_with({"salud": ["diabetes tipo 2", "hipertensión"]}).anonymize(
            "tengo hipertensión desde 2019"
        )
        assert "hipertensión" not in safe


class TestNormalization:
    def test_terms_are_lower_cased(self):
        """Matching is case-insensitive, so a capitalized entry would look
        like it worked while matching nothing extra."""
        vocab = SpecialCategories.vocabularies({"project": ["Atlas", "REDWOOD"]})
        assert vocab["project"] == frozenset({"atlas", "redwood"})

    def test_blank_terms_are_dropped(self):
        vocab = SpecialCategories.vocabularies({"project": ["atlas", "", "   "]})
        assert vocab["project"] == frozenset({"atlas"})

    def test_surrounding_space_is_trimmed(self):
        vocab = SpecialCategories.vocabularies({"project": ["  atlas  "]})
        assert vocab["project"] == frozenset({"atlas"})

    def test_a_capitalized_term_still_matches(self):
        safe, _ = anonymizer_with({"project": ["Atlas"]}).anonymize("shipping Atlas")
        assert "Atlas" not in safe


class TestSelectingCategories:
    def test_only_the_named_ones_are_built(self):
        detectors = SpecialCategories.special_category_detectors(
            categories=("health", "religion")
        )
        assert {d.label for d in detectors} == {"health", "religion"}

    def test_a_new_category_can_be_selected(self):
        detectors = SpecialCategories.special_category_detectors(
            categories=("project",), extra={"project": ["atlas"]}
        )
        assert [d.label for d in detectors] == ["project"]

    def test_an_unknown_category_is_skipped_not_raised(self):
        """So a caller can name one they expect a future version to add."""
        detectors = SpecialCategories.special_category_detectors(
            categories=("health", "not_a_category")
        )
        assert [d.label for d in detectors] == ["health"]

    def test_no_extra_gives_exactly_the_shipped_set(self):
        detectors = SpecialCategories.special_category_detectors()
        assert {d.label for d in detectors} == set(SPECIAL_CATEGORIES)


class TestReplacingRatherThanExtending:
    def test_category_detector_takes_a_set_outright(self):
        """For the caller who really does want to replace a vocabulary —
        `extra` deliberately cannot do this."""
        detector = SpecialCategories.category_detector("health", frozenset({"neuropathy"}))
        anonymizer = Anonymizer(detectors=(detector,))
        safe, _ = anonymizer.anonymize("I have neuropathy and diabetes")
        assert "neuropathy" not in safe
        assert "diabetes" in safe
