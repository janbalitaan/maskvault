"""Changing a shipped detector set without waiting for a release.

A pattern in a library is a liability on someone else's release cycle. Adding
was always possible; replacing one of forty-one meant rebuilding the list by
hand and keeping that code in step with every future version.

Two properties carry the weight. A replacement keeps its *position*, because
the shipped ordering is a correctness guarantee rather than a preference. And
a label that is not in the set raises, because silently doing nothing would
leave a caller believing their replacement was in effect.
"""

from __future__ import annotations

import re

import pytest

from maskvault import (
    Action,
    Anonymizer,
    Detector,
    EntropyDetector,
    EntropyThresholds,
    Level,
    Levels,
    PhoneShape,
    Registry,
)
from maskvault.exceptions import DetectorError
from maskvault.patterns import PHONE

BETTER_AWS = Detector(
    label="aws_access_key",
    pattern=re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    action=Action.DESTROY,
    notice="[an AWS key was removed]",
)
MINE = Detector(
    label="internal_id",
    pattern=re.compile(r"\bEMP-\d{6}\b"),
    action=Action.REVERSIBLE,
)


def labels(detectors) -> list[str]:
    return [detector.label for detector in detectors]


class TestReplacing:
    def test_the_replacement_is_used(self):
        detectors = Levels.detectors_for(Level.STANDARD, replace={"aws_access_key": BETTER_AWS})
        safe, _ = Anonymizer(detectors=detectors).anonymize("key AROAIOSFODNN7EXAMPLE")
        assert "AROAIOSFODNN7EXAMPLE" not in safe

    def test_the_original_is_gone(self):
        """Not shadowed, replaced — otherwise both would run."""
        detectors = Levels.detectors_for(Level.STANDARD, replace={"aws_access_key": BETTER_AWS})
        matching = [d for d in detectors if d.label == "aws_access_key"]
        assert matching == [BETTER_AWS]

    def test_the_position_is_preserved(self):
        """The shipped ordering is a correctness guarantee: specific before
        generic, destructive before reversible, entropy last. A replacement
        appended to the end would break it."""
        before = labels(Levels.detectors_for(Level.STANDARD))
        after = labels(
            Levels.detectors_for(Level.STANDARD, replace={"aws_access_key": BETTER_AWS})
        )
        assert before == after

    def test_the_set_is_the_same_size(self):
        assert len(Levels.detectors_for(Level.STANDARD)) == len(
            Levels.detectors_for(Level.STANDARD, replace={"aws_access_key": BETTER_AWS})
        )

    def test_registry_supports_it_too(self):
        detectors = Registry.all_detectors(replace={"aws_access_key": BETTER_AWS})
        assert BETTER_AWS in detectors


class TestRemoving:
    def test_the_detector_is_gone(self):
        detectors = Levels.detectors_for(Level.STANDARD, without=("age",))
        assert "age" not in labels(detectors)

    def test_several_can_go_at_once(self):
        detectors = Levels.detectors_for(Level.STANDARD, without=("age", "salary"))
        assert "age" not in labels(detectors)
        assert "salary" not in labels(detectors)

    def test_the_rest_are_untouched(self):
        before = labels(Levels.detectors_for(Level.STANDARD))
        after = labels(Levels.detectors_for(Level.STANDARD, without=("age",)))
        assert after == [label for label in before if label != "age"]

    def test_a_removed_detector_no_longer_fires(self):
        detectors = Levels.detectors_for(Level.STANDARD, without=("email",))
        safe, _ = Anonymizer(detectors=detectors).anonymize("write to me@acme.com")
        assert "me@acme.com" in safe


class TestAdding:
    def test_a_new_detector_fires(self):
        detectors = Levels.detectors_for(Level.STANDARD, add=(MINE,))
        safe, _ = Anonymizer(detectors=detectors).anonymize("see EMP-004212")
        assert "EMP-004212" not in safe

    def test_it_goes_on_the_end(self):
        """After the shipped ones have had their chance to claim a span."""
        detectors = Levels.detectors_for(Level.STANDARD, add=(MINE,))
        assert labels(detectors)[-1] == "internal_id"

    def test_all_three_compose(self):
        detectors = Levels.detectors_for(
            Level.STANDARD,
            replace={"aws_access_key": BETTER_AWS},
            without=("age",),
            add=(MINE,),
        )
        names = labels(detectors)
        assert "age" not in names
        assert "internal_id" in names
        assert BETTER_AWS in detectors


class TestAnUnknownLabelIsRefused:
    """Silently doing nothing would leave a caller believing a replacement
    was in effect while the original was still running."""

    def test_replacing_something_absent_raises(self):
        with pytest.raises(DetectorError, match="replace names a detector"):
            Levels.detectors_for(Level.STANDARD, replace={"nope": MINE})

    def test_removing_something_absent_raises(self):
        with pytest.raises(DetectorError, match="without names a detector"):
            Levels.detectors_for(Level.STANDARD, without=("aws_acces_key",))

    def test_the_message_lists_what_is_available(self):
        with pytest.raises(DetectorError) as caught:
            Levels.detectors_for(Level.STANDARD, without=("nope",))
        assert "aws_access_key" in str(caught.value)

    def test_a_label_absent_from_this_level_raises(self):
        """`health` ships, but not at STANDARD — and a caller who thinks they
        removed it there should hear so."""
        with pytest.raises(DetectorError):
            Levels.detectors_for(Level.STANDARD, without=("health",))

    def test_but_it_works_at_the_level_that_has_it(self):
        detectors = Levels.detectors_for(Level.STRICT, without=("health",))
        assert "health" not in labels(detectors)


class TestRegionalPhoneBounds:
    def test_a_short_extension_is_rejected_by_default(self):
        safe, _ = Anonymizer().anonymize("call 555123 today")
        assert "555123" in safe

    def test_and_accepted_when_the_bounds_are_widened(self):
        regional = Detector(
            label="phone",
            pattern=PHONE,
            action=Action.REVERSIBLE,
            validate=PhoneShape.bounded(6, 12),
        )
        detectors = Levels.detectors_for(Level.STANDARD, replace={"phone": regional})
        safe, _ = Anonymizer(detectors=detectors).anonymize("call 555123 today")
        assert "555123" not in safe

    def test_the_date_exclusion_survives(self):
        """`bounded` keeps the thing the validator exists for."""
        validate = PhoneShape.bounded(6, 12)
        assert not validate("2026-10-25")
        assert not validate("14:02:11")
        assert validate("555123")

    def test_nonsense_bounds_are_refused(self):
        with pytest.raises(DetectorError, match="cannot have between"):
            PhoneShape.bounded(10, 2)
        with pytest.raises(DetectorError):
            PhoneShape.bounded(0, 5)

    def test_the_default_bounds_are_unchanged(self):
        assert PhoneShape.looks_like_a_phone_number("+63 917 555 1234")
        assert not PhoneShape.looks_like_a_phone_number("555123")


class TestTunableEntropyBars:
    DIGEST = "d41d8cd98f00b204e9800998"

    def test_the_bars_can_be_set_individually(self):
        """One per alphabet, because the maximum differs: hex tops out at 4
        bits per character and base64 at 6."""
        strict = EntropyThresholds(hex=2.0)
        assert strict.for_alphabet("hex") == 2.0
        assert strict.for_alphabet("base64") == EntropyThresholds().base64

    def test_an_unknown_alphabet_gets_the_mixed_bar(self):
        """The strictest reasonable default, since an unknown name would
        mean a bug rather than bad caller input."""
        bars = EntropyThresholds()
        assert bars.for_alphabet("something-else") == bars.mixed

    def test_relaxed_by_lowers_everything(self):
        relaxed = EntropyThresholds.relaxed_by(0.5)
        default = EntropyThresholds()
        assert relaxed.hex == default.hex - 0.5
        assert relaxed.base64 == default.base64 - 0.5

    def test_relaxing_never_goes_below_zero(self):
        assert EntropyThresholds.relaxed_by(99).hex == 0.0

    def test_a_negative_bar_is_refused(self):
        with pytest.raises(DetectorError, match="cannot be negative"):
            EntropyThresholds(hex=-1)

    def test_zero_classes_is_refused(self):
        with pytest.raises(DetectorError, match="at least 1"):
            EntropyThresholds(minimum_classes=0)

    def test_a_tuned_detector_can_replace_the_shipped_one(self):
        detector = EntropyDetector.build(thresholds=EntropyThresholds(hex=2.0))
        detectors = Levels.detectors_for(Level.STANDARD, replace={"high_entropy": detector})
        assert detector in detectors

    def test_describe_carries_the_bars(self):
        described = EntropyThresholds(hex=2.5).describe()
        assert "2.5" in described
        assert "character classes" in described


class TestADetectorThatHasToWin:
    """`add` appends, which is right for a detector catching what the shipped
    ones missed. It is wrong for one that has to beat a shipped detector to a
    span — and an internal identifier is exactly that, being a punctuated
    digit run the phone detector will take.
    """

    REGIONAL = Detector(
        label="phone",
        pattern=PHONE,
        action=Action.REVERSIBLE,
        validate=PhoneShape.bounded(6, 12),
    )

    def test_append_loses_the_span(self):
        detectors = Levels.detectors_for(
            Level.STANDARD, replace={"phone": self.REGIONAL}, add=(MINE,)
        )
        safe, _ = Anonymizer(detectors=detectors).anonymize("see EMP-004212")
        assert "PHONE" in safe

    def test_add_first_wins_it(self):
        detectors = Levels.detectors_for(
            Level.STANDARD, replace={"phone": self.REGIONAL}, add_first=(MINE,)
        )
        safe, _ = Anonymizer(detectors=detectors).anonymize("see EMP-004212")
        assert "INTERNAL_ID" in safe

    def test_add_first_goes_before_everything(self):
        detectors = Levels.detectors_for(Level.STANDARD, add_first=(MINE,))
        assert labels(detectors)[0] == "internal_id"

    def test_both_can_be_used_at_once(self):
        other = Detector(
            label="late", pattern=re.compile(r"\bLATE\b"), action=Action.REVERSIBLE
        )
        names = labels(Levels.detectors_for(Level.STANDARD, add_first=(MINE,), add=(other,)))
        assert names[0] == "internal_id"
        assert names[-1] == "late"

    def test_registry_supports_it_too(self):
        assert labels(Registry.all_detectors(add_first=(MINE,)))[0] == "internal_id"
