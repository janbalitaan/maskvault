"""A detector that captures part of its match rather than all of it.

A keyword-led pattern like `password=(\\S+)` has to replace only the value, or
the token would cover the keyword too and the output would no longer parse.
The capture group is how that is expressed, and getting it wrong is the kind
of mistake that looks like the detector working.
"""

from __future__ import annotations

import re

import pytest

from maskvault.exceptions import DetectorError
from maskvault.models.action import Action
from maskvault.models.detector import Detector


class TestACapturingDetector:
    def test_it_replaces_only_the_captured_part(self):
        detector = Detector(
            label="password_assignment",
            pattern=re.compile(r"password=(\S+)"),
            action=Action.DESTROY,
            group=1,
        )
        match = detector.pattern.search("password=hunter2")
        assert detector.value_of(match) == "hunter2"
        assert detector.span_of(match) == (9, 16)

    def test_without_a_group_it_takes_the_whole_match(self):
        detector = Detector(
            label="email", pattern=re.compile(r"\S+@\S+"), action=Action.REVERSIBLE
        )
        match = detector.pattern.search("write to me@acme.com")
        assert detector.value_of(match) == "me@acme.com"
        assert detector.span_of(match) == (9, 20)

    def test_an_empty_capture_yields_an_empty_value(self):
        """`password=` with nothing after it. Returning None would propagate
        into the vault as a null."""
        detector = Detector(
            label="maybe",
            pattern=re.compile(r"password=(\S*)"),
            action=Action.DESTROY,
            group=1,
        )
        match = detector.pattern.search("password=")
        assert detector.value_of(match) == ""


class TestAGroupThatDoesNotExist:
    def test_it_is_refused_at_construction(self):
        """Falling back to the whole match would look like the detector
        working, while the token silently covered the keyword as well."""
        with pytest.raises(DetectorError, match="capture group"):
            Detector(
                label="broken",
                pattern=re.compile(r"password=\S+"),
                action=Action.DESTROY,
                group=1,
            )

    def test_the_message_names_the_detector_and_the_counts(self):
        with pytest.raises(DetectorError) as caught:
            Detector(
                label="broken",
                pattern=re.compile(r"(a)(b)"),
                action=Action.DESTROY,
                group=5,
            )
        message = str(caught.value)
        assert "'broken'" in message
        assert "5" in message
        assert "2 group" in message

    def test_group_zero_is_the_whole_match_and_is_fine(self):
        detector = Detector(
            label="plain", pattern=re.compile(r"\d+"), action=Action.DESTROY, group=0
        )
        match = detector.pattern.search("abc 123")
        assert detector.value_of(match) == "123"


class TestValidation:
    def test_a_detector_without_a_validator_accepts_everything(self):
        detector = Detector(label="any", pattern=re.compile(r"\d+"), action=Action.DESTROY)
        assert detector.matches("anything")

    def test_a_validator_decides(self):
        detector = Detector(
            label="short",
            pattern=re.compile(r"\d+"),
            action=Action.DESTROY,
            validate=lambda candidate: len(candidate) < 4,
        )
        assert detector.matches("123")
        assert not detector.matches("12345")
