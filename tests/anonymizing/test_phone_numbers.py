"""Partial matches are the failure mode that matters."""

from __future__ import annotations

import re

import pytest

from maskvault import Anonymizer, is_phone_shaped


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(terms={"ORG": ["Acme Corporation", "Acme", "Initech"]})


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
