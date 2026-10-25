"""TestStructuredPersonalDetails."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


@pytest.fixture
def strict() -> Anonymizer:
    return Anonymizer(level=Level.STRICT)


class TestStructuredPersonalDetails:
    @pytest.mark.parametrize(
        "text,secret",
        [
            ("I live at 42 Rizal Street", "42 Rizal Street"),
            ("my salary is $95,000 a year", "95,000"),
            ("coordinates 14.599512, 120.984222", "14.599512"),
            ("employee id EMP-4421", "EMP-4421"),
            ("tax id 123-456-789", "123-456-789"),
            ("policy number ABC123456", "ABC123456"),
            ("driver's license N01-23-456789", "N01-23-456789"),
            ("date of birth 1991-03-14", "1991-03-14"),
        ],
    )
    def test_it_is_replaced(self, strict, text, secret):
        safe, _ = strict.anonymize(text)
        assert secret not in safe

    @pytest.mark.parametrize(
        "text",
        [
            "I have 12 years of experience",
            "we shipped 3 releases",
            "the service handles 40 requests per second",
            "Python 3.12 and Django 5.0",
        ],
    )
    def test_ordinary_numbers_survive(self, strict, text):
        """A number is not a personal detail just because it is a number."""
        safe, _ = strict.anonymize(text)
        assert safe == text
