"""A log is mostly timestamps, and none of them are phone numbers.

The phone pattern matches any punctuated digit run and decides in code, which
is deliberate — encoding the grammar of international formats in a regex
invites catastrophic backtracking. The cost is that the decision has to reject
everything else shaped like a digit run, and a timestamp is the most common
thing in that category.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer
from maskvault.detectors import PhoneShape

NOT_PHONE_NUMBERS = [
    "2026-10-25 14",  # the leading span of an ISO timestamp
    "2026-10-25",
    "2026-10",
    "14:02:11",
    "14:02",
    "2026-10-25T14:02:11",
    "1999-01-01 00",
]

REAL_PHONE_NUMBERS = [
    "+63 917 555 1234",
    "(555) 123-4567",
    "555-1234567",
    "+1-202-555-0173",
    "+44 20 7946 0958",
]


class TestDatesAreNotPhoneNumbers:
    @pytest.mark.parametrize("candidate", NOT_PHONE_NUMBERS)
    def test_a_date_or_time_is_rejected(self, candidate):
        assert not PhoneShape.looks_like_a_phone_number(candidate)

    @pytest.mark.parametrize("candidate", REAL_PHONE_NUMBERS)
    def test_a_real_number_is_still_accepted(self, candidate):
        assert PhoneShape.looks_like_a_phone_number(candidate)

    def test_a_log_line_keeps_its_timestamp(self):
        """The failure this guards: an anchored date check only rejected a
        date standing alone, so a timestamp inside a line was matched as a
        ten-digit run and the line came back as `!|PHONE_1|!:02:11`."""
        line = "2026-10-25 14:02:11 INFO  request from 10.42.7.19"
        safe, _ = Anonymizer().anonymize(line)
        assert safe.startswith("2026-10-25 14:02:11 INFO")

    def test_a_number_beside_a_timestamp_is_still_found(self):
        """Rejecting dates must not reject the line they appear on."""
        line = "2026-10-25 14:02:11 called +63 917 555 1234"
        safe, vault = Anonymizer().anonymize(line)
        assert "+63 917 555 1234" not in safe
        assert "2026-10-25 14:02:11" in safe
        assert vault.replaced == 1
