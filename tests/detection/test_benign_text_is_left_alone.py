"""Over-masking costs as much as under-masking.

A value replaced by a token is a value the model cannot reason about. A log
line whose byte count became `!|PHONE_1|!` is a question the assistant can no
longer answer, and the person reading the reply has no idea why.

So false positives are measured, not assumed away. These are sentences from
ordinary engineering prose that must survive untouched — found by running
twenty of them and watching five come back masked.
"""

from __future__ import annotations

import pytest

from maskvault import Action, Anonymizer, Detector, Level, Levels, PhoneShape
from maskvault.patterns import PHONE

BENIGN = [
    "The build took 42 seconds and used 8 workers.",
    "Version 2.14.1 is out; see release 3847 for the changelog.",
    "Set the retry limit to 5 and the timeout to 30000 ms.",
    "HTTP 404 on /api/v2/users/1234 after 15 attempts.",
    "The queue held 95000 messages at peak.",
    "Error code 0x8007000E, exit status 127.",
    "We shipped 12 features in Q3 and closed 3847 tickets.",
    "The commit is a1b2c3d and the PR is #4821.",
    "Allocate 4096 MB and 2 vCPUs per node.",
    "Latency p99 was 1250 ms across 180000 requests.",
    "The file is 1048576 bytes, checksum 9f86d081884c7d65.",
    "The policy allows 3 retries with 500 ms backoff.",
    "Our SLA is 99.95% over 30 days.",
    "Batch 7 of 12 processed 65536 rows.",
    "Use port 5432 on host db-primary-01.",
    "The index has 1000000 entries and 4 shards.",
    "Config key max_connections = 200.",
    "Thread 14 waited 02:30 for the lock.",
    "ISBN 978-3-16-148410-0 is the reference.",
]


@pytest.mark.parametrize("level", [Level.STANDARD, Level.STRICT])
class TestOrdinaryProseSurvives:
    @pytest.mark.parametrize("text", BENIGN, ids=lambda item: item[:28])
    def test_nothing_is_replaced(self, level, text):
        anonymizer = Anonymizer(detectors=Levels.detectors_for(level))
        replaced = [finding.label for finding in anonymizer.explain(text) if finding.replaced]
        assert replaced == [], f"{replaced} fired on benign text"


class TestABareDigitRunIsNotAPhoneNumber:
    """`1048576` and `1000000` are seven digits and were read as phone
    numbers, so a file size and a row count became reversible tokens.

    Ten digits is the bar, because that is where national numbers start once
    a trunk prefix or area code is included.
    """

    @pytest.mark.parametrize(
        "text",
        [
            "The file is 1048576 bytes",
            "The index has 1000000 entries",
            "processed 65536 rows",
            "timeout 30000 ms",
            "held 180000 requests",
        ],
    )
    def test_a_short_bare_run_is_left_alone(self, text):
        anonymizer = Anonymizer()
        assert "PHONE" not in anonymizer.anonymize(text)[0]

    @pytest.mark.parametrize(
        "number",
        [
            "+63 917 555 1234",
            "(415) 555-0132",
            "415.555.0132",
            "09175551234",
            "4155550132",
            "+44 20 7946 0958",
        ],
    )
    def test_a_real_number_is_still_caught(self, number):
        """The rule must not buy its precision with recall."""
        anonymizer = Anonymizer()
        assert "PHONE" in anonymizer.anonymize(f"call {number} today")[0]

    def test_an_isbn_is_not_a_phone_number(self):
        """Thirteen digits in hyphenated groups is exactly an international
        number's shape; the 978/979 prefix is what separates them."""
        anonymizer = Anonymizer()
        text = "ISBN 978-3-16-148410-0 is the reference."
        assert anonymizer.anonymize(text)[0] == text

    def test_an_explicit_bound_overrides_the_default(self):
        """A caller who says six digits is a phone here meant it."""
        regional = Detector(
            label="phone",
            pattern=PHONE,
            action=Action.REVERSIBLE,
            validate=PhoneShape.bounded(6, 12),
        )
        anonymizer = Anonymizer(
            detectors=Levels.detectors_for(Level.STANDARD, replace={"phone": regional})
        )
        assert "PHONE" in anonymizer.anonymize("call 555123 today")[0]

    def test_the_default_still_ignores_six_bare_digits(self):
        anonymizer = Anonymizer()
        assert "PHONE" not in anonymizer.anonymize("call 555123 today")[0]


class TestAPolicyKeywordDoesNotSwallowProse:
    """`(?i)` covered the value class as well as the keyword, so
    `[A-Z0-9 -]` matched lowercase and "policy allows 3 retries" captured
    "allows 3 retries" as a policy number. The keyword is a common English
    word, so everything after it matched."""

    @pytest.mark.parametrize(
        "text",
        [
            "The policy allows 3 retries with 500 ms backoff.",
            "policy requires review",
            "our insurance covers this",
            "member since 2019",
            "the patient portal is down",
        ],
    )
    def test_prose_after_the_keyword_is_left_alone(self, text):
        anonymizer = Anonymizer()
        replaced = [f.label for f in anonymizer.explain(text) if f.replaced]
        assert "POLICY_NUMBER" not in replaced

    @pytest.mark.parametrize(
        "text",
        [
            "policy AB1234567",
            "Policy No: 9988776655",
            "MRN 12345678",
            "PhilHealth 12-345678901-2",
            "member id M4821993",
        ],
    )
    def test_a_real_identifier_is_still_caught(self, text):
        anonymizer = Anonymizer()
        replaced = [f.label for f in anonymizer.explain(text) if f.replaced]
        assert "POLICY_NUMBER" in replaced

    def test_the_value_must_contain_a_digit(self):
        """What separates an identifier from a run of words."""
        anonymizer = Anonymizer()
        replaced = [f.label for f in anonymizer.explain("policy ABCDEFGH") if f.replaced]
        assert "POLICY_NUMBER" not in replaced
