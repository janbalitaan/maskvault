"""Two gaps a recall measurement found.

Both were silent: an IPv6 host and a plainly written salary went out in the
clear at every level, and nothing failed. Found by planting known values and
counting what came back rather than by reading the patterns.
"""

from __future__ import annotations

import time

import pytest

from maskvault import Anonymizer, Level, Levels
from maskvault.patterns import IPV6_ADDRESS, SALARY


class TestIpv6WasNotDetectedAtAll:
    """`IP_ADDRESS` is IPv4 only, so there was no IPv6 pattern to miss with."""

    @pytest.mark.parametrize(
        "address",
        [
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "2001:db8::1",
            "::1",
            "fe80::",
            "::ffff:0:0",
            "2001:db8::8a2e:370:7334",
            "64:ff9b::192.0.2.33",
        ],
    )
    def test_it_matches_the_whole_address(self, address):
        match = IPV6_ADDRESS.search(address)
        assert match is not None
        assert match.group(0) == address, "a partial match leaves part of it in the text"

    @pytest.mark.parametrize(
        "address", ["::ffff:10.0.0.1", "::ffff:0:10.0.0.1", "2001:db8::10.0.0.1"]
    )
    def test_an_ipv4_embedded_address_matches_whole(self, address):
        """The hex-only branches matched `::ffff:10` and stopped, leaving
        `.0.0.1` behind — part of an address published in the clear, which is
        worse than not matching."""
        match = IPV6_ADDRESS.search(address)
        assert match is not None
        assert match.group(0) == address

    @pytest.mark.parametrize(
        "text",
        [
            "14:02:11",
            "2026-10-26 14:02",
            "version 1:2",
            "aa:bb:cc:dd:ee:ff",
            "ratio 3:4",
            "10.0.0.1",
            "version 1.2.3.4",
        ],
    )
    def test_it_does_not_match_these(self, text):
        """A loose pattern reads `14:02:11` as an address, so a timestamp in a
        log line gets replaced by a token."""
        assert IPV6_ADDRESS.search(text) is None

    def test_a_long_near_miss_does_not_backtrack(self):
        """Each branch has a bounded repeat with no nesting, so there is no
        input that makes the matcher hang."""
        for probe in ("a" * 400, "1234:" * 200, ("1234:" * 200) + "zz"):
            started = time.perf_counter()
            IPV6_ADDRESS.search(probe)
            assert time.perf_counter() - started < 0.1


class TestIpv6IsAnonymized:
    def test_it_is_replaced_at_standard(self):
        anonymizer = Anonymizer()
        safe, _ = anonymizer.anonymize("host 2001:db8::8a2e:370:7334 up")
        assert "2001:db8" not in safe

    def test_it_round_trips(self):
        anonymizer = Anonymizer()
        text = "host 2001:db8::8a2e:370:7334 up"
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) == text

    def test_an_embedded_ipv4_leaves_nothing_behind(self):
        anonymizer = Anonymizer()
        safe, _ = anonymizer.anonymize("host ::ffff:10.0.0.1 up")
        assert "10.0.0.1" not in safe
        assert ".0.0.1" not in safe

    def test_ipv6_runs_before_ipv4(self):
        """The more specific shape has to claim the span, or the v4 detector
        takes the tail of a mapped address and leaves the prefix."""
        labels = [d.label for d in Levels.detectors_for(Level.STANDARD)]
        assert labels.index("ipv6_address") < labels.index("ip_address")

    def test_plain_ipv4_is_still_its_own_label(self):
        anonymizer = Anonymizer()
        findings = anonymizer.explain("host 10.42.7.19 up")
        assert [f.label for f in findings] == ["IP_ADDRESS"]


class TestSalaryRequiredACommaGroup:
    """`\\d{1,3}(?:,\\d{3})+` made the comma mandatory, so `95000` never
    matched while `95,000` did — and the plain integer is the common form."""

    @pytest.mark.parametrize(
        "text",
        [
            "salary is 95000 USD",
            "salary: 95000",
            "annual salary 95000",
            "salary of $95,000",
            "earns 95000 USD a year",
            "compensation 120000",
            "pay rate 45000 per year",
        ],
    )
    def test_it_matches_now(self, text):
        assert SALARY.search(text) is not None

    @pytest.mark.parametrize(
        "text", ["rate 3", "offer 12", "pay attention", "the rate limit is 100"]
    )
    def test_a_small_number_after_a_keyword_is_not_pay(self, text):
        """Four digits minimum without commas, so "rate 3" is not a salary."""
        assert SALARY.search(text) is None

    def test_a_currency_code_may_follow_the_amount(self):
        """`$95,000` and `95000 USD` are both ordinary; only the first was
        handled."""
        match = SALARY.search("salary is 95000 USD")
        assert match is not None
        assert "USD" in match.group(0)

    def test_it_is_anonymized_at_strict(self):
        anonymizer = Anonymizer(detectors=Levels.detectors_for(Level.STRICT))
        safe, _ = anonymizer.anonymize("His salary is 95000 USD annually.")
        assert "95000" not in safe


class TestAPassportNeedsItsKeyword:
    """Not a gap. A bare `P1234567` is indistinguishable from a part number,
    a ticket id or a SKU, and detecting it would misfire constantly."""

    def test_with_the_keyword_it_is_caught(self):
        anonymizer = Anonymizer()
        safe, _ = anonymizer.anonymize("passport P1234567")
        assert "P1234567" not in safe

    def test_without_it_the_value_is_left_alone(self):
        anonymizer = Anonymizer()
        safe, _ = anonymizer.anonymize("part P1234567")
        assert "P1234567" in safe
