"""`explain` has to report what `anonymize` will actually do.

It is documented as the way to see the policy's decisions before trusting it,
so a count it reports that differs from the count it performs is worse than no
report — a developer reads nine, gets six, and stops believing the tool.

The failure was double-reporting: every detector's matches were listed
independently, so a value two patterns both claimed appeared twice.
"""

from __future__ import annotations

from itertools import pairwise

import pytest

from maskvault import Anonymizer, Level
from maskvault.models.token_format import TokenFormat

STRIPE_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
LOG = (
    "2026-10-25 14:02:11 INFO request from 10.42.7.19 user=jan.doe@acme.com\n"
    f"2026-10-25 14:02:12 ERROR stripe failed key={STRIPE_KEY}\n"
    "2026-10-25 14:02:13 INFO contact +63 917 555 1234 ref 8842-1193\n"
)


def performed(vault) -> list[str]:
    """Every label the anonymizer actually acted on, lowercased."""

    pattern = vault.token_format.pattern if vault.values else TokenFormat.default().pattern
    acted = [pattern.match(token).group(1).lower() for token in vault.values]
    return sorted(acted + list(vault.destroyed))


def reported(anonymizer, text) -> list[str]:
    return sorted(
        finding.label.lower() for finding in anonymizer.explain(text) if finding.replaced
    )


class TestExplainAgreesWithAnonymize:
    @pytest.mark.parametrize(
        "level", [Level.MINIMAL, Level.STANDARD, Level.STRICT, Level.PARANOID]
    )
    def test_the_counts_match_at_every_level(self, level):
        anonymizer = Anonymizer(level=level)
        _, vault = anonymizer.anonymize(LOG)
        assert len(reported(anonymizer, LOG)) == len(performed(vault))

    def test_the_labels_match(self):
        """Not just the count: an overlap resolved to the wrong winner gives
        the right total and the wrong story."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize(LOG)
        assert reported(anonymizer, LOG) == performed(vault)

    def test_no_two_findings_claim_the_same_span(self):
        findings = Anonymizer().explain(LOG)
        spans = sorted((finding.start, finding.end) for finding in findings)
        for earlier, later in pairwise(spans):
            assert earlier[1] <= later[0], f"{earlier} overlaps {later}"


class TestTheWinnerIsTheDetectorThatRunsFirst:
    def test_a_vendor_format_beats_the_entropy_net(self):
        """The entropy candidate starts a few characters earlier, taking the
        `key=` prefix with it — so resolving by position picks the wrong one
        and reports a Stripe key as an anonymous high-entropy blob."""
        anonymizer = Anonymizer()
        findings = anonymizer.explain(f"key={STRIPE_KEY}")
        assert [finding.label for finding in findings] == ["STRIPE_KEY"]

    def test_and_the_vault_records_the_same_label(self):
        _, vault = Anonymizer().anonymize(f"key={STRIPE_KEY}")
        assert vault.destroyed == ["stripe_key"]

    def test_a_precise_identifier_beats_a_loose_digit_run(self):
        anonymizer = Anonymizer()
        findings = anonymizer.explain("request from 10.42.7.19")
        assert [finding.label for finding in findings] == ["IP_ADDRESS"]

    def test_a_report_still_reads_in_text_order(self):
        """Resolution happens in detector order; the report is sorted after,
        so it reads top to bottom like the text does."""
        findings = Anonymizer().explain(LOG)
        starts = [finding.start for finding in findings]
        assert starts == sorted(starts)
