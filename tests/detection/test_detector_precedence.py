"""The first detector to match a span claims it, so order is correctness."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


@pytest.fixture
def strict() -> Anonymizer:
    return Anonymizer(level=Level.STRICT)


class TestDetectorPrecedence:
    """The first detector to match a span claims it, so order is correctness.

    Each case here is a precise format that a looser, keyword-led detector
    would otherwise claim part of.
    """

    def test_an_email_is_not_claimed_as_a_social_handle(self, strict):
        safe, vault = strict.anonymize("write to me@x.com today")
        assert vault.token_format.render("EMAIL", 1) in safe
        assert "SOCIAL_HANDLE" not in safe

    def test_an_email_on_a_platform_domain_is_still_an_email(self, strict):
        safe, vault = strict.anonymize("write to me@telegram.org today")
        assert vault.token_format.render("EMAIL", 1) in safe

    def test_a_url_is_not_broken_up(self, strict):
        safe, vault = strict.anonymize("see https://discord.gg/abc123 for details")
        assert vault.token_format.render("URL", 1) in safe

    def test_a_real_handle_is_still_caught(self, strict):
        safe, _ = strict.anonymize("my telegram is janbalitaan")
        assert "janbalitaan" not in safe

    def test_a_vendor_key_keeps_its_label(self, strict):
        """A specific credential pattern must win over the entropy net, or the
        log loses what kind of secret appeared."""
        _, vault = strict.anonymize("key AKIAIOSFODNN7EXAMPLE")
        assert vault.destroyed == ["aws_access_key"]
