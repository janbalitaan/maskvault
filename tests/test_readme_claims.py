"""Every output the README claims, asserted.

Documentation that drifts from behavior is worse than no documentation,
because a reader trusts it. Each test here corresponds to a specific claim in
README.md, so changing behavior without updating the docs fails the suite.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level, TokenFormat


class TestQuickStart:
    def test_the_opening_example(self):
        """README: 'I work at [[ORG_1]], email [[EMAIL_1]]'."""
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize("I work at Acme Corp, email me@acme.com")
        assert safe == "I work at [[ORG_1]], email [[EMAIL_1]]"
        assert anonymizer.restore(safe, vault) == "I work at Acme Corp, email me@acme.com"


class TestCredentialsSection:
    def test_the_destroyed_notice_and_vault_entry(self):
        """README shows the notice text and `vault.destroyed == ["api_key"]`."""
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize(
            "key sk-abcdefghijklmnopqrstuvwxyz1234 and I work at Acme Corp"
        )
        assert "[an API key was removed before sending]" in safe
        assert vault.destroyed == ["api_key"]
        assert "[[ORG_1]]" in safe

    def test_a_destroyed_value_breaks_the_round_trip(self):
        """README: 'an exact round trip holds only when nothing was destroyed'."""
        anonymizer = Anonymizer(level=Level.STRICT)
        text = "key sk-abcdefghijklmnopqrstuvwxyz1234"
        safe, vault = anonymizer.anonymize(text)
        assert anonymizer.restore(safe, vault) != text


class TestLevelsSection:
    @pytest.mark.parametrize(
        "level", [Level.MINIMAL, Level.STANDARD, Level.STRICT, Level.PARANOID]
    )
    def test_every_documented_level_exists(self, level):
        assert Anonymizer(level=level).level is level

    def test_strict_adds_the_special_categories(self):
        """README: STRICT adds health, religion, politics, identity, origin,
        criminal."""
        standard, _ = Anonymizer(level=Level.STANDARD).anonymize("I have diabetes")
        strict, _ = Anonymizer(level=Level.STRICT).anonymize("I have diabetes")
        assert "diabetes" in standard
        assert "diabetes" not in strict


class TestControlSection:
    def test_every_documented_whitelist_key_is_honored(self):
        """README lists nine keys. Each has to actually do something."""
        anonymizer = Anonymizer(
            level=Level.STRICT,
            whitelist={
                "labels": ["url", "age"],
                "categories": ["identity"],
                "values": ["Python", "FastAPI"],
                "words": ["black", "native"],
                "contains": ["github.com"],
                "prefixes": ["https://mysite.dev/"],
                "suffixes": ["@mycompany.com"],
                "domains": ["mycompany.com"],
                "patterns": [r"^EMP-\d{4}$"],
            },
        )
        whitelist = anonymizer.whitelist
        assert whitelist.allows_label("url")
        assert whitelist.allows_label("identity")
        assert whitelist.allows_value("Python")
        assert whitelist.allows_value("black")
        assert whitelist.allows_value("https://github.com/x")
        assert whitelist.allows_value("https://mysite.dev/about")
        assert whitelist.allows_value("me@mycompany.com")
        assert whitelist.allows_value("EMP-1234")

    def test_nothing_is_allowed_by_default(self):
        """README: 'Nothing is allowed through by default'."""
        assert Anonymizer().whitelist.describe() == "nothing allowed through"


class TestInspectionSection:
    def test_preview_reports_the_documented_shape(self):
        """README shows lines of 'state LABEL value' and a closing count."""
        anonymizer = Anonymizer(level=Level.STRICT)
        report = anonymizer.preview("me@example.com and key AKIAIOSFODNN7EXAMPLE")
        assert "findings at level strict" in report
        assert "EMAIL" in report
        assert "AWS_ACCESS_KEY" in report
        assert "would be replaced" in report

    def test_the_vault_summary_shape(self):
        """README: '1 age, 2 health, 1 salary, 1 street_address, 1 destroyed'."""
        anonymizer = Anonymizer(level=Level.STRICT)
        _, vault = anonymizer.anonymize("I have diabetes and a heart attack")
        assert "2 health" in vault.summary()

    def test_suggest_whitelist_is_usable_as_config(self):
        anonymizer = Anonymizer(level=Level.STRICT)
        draft = anonymizer.suggest_whitelist("me@example.com")
        relaxed = Anonymizer(level=Level.STRICT, whitelist=draft)
        assert "me@example.com" in relaxed.anonymize("me@example.com")[0]


class TestTokenFormatSection:
    def test_the_wikilink_example(self):
        """README: 'see [[Notes]], I work at @@ORG_1@@' and name 'at_signs'."""
        anonymizer = Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})
        safe, vault = anonymizer.anonymize("see [[Notes]], I work at Acme Corp")
        assert safe == "see [[Notes]], I work at @@ORG_1@@"
        assert vault.token_format.name == "at_signs"

    def test_pinning_by_name_works(self):
        """README: Anonymizer(token_format="at_signs")."""
        anonymizer = Anonymizer(token_format="at_signs", terms={"ORG": ["Acme"]})
        assert "@@ORG_1@@" in anonymizer.anonymize("I work at Acme")[0]

    def test_the_lowercase_custom_format_example(self):
        """README shows this exact format producing <%|org_1|%>."""
        anonymizer = Anonymizer(
            token_format=TokenFormat(
                name="mine",
                opening="<%|",
                closing="|%>",
                label_pattern=r"[a-z_]+",
                label_case="lower",
            ),
            terms={"ORG": ["Acme"]},
        )
        assert "<%|org_1|%>" in anonymizer.anonymize("I work at Acme")[0]

    def test_the_documented_validation_error(self):
        """README shows the ValueError text for a mismatched format."""
        with pytest.raises(ValueError, match=r"cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern=r"\d+")


class TestLimitationsSection:
    """The limitations are claims too, and a reader relies on them being
    accurate in both directions."""

    def test_it_cannot_find_an_unlisted_name(self):
        """README: 'will not find "Maria Santos" unless you list it'."""
        safe, _ = Anonymizer(level=Level.STRICT).anonymize("I spoke with Maria Santos")
        assert "Maria Santos" in safe

    def test_an_unlisted_condition_passes_through(self):
        """README: 'misses what is not listed'."""
        safe, _ = Anonymizer(level=Level.STRICT).anonymize("I have sarcoidosis")
        assert "sarcoidosis" in safe

    def test_a_passphrase_is_not_caught(self):
        """README: 'correct horse battery staple scores like ordinary words'."""
        safe, _ = Anonymizer(level=Level.PARANOID).anonymize(
            "my passphrase is correct horse battery staple"
        )
        assert "correct horse battery staple" in safe

    def test_the_aws_key_entropy_figure(self):
        """README cites 3.68 bits for an AWS access key id."""
        from maskvault import shannon_entropy

        assert round(shannon_entropy("AKIAIOSFODNN7EXAMPLE"), 2) == 3.68

    def test_the_quick_brown_fox_figure(self):
        """README: 'the quick brown fox jumps scores above 4 bits'."""
        from maskvault import shannon_entropy

        assert shannon_entropy("the quick brown fox jumps") > 4.0
