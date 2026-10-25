"""Personal details, the entropy net, and the inspection API.

The entropy tests matter in both directions. A net that misses real secrets
gives false assurance; one that flags ordinary prose makes the library
unusable and gets switched off, which is the same outcome.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.entropy import character_classes, classify, find_secrets, shannon_entropy
from maskvault.personal import special_category_detectors
from maskvault.vocabularies import SPECIAL_CATEGORIES


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


class TestSpecialCategories:
    @pytest.mark.parametrize("category", list(SPECIAL_CATEGORIES))
    def test_every_category_has_a_detector(self, category):
        labels = {detector.label for detector in special_category_detectors()}
        assert category in labels

    @pytest.mark.parametrize(
        "text,term",
        [
            ("I was diagnosed with diabetes", "diabetes"),
            ("I am a practicing Catholic", "Catholic"),
            ("I am a union member", "union member"),
            ("I came out as gay in 2015", "gay"),
            ("I am on an H1B visa", "visa"),
            ("I filed for bankruptcy", "bankruptcy"),
        ],
    )
    def test_a_listed_term_is_replaced(self, strict, text, term):
        safe, _ = strict.anonymize(text)
        assert term.lower() not in safe.lower()

    def test_a_longer_term_wins(self, strict):
        """'heart attack' must not be matched as 'heart' with 'attack' left."""
        safe, _ = strict.anonymize("I had a heart attack")
        assert "attack" not in safe

    def test_the_surrounding_sentence_stays_usable(self, strict):
        """Tokenizing the term rather than the sentence keeps the text
        meaningful to whatever reads it next."""
        safe, _ = strict.anonymize("I was diagnosed with diabetes in 2019")
        assert "in 2019" in safe

    def test_a_term_restores(self, strict):
        text = "I am a practicing Catholic"
        safe, vault = strict.anonymize(text)
        assert strict.restore(safe, vault) == text

    def test_an_unlisted_condition_passes_through(self, strict):
        """A vocabulary is a floor, not a guarantee. Stated here so the
        limitation is visible in the suite rather than only in the README."""
        safe, _ = strict.anonymize("I have been diagnosed with sarcoidosis")
        assert "sarcoidosis" in safe


class TestEntropy:
    def test_per_character_entropy_does_not_separate_short_prose(self):
        """The reason entropy is not the only condition.

        A short varied phrase barely repeats a character, so it scores like a
        generated string. Whitespace is what actually separates the two, and
        classify checks that first.
        """
        assert shannon_entropy("the quick brown fox jumps") > 4.0
        assert not classify("the quick brown fox jumps").is_secret

    def test_a_generated_secret_is_high_entropy(self):
        assert shannon_entropy("aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ=") > 4.0

    def test_empty_text_has_no_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_character_classes_counts_four(self):
        assert character_classes("aB3!") == 4
        assert character_classes("abc") == 1

    @pytest.mark.parametrize(
        "secret",
        [
            "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ=",
            "9f8c2b1a7e4d6c3b8a5f2e1d9c7b4a6e",
            "dGhpcyBpcyBhIHZlcnkgbG9uZyBzZXNzaW9uIGNvb2tpZQ",
        ],
    )
    def test_real_secrets_are_caught(self, secret):
        assert classify(secret).is_secret

    @pytest.mark.parametrize(
        "innocent",
        [
            "I build backend services and automation",
            "550e8400-e29b-41d4-a716-446655440000",
            "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
            "configuration_management_database_handler",
            "supercalifragilisticexpialidocious",
            "2024-06-01",
        ],
    )
    def test_innocent_text_is_not_flagged(self, innocent):
        assert not find_secrets(innocent)

    def test_a_short_secret_cannot_be_judged(self):
        """Below the minimum length entropy is too noisy to act on."""
        verdict = classify("sk-abc123")
        assert not verdict.is_secret
        assert "too short" in verdict.reason

    def test_a_passphrase_is_not_caught(self):
        """Entropy is measured per character, so a long passphrase of common
        words scores like the prose it is made of. Documented as a known gap."""
        assert not classify("correct horse battery staple").is_secret

    def test_a_verdict_explains_itself(self):
        verdict = classify("I build backend services and automation")
        assert not verdict.is_secret
        assert "whitespace" in verdict.reason

    def test_a_multi_word_phrase_is_never_a_secret(self):
        """classify is for single tokens. Passing prose must fail closed."""
        for phrase in ("hello world", " leading space", "trailing "):
            assert not classify(phrase).is_secret

    def test_duplicates_are_reported_once(self):
        secret = "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ="
        assert len(find_secrets(f"{secret} and again {secret}")) == 1


class TestInspection:
    def test_explain_reports_what_would_happen(self, strict):
        findings = strict.explain("me@example.com and key AKIAIOSFODNN7EXAMPLE")
        labels = {finding.label for finding in findings}
        assert "EMAIL" in labels
        assert "AWS_ACCESS_KEY" in labels

    def test_explain_marks_allowed_values(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        findings = anonymizer.explain("me@example.com")
        assert findings
        assert all(finding.allowed for finding in findings)

    def test_findings_are_in_text_order(self, strict):
        findings = strict.explain("first me@example.com then 10.0.0.1")
        positions = [finding.start for finding in findings]
        assert positions == sorted(positions)

    def test_preview_is_readable(self, strict):
        report = strict.preview("me@example.com")
        assert "EMAIL" in report
        assert "would be replaced" in report

    def test_preview_says_so_when_nothing_matches(self, strict):
        assert strict.preview("hello there") == "nothing would be replaced"

    def test_suggest_whitelist_omits_credentials(self, strict):
        """Allowing a credential through is almost never correct, so a
        generated draft must not propose it."""
        draft = strict.suggest_whitelist("me@example.com key AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in draft["values"]
        assert "me@example.com" in draft["values"]

    def test_suggest_whitelist_output_is_usable_as_config(self, strict):
        draft = strict.suggest_whitelist("me@example.com")
        relaxed = Anonymizer(level=Level.STRICT, whitelist=draft)
        safe, _ = relaxed.anonymize("me@example.com")
        assert "me@example.com" in safe

    def test_explain_does_not_mutate_the_text(self, strict):
        text = "me@example.com"
        strict.explain(text)
        assert text == "me@example.com"


class TestDetectorPrecedence:
    """The first detector to match a span claims it, so order is correctness.

    Each case here is a precise format that a looser, keyword-led detector
    would otherwise claim part of.
    """

    def test_an_email_is_not_claimed_as_a_social_handle(self, strict):
        safe, _ = strict.anonymize("write to me@x.com today")
        assert "[[EMAIL_1]]" in safe
        assert "SOCIAL_HANDLE" not in safe

    def test_an_email_on_a_platform_domain_is_still_an_email(self, strict):
        safe, _ = strict.anonymize("write to me@telegram.org today")
        assert "[[EMAIL_1]]" in safe

    def test_a_url_is_not_broken_up(self, strict):
        safe, _ = strict.anonymize("see https://discord.gg/abc123 for details")
        assert "[[URL_1]]" in safe

    def test_a_real_handle_is_still_caught(self, strict):
        safe, _ = strict.anonymize("my telegram is janbalitaan")
        assert "janbalitaan" not in safe

    def test_a_vendor_key_keeps_its_label(self, strict):
        """A specific credential pattern must win over the entropy net, or the
        log loses what kind of secret appeared."""
        _, vault = strict.anonymize("key AKIAIOSFODNN7EXAMPLE")
        assert vault.destroyed == ["aws_access_key"]
