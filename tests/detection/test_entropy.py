"""TestEntropy."""

from __future__ import annotations

import pytest

from maskvault.entropy import character_classes, classify, find_secrets, shannon_entropy


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
