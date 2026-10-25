"""TestEntropy."""

from __future__ import annotations

import pytest

from maskvault.entropy import Entropy


class TestEntropy:
    def test_per_character_entropy_does_not_separate_short_prose(self):
        """The reason entropy is not the only condition.

        A short varied phrase barely repeats a character, so it scores like a
        generated string. Whitespace is what actually separates the two, and
        classify checks that first.
        """
        assert Entropy.shannon_entropy("the quick brown fox jumps") > 4.0
        assert not Entropy.classify("the quick brown fox jumps").is_secret

    def test_a_generated_secret_is_high_entropy(self):
        assert Entropy.shannon_entropy("aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ=") > 4.0

    def test_empty_text_has_no_entropy(self):
        assert Entropy.shannon_entropy("") == 0.0

    def test_character_classes_counts_four(self):
        assert Entropy.character_classes("aB3!") == 4
        assert Entropy.character_classes("abc") == 1

    @pytest.mark.parametrize(
        "secret",
        [
            "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ=",
            "9f8c2b1a7e4d6c3b8a5f2e1d9c7b4a6e",
            "dGhpcyBpcyBhIHZlcnkgbG9uZyBzZXNzaW9uIGNvb2tpZQ",
        ],
    )
    def test_real_secrets_are_caught(self, secret):
        assert Entropy.classify(secret).is_secret

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
        assert not Entropy.find_secrets(innocent)

    def test_a_short_secret_cannot_be_judged(self):
        """Below the minimum length entropy is too noisy to act on."""
        verdict = Entropy.classify("sk-abc123")
        assert not verdict.is_secret
        assert "too short" in verdict.reason

    def test_a_passphrase_is_not_caught(self):
        """Entropy is measured per character, so a long passphrase of common
        words scores like the prose it is made of. Documented as a known gap."""
        assert not Entropy.classify("correct horse battery staple").is_secret

    def test_a_verdict_explains_itself(self):
        verdict = Entropy.classify("I build backend services and automation")
        assert not verdict.is_secret
        assert "whitespace" in verdict.reason

    def test_a_multi_word_phrase_is_never_a_secret(self):
        """classify is for single tokens. Passing prose must fail closed."""
        for phrase in ("hello world", " leading space", "trailing "):
            assert not Entropy.classify(phrase).is_secret

    def test_duplicates_are_reported_once(self):
        secret = "aGVsbG8gd29ybGQgdGhpcyBpcyBzZWNyZXQ="
        assert len(Entropy.find_secrets(f"{secret} and again {secret}")) == 1


class TestVerdictReporting:
    """`find_secrets` returns a verdict per candidate, which is what makes a
    threshold adjustable from evidence rather than from guesswork."""

    def test_it_reports_a_verdict_for_a_real_secret(self):
        verdicts = Entropy.find_secrets("token=" + "aB3dE5fG7hJ9kL1mN3pQ5rS7")
        assert verdicts
        assert any(verdict.is_secret for verdict in verdicts)

    def test_a_verdict_carries_the_measurements(self):
        verdicts = Entropy.find_secrets("aB3dE5fG7hJ9kL1mN3pQ5rS7")
        verdict = verdicts[0]
        assert verdict.entropy > 0
        assert verdict.character_classes > 0
        assert verdict.alphabet
        assert verdict.reason

    def test_prose_yields_no_secret_verdict(self):
        verdicts = Entropy.find_secrets("the quick brown fox jumps over it")
        assert not any(verdict.is_secret for verdict in verdicts)


class TestWhyACandidateWasSpared:
    """Each condition rejects on its own, and the verdict says which — so a
    threshold can be adjusted from evidence rather than by trial and error."""

    def test_find_secrets_returns_only_secrets(self):
        """The name is the contract: a spared candidate is absent rather than
        present with is_secret false. `classify` is what explains one."""
        assert Entropy.find_secrets("abcdefghijklmnopqrstuvwxyzabcd") == []

    def test_classify_explains_a_candidate_that_was_spared(self):
        """Which is the method to reach for when adjusting a threshold: it
        reports the measurements and the reason for any candidate, secret or
        not."""
        verdict = Entropy.classify("abcdefghijklmnopqrstuvwxyzabcd")
        assert not verdict.is_secret
        assert verdict.reason
        assert verdict.entropy > 0

    def test_a_hex_digest_is_not_rejected_for_being_single_class(self):
        verdicts = Entropy.find_secrets("d41d8cd98f00b204e9800998ecf8427e")
        assert verdicts
        assert verdicts[0].alphabet == "hex"

    def test_a_short_candidate_is_not_judged_at_all(self):
        """Below the minimum, entropy is too noisy to act on."""
        assert Entropy.find_secrets("short") == []
