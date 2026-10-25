"""Three values go out. The reply comes back mentioning two.

A reply need not repeat everything it was given, so this is ordinary rather
than an error — but whether it is *acceptable* is the application's call. A
summarizer mentioning two of three contacts is fine; a form-filler returning
two of three fields is a failure. So the counts are reported and not judged.

Three outcomes, which have to be distinguishable:

    resolved 3, leaked 0   everything came back
    resolved 2, leaked 0   one was not mentioned — usually fine
    resolved 2, leaked 1   one was mangled — the reply has lost a value
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Vault

ORIGINAL = "Contact alice@acme.com or bob@other.com, or call +63 917 555 1234."


@pytest.fixture
def masked() -> tuple[Anonymizer, Vault, list[str]]:
    anonymizer = Anonymizer()
    vault = Vault.for_key("conversation-1")
    anonymizer.anonymize_into(ORIGINAL, vault)
    return anonymizer, vault, list(vault.values)


class TestThreeValuesWereMasked:
    def test_the_vault_holds_three(self, masked):
        _, _, tokens = masked
        assert len(tokens) == 3

    def test_two_emails_and_a_phone(self, masked):
        _, _, tokens = masked
        labels = sorted(token.strip("!|").rsplit("_", 1)[0].split("_")[0] for token in tokens)
        assert labels == ["EMAIL", "EMAIL", "PHONE"]


class TestAllThreeComeBack:
    def test_every_value_is_restored(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second}, ringing {third}."
        restored = anonymizer.restore(reply, vault)
        assert "alice@acme.com" in restored
        assert "bob@other.com" in restored

    def test_resolved_counts_three(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second}, ringing {third}."
        assert len(anonymizer.resolved(reply, vault)) == 3

    def test_nothing_is_unresolved(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second}, ringing {third}."
        assert anonymizer.unresolved(reply, vault) == []

    def test_nothing_leaked(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second}, ringing {third}."
        assert anonymizer.leaked(reply, vault) == []


class TestOnlyTwoAreMentioned:
    """Normal. The reply did not need the third."""

    def test_the_mentioned_two_are_restored(self, masked):
        anonymizer, vault, (first, _, third) = masked
        reply = f"Emailing {first}, ringing {third}."
        restored = anonymizer.restore(reply, vault)
        assert "alice@acme.com" in restored
        assert "+63 917 555 1234" in restored

    def test_the_absent_one_is_not_invented(self, masked):
        """Nothing is substituted for a value the reply never referred to."""
        anonymizer, vault, (first, _, third) = masked
        reply = f"Emailing {first}, ringing {third}."
        assert "bob@other.com" not in anonymizer.restore(reply, vault)

    def test_resolved_counts_two(self, masked):
        anonymizer, vault, (first, _, third) = masked
        reply = f"Emailing {first}, ringing {third}."
        assert len(anonymizer.resolved(reply, vault)) == 2

    def test_unresolved_names_the_third(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first}, ringing {third}."
        assert anonymizer.unresolved(reply, vault) == [second]

    def test_nothing_leaked_because_nothing_broke(self, masked):
        """This is the case that must stay quiet. A reply that legitimately
        omits a value is not a reply to throw away."""
        anonymizer, vault, (first, _, third) = masked
        reply = f"Emailing {first}, ringing {third}."
        assert anonymizer.leaked(reply, vault) == []


class TestTwoIntactAndOneMangled:
    """The case that must be loud. A value has silently gone missing."""

    @pytest.mark.parametrize(
        ("shape", "damage"),
        [
            ("lower-cased", lambda token: token.lower()),
            ("inner spaces", lambda token: token.replace("_", " _ ")),
            ("delimiters dropped", lambda token: token.strip("!|")),
            ("broken over a line", lambda token: f"{token[:8]}\n{token[8:]}"),
            ("square brackets", lambda token: f"[{token.strip('!|')}]"),
        ],
    )
    def test_leaked_reports_it(self, masked, shape, damage):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {damage(second)}, ringing {third}."
        assert anonymizer.leaked(reply, vault), f"{shape} went unreported"

    def test_the_two_intact_ones_still_restore(self, masked):
        """A damaged third does not cost the caller the other two."""
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second.lower()}, ringing {third}."
        restored = anonymizer.restore(reply, vault)
        assert "alice@acme.com" in restored
        assert "+63 917 555 1234" in restored

    def test_resolved_still_counts_two(self, masked):
        anonymizer, vault, (first, second, third) = masked
        reply = f"Emailing {first} and {second.lower()}, ringing {third}."
        assert len(anonymizer.resolved(reply, vault)) == 2

    def test_the_combination_distinguishes_it_from_an_omission(self, masked):
        """Same resolved count as an omission; `leaked` is what separates
        them, which is why both are needed."""
        anonymizer, vault, (first, second, third) = masked
        omitted = f"Emailing {first}, ringing {third}."
        mangled = f"Emailing {first} and {second.lower()}, ringing {third}."
        assert len(anonymizer.resolved(omitted, vault)) == len(
            anonymizer.resolved(mangled, vault)
        )
        assert not anonymizer.leaked(omitted, vault)
        assert anonymizer.leaked(mangled, vault)


class TestNoneAreMentioned:
    def test_resolved_is_empty(self, masked):
        anonymizer, vault, _ = masked
        assert anonymizer.resolved("Noted, thank you.", vault) == []

    def test_everything_is_unresolved(self, masked):
        anonymizer, vault, tokens = masked
        assert len(anonymizer.unresolved("Noted, thank you.", vault)) == len(tokens)

    def test_nothing_leaked(self, masked):
        anonymizer, vault, _ = masked
        assert anonymizer.leaked("Noted, thank you.", vault) == []


class TestADestroyedValueHasNoToken:
    def test_it_never_appears_in_either_list(self):
        """A credential is destroyed, not tokenized, so there is nothing for
        a reply to return and nothing to count."""
        anonymizer = Anonymizer()
        vault = Vault.for_key("c")
        safe = anonymizer.anonymize_into("key sk-" + "a" * 40, vault)
        assert "sk-" not in safe
        assert anonymizer.resolved(safe, vault) == []
        assert anonymizer.unresolved(safe, vault) == []
