"""A caller owns the format. The library's job is to stop them shipping a"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.formats import format_from_dict, random_format
from maskvault.models.token_format import TokenFormat


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestCustomFormats:
    """A caller owns the format. The library's job is to stop them shipping a
    broken one, not to limit what they can choose."""

    def test_a_fully_custom_format_round_trips(self):
        custom = TokenFormat(name="mine", opening="<%|", closing="|%>")
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        text = "I work at Acme"
        safe, vault = anonymizer.anonymize(text)
        assert "<%|ORG_1|%>" in safe
        assert anonymizer.restore(safe, vault) == text

    def test_lowercase_labels_work_end_to_end(self):
        custom = TokenFormat(
            name="lower",
            opening="{{",
            closing="}}",
            label_pattern=r"[a-z_]+",
            label_case="lower",
        )
        anonymizer = Anonymizer(token_format=custom, terms={"ORG": ["Acme"]})
        safe, vault = anonymizer.anonymize("I work at Acme")
        assert "{{org_1}}" in safe
        assert anonymizer.restore(safe, vault) == "I work at Acme"

    def test_a_caller_supplies_their_own_candidates(self):
        mine = TokenFormat(name="mine", opening="<%|", closing="|%>")
        anonymizer = Anonymizer(format_candidates=(mine,), terms={"ORG": ["Acme"]})
        safe, _ = anonymizer.anonymize("see [[Notes]], I work at Acme")
        assert "<%|ORG_1|%>" in safe

    def test_candidates_are_reported(self):
        mine = TokenFormat(name="mine", opening="<%|", closing="|%>")
        assert Anonymizer(format_candidates=(mine,)).format_candidates == (mine,)

    def test_a_random_format_is_unguessable_and_works(self):
        anonymizer = Anonymizer(token_format=random_format(), terms={"ORG": ["Acme"]})
        text = "I work at Acme"
        safe, vault = anonymizer.anonymize(text)
        assert "Acme" not in safe
        assert anonymizer.restore(safe, vault) == text

    def test_two_random_formats_differ(self):
        assert random_format().opening != random_format().opening

    def test_a_format_round_trips_through_config(self):
        custom = TokenFormat(
            name="mine",
            opening="<%|",
            closing="|%>",
            label_pattern=r"[a-z_]+",
            label_case="lower",
        )
        assert format_from_dict(custom.as_dict()) == custom

    def test_label_case_and_label_pattern_are_validated_together(self):
        """They can only drift apart once, at construction, rather than
        silently at restore time."""
        with pytest.raises(ValueError, match="cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_case="lower")

    def test_config_without_required_keys_is_rejected(self):
        with pytest.raises(ValueError, match="opening"):
            format_from_dict({"name": "incomplete"})
