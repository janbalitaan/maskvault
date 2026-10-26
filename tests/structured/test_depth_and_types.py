"""The edges of walking a structure: depth, odd leaves, opt-in numbers.

A structure that references itself would recurse forever, and the depth cap is
cheaper than cycle detection at every node. The cap has to be tested from both
sides: deep enough still works, too deep stops rather than crashing.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level, anonymize_data, restore_data
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.exceptions import StructureError
from maskvault.structured.sampler import TextSampler


def nest(depth: int, leaf: object) -> dict:
    """Build a structure `depth` levels deep with `leaf` at the bottom."""
    node: object = leaf
    for _ in range(depth):
        node = {"nested": node}
    return node  # type: ignore[return-value]


class TestTheDepthCap:
    def test_a_structure_within_the_cap_is_processed(self):
        data = nest(MAX_STRUCTURE_DEPTH - 2, "write to me@acme.com")
        _, vault = anonymize_data(data, Anonymizer())
        assert vault.replaced == 1

    def test_a_structure_past_the_cap_raises(self):
        """Returning the node untouched was *not* the safe answer.

        It was the unsafe one: a structure eighty levels deep had everything
        below sixty-four returned as it came in, so the values there passed
        through in the clear with an empty vault and a successful return.
        Nothing said so. A privacy filter that silently stops filtering is
        the one failure worth refusing outright.
        """
        data = nest(MAX_STRUCTURE_DEPTH + 10, "write to me@acme.com")
        with pytest.raises(StructureError, match="deeper than"):
            anonymize_data(data, Anonymizer())

    def test_the_value_below_the_cap_was_leaking(self):
        """The regression itself, stated as a test."""
        data = nest(MAX_STRUCTURE_DEPTH + 10, "write to me@acme.com")
        with pytest.raises(StructureError):
            anonymize_data(data, Anonymizer())

    def test_the_caller_can_raise_the_limit(self):
        """For a structure that is genuinely this deep."""
        data = nest(MAX_STRUCTURE_DEPTH + 10, "write to me@acme.com")
        safe, vault = anonymize_data(data, Anonymizer(), max_depth=MAX_STRUCTURE_DEPTH + 20)
        assert len(vault.values) == 1
        assert "me@acme.com" not in repr(safe)

    def test_a_structure_within_the_cap_is_unaffected(self):
        data = nest(10, "write to me@acme.com")
        safe, vault = anonymize_data(data, Anonymizer())
        assert len(vault.values) == 1
        assert "me@acme.com" not in repr(safe)

    def test_restoring_past_the_cap_also_stops(self):
        data = nest(MAX_STRUCTURE_DEPTH + 10, "!|EMAIL_1|!")
        anonymizer = Anonymizer()
        _, vault = anonymize_data({"x": "me@acme.com"}, anonymizer)
        assert restore_data(data, anonymizer, vault) is not None


class TestLeavesThatAreNotStrings:
    def test_a_number_is_left_alone_by_default(self):
        """Coercing it would change the type of the data passing through."""
        safe, vault = anonymize_data({"port": 5432}, Anonymizer())
        assert safe == {"port": 5432}
        assert vault.replaced == 0

    def test_a_number_is_examined_when_the_caller_opts_in(self):
        """For the case where a bare integer is an account number."""
        safe, _ = anonymize_data(
            {"account": 4111111111111111},
            Anonymizer(),
            stringify_numbers=True,
        )
        assert safe["account"] != 4111111111111111

    def test_a_number_that_matches_nothing_keeps_its_type(self):
        """Opting in must not turn every integer into a string."""
        safe, _ = anonymize_data({"port": 5432}, Anonymizer(), stringify_numbers=True)
        assert safe["port"] == 5432
        assert isinstance(safe["port"], int)

    def test_none_and_booleans_pass_through(self):
        data = {"enabled": True, "missing": None, "ratio": 1.5}
        safe, _ = anonymize_data(data, Anonymizer())
        assert safe == data

    def test_bytes_are_not_walked_as_a_sequence(self):
        """Bytes are a Sequence, and iterating one yields integers — walking
        it that way would turn a blob into a list of numbers. They are
        decoded and scanned as text instead."""
        safe, _ = anonymize_data({"blob": b"me@acme.com"}, Anonymizer())
        assert isinstance(safe["blob"], bytes)
        assert b"me@acme.com" not in safe["blob"]

    def test_a_set_is_handled(self):
        safe, vault = anonymize_data({"emails": {"me@acme.com"}}, Anonymizer())
        assert vault.replaced == 1
        assert isinstance(safe["emails"], (set, frozenset))

    def test_a_tuple_stays_a_sequence(self):
        safe, _ = anonymize_data({"contacts": ("me@acme.com",)}, Anonymizer())
        assert len(safe["contacts"]) == 1
        assert "me@acme.com" not in str(safe["contacts"])


class TestKeys:
    def test_keys_are_left_alone_by_default(self):
        """A key is schema, not data — replacing it would make the output
        unparseable by whatever reads it."""
        safe, _ = anonymize_data({"me@acme.com": "value"}, Anonymizer())
        assert "me@acme.com" in safe

    def test_keys_can_be_included(self):
        safe, _ = anonymize_data({"me@acme.com": "value"}, Anonymizer(), include_keys=True)
        assert "me@acme.com" not in safe

    def test_an_included_key_round_trips(self):
        anonymizer = Anonymizer(level=Level.STANDARD)
        original = {"me@acme.com": "value"}
        safe, vault = anonymize_data(original, anonymizer, include_keys=True)
        assert restore_data(safe, anonymizer, vault) == original


class TestSampling:
    """Choosing a token format needs a sample of the text, not all of it —
    walking a large structure in full would cost more than the choice."""

    def test_a_format_is_chosen_from_a_sample(self):
        data = {"note": "a text with [[brackets]] already in it"}
        assert "[[brackets]]" in TextSampler.sample(data)

    def test_sampling_stops_near_the_limit(self):
        """A bound on work, not an exact length: a value is added whole, so
        the total can exceed the budget by the size of the last one. It used
        to exceed it by every remaining key as well."""
        value_length = 200
        data = {str(index): "x" * value_length for index in range(100)}
        sampled = TextSampler.sample(data, limit=1000)
        assert len(sampled) <= 1000 + value_length + 8

    def test_a_mapping_with_many_keys_does_not_overrun(self):
        """Keys were added without checking the budget, so a wide mapping
        collected everything after the limit was reached."""
        data = {f"key_number_{index}": "v" for index in range(500)}
        assert len(TextSampler.sample(data, limit=100)) < 200

    def test_a_format_avoids_delimiters_already_in_the_structure(self):
        """The reason sampling exists: a token using delimiters the text
        already contains cannot be told apart from the text."""
        data = {"note": "see @@NOTE@@ and @@OTHER@@ in the log"}
        safe, _ = anonymize_data(data, Anonymizer(), stringify_numbers=False)
        assert safe is not None

    def test_a_sequence_stops_at_the_budget_too(self):
        """A long list would otherwise collect every element past the limit,
        the same way a wide mapping collected every key."""
        data = ["x" * 50 for _ in range(200)]
        assert len(TextSampler.sample(data, limit=100)) < 250

    def test_a_non_string_key_is_skipped_without_stopping_the_walk(self):
        """JSON has only string keys, but this walks Python structures and a
        dict keyed by integers is ordinary."""
        data = {1: "write to me@acme.com", 2: "and you@acme.com"}
        assert "me@acme.com" in TextSampler.sample(data)
