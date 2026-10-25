"""Walking a nested structure, replacing values and putting them back."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level, anonymize_data, restore_data


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT, terms={"ORG": ["Acme Corp"]})


class TestWalkingData:
    def test_a_nested_value_is_replaced(self, anonymizer):
        safe, _ = anonymize_data({"user": {"email": "me@acme.com"}}, anonymizer)
        assert safe["user"]["email"] != "me@acme.com"

    def test_the_structure_is_preserved(self, anonymizer):
        data = {"a": {"b": ["me@acme.com", 1, True, None]}}
        safe, _ = anonymize_data(data, anonymizer)
        assert list(safe) == ["a"]
        assert list(safe["a"]) == ["b"]
        assert len(safe["a"]["b"]) == 4

    def test_it_round_trips(self, anonymizer):
        data = {
            "user": {"email": "me@acme.com", "employer": "Acme Corp"},
            "notes": ["call me on +63 917 555 1234", "no issues"],
        }
        safe, vault = anonymize_data(data, anonymizer)
        assert restore_data(safe, anonymizer, vault) == data

    def test_one_value_in_two_places_gets_one_token(self, anonymizer):
        data = {"primary": "me@acme.com", "backup": "me@acme.com"}
        safe, vault = anonymize_data(data, anonymizer)
        assert safe["primary"] == safe["backup"]
        assert vault.replaced == 1

    def test_keys_are_left_alone_by_default(self, anonymizer):
        """A key is schema, not data. Replacing it would make the output
        unparseable by whatever reads it next."""
        safe, _ = anonymize_data({"me@acme.com": "value"}, anonymizer)
        assert "me@acme.com" in safe

    def test_keys_can_be_included(self, anonymizer):
        safe, _ = anonymize_data({"me@acme.com": "value"}, anonymizer, include_keys=True)
        assert "me@acme.com" not in safe

    def test_numbers_are_left_alone_by_default(self, anonymizer):
        """Coercing a number to a string would change the type of the data
        passing through."""
        safe, _ = anonymize_data({"count": 42, "ratio": 1.5}, anonymizer)
        assert safe["count"] == 42
        assert safe["ratio"] == 1.5

    def test_booleans_are_never_touched(self, anonymizer):
        """bool is a subclass of int, so it needs excluding explicitly."""
        safe, _ = anonymize_data(
            {"active": True, "deleted": False}, anonymizer, stringify_numbers=True
        )
        assert safe["active"] is True
        assert safe["deleted"] is False

    def test_skip_keys_passes_a_value_through(self, anonymizer):
        """An id a downstream system matches on would break if tokenized."""
        data = {"id": "me@acme.com", "contact": "me@acme.com"}
        safe, _ = anonymize_data(data, anonymizer, skip_keys=frozenset({"id"}))
        assert safe["id"] == "me@acme.com"
        assert safe["contact"] != "me@acme.com"

    def test_a_tuple_stays_a_tuple(self, anonymizer):
        safe, _ = anonymize_data({"items": ("me@acme.com",)}, anonymizer)
        assert isinstance(safe["items"], tuple)

    def test_a_list_stays_a_list(self, anonymizer):
        safe, _ = anonymize_data({"items": ["me@acme.com"]}, anonymizer)
        assert isinstance(safe["items"], list)

    def test_a_bare_string_works(self, anonymizer):
        safe, vault = anonymize_data("me@acme.com", anonymizer)
        assert safe != "me@acme.com"
        assert restore_data(safe, anonymizer, vault) == "me@acme.com"

    def test_an_empty_structure_is_safe(self, anonymizer):
        safe, vault = anonymize_data({}, anonymizer)
        assert safe == {}
        assert vault.replaced == 0

    def test_a_cycle_does_not_hang(self, anonymizer):
        """Depth is capped rather than cycles detected, because the cap is
        cheaper than checking every node and the failure is the same."""
        data: dict = {"name": "me@acme.com"}
        data["self"] = data
        safe, _ = anonymize_data(data, anonymizer)
        assert safe["name"] != "me@acme.com"

    def test_credentials_are_still_destroyed(self, anonymizer):
        safe, vault = anonymize_data({"config": {"key": "AKIAIOSFODNN7EXAMPLE"}}, anonymizer)
        assert "AKIAIOSFODNN7EXAMPLE" not in str(safe)
        assert "aws_access_key" in vault.destroyed

    def test_the_format_avoids_markup_already_in_the_data(self, anonymizer):
        """Collision avoidance samples the whole structure, not one string."""
        data = {"note": "see !|EXISTING|!", "email": "me@acme.com"}
        safe, vault = anonymize_data(data, anonymizer)
        assert vault.token_format.name != "pipe_bang"
        assert safe["note"] == "see !|EXISTING|!"
