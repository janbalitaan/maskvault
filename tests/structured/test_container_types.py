"""Container types the walk must not silently skip.

A structure this does not recognize is returned unchanged while the call
reports success — the values pass through and nothing says so. That is the
one failure mode a privacy filter cannot have, and it is what an
`isinstance(node, dict)` check causes the moment a caller passes a
MappingProxyType, a defaultdict, or a set.
"""

from __future__ import annotations

from collections import OrderedDict, defaultdict
from types import MappingProxyType

import pytest

from maskvault import Anonymizer, Level, anonymize_data, restore_data

SECRET = "me@acme.com"


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(level=Level.STRICT)


class TestContainerTypes:
    @pytest.mark.parametrize(
        "name,build",
        [
            ("dict", lambda: {"email": SECRET}),
            ("MappingProxyType", lambda: MappingProxyType({"email": SECRET})),
            ("OrderedDict", lambda: OrderedDict([("email", SECRET)])),
            ("defaultdict", lambda: defaultdict(str, {"email": SECRET})),
        ],
    )
    def test_every_mapping_type_is_walked(self, anonymizer, name, build):
        safe, vault = anonymize_data(build(), anonymizer)
        assert SECRET not in str(safe), f"{name} passed through unchanged"
        assert vault.replaced == 1

    @pytest.mark.parametrize(
        "name,build",
        [
            ("list", lambda: {"items": [SECRET]}),
            ("tuple", lambda: {"items": (SECRET,)}),
            ("set", lambda: {"items": {SECRET}}),
            ("frozenset", lambda: {"items": frozenset({SECRET})}),
        ],
    )
    def test_every_collection_type_is_walked(self, anonymizer, name, build):
        safe, vault = anonymize_data(build(), anonymizer)
        assert SECRET not in str(safe), f"{name} passed through unchanged"
        assert vault.replaced == 1

    @pytest.mark.parametrize(
        "name,build,expected",
        [
            ("list", lambda: {"i": [SECRET]}, list),
            ("tuple", lambda: {"i": (SECRET,)}, tuple),
            ("set", lambda: {"i": {SECRET}}, set),
            ("frozenset", lambda: {"i": frozenset({SECRET})}, frozenset),
        ],
    )
    def test_the_container_type_is_preserved(self, anonymizer, name, build, expected):
        safe, _ = anonymize_data(build(), anonymizer)
        assert isinstance(safe["i"], expected)

    @pytest.mark.parametrize(
        "build",
        [
            lambda: {"items": [SECRET]},
            lambda: {"items": (SECRET,)},
            lambda: {"items": {SECRET}},
            lambda: {"items": frozenset({SECRET})},
        ],
    )
    def test_restoring_mirrors_the_walk(self, anonymizer, build):
        """A type the walk replaced and the restore skipped would leave
        tokens in the output, which is worse than not anonymizing."""
        original = build()
        safe, vault = anonymize_data(original, anonymizer)
        assert restore_data(safe, anonymizer, vault) == original

    def test_a_string_is_not_walked_character_by_character(self, anonymizer):
        """`str` is a Sequence, so the string branch has to come first."""
        safe, vault = anonymize_data(SECRET, anonymizer)
        assert safe != SECRET
        assert vault.replaced == 1

    def test_bytes_are_left_alone(self, anonymizer):
        """`bytes` is a Sequence too, and iterating one yields integers."""
        payload = {"blob": b"me@acme.com"}
        safe, _ = anonymize_data(payload, anonymizer)
        assert safe["blob"] == b"me@acme.com"

    def test_booleans_survive_stringify_numbers(self, anonymizer):
        """`bool` subclasses `int`, so it needs excluding explicitly."""
        safe, _ = anonymize_data({"on": True, "off": False}, anonymizer, stringify_numbers=True)
        assert safe["on"] is True
        assert safe["off"] is False
