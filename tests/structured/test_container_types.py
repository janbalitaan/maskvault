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

    def test_text_in_bytes_is_replaced(self, anonymizer):
        """Bytes used to be left alone entirely, which meant a request body
        read in binary mode carried its email addresses out in the clear
        while the strings beside it were masked."""
        safe, vault = anonymize_data({"blob": b"me@acme.com"}, anonymizer)
        assert b"me@acme.com" not in safe["blob"]
        assert len(vault.values) == 1

    def test_bytes_are_not_walked_as_a_sequence(self, anonymizer):
        """`bytes` is a Sequence, and iterating one yields integers — walking
        it that way would turn a blob into a list of numbers."""
        safe, _ = anonymize_data({"blob": b"me@acme.com"}, anonymizer)
        assert isinstance(safe["blob"], bytes)

    def test_binary_that_is_not_text_is_left_alone(self, anonymizer):
        """An image or a compressed blob cannot hold a readable address, and
        guessing at another encoding would corrupt it."""
        blob = b"\x89PNG\r\n\x1a\n\x00\x00\xff\xfe"
        safe, _ = anonymize_data({"blob": blob}, anonymizer)
        assert safe["blob"] == blob

    def test_a_bytearray_comes_back_as_one(self, anonymizer):
        safe, _ = anonymize_data({"blob": bytearray(b"me@acme.com")}, anonymizer)
        assert isinstance(safe["blob"], bytearray)

    def test_bytes_round_trip(self, anonymizer):
        """Masking without being able to restore would be worse than not
        masking: the value in the vault, the token in the payload, and the
        caller getting neither."""
        payload = {"blob": b"me@acme.com", "ba": bytearray(b"call +63 917 555 1234")}
        safe, vault = anonymize_data(payload, anonymizer)
        assert restore_data(safe, anonymizer, vault) == payload

    def test_booleans_survive_stringify_numbers(self, anonymizer):
        """`bool` subclasses `int`, so it needs excluding explicitly."""
        safe, _ = anonymize_data({"on": True, "off": False}, anonymizer, stringify_numbers=True)
        assert safe["on"] is True
        assert safe["off"] is False


class TestRestoringBinaryThatIsNotText:
    """The restorer's mirror of the walker's rule.

    Bytes that do not decode as UTF-8 were never scanned, so there is nothing
    in them to restore — and attempting it would mean decoding with errors
    suppressed, which corrupts the blob on the way back.
    """

    def test_binary_passes_through_restore_unchanged(self, anonymizer):
        """A sensitive value sits beside it, so the vault is not empty and
        `restore_data` really walks — an all-binary payload short-circuits
        before reaching this branch."""
        blob = b"\x89PNG\r\n\x1a\n\x00\x00\xff\xfe"
        payload = {"blob": blob, "note": "write to me@acme.com"}
        safe, vault = anonymize_data(payload, anonymizer)
        assert vault.values, "the vault must not be empty for the walk to happen"
        assert restore_data(safe, anonymizer, vault) == payload

    def test_a_binary_bytearray_also_passes_through(self, anonymizer):
        blob = bytearray(b"\xff\xfe\x00\x01")
        payload = {"blob": blob, "note": "write to me@acme.com"}
        safe, vault = anonymize_data(payload, anonymizer)
        restored = restore_data(safe, anonymizer, vault)["blob"]
        assert restored == blob
        assert isinstance(restored, bytearray)
