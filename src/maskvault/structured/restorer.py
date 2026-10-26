"""Putting the original values back into a structure.

The mirror of the walker: where that one descends looking for text to replace,
this one descends looking for tokens to put back. Separate from the walker
because the two differ in what they do at a leaf, and a single class that did
both would need a mode flag at every level of the recursion.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from maskvault.anonymizer import Anonymizer
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.models.vault import Vault
from maskvault.structured.text_bytes import BytesText


class Restorer:
    """Putting the originals back throughout a structure.

    The branches and their order mirror Walker._handler_for. They have to: a
    type the walk replaced and the restore skipped would leave tokens in the
    output, which is worse than not anonymizing at all.

    A class for the same reason Walker is one — the anonymizer and the vault
    are fixed for one traversal, and threading them through every recursive
    call is what pushed the function form past the complexity limit.
    """

    def __init__(self, anonymizer: Anonymizer, vault: Vault) -> None:
        self._anonymizer = anonymizer
        self._vault = vault

    def restore(self, data: Any, depth: int = 0) -> Any:
        """Restore one node, recursing into containers."""
        if depth > MAX_STRUCTURE_DEPTH:
            # Unchanged is safe here, unlike in the walker: an unrestored
            # token is a token, which `leaked()` reports. The walker returning
            # a node unchanged meant real values passing through unexamined.
            return data
        # Order is the contract. `str` before `Sequence` because a string is
        # one and walking it character by character restores nothing; `bytes`
        # before `Sequence` for the same reason, a byte string being a
        # sequence of integers.
        if isinstance(data, (str, bytes, bytearray)):
            return self._leaf(data)
        if isinstance(data, Mapping):
            return self._mapping(data, depth)
        if isinstance(data, (set, frozenset)):
            return self._set(data, depth)
        if isinstance(data, Sequence):
            return self._sequence(data, depth)
        return data

    def _leaf(self, data: str | bytes | bytearray) -> str | bytes | bytearray:
        """Restore a text leaf, whether it arrived as text or as bytes."""
        if isinstance(data, str):
            return self._anonymizer.restore(data, self._vault)
        return self._bytes(data)

    def _bytes(self, data: bytes | bytearray) -> bytes | bytearray:
        """Restore inside bytes, using the encoding the vault recorded.

        The vault carries it so that anonymizing with one encoding and
        restoring with another is not expressible.
        """
        return BytesText.transform(
            data,
            self._vault.bytes_encoding,
            lambda text: self._anonymizer.restore(text, self._vault),
        )

    def _mapping(self, data: Mapping, depth: int) -> dict:
        """Restore a mapping, handling keys only where they were replaced."""
        return {
            self._anonymizer.restore(key, self._vault)
            if isinstance(key, str)
            else key: self.restore(value, depth + 1)
            for key, value in data.items()
        }

    def _set(self, data: set | frozenset, depth: int) -> Any:
        """Restore a set, preserving mutability."""
        restored = {self.restore(item, depth + 1) for item in data}
        return frozenset(restored) if isinstance(data, frozenset) else restored

    def _sequence(self, data: Sequence, depth: int) -> Any:
        """Restore a list or tuple, preserving the original type."""
        restored = [self.restore(item, depth + 1) for item in data]
        return tuple(restored) if isinstance(data, tuple) else restored
