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
            return data
        if isinstance(data, str):
            return self._anonymizer.restore(data, self._vault)
        if isinstance(data, Mapping):
            return self._mapping(data, depth)
        if isinstance(data, (set, frozenset)):
            return self._set(data, depth)
        if isinstance(data, Sequence) and not isinstance(data, bytes):
            return self._sequence(data, depth)
        return data

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
