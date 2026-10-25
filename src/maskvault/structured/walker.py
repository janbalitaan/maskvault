"""Walking a structure, replacing the sensitive values in it."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from maskvault.anonymizer import Anonymizer
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.models.vault import Vault


class Walker:
    """Carries the options down the recursion.

    A class rather than six arguments threaded through every call: the
    options are fixed for one traversal, and only the node and depth change.
    """

    def __init__(
        self,
        anonymizer: Anonymizer,
        vault: Vault,
        include_keys: bool,
        stringify_numbers: bool,
        skip_keys: frozenset[str],
    ) -> None:
        self._anonymizer = anonymizer
        self._vault = vault
        self._include_keys = include_keys
        self._stringify_numbers = stringify_numbers
        self._skip_keys = {key.lower() for key in skip_keys}

    def walk(self, node: Any, depth: int) -> Any:
        """Replace sensitive values in one node, recursing into containers.

        Checks `Mapping` and `Sequence` rather than `dict` and `list`,
        because a `MappingProxyType` is a mapping and is not a dict — and a
        structure this did not recognize would be returned unchanged, which
        in a privacy filter means the values pass through while the call
        reports success.

        The string check comes first because `str` is itself a Sequence, and
        walking one character by character would replace nothing.
        """
        if depth > MAX_STRUCTURE_DEPTH:
            return node
        handler = self._handler_for(node)
        return handler(node, depth) if handler else node

    def _handler_for(self, node: Any) -> Callable[[Any, int], Any] | None:
        """Pick the branch for this node's type, or None to leave it alone.

        Ordered deliberately. `str` comes before `Sequence` because a string
        is a Sequence and walking one character by character would replace
        nothing. `bool` is excluded before the numeric branch because `bool`
        subclasses `int` and a boolean holds nothing sensitive.
        """
        if isinstance(node, str):
            return lambda value, _: self._text(value)
        if isinstance(node, Mapping):
            return self._mapping
        if isinstance(node, (set, frozenset)):
            return self._set
        if isinstance(node, Sequence) and not isinstance(node, bytes):
            return self._sequence
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            return lambda value, _: self._number(value)
        return None

    def _sequence(self, node: Sequence, depth: int) -> Any:
        """Walk a list or tuple, preserving the original type."""
        walked = [self.walk(item, depth + 1) for item in node]
        return tuple(walked) if isinstance(node, tuple) else walked

    def _set(self, node: set | frozenset, depth: int) -> Any:
        """Walk a set, preserving mutability.

        Handled explicitly because a set is not a Sequence, so without this
        branch a set of addresses would be returned untouched while the call
        reported success — the silent pass-through a privacy filter cannot
        have.
        """
        walked = {self.walk(item, depth + 1) for item in node}
        return frozenset(walked) if isinstance(node, frozenset) else walked

    def _text(self, value: str) -> str:
        """One string, through the anonymizer, sharing the traversal's vault."""
        return self._anonymizer.anonymize_into(value, self._vault)

    def _mapping(self, node: Mapping, depth: int) -> dict:
        """Walk a mapping, preserving keys unless asked otherwise."""
        result = {}
        for key, value in node.items():
            if isinstance(key, str) and key.lower() in self._skip_keys:
                result[key] = value
                continue
            new_key = self._text(key) if self._include_keys and isinstance(key, str) else key
            result[new_key] = self.walk(value, depth + 1)
        return result

    def _number(self, value: int | float) -> Any:
        """Handle a number, which is only examined when the caller opted in."""
        if not self._stringify_numbers:
            return value
        replaced = self._text(str(value))
        # Unchanged means nothing matched, so the original type is kept.
        return value if replaced == str(value) else replaced
