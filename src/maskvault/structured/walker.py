"""Walking a structure, replacing the sensitive values in it."""

from __future__ import annotations

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
        """Replace sensitive values in one node, recursing into containers."""
        if depth > MAX_STRUCTURE_DEPTH:
            return node
        if isinstance(node, str):
            return self._text(node)
        if isinstance(node, dict):
            return self._mapping(node, depth)
        if isinstance(node, (list, tuple)):
            return self._sequence(node, depth)
        # bool is a subclass of int, and a boolean holds nothing sensitive.
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            return self._number(node)
        return node

    def _sequence(self, node: list | tuple, depth: int) -> Any:
        """Walk a list or tuple, preserving the original type."""
        walked = [self.walk(item, depth + 1) for item in node]
        return tuple(walked) if isinstance(node, tuple) else walked

    def _text(self, value: str) -> str:
        """One string, through the anonymizer, sharing the traversal's vault."""
        return self._anonymizer.anonymize_into(value, self._vault)

    def _mapping(self, node: dict, depth: int) -> dict:
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
