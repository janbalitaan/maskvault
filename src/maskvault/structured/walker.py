"""Walking a structure, replacing the sensitive values in it."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from maskvault.anonymizer import Anonymizer
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.exceptions import StructureError
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
        *,
        include_keys: bool,
        stringify_numbers: bool,
        skip_keys: frozenset[str],
        max_depth: int = MAX_STRUCTURE_DEPTH,
    ) -> None:
        self._anonymizer = anonymizer
        self._vault = vault
        self._include_keys = include_keys
        self._stringify_numbers = stringify_numbers
        self._skip_keys = {key.lower() for key in skip_keys}
        self._max_depth = max_depth
        # Containers on the current path, by identity. A structure that
        # refers to itself is a cycle, and it is cheaper and clearer to say
        # so than to let a depth limit stand in for the answer.
        #
        # Identity rather than equality: two distinct dicts that happen to be
        # equal are not a cycle, and comparing them would be both wrong and
        # expensive. Only the path is tracked, not everything seen, so a
        # structure that legitimately holds the same object twice side by side
        # still walks.
        self._on_path: set[int] = set()

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
        # Raised, not worked around. Returning the node unchanged here meant
        # a structure eighty levels deep had everything below sixty-four pass
        # through in the clear — empty vault, successful return, nothing said.
        # A privacy filter that silently stops filtering is the one failure
        # worth refusing outright.
        if depth > self._max_depth:
            raise StructureError(
                f"this structure is deeper than {self._max_depth} levels. "
                "Nothing below that was examined, so returning it would hand "
                "back values that were never checked. Raise max_depth if the "
                "structure is genuinely this deep, or flatten it first."
            )
        handler = self._handler_for(node)
        if handler is None:
            return node
        if not isinstance(node, (str, bytes, bytearray)):
            return self._walk_container(node, depth, handler)
        return handler(node, depth)

    def _walk_container(self, node: Any, depth: int, handler: Callable[[Any, int], Any]) -> Any:
        """Walk a container, refusing one that refers to itself."""
        marker = id(node)
        if marker in self._on_path:
            raise StructureError(
                "this structure refers to itself. Walking it would not "
                "terminate, and the output would hold a reference to the "
                "original object — with its real values in it. Flatten the "
                "cycle before anonymizing."
            )
        self._on_path.add(marker)
        try:
            return handler(node, depth)
        finally:
            # Removed on the way back up, so the same object appearing twice
            # side by side is not mistaken for a cycle.
            self._on_path.discard(marker)

    def _handler_for(self, node: Any) -> Callable[[Any, int], Any] | None:
        """Pick the branch for this node's type, or None to leave it alone.

        Ordered deliberately. `str` comes before `Sequence` because a string
        is a Sequence and walking one character by character would replace
        nothing. `bool` is excluded before the numeric branch because `bool`
        subclasses `int` and a boolean holds nothing sensitive.
        """
        if isinstance(node, (str, bytes, bytearray)):
            return lambda value, _: self._leaf(value)
        if isinstance(node, Mapping):
            return self._mapping
        if isinstance(node, (set, frozenset)):
            return self._set
        if isinstance(node, Sequence):
            return self._sequence
        if isinstance(node, (int, float)) and not isinstance(node, bool):
            return lambda value, _: self._number(value)
        return None

    def _leaf(self, node: str | bytes | bytearray) -> str | bytes | bytearray:
        """Replace in a text leaf, whether it arrived as text or as bytes."""
        if isinstance(node, str):
            return self._text(node)
        return self._bytes(node)

    def _bytes(self, node: bytes | bytearray) -> bytes | bytearray:
        """Scan bytes that hold text, and leave the rest alone.

        Bytes had no handler, so they fell through unchanged — a request body
        read as bytes carried its email addresses out in the clear while the
        strings beside it were masked, and the call reported success.

        Decoded strictly as UTF-8. Bytes that decode are text — a JSON body,
        a form payload, a file read in binary mode — and are scanned like any
        string. Bytes that do not are binary: an image, a compressed blob, a
        key. They cannot hold a readable email address, and guessing at
        another encoding would be more likely to corrupt them than to find
        anything. Text in a non-UTF-8 encoding is the gap this leaves, and
        the remedy is to decode it yourself before anonymizing.

        The type is preserved, so a `bytearray` comes back as one.
        """
        try:
            text = bytes(node).decode("utf-8")
        except UnicodeDecodeError:
            return node
        replaced = self._text(text).encode("utf-8")
        return bytearray(replaced) if isinstance(node, bytearray) else replaced

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
