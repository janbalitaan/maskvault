"""Sampling a structure's text, to choose a token format for it."""

from __future__ import annotations

from typing import Any

from maskvault.constants import MAX_STRUCTURE_DEPTH


class TextSampler:
    """Collects enough of a structure's strings to choose a token format.

    Only the strings matter, and only the first few thousand characters of
    them: the question is whether a delimiter appears anywhere, and a sample
    that size will find one in any realistic payload.

    A class rather than a nested function because the budget and the depth
    have to be shared across the recursion, and threading them through
    arguments is what pushed the original version past the complexity limit.
    """

    def __init__(self, limit: int) -> None:
        self._limit = limit
        self._pieces: list[str] = []
        self._size = 0

    @property
    def full(self) -> bool:
        """Whether enough text has been gathered to decide."""
        return self._size >= self._limit

    def text(self) -> str:
        """Everything gathered, as one string."""
        return " ".join(self._pieces)

    def collect(self, node: Any, depth: int = 0) -> None:
        """Walk a node, gathering its strings."""
        if depth > MAX_STRUCTURE_DEPTH or self.full:
            return
        if isinstance(node, str):
            self._add(node)
        elif isinstance(node, dict):
            self._collect_mapping(node, depth)
        elif isinstance(node, (list, tuple, set)):
            self._collect_sequence(node, depth)

    def _add(self, value: str) -> None:
        self._pieces.append(value)
        self._size += len(value)

    def _collect_mapping(self, node: dict, depth: int) -> None:
        for key, value in node.items():
            if isinstance(key, str):
                self._add(key)
            self.collect(value, depth + 1)

    def _collect_sequence(self, node: list | tuple | set, depth: int) -> None:
        for item in node:
            self.collect(item, depth + 1)
