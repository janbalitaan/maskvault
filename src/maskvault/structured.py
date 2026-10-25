"""Anonymizing data, not just text.

A string is the easy case. The data a developer actually wants to pass
somewhere is usually a request body, a log record, a config dump or a row from
a database — nested dicts and lists with strings scattered through them.
Flattening that to text and back loses the structure, so this walks it
instead.

    anonymizer = Anonymizer(level=Level.STRICT)
    safe, vault = anonymize_data({"user": {"email": "me@acme.com"}}, anonymizer)
    # {"user": {"email": "[[EMAIL_1]]"}}

One vault covers the whole structure, so the same value appearing in two
places gets the same token and restoring puts both back.

Three decisions worth knowing:

**Keys are left alone by default.** A key is schema, not data — replacing
`email` with a token would make the output unparseable by whatever reads it.
`include_keys=True` is there for the case where a key is itself sensitive, as
in `{"my.private.hostname": ...}`.

**Non-string leaves are left alone.** A number, boolean or None has no
delimiters to tokenize into, and coercing them to strings would change the
type of the data passing through. `stringify_numbers=True` opts in, for the
case where a bare integer is an account number.

**Depth is capped.** A structure that references itself would otherwise
recurse forever, and the cap is cheaper than cycle detection on every node.
"""

from __future__ import annotations

from typing import Any

from maskvault.anonymizer import Anonymizer
from maskvault.models.token_format import choose_format
from maskvault.models.vault import Vault

# Deep enough for any realistic payload, shallow enough to stop a cycle.
MAX_DEPTH = 64


def anonymize_data(
    data: Any,
    anonymizer: Anonymizer,
    *,
    include_keys: bool = False,
    stringify_numbers: bool = False,
    skip_keys: frozenset[str] | None = None,
) -> tuple[Any, Vault]:
    """Walk a structure, replacing sensitive values, and return it with a vault.

    `skip_keys` names keys whose values pass through untouched — useful for
    an id or a timestamp that a downstream system matches on and that would
    break if tokenized.
    """
    token_format = anonymizer.token_format or choose_format(_sample_text(data))
    vault = Vault(token_format=token_format)
    walker = _Walker(
        anonymizer=anonymizer,
        vault=vault,
        include_keys=include_keys,
        stringify_numbers=stringify_numbers,
        skip_keys=skip_keys or frozenset(),
    )
    return walker.walk(data, depth=0), vault


def restore_data(data: Any, anonymizer: Anonymizer, vault: Vault) -> Any:
    """Put the original values back throughout a structure."""
    if not vault.values:
        return data
    return _restore(data, anonymizer, vault, depth=0)


class _TextSampler:
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
        return self._size >= self._limit

    def text(self) -> str:
        return " ".join(self._pieces)

    def collect(self, node: Any, depth: int = 0) -> None:
        """Walk a node, gathering its strings."""
        if depth > MAX_DEPTH or self.full:
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


def _sample_text(data: Any, limit: int = 4096) -> str:
    """Return enough of the structure's text to choose a token format."""
    sampler = _TextSampler(limit)
    sampler.collect(data)
    return sampler.text()


def _restore(data: Any, anonymizer: Anonymizer, vault: Vault, depth: int) -> Any:
    """Recursively restore, mirroring the walk."""
    if depth > MAX_DEPTH:
        return data
    if isinstance(data, str):
        return anonymizer.restore(data, vault)
    if isinstance(data, dict):
        return {
            anonymizer.restore(key, vault) if isinstance(key, str) else key: _restore(
                value, anonymizer, vault, depth + 1
            )
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [_restore(item, anonymizer, vault, depth + 1) for item in data]
    if isinstance(data, tuple):
        return tuple(_restore(item, anonymizer, vault, depth + 1) for item in data)
    return data


class _Walker:
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
        if depth > MAX_DEPTH:
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
