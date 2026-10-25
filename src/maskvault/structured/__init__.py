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

from collections.abc import Mapping, Sequence
from typing import Any

from maskvault.anonymizer import Anonymizer
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.formats import choose_format
from maskvault.models.vault import Vault
from maskvault.structured.sampler import TextSampler
from maskvault.structured.walker import Walker

__all__ = ["TextSampler", "Walker", "anonymize_data", "restore_data"]


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
    walker = Walker(
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
    return _Restorer(anonymizer, vault).restore(data)


def _sample_text(data: Any, limit: int = 4096) -> str:
    """Return enough of the structure's text to choose a token format."""
    sampler = TextSampler(limit)
    sampler.collect(data)
    return sampler.text()


class _Restorer:
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
