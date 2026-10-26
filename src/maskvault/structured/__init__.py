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
from maskvault.constants import MAX_STRUCTURE_DEPTH
from maskvault.formats import TokenFormats
from maskvault.models.vault import Vault
from maskvault.structured.restorer import Restorer
from maskvault.structured.sampler import TextSampler
from maskvault.structured.walker import Walker

__all__ = ["Restorer", "TextSampler", "Walker", "anonymize_data", "restore_data"]


def anonymize_data(
    data: Any,
    anonymizer: Anonymizer,
    *,
    include_keys: bool = True,
    stringify_numbers: bool = False,
    skip_keys: frozenset[str] | None = None,
    max_depth: int = MAX_STRUCTURE_DEPTH,
    bytes_encoding: str | None = "utf-8",
) -> tuple[Any, Vault]:
    """Walk a structure, replacing sensitive values, and return it with a vault.

    `include_keys` scans the keys as well as the values, and defaults to
    **on**. A key holding personal data is personal data: `{"alice@acme.com":
    {...}}` is how a map of users by email address looks, and leaving it
    unexamined meant the one structure most likely to be keyed by an
    identifier was the one structure that leaked it. Ordinary structural keys
    — `email`, `name`, `user_id` — match no detector and pass through
    untouched, so this costs nothing on a normal payload.

    Turn it off where a downstream system matches on the literal key and
    tokenizing one would break it; `skip_keys` is the narrower tool for the
    same job.

    `skip_keys` names keys whose values pass through untouched — useful for
    an id or a timestamp that a downstream system matches on and that would
    break if tokenized.

    `bytes_encoding` says how to read text held in `bytes`. UTF-8 by default
    because it refuses binary — a PNG raises and is left alone. Declare
    another where your payload uses one: `"cp1252"`, `"shift_jis"`. It is
    recorded on the vault, so restoring cannot use a different one. `None`
    scans no bytes at all. A byte-order mark overrides it, because a BOM is
    the payload declaring its own encoding rather than a guess.

    `max_depth` bounds the recursion. Past it this **raises** rather than
    returning what it has: the earlier behaviour returned the node unchanged,
    so a structure eighty levels deep had everything below sixty-four pass
    through in the clear, with an empty vault and a successful return. A
    structure that refers to itself raises too, and says so — the output
    otherwise held a reference to the original object with its real values.
    """
    token_format = anonymizer.token_format or TokenFormats.choose_format(
        TextSampler.sample(data)
    )
    vault = Vault(token_format=token_format, bytes_encoding=bytes_encoding)
    walker = Walker(
        anonymizer=anonymizer,
        vault=vault,
        include_keys=include_keys,
        stringify_numbers=stringify_numbers,
        skip_keys=skip_keys or frozenset(),
        max_depth=max_depth,
    )
    return walker.walk(data, depth=0), vault


def restore_data(data: Any, anonymizer: Anonymizer, vault: Vault) -> Any:
    """Put the original values back throughout a structure."""
    if not vault.values:
        return data
    return Restorer(anonymizer, vault).restore(data)
