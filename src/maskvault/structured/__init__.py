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
    include_keys: bool = False,
    stringify_numbers: bool = False,
    skip_keys: frozenset[str] | None = None,
) -> tuple[Any, Vault]:
    """Walk a structure, replacing sensitive values, and return it with a vault.

    `skip_keys` names keys whose values pass through untouched — useful for
    an id or a timestamp that a downstream system matches on and that would
    break if tokenized.
    """
    token_format = anonymizer.token_format or TokenFormats.choose_format(
        TextSampler.sample(data)
    )
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
    return Restorer(anonymizer, vault).restore(data)
