# Structured data

A string is the easy case. What a developer actually wants to pass somewhere
is usually a request body, a log record, a config dump or a database row —
nested dicts and lists with strings scattered through them. Flattening that
to text and back loses the structure, so this walks it instead.

```python
from maskvault import Anonymizer, anonymize_data, restore_data

anonymizer = Anonymizer()
safe, vault = anonymize_data(
    {"user": {"email": "alice@acme.com", "ip": "10.42.7.19"}, "retries": 3},
    anonymizer,
)
# {"user": {"email": "!|EMAIL_1|!", "ip": "!|IP_ADDRESS_1|!"}, "retries": 3}

restore_data(safe, anonymizer, vault) == original   # True
```

One vault covers the whole structure, so the same value appearing in two
places gets the same token and restoring puts both back.

## Three decisions worth knowing

**Keys are scanned, like values.** A key is usually schema — and a schema
key matches no detector, so `email`, `name` and `user_id` pass through
untouched. But `{"alice@acme.com": {...}}` is how a map of users by email
address looks, and `{"10.42.7.19": "primary"}` is how a host map looks. Those
keys *are* the data, and leaving them unexamined meant the structure most
likely to be keyed by an identifier was the one that leaked it.

```python
anonymize_data(data, anonymizer, include_keys=False)
```

turns it off, for a downstream system that matches on the literal key.
`skip_keys` is the narrower tool for the same job — it names the keys to
leave alone rather than all of them.

**Non-string leaves are left alone.** A number, boolean or `None` has no
delimiters to tokenize into, and coercing them to strings would change the
type of the data passing through.

```python
anonymize_data(data, anonymizer, stringify_numbers=True)
```

opts in, for the case where a bare integer is an account number. A number
that matches nothing keeps its type.

**Depth is capped** at 64 levels. A structure that references itself would
otherwise recurse forever, and the cap is cheaper than cycle detection at
every node. Past it, a node is returned untouched rather than raising —
`RecursionError` taking down the caller's request is the worse outcome.

## What is walked

| Type | Handled |
| --- | --- |
| `dict` and any `Mapping` | values and keys; `include_keys=False` for values only |
| `list`, `tuple`, any `Sequence` | each element, type preserved |
| `set`, `frozenset` | each element |
| `str` | anonymized |
| `int`, `float` | only with `stringify_numbers` |
| `bytes` | **left alone** |
| anything else | returned as it is |

`bytes` is a `Sequence`, and iterating one yields integers — walking it would
turn a blob into a list of numbers. It is skipped deliberately.

## Skipping a subtree

```python
anonymize_data(data, anonymizer, skip_keys=frozenset({"raw_payload", "trace"}))
```

For a field you know holds something large or already-sanitized, and would
rather not pay to walk.

## The format is chosen from the whole structure

Collision avoidance samples the structure, not one string — so a token's
delimiters are absent from every leaf, not just the first:

```python
safe, vault = anonymize_data({"note": "see !|EXISTING|!", "email": "a@b.com"}, anonymizer)
vault.token_format.name   # "pipe_brackets", since the default was taken
```

Sampling is bounded, because walking a large structure in full would cost
more than the choice is worth. See [token formats](token-formats.md).

## Accumulating across calls

```python
vault = Vault()
for turn in conversation:
    safe = anonymizer.anonymize_into(turn, vault)
```

One vault across many strings — a conversation turn by turn, or a structure
you walk yourself. A value appearing in two of them keeps one token, so
whatever reads the result can still tell the mentions refer to one thing.

This is safe to do from concurrent callers; see [concurrency](concurrency.md).
