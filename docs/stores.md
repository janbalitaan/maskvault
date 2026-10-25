# Stores

## The common case needs no store

A vault is returned to you rather than held by the anonymizer, which is what
makes the ordinary shape need nothing at all:

```python
def answer(question: str) -> str:
    safe, vault = anonymizer.anonymize(question)   # a local variable
    reply = provider.complete(safe)
    return anonymizer.restore(reply, vault)        # the same local
```

Anonymize, call the provider and restore in one request handler, and the
vault never leaves it. Scale that to any number of nodes and nothing crosses,
because nothing is shared.

**Adding a store here makes it less private, not more.** A stored vault is
plaintext somewhere it was not before.

## When you do need one

- a multi-turn conversation where one person should keep one token
- anonymizing on one node and restoring on another
- a queue, where the worker is a different process

```python
from maskvault.ciphers import FernetCipher
from maskvault.stores import (
    DatabaseVaultStore,
    MemoryVaultStore,
    SerializedVaultStore,
)

MemoryVaultStore()                                       # one process
SerializedVaultStore(backend, FernetCipher.from_env())    # Redis, Valkey, ...
DatabaseVaultStore(connection, FernetCipher.from_env())   # PostgreSQL, MySQL
```

All three take the same four methods: `save`, `load`, `delete`, `in`.

## What happens without the vault

Worth knowing, because the two outcomes are not equally bad.

**Node 2 has no vault.** The token stays visible. Wrong, but obviously
wrong, and `leaked()` reports it:

```python
anonymizer.leaked(reply, Vault())   # ['!|EMAIL_1|!']
```

**Node 2 has its own unrelated vault.** Both vaults independently minted the
identical string, so node 1's token is found in node 2's vault and resolves
to *someone else's value*. A wrong answer rather than a missing one, and
`leaked()` sees nothing because the token really is there.

`Vault.scoped()` makes the second impossible — a random marker in every
label, so two vaults cannot mint the same token:

```python
vault = Vault.scoped()      # tokens look like !|EMAIL_GUTK_1|!
```

Off by default, because a longer token is one a model is more likely to
reformat. Worth it when restoring happens in a different process.

## A key-value backend is about ten lines

Which is why none of them is a dependency here:

```python
class RedisBackend:
    def __init__(self, client):
        self._client = client

    def get(self, key):
        return self._client.get(key)

    def set(self, key, value, ttl_seconds):
        self._client.set(key, value, ex=int(ttl_seconds))

    def delete(self, key):
        self._client.delete(key)
```

Memcached, DynamoDB and a two-column table are the same shape. Bytes rather
than `str`, because that is what these stores natively hold — handing them a
`str` means guessing an encoding somewhere, and the guess stays invisible
until a non-ASCII value arrives.

## A database is different in two ways

```python
store = DatabaseVaultStore(connection, cipher, paramstyle="format")
store.create_table()      # once, at deploy
```

**No native expiry.** The lifetime is a column, filtered on every read and
reclaimed by `purge()` — which something has to call: a cron, a startup hook,
a periodic task. An unswept table of vaults is a growing pile of plaintext,
and that is the one failure a database store has which a cache does not.

**`paramstyle` is explicit.** `"qmark"` for sqlite3 and oracledb, `"format"`
for psycopg and the MySQL drivers — the PEP 249 names. Not detected
automatically, because `paramstyle` is a module attribute rather than a
connection one, and guessing from a class name breaks on a wrapper or a pool.

A table name cannot be a bound parameter, so it is interpolated — and
validated against `^[A-Za-z_][A-Za-z0-9_]*$` rather than trusted. Every
*value* is bound.

## The lifetime is yours

Entries expire after fifteen minutes unless you say otherwise, because a
vault's lifetime is the window in which its values are exposed.

```python
DatabaseVaultStore(connection, cipher, ttl_seconds=0)     # no expiry
DatabaseVaultStore(connection, cipher, ttl_seconds=3600)  # an hour
```

**Zero means no expiry**, handing retention to you. That is the point of
using a database rather than a cache: retention there is already somebody's
job — a nightly job, a partition drop, a policy the DBA owns — and a library
second-guessing it is a library fighting the deployment.

A negative value raises rather than being read as zero. A TTL is usually
computed, and one that came out negative is a bug worth hearing about, not a
silent switch to keeping plaintext forever.

## Keys are yours to choose, and the choice matters

A key shared between two unrelated requests hands one caller's values to
another. A conversation id or a request id is right; a user id usually is
not, because one user has more than one conversation.

```python
SerializedVaultStore(backend, cipher, prefix="acme:masked:")
```

The prefix namespaces vaults within a shared keyspace. Overridable, because
a deployment with its own convention should not have to fight this one.

## Logging what you chose

```python
store.describe()
# "vault store: fernet (AES-128-CBC with an HMAC-SHA256 tag), entries expire after 900s"
# "vault store: plaintext (not encrypted), entries do not expire; retention is yours to manage"
```

Worth logging at startup. "plaintext" in a production log is the kind of
thing someone notices.

## Serializing a vault yourself

If you would rather not use a store at all:

```python
payload = json.dumps(vault.as_dict())      # to a response, a queue, a cookie
vault = Vault.from_dict(json.loads(payload))
```

Lossless — the values, the destroyed labels, the scope and the format's own
patterns. A payload with no `values` raises rather than loading as an empty
vault, because an empty one restores nothing and looks identical to a vault
whose values were all absent.

JSON rather than pickle. A pickled payload is executable on load, so a store
an attacker can write becomes code execution in every process that reads it.
