"""Moving a vault between the process that made it and the one that uses it.

A vault is returned to the caller rather than held by the anonymizer, which
is what makes the common case need nothing at all:

    safe, vault = anonymizer.anonymize(question)   # a local variable
    reply = provider.complete(safe)
    answer = anonymizer.restore(reply, vault)      # the same local

Anonymizing and restoring in one request handler means the vault never leaves
it. Scale to any number of nodes and nothing crosses, because nothing is
shared. **No store is needed for that, and adding one makes it less private,
not more.**

A store is for when the vault has to outlive the request:

    a multi-turn conversation where the same person should keep one token
    anonymizing on one node and restoring on another
    a queue, where the worker is a different process

Two implementations and a port:

    MemoryVaultStore       one process. Right for a single node or a test.
    SerializedVaultStore   any key-value backend: Redis, Valkey, Memcached,
                           DynamoDB, a signed cookie.
    DatabaseVaultStore     any PEP 249 connection: PostgreSQL, MySQL, SQLite.
    KeyValueBackend        the ten lines you write for a cache, so none of
                           them become a dependency here.

Every store takes a cipher, with no default. See `maskvault.ciphers`: there
is no secure value to fall back to, because a key cannot be invented.

**What a store holds is the plaintext.** A vault maps tokens back to original
values, so storing one moves the exposure rather than removing it. Encrypt at
rest, keep the lifetime short, delete when the conversation ends, and never
key by something two callers can share.
"""

from __future__ import annotations

from maskvault.stores.backend import KeyValueBackend
from maskvault.stores.base import VaultStore
from maskvault.stores.database import DatabaseVaultStore
from maskvault.stores.memory import MemoryVaultStore
from maskvault.stores.serialized import SerializedVaultStore

__all__ = [
    "DatabaseVaultStore",
    "KeyValueBackend",
    "MemoryVaultStore",
    "SerializedVaultStore",
    "VaultStore",
]
