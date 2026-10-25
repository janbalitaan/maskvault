"""Holding vaults in anything that stores bytes under a key."""

from __future__ import annotations

import json

from maskvault.ciphers.base import VaultCipher
from maskvault.constants import VAULT_TTL_SECONDS
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault
from maskvault.stores.backend import KeyValueBackend


class SerializedVaultStore:
    """Puts vaults in any key-value backend, as JSON.

    This is the adapter for the multi-node case: node 1 saves, node 2 loads,
    and the backend is whatever that deployment already runs. Redis, Valkey,
    Memcached, DynamoDB, a table with two columns — each needs about ten
    lines satisfying `KeyValueBackend`, and none of them become a dependency
    of this library.

        store = SerializedVaultStore(
            RedisBackend(redis_client), FernetCipher.from_env()
        )
        store.save(conversation_id, vault)       # on node 1
        vault = store.load(conversation_id)      # on node 2

    JSON rather than pickle, deliberately. A pickled payload is executable on
    load, so a backend an attacker can write becomes code execution in every
    process that reads it. JSON cannot do that, and it survives a version
    upgrade or a different language reading the same store.

    **A cipher is required, not defaulted.** What gets stored is every
    original value, so the store refuses to be built without one being chosen
    — `FernetCipher` to encrypt, or `PlaintextCipher` to say out loud that
    this backend is trusted. Keep the TTL short either way, and key by
    something two callers cannot share; `stores/base.py` has the reasoning.
    """

    # Prefixed so a vault is recognizable in a shared keyspace and cannot
    # collide with whatever else the backend holds.
    PREFIX = "maskvault:vault:"

    def __init__(
        self,
        backend: KeyValueBackend,
        cipher: VaultCipher,
        ttl_seconds: float = VAULT_TTL_SECONDS,
    ) -> None:
        """Wrap a backend, encrypting with `cipher` and expiring after the TTL.

        `cipher` is required, with no default. There is no secure value to
        default to — a key cannot be invented, because a random one per
        process would leave the node that restores unable to decrypt what the
        node that anonymized wrote. And defaulting to plaintext would mean a
        store that looks encrypted to anyone who did not read the signature,
        holding every value the caller went to the trouble of anonymizing.

        So the choice is at the call site:

            SerializedVaultStore(backend, FernetCipher.from_env())
            SerializedVaultStore(backend, PlaintextCipher())
        """
        self._backend = backend
        self._cipher = cipher
        self._ttl = ttl_seconds

    def save(self, key: str, vault: Vault) -> None:
        """Serialize a vault and store it under `key`."""
        serialized = json.dumps(vault.as_dict()).encode("utf-8")
        self._backend.set(self._key(key), self._cipher.encrypt(serialized), self._ttl)

    def load(self, key: str) -> Vault | None:
        """Return the vault under `key`, or None when there is none.

        A payload that will not parse raises rather than returning None: an
        unreadable vault is a wiring or corruption problem, and treating it as
        absent would hide that behind every token coming back unrestored.
        """
        raw = self._backend.get(self._key(key))
        if raw is None:
            return None
        # Decryption failures surface as themselves — a wrong key or a
        # modified store is a different event from a cache miss, and
        # reporting it as absence would hide tampering.
        serialized = self._cipher.decrypt(raw)
        try:
            return Vault.from_dict(json.loads(serialized.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VaultError(
                f"the stored vault under {key!r} is not readable JSON: {error}"
            ) from error

    def delete(self, key: str) -> None:
        """Forget the vault under `key`."""
        self._backend.delete(self._key(key))

    def __contains__(self, key: str) -> bool:
        """Whether a vault is stored under `key`."""
        return self._backend.get(self._key(key)) is not None

    def describe(self) -> str:
        """Summarize how this store protects what it holds, safe to log.

        Worth logging at startup: "plaintext" in a production log is the kind
        of thing someone notices, and a silent default never would be.
        """
        return f"vault store: {self._cipher.describes}, entries expire after {self._ttl:.0f}s"

    @classmethod
    def _key(cls, key: str) -> str:
        """Namespace a caller's key within the backend's keyspace."""
        return f"{cls.PREFIX}{key}"
