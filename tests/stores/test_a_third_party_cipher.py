"""A cipher the library has never heard of has to work.

`VaultCipher` is a Protocol, which means a custom cipher needs no base class
and no registration. That is only true as long as nothing on the path does an
`isinstance` check against the shipped types — so the contract is tested with
a cipher that deliberately inherits nothing, rather than assumed from the
type annotation.

The backend is hand-written too, for the same reason: `KeyValueBackend` is a
Protocol, and a developer swapping in Redis should not discover that one half
was open and the other closed.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from maskvault import Anonymizer
from maskvault.stores import SerializedVaultStore


class HmacStreamCipher:
    """Standard library only, inheriting nothing from maskvault."""

    TAG_BYTES = 32

    def __init__(self, key: bytes) -> None:
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        body = self._mask(plaintext)
        return self._tag(body) + body

    def decrypt(self, ciphertext: bytes) -> bytes:
        tag, body = ciphertext[: self.TAG_BYTES], ciphertext[self.TAG_BYTES :]
        if not hmac.compare_digest(tag, self._tag(body)):
            raise ValueError("the stored vault failed authentication")
        return self._mask(body)

    @property
    def describes(self) -> str:
        return "hmac-stream (test)"

    def _tag(self, body: bytes) -> bytes:
        return hmac.new(self._key, body, hashlib.sha256).digest()

    def _mask(self, data: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(data, self._keystream(len(data)), strict=True))

    def _keystream(self, length: int) -> bytes:
        blocks, counter = [], 0
        while sum(len(block) for block in blocks) < length:
            blocks.append(hashlib.sha256(self._key + counter.to_bytes(4, "big")).digest())
            counter += 1
        return b"".join(blocks)[:length]


class DictBackend:
    """A key-value backend written from scratch, standing in for Redis."""

    def __init__(self) -> None:
        self.rows: dict[str, bytes] = {}
        self.ttls: dict[str, float] = {}

    def only_row(self) -> tuple[str, bytes]:
        """The single stored row, whatever the store prefixed its key with.

        The prefix is the store's business, and a test that hard-coded it
        would fail the day it changed for a reason that has nothing to do
        with what is being checked here.
        """
        assert len(self.rows) == 1, f"expected one row, got {sorted(self.rows)}"
        return next(iter(self.rows.items()))

    def get(self, key: str) -> bytes | None:
        return self.rows.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        self.rows[key] = value
        self.ttls[key] = ttl_seconds

    def delete(self, key: str) -> None:
        self.rows.pop(key, None)


TEXT = "Email jan@acme.com about invoice 8841."
KEY = b"a key from your own KMS"


@pytest.fixture
def store_and_backend() -> tuple[SerializedVaultStore, DictBackend]:
    backend = DictBackend()
    return SerializedVaultStore(backend, cipher=HmacStreamCipher(KEY)), backend


class TestACustomCipherIsAccepted:
    def test_the_store_can_be_built_with_it(self, store_and_backend):
        store, _ = store_and_backend
        assert store is not None

    def test_describe_names_the_custom_cipher(self, store_and_backend):
        """So a log line says which cipher is in force, not just "a cipher"."""
        store, _ = store_and_backend
        assert "hmac-stream (test)" in store.describe()

    def test_describe_contains_no_key_material(self, store_and_backend):
        store, _ = store_and_backend
        assert KEY.decode() not in store.describe()


class TestTheRoundTripHolds:
    def test_a_vault_survives_save_and_load(self, store_and_backend):
        store, _ = store_and_backend
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize(TEXT)
        store.save("session", vault)
        assert anonymizer.restore(safe, store.load("session")) == TEXT

    def test_the_stored_bytes_do_not_contain_the_value(self, store_and_backend):
        """The whole point: the store operator cannot read the vault."""
        store, backend = store_and_backend
        _, vault = Anonymizer().anonymize(TEXT)
        store.save("session", vault)
        _, stored = backend.only_row()
        assert b"jan@acme.com" not in stored

    def test_the_ttl_reaches_the_backend(self, store_and_backend):
        """A custom backend has to receive the expiry, or vaults never die."""
        store, backend = store_and_backend
        _, vault = Anonymizer().anonymize(TEXT)
        store.save("session", vault)
        key, _ = backend.only_row()
        assert backend.ttls[key] > 0


class TestAuthenticationIsRespected:
    def test_a_wrong_key_is_refused(self, store_and_backend):
        store, backend = store_and_backend
        _, vault = Anonymizer().anonymize(TEXT)
        store.save("session", vault)
        other = SerializedVaultStore(backend, cipher=HmacStreamCipher(b"different"))
        with pytest.raises(ValueError, match="failed authentication"):
            other.load("session")

    def test_tampering_is_refused(self, store_and_backend):
        """A vault an attacker can edit is one whose tokens can be pointed at
        values of their choosing."""
        store, backend = store_and_backend
        _, vault = Anonymizer().anonymize(TEXT)
        store.save("session", vault)
        key, stored = backend.only_row()
        row = bytearray(stored)
        row[-1] ^= 0xFF
        backend.rows[key] = bytes(row)
        with pytest.raises(ValueError):
            store.load("session")

    def test_the_cipher_error_is_not_swallowed(self, store_and_backend):
        """It propagates rather than becoming a None that looks like a miss.
        A silent miss would read as "no vault for this session" and the caller
        would carry on with tokens it cannot resolve."""
        store, backend = store_and_backend
        _, vault = Anonymizer().anonymize(TEXT)
        store.save("session", vault)
        key, _ = backend.only_row()
        backend.rows[key] = b"\x00" * 64
        with pytest.raises(ValueError):
            store.load("session")


class TestAMissingVaultIsStillAMiss:
    def test_an_absent_key_returns_none(self, store_and_backend):
        """Distinct from a decryption failure, which raises."""
        store, _ = store_and_backend
        assert store.load("never-saved") is None
