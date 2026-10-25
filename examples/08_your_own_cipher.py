"""Encrypting a stored vault with your own algorithm.

`VaultCipher` is a Protocol, so a cipher is anything with `encrypt`,
`decrypt` and `describes`. Nothing to inherit, nothing to register — which
means a KMS client, an HSM, a Vault transit backend or an algorithm your
organization is required to use all drop in the same way.

The same is true of the storage: `KeyValueBackend` is a Protocol too, so the
cipher below is paired with a hand-written backend to show that neither half
needs anything from this library.

    python examples/08_your_own_cipher.py
"""

import hashlib
import hmac

from maskvault import Anonymizer
from maskvault.stores import SerializedVaultStore


class HmacStreamCipher:
    """A stream cipher with an HMAC tag, built from the standard library.

    Illustrative, not a recommendation: use `FernetCipher` or your platform's
    KMS for real work. What it shows is the shape — and in particular that
    **authentication is part of the job**. A vault an attacker can modify is
    a vault whose tokens can be pointed at values of their choosing, so the
    answer your reader sees becomes the one the attacker wrote. Encrypting
    without a tag would leave that open.
    """

    TAG_BYTES = 32
    MIN_KEY_BYTES = 16

    def __init__(self, key: bytes) -> None:
        if len(key) < self.MIN_KEY_BYTES:
            raise ValueError(
                f"a key shorter than {self.MIN_KEY_BYTES} bytes is not worth having"
            )
        self._key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return the tag followed by the keystream-masked plaintext."""
        body = self._mask(plaintext)
        return self._tag(body) + body

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return the plaintext, refusing anything that fails its tag."""
        tag, body = ciphertext[: self.TAG_BYTES], ciphertext[self.TAG_BYTES :]
        # compare_digest rather than ==, so the comparison does not leak
        # where the two differ through how long it took.
        if not hmac.compare_digest(tag, self._tag(body)):
            raise ValueError("the stored vault failed authentication")
        return self._mask(body)

    @property
    def describes(self) -> str:
        """A name for logs, with no key material in it."""
        return "hmac-stream (example)"

    def _tag(self, body: bytes) -> bytes:
        return hmac.new(self._key, body, hashlib.sha256).digest()

    def _mask(self, data: bytes) -> bytes:
        """XOR against a keystream. Symmetric, so this both ways."""
        return bytes(a ^ b for a, b in zip(data, self._keystream(len(data)), strict=True))

    def _keystream(self, length: int) -> bytes:
        blocks, counter = [], 0
        while sum(len(block) for block in blocks) < length:
            blocks.append(hashlib.sha256(self._key + counter.to_bytes(4, "big")).digest())
            counter += 1
        return b"".join(blocks)[:length]


class DictBackend:
    """Stands in for Redis, Valkey or Memcached in one screen.

    The real thing is the same three methods over a client.
    """

    def __init__(self) -> None:
        self.rows: dict[str, bytes] = {}
        self.ttls: dict[str, float] = {}

    def get(self, key: str) -> bytes | None:
        return self.rows.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        self.rows[key] = value
        # A real backend hands this to the client — SETEX, EXPIRE, or the
        # exptime argument. Zero means no expiry, so the caller keeps control
        # of retention rather than inheriting a default they cannot see.
        self.ttls[key] = ttl_seconds

    def delete(self, key: str) -> None:
        self.rows.pop(key, None)


text = "Email jan@acme.com or call +63 917 555 1234 about invoice 8841."
anonymizer = Anonymizer()
safe, vault = anonymizer.anonymize(text)

backend = DictBackend()
store = SerializedVaultStore(backend, cipher=HmacStreamCipher(b"a key from your own KMS"))
store.save("session-1", vault)

print(f"policy:   {store.describe()}")
print(f"sent:     {safe}")

stored = next(iter(backend.rows.values()))
print(f"\nstored:   {len(stored)} bytes, beginning {stored[:12].hex()}")
print(f"          the email is absent from it: {b'jan@acme.com' not in stored}")

restored = anonymizer.restore(safe, store.load("session-1"))
print(f"\nrestored: {restored}")
print(f"          exact: {restored == text}")

print("\nthe wrong key is refused rather than returning rubbish:")
wrong = SerializedVaultStore(backend, cipher=HmacStreamCipher(b"a different key!!"))
try:
    wrong.load("session-1")
except ValueError as error:
    print(f"          ValueError: {error}")
