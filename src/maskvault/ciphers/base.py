"""What a vault cipher has to provide.

A stored vault holds every original value in plaintext, and it usually goes
somewhere with wider access than the application: Redis, a shared cache, a
table, a backup of any of those. The key stays in the application while the
ciphertext sits in that store, and those are different trust domains — which
is what makes encrypting here worth doing, unlike encrypting a value in
memory where the key would sit beside it.

A Protocol rather than a base class, so a cipher is anything with the right
shape — a KMS client, an HSM, a Vault transit backend, or the Fernet
implementation beside this file.

**The key cannot be defaulted.** A random key per process would mean the node
that restores cannot decrypt what the node that anonymized wrote, which is
the entire use case. So the key comes from the caller, and a store cannot
quietly fall back to plaintext: `SerializedVaultStore` refuses to be built
without a cipher, and `PlaintextCipher` is the name you have to type to opt
out.
"""

from __future__ import annotations

from typing import Protocol


class VaultCipher(Protocol):
    """Encrypts a serialized vault on the way out and back.

    Both methods take and return bytes, because that is what a store holds
    and what every cipher works on. Encoding happens once, in the store.
    """

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return the ciphertext for `plaintext`."""
        ...

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return the plaintext for `ciphertext`.

        Raises when the ciphertext was tampered with or the key is wrong.
        Authentication matters as much as secrecy here: a vault an attacker
        can modify is a vault whose tokens can be pointed at values of their
        choosing, which turns a reader's answer into one the attacker wrote.
        """
        ...

    @property
    def describes(self) -> str:
        """A short name for logs and `describe()` output, with no key in it."""
        ...
