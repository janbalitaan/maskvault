"""Storing a vault without encrypting it."""

from __future__ import annotations


class PlaintextCipher:
    """Stores the vault as it is. Named so that choosing it is visible.

    This is the faster option and sometimes the right one — a store only the
    application can reach, a vault that never leaves the process, a test. But
    it has to be chosen rather than fallen into, because the thing being
    stored is every value the caller went to the trouble of anonymizing.

    `SerializedVaultStore` refuses to be built without a cipher for exactly
    that reason: the alternative is a default that looks like encryption to
    anyone who did not read the signature.
    """

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return the bytes unchanged."""
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return the bytes unchanged."""
        return ciphertext

    @property
    def describes(self) -> str:
        """Name this cipher, for logs and `describe()` output."""
        return "plaintext (not encrypted)"
