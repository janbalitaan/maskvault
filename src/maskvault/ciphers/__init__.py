"""Encrypting a vault before it is stored.

A stored vault holds every original value, and it usually goes somewhere with
wider access than the application. The key stays in the application while the
ciphertext sits in the store, which makes these different trust domains — and
is why encrypting here is worth doing, unlike encrypting a value in memory
where the key would sit beside it.

    VaultCipher       the port. A KMS, an HSM, a transit backend — yours.
    FernetCipher      authenticated encryption, via the `encryption` extra.
    PlaintextCipher   the explicit opt-out, named so that choosing it shows.

A store cannot be built without one of these. There is no secure default to
fall back to, because a key cannot be defaulted: a random key per process
would leave the node that restores unable to decrypt what the node that
anonymized wrote.
"""

from __future__ import annotations

from maskvault.ciphers.base import VaultCipher
from maskvault.ciphers.fernet import FernetCipher
from maskvault.ciphers.plaintext import PlaintextCipher

__all__ = ["FernetCipher", "PlaintextCipher", "VaultCipher"]
