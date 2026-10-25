"""Encrypting a stored vault with Fernet."""

from __future__ import annotations

import os

from maskvault.exceptions import VaultError

# An optional extra. Imported at module level and set to None when absent, so
# every import in this file is at the top and the absence is still handled
# with a message that says what to install.
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:  # pragma: no cover - depends on the install
    Fernet = None
    InvalidToken = Exception


class FernetCipher:
    """Authenticated encryption for a stored vault, via `cryptography`.

    Fernet rather than a hand-rolled construction, because this library has
    no business implementing a cipher. It is AES-128-CBC with an HMAC-SHA256
    tag and a timestamp, which gives the two properties that matter:
    a store operator cannot read the vault, and cannot modify it undetected.

    The second is easy to overlook. A vault an attacker can edit is one whose
    tokens can be pointed at values of their choosing — so the answer a
    reader sees becomes the answer the attacker wrote. Secrecy alone would
    not prevent that.

        key = FernetCipher.generate_key()      # once, at deployment
        cipher = FernetCipher(key)             # in every node

    Or from the environment, which is where a key injected by a platform
    already lives:

        cipher = FernetCipher.from_env()

    Needs the encryption extra: `pip install 'maskvault[encryption]'`.
    """

    # Where `from_env` looks. Named rather than inlined so a deployment can
    # grep for it.
    ENVIRONMENT_VARIABLE = "MASKVAULT_VAULT_KEY"

    def __init__(self, key: bytes | str) -> None:
        """Build a cipher from a Fernet key.

        The same key has to reach every node that restores. A key generated
        per process would mean the node that anonymized is the only one able
        to decrypt, which is the case a store exists to avoid.
        """
        if Fernet is None:
            raise VaultError(
                "encrypting a stored vault needs the encryption extra: "
                "pip install 'maskvault[encryption]'. To store without "
                "encryption, pass cipher=PlaintextCipher() deliberately."
            )
        try:
            self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())
        except (ValueError, TypeError) as error:
            raise VaultError(
                f"not a usable Fernet key: {error}. Generate one with "
                "FernetCipher.generate_key()."
            ) from error

    @staticmethod
    def generate_key() -> bytes:
        """Return a new key, to be stored wherever this deployment keeps secrets.

        Run once and kept, not called per process: every node that restores
        needs the same key.
        """
        if Fernet is None:
            raise VaultError(
                "generating a key needs the encryption extra: "
                "pip install 'maskvault[encryption]'"
            )
        return Fernet.generate_key()

    @classmethod
    def from_env(cls, variable: str | None = None) -> FernetCipher:
        """Build a cipher from a key in the environment.

        Raises when the variable is unset rather than falling back to
        plaintext. A deployment that forgot to inject the key should fail at
        startup, not store readable vaults until someone notices.
        """
        name = variable or cls.ENVIRONMENT_VARIABLE
        key = os.environ.get(name, "").strip()
        if not key:
            raise VaultError(
                f"{name} is not set. Generate a key with "
                "FernetCipher.generate_key() and inject it, or pass "
                "cipher=PlaintextCipher() to store without encryption."
            )
        return cls(key)

    def __repr__(self) -> str:
        """Describe this cipher without its key.

        Explicit rather than relying on the default, which happens to be safe
        only because this is a plain class. Adding `@dataclass` or a
        `__dict__`-printing repr later would start putting the key into every
        traceback, log line and pytest failure — and the default being safe
        today is luck, not a guarantee.
        """
        return f"FernetCipher({self.describes})"

    def encrypt(self, plaintext: bytes) -> bytes:
        """Return the ciphertext for `plaintext`."""
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Return the plaintext, or raise when it was tampered with.

        A failure here is reported as a failure rather than as an absent
        vault, because the two mean different things: absent is a cache miss,
        and undecryptable is a wrong key or a modified store.
        """
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as error:
            raise VaultError(
                "the stored vault could not be decrypted: the key is wrong, "
                "or the stored bytes were modified"
            ) from error

    @property
    def describes(self) -> str:
        """Name this cipher, for logs and `describe()` output."""
        return "fernet (AES-128-CBC with an HMAC-SHA256 tag)"
