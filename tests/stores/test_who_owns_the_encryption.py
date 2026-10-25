"""Who does what, when a stored vault is encrypted.

maskvault performs the encryption and implements none of it. It calls into
`cryptography`'s Fernet — an audited implementation — and never writes a
primitive of its own. The key is the caller's throughout: where it lives, how
it rotates, and whether it ever reaches this process at all.

A caller who wants to own the whole thing implements `VaultCipher`. A KMS, an
HSM, a Vault transit backend, or encryption done at the backend layer are all
reachable that way, and none of them require importing anything from here.
"""

from __future__ import annotations

import ast
import inspect
import json
import pathlib
import textwrap

import pytest

import maskvault
from maskvault import Anonymizer
from maskvault.ciphers import FernetCipher, PlaintextCipher, fernet
from maskvault.stores import SerializedVaultStore


class DictBackend:
    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        self.data[key] = value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)


class TestMaskvaultImplementsNoCryptography:
    def test_the_cipher_only_delegates(self):
        """The whole implementation is a call into `cryptography`. If that
        stops being true, this library has taken on a responsibility it
        should not have."""
        source = inspect.getsource(fernet.FernetCipher.encrypt)
        assert "self._fernet.encrypt" in source

    def test_nothing_in_the_package_rolls_its_own(self):
        """A crude check, but the failure it guards against is someone
        implementing a cipher here rather than calling one."""
        root = pathlib.Path(maskvault.__file__).parent
        suspicious = ("S-box", "sbox", "feistel", "def _xor", "rotate_left")
        for path in root.rglob("*.py"):
            text = path.read_text()
            for marker in suspicious:
                assert marker not in text, f"{path.name} contains {marker!r}"


class TestTheKeyNeverLeaks:
    """Nine surfaces maskvault writes to, none of which may carry the key."""

    @pytest.fixture
    def key(self):
        return FernetCipher.generate_key()

    def test_not_in_the_ciphers_repr(self, key):
        """Explicit rather than relying on the default. Adding `@dataclass`
        later would otherwise start printing the key in every traceback."""
        assert key.decode() not in repr(FernetCipher(key))

    def test_not_in_describes(self, key):
        assert key.decode() not in FernetCipher(key).describes

    def test_not_in_the_stores_describe(self, key):
        store = SerializedVaultStore(DictBackend(), FernetCipher(key))
        assert key.decode() not in store.describe()

    def test_not_in_the_stores_repr(self, key):
        store = SerializedVaultStore(DictBackend(), FernetCipher(key))
        assert key.decode() not in repr(store)

    def test_not_in_the_vault(self, key):
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        SerializedVaultStore(DictBackend(), FernetCipher(key)).save("c1", vault)
        assert key.decode() not in json.dumps(vault.as_dict())
        assert key.decode() not in repr(vault)
        assert key.decode() not in vault.summary()

    def test_not_in_the_stored_bytes(self, key):
        """The one place an operator of the backend can actually look."""
        backend = DictBackend()
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        SerializedVaultStore(backend, FernetCipher(key)).save("c1", vault)
        assert key not in next(iter(backend.data.values()))

    def test_not_in_the_anonymized_text(self, key):
        anonymizer = Anonymizer()
        safe, _ = anonymizer.anonymize("email alice@acme.com")
        assert key.decode() not in safe

    def test_the_repr_still_says_which_cipher(self, key):
        """Safe is not the same as useless: a log line should identify the
        cipher so "plaintext" in production is noticeable."""
        assert "fernet" in repr(FernetCipher(key))
        assert "not encrypted" in repr(PlaintextCipher())


class KmsCipher:
    """A cipher where the key never reaches this process.

    Written here as a test fixture *and* as the documented shape: it
    satisfies the protocol without importing anything from maskvault, which
    is the property that makes the port worth having.
    """

    def __init__(self, client, key_id: str) -> None:
        self._client = client
        self._key_id = key_id

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._client.encrypt(self._key_id, plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._client.decrypt(ciphertext)

    @property
    def describes(self) -> str:
        return f"external kms, key {self._key_id}"


class FakeKmsClient:
    """Stands in for boto3 or an HSM. Not a cipher — just reversible."""

    def __init__(self) -> None:
        self.calls: list[str] = []

    def encrypt(self, key_id: str, plaintext: bytes) -> bytes:
        self.calls.append("encrypt")
        return b"ext:" + plaintext[::-1]

    def decrypt(self, ciphertext: bytes) -> bytes:
        self.calls.append("decrypt")
        return ciphertext[4:][::-1]


class TestACallerCanOwnItEntirely:
    def test_a_foreign_cipher_works(self):
        client = FakeKmsClient()
        backend = DictBackend()
        store = SerializedVaultStore(backend, KmsCipher(client, "alias/vaults"))

        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", vault)
        assert anonymizer.restore(safe, store.load("c1")) == "email alice@acme.com"

    def test_the_cipher_is_actually_used(self):
        """Not silently bypassed: both directions go through it."""
        client = FakeKmsClient()
        store = SerializedVaultStore(DictBackend(), KmsCipher(client, "k"))
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", vault)
        store.load("c1")
        assert client.calls == ["encrypt", "decrypt"]

    def test_the_value_is_not_in_the_backend(self):
        client = FakeKmsClient()
        backend = DictBackend()
        store = SerializedVaultStore(backend, KmsCipher(client, "k"))
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", vault)
        assert b"alice@acme.com" not in next(iter(backend.data.values()))

    def test_it_describes_itself_in_the_store(self):
        store = SerializedVaultStore(DictBackend(), KmsCipher(FakeKmsClient(), "alias/prod"))
        assert "external kms" in store.describe()
        assert "alias/prod" in store.describe()

    def test_no_maskvault_import_is_needed(self):
        """The property that makes a Protocol worth having over a base class.

        Checked by parsing for an import rather than searching for the word,
        which the class's own docstring contains.
        """
        tree = ast.parse(textwrap.dedent(inspect.getsource(KmsCipher)))
        imported = [
            node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))
        ]
        assert imported == []
