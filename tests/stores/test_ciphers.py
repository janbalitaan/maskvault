"""Encrypting a vault before it is stored.

Different from encrypting a value in memory, which this library declines to
do: there the key would sit beside the ciphertext, so it protects nothing.
Here the key stays in the application while the ciphertext goes to a shared
cache or a table, and those are different trust domains.

Two properties matter, and the second is easy to overlook. Secrecy stops a
store operator reading the vault. Authentication stops them *modifying* it —
a vault an attacker can edit is one whose tokens can be pointed at values of
their choosing, so the answer a reader sees becomes the one the attacker
wrote.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer
from maskvault.ciphers import FernetCipher, PlaintextCipher
from maskvault.exceptions import VaultError
from maskvault.stores import SerializedVaultStore

# Fernet needs the optional `encryption` extra. Without it the library still
# works — every store falls back to PlaintextCipher and FernetCipher raises a
# message naming the extra — so these tests skip rather than fail. A
# contributor running `uv sync && pytest` without the extras should see a
# working repository, not twenty-five red tests for a feature they did not
# install. CI installs `--all-extras`, so nothing here goes unexercised.
cryptography = pytest.importorskip(
    "cryptography", reason="the encryption extra is not installed"
)


@pytest.fixture
def key():
    return FernetCipher.generate_key()


class TestFernetCipher:
    def test_a_round_trip_returns_the_plaintext(self, key):
        cipher = FernetCipher(key)
        assert cipher.decrypt(cipher.encrypt(b"secret bytes")) == b"secret bytes"

    def test_the_ciphertext_does_not_contain_the_plaintext(self, key):
        encrypted = FernetCipher(key).encrypt(b"alice@acme.com")
        assert b"alice@acme.com" not in encrypted

    def test_two_encryptions_of_the_same_value_differ(self):
        """Fernet carries a random IV, so an observer cannot tell that two
        stored vaults hold the same values."""
        cipher = FernetCipher(FernetCipher.generate_key())
        assert cipher.encrypt(b"same") != cipher.encrypt(b"same")

    def test_a_different_key_cannot_decrypt(self):
        encrypted = FernetCipher(FernetCipher.generate_key()).encrypt(b"x")
        with pytest.raises(VaultError, match="could not be decrypted"):
            FernetCipher(FernetCipher.generate_key()).decrypt(encrypted)

    def test_tampering_is_detected(self, key):
        """The property that stops a store operator pointing a token at a
        value of their choosing."""
        cipher = FernetCipher(key)
        encrypted = bytearray(cipher.encrypt(b"alice@acme.com"))
        encrypted[-1] ^= 0x01
        with pytest.raises(VaultError, match="modified"):
            cipher.decrypt(bytes(encrypted))

    def test_a_string_key_is_accepted(self):
        """Keys arrive from an environment variable as text."""
        key = FernetCipher.generate_key().decode()
        cipher = FernetCipher(key)
        assert cipher.decrypt(cipher.encrypt(b"x")) == b"x"

    def test_a_nonsense_key_is_refused_at_construction(self):
        """Not at first use: a deployment with a bad key should fail at
        startup rather than when the first vault is stored."""
        with pytest.raises(VaultError, match="not a usable Fernet key"):
            FernetCipher(b"too short")

    def test_the_message_names_the_generator(self):
        with pytest.raises(VaultError) as caught:
            FernetCipher(b"nope")
        assert "generate_key" in str(caught.value)

    def test_it_describes_itself_without_the_key(self, key):
        described = FernetCipher(key).describes
        assert "fernet" in described
        assert key.decode() not in described


class TestFromEnvironment:
    def test_it_reads_the_documented_variable(self, monkeypatch, key):
        monkeypatch.setenv(FernetCipher.ENVIRONMENT_VARIABLE, key.decode())
        cipher = FernetCipher.from_env()
        assert cipher.decrypt(cipher.encrypt(b"x")) == b"x"

    def test_a_custom_variable_can_be_named(self, monkeypatch, key):
        monkeypatch.setenv("MY_KEY", key.decode())
        assert FernetCipher.from_env("MY_KEY") is not None

    def test_an_unset_variable_raises(self, monkeypatch):
        """Rather than falling back to plaintext. A deployment that forgot to
        inject the key should fail at startup, not store readable vaults
        until someone notices."""
        monkeypatch.delenv(FernetCipher.ENVIRONMENT_VARIABLE, raising=False)
        with pytest.raises(VaultError, match="is not set"):
            FernetCipher.from_env()

    def test_an_empty_variable_counts_as_unset(self, monkeypatch):
        monkeypatch.setenv(FernetCipher.ENVIRONMENT_VARIABLE, "   ")
        with pytest.raises(VaultError, match="is not set"):
            FernetCipher.from_env()

    def test_the_message_names_both_options(self, monkeypatch):
        monkeypatch.delenv(FernetCipher.ENVIRONMENT_VARIABLE, raising=False)
        with pytest.raises(VaultError) as caught:
            FernetCipher.from_env()
        message = str(caught.value)
        assert "generate_key" in message
        assert "PlaintextCipher" in message


class TestPlaintextCipher:
    def test_it_returns_the_bytes_unchanged(self):
        cipher = PlaintextCipher()
        assert cipher.encrypt(b"x") == b"x"
        assert cipher.decrypt(b"x") == b"x"

    def test_it_says_it_is_not_encrypted(self):
        """So a startup log makes the choice visible."""
        assert "not encrypted" in PlaintextCipher().describes


class TestEndToEnd:
    def test_an_encrypted_vault_round_trips_through_a_store(self, key):

        class DictBackend:
            def __init__(self):
                self.data = {}

            def get(self, k):
                return self.data.get(k)

            def set(self, k, v, ttl):
                self.data[k] = v

            def delete(self, k):
                self.data.pop(k, None)

        backend = DictBackend()
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")

        store = SerializedVaultStore(backend, FernetCipher(key))
        store.save("c1", vault)

        # What the backend operator can see.
        stored = next(iter(backend.data.values()))
        assert b"alice@acme.com" not in stored
        assert b"EMAIL" not in stored

        loaded = store.load("c1")
        assert anonymizer.restore(safe, loaded) == "email alice@acme.com"

    def test_the_store_describes_its_protection(self, key):

        class NullBackend:
            def get(self, k):
                return None

            def set(self, k, v, ttl):
                pass

            def delete(self, k):
                pass

        encrypted = SerializedVaultStore(NullBackend(), FernetCipher(key))
        plain = SerializedVaultStore(NullBackend(), PlaintextCipher())
        assert "fernet" in encrypted.describe()
        assert "not encrypted" in plain.describe()


class TestWhenTheExtraIsNotInstalled:
    """The encryption extra is optional, so the absent case has a path of its
    own — and it has to say what to install rather than fail obscurely.

    Simulated by clearing the module attribute, because the test environment
    has the extra installed and the branch is otherwise unreachable.
    """

    def test_building_a_cipher_says_what_to_install(self, monkeypatch):
        monkeypatch.setattr("maskvault.ciphers.fernet.Fernet", None)
        with pytest.raises(VaultError, match="maskvault\\[encryption\\]"):
            FernetCipher(b"anything")

    def test_it_also_names_the_opt_out(self, monkeypatch):
        """So a caller who does not want encryption is not stuck installing
        a dependency to find that out."""
        monkeypatch.setattr("maskvault.ciphers.fernet.Fernet", None)
        with pytest.raises(VaultError) as caught:
            FernetCipher(b"anything")
        assert "PlaintextCipher" in str(caught.value)

    def test_generating_a_key_says_what_to_install(self, monkeypatch):
        monkeypatch.setattr("maskvault.ciphers.fernet.Fernet", None)
        with pytest.raises(VaultError, match="maskvault\\[encryption\\]"):
            FernetCipher.generate_key()
