"""The two stores, and the port that keeps a backend out of this library.

A store exists for one thing: the vault outliving the request that made it.
Both implementations are tested against the same behaviour, because a caller
who swaps one for the other should not have to re-read their own code.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer
from maskvault.ciphers import PlaintextCipher
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault
from maskvault.stores import MemoryVaultStore, SerializedVaultStore


class DictBackend:
    """A backend satisfying KeyValueBackend, as a Redis adapter would.

    Written out rather than mocked, because the point of the port is that it
    takes about ten lines — and a test that proves it is a better argument
    than a paragraph saying so.
    """

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}
        self.ttls: dict[str, float] = {}

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        self.data[key] = value
        self.ttls[key] = ttl_seconds

    def delete(self, key: str) -> None:
        self.data.pop(key, None)
        self.ttls.pop(key, None)


@pytest.fixture(params=["memory", "serialized"])
def store(request):
    """Both stores, so the shared behaviour is tested once."""
    if request.param == "memory":
        return MemoryVaultStore()
    return SerializedVaultStore(DictBackend(), PlaintextCipher())


@pytest.fixture
def vault():
    anonymizer = Anonymizer()
    _, built = anonymizer.anonymize("email alice@acme.com and ip 10.42.7.19")
    return built


class TestBothStores:
    def test_a_saved_vault_comes_back(self, store, vault):
        store.save("conversation-1", vault)
        assert store.load("conversation-1") == vault

    def test_a_missing_key_returns_none(self, store):
        """None rather than an empty vault: an empty one restores nothing and
        looks identical to a vault whose values were all absent."""
        assert store.load("never-saved") is None

    def test_a_restore_works_from_a_loaded_vault(self, store):
        anonymizer = Anonymizer()
        safe, built = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", built)
        loaded = store.load("c1")
        assert anonymizer.restore(safe, loaded) == "email alice@acme.com"

    def test_saving_twice_replaces(self, store, vault):
        store.save("c1", vault)
        anonymizer = Anonymizer()
        _, other = anonymizer.anonymize("email bob@other.com")
        store.save("c1", other)
        assert store.load("c1") == other

    def test_delete_forgets_it(self, store, vault):
        """Worth calling when a conversation ends: a stored vault holds
        plaintext, so its lifetime is the exposure window."""
        store.save("c1", vault)
        store.delete("c1")
        assert store.load("c1") is None

    def test_deleting_something_absent_is_fine(self, store):
        store.delete("never-saved")

    def test_contains_reports_presence(self, store, vault):
        assert "c1" not in store
        store.save("c1", vault)
        assert "c1" in store

    def test_two_keys_do_not_see_each_other(self, store):
        """The failure a shared key would cause: one caller's values handed
        to another."""
        anonymizer = Anonymizer()
        _, alice = anonymizer.anonymize("email alice@acme.com")
        _, bob = anonymizer.anonymize("email bob@other.com")
        store.save("alice", alice)
        store.save("bob", bob)
        assert "alice@acme.com" in str(store.load("alice").snapshot())
        assert "alice@acme.com" not in str(store.load("bob").snapshot())

    def test_a_scoped_vault_survives(self, store):
        anonymizer = Anonymizer()
        scoped = Vault.scoped()
        safe = anonymizer.anonymize_into("email carol@acme.com", scoped)
        store.save("c1", scoped)
        loaded = store.load("c1")
        assert loaded.scope == scoped.scope
        assert anonymizer.restore(safe, loaded) == "email carol@acme.com"


class TestMemoryStoreSpecifics:
    def test_an_expired_entry_is_gone(self):
        store = MemoryVaultStore(ttl_seconds=0)
        store.save("c1", Vault())
        assert store.load("c1") is None

    def test_a_live_entry_is_not(self):
        store = MemoryVaultStore(ttl_seconds=60)
        store.save("c1", Vault())
        assert store.load("c1") is not None

    def test_expiry_also_reclaims_the_memory(self):
        """Not just hiding the entry: a vault holds plaintext, so leaving it
        in the dict leaves the values in memory."""
        store = MemoryVaultStore(ttl_seconds=0)
        store.save("c1", Vault())
        store.load("c1")
        assert len(store) == 0

    def test_purge_reclaims_entries_nobody_asked_for(self):
        """Expiry is checked on access, so an entry never loaded again would
        otherwise sit there for the life of the process."""
        store = MemoryVaultStore(ttl_seconds=0)
        for index in range(5):
            store.save(f"c{index}", Vault())
        assert len(store) == 5
        assert store.purge() == 5
        assert len(store) == 0

    def test_purge_keeps_live_entries(self):
        store = MemoryVaultStore(ttl_seconds=60)
        store.save("c1", Vault())
        assert store.purge() == 0
        assert len(store) == 1

    def test_clear_forgets_everything(self):
        store = MemoryVaultStore()
        store.save("c1", Vault())
        store.clear()
        assert len(store) == 0


class TestSerializedStoreSpecifics:
    def test_it_stores_json_not_pickle(self):
        """A pickled payload executes on load, so a backend an attacker can
        write would be code execution in every process that reads it."""
        backend = DictBackend()
        store = SerializedVaultStore(backend, PlaintextCipher())
        store.save("c1", Vault(values={"!|EMAIL_1|!": "me@acme.com"}))
        raw = next(iter(backend.data.values()))
        assert raw.startswith(b"{")
        assert b"me@acme.com" in raw

    def test_it_passes_the_ttl_to_the_backend(self):
        """The expiry is not optional: an entry that never expires is an
        exposure with no end."""
        backend = DictBackend()
        SerializedVaultStore(backend, PlaintextCipher(), ttl_seconds=42).save("c1", Vault())
        assert set(backend.ttls.values()) == {42}

    def test_keys_are_namespaced(self):
        """So a vault is recognizable in a shared keyspace and cannot collide
        with whatever else the backend holds."""
        backend = DictBackend()
        SerializedVaultStore(backend, PlaintextCipher()).save("c1", Vault())
        assert all(key.startswith("maskvault:vault:") for key in backend.data)

    def test_an_unreadable_payload_raises(self):
        """Rather than returning None: corruption is a different event from
        absence, and treating it as absence hides it behind every token
        coming back unrestored."""
        backend = DictBackend()
        store = SerializedVaultStore(backend, PlaintextCipher())
        backend.set("maskvault:vault:c1", b"{not json", 60)
        with pytest.raises(VaultError, match="not readable JSON"):
            store.load("c1")

    def test_a_payload_that_is_not_a_vault_raises(self):
        backend = DictBackend()
        store = SerializedVaultStore(backend, PlaintextCipher())
        backend.set("maskvault:vault:c1", b'{"something": "else"}', 60)
        with pytest.raises(VaultError, match="not a vault"):
            store.load("c1")

    def test_non_utf8_bytes_raise(self):
        backend = DictBackend()
        store = SerializedVaultStore(backend, PlaintextCipher())
        backend.set("maskvault:vault:c1", b"\xff\xfe", 60)
        with pytest.raises(VaultError, match="not readable JSON"):
            store.load("c1")


class TestTheTwoNodeHandover:
    def test_node_one_saves_and_node_two_restores(self):
        """The scenario the stores exist for, end to end."""
        backend = DictBackend()  # stands in for Redis, shared by both nodes

        node1 = Anonymizer()
        store1 = SerializedVaultStore(backend, PlaintextCipher())
        _, vault = node1.anonymize("email alice@acme.com about the invoice")
        store1.save("request-7", vault)

        # A different process, holding nothing but the key.
        node2 = Anonymizer()
        store2 = SerializedVaultStore(backend, PlaintextCipher())
        loaded = store2.load("request-7")
        reply = f"I will contact {next(iter(loaded.snapshot()))} today."
        assert "alice@acme.com" in node2.restore(reply, loaded)

    def test_node_two_without_the_key_gets_nothing_rather_than_the_wrong_thing(self):
        backend = DictBackend()
        node1 = Anonymizer()
        store = SerializedVaultStore(backend, PlaintextCipher())
        _, vault = node1.anonymize("email alice@acme.com")
        store.save("request-7", vault)

        assert store.load("request-8") is None
