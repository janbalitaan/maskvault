"""Zero means no expiry, which hands retention to the caller.

That is the conventional meaning for a configuration value, and it is the one
a database deployment wants: retention there is already somebody's job — a
nightly job, a partition drop, a policy the DBA owns — and a library
second-guessing it is a library fighting the deployment.

A negative value raises rather than being treated as zero. A TTL is usually
computed, and a computation that came out negative is a bug the caller wants
to hear about, not a silent switch to keeping plaintext forever.
"""

from __future__ import annotations

import sqlite3
import time

import pytest

from maskvault import Anonymizer
from maskvault.ciphers import PlaintextCipher
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault
from maskvault.stores import (
    DatabaseVaultStore,
    MemoryVaultStore,
    SerializedVaultStore,
)
from maskvault.stores.expiry import Expiry


class DictBackend:
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


class TestTheRule:
    def test_zero_means_never(self):
        assert Expiry(0).never

    def test_a_positive_value_does_not(self):
        assert not Expiry(60).never

    def test_a_negative_value_is_refused(self):
        """A computed TTL that came out negative is a bug, and treating it as
        "keep forever" would be the least safe reading of it."""
        with pytest.raises(VaultError, match="cannot be negative"):
            Expiry(-1)

    def test_the_message_says_what_zero_does(self):
        with pytest.raises(VaultError) as caught:
            Expiry(-30)
        assert "0 for no expiry" in str(caught.value)

    def test_a_deadline_is_infinite_when_nothing_expires(self):
        """So a store writes one comparable value either way, rather than a
        nullable column that every query has to handle."""
        assert Expiry(0).deadline() == float("inf")

    def test_a_deadline_is_in_the_future_otherwise(self):
        assert Expiry(60).deadline() > time.time()

    def test_an_infinite_deadline_never_counts_as_expired(self):
        rule = Expiry(0)
        assert not rule.expired(rule.deadline())

    def test_it_describes_both_cases(self):
        assert "do not expire" in Expiry(0).describe()
        assert "900s" in Expiry(900).describe()


class TestMemoryStore:
    def test_zero_keeps_an_entry(self):
        store = MemoryVaultStore(ttl_seconds=0)
        store.save("c1", Vault())
        time.sleep(0.02)
        assert store.load("c1") is not None

    def test_purge_removes_nothing_when_nothing_expires(self):
        """Rather than sweeping everything, which a naive cutoff would."""
        store = MemoryVaultStore(ttl_seconds=0)
        for index in range(3):
            store.save(f"c{index}", Vault())
        assert store.purge() == 0
        assert len(store) == 3

    def test_delete_still_works(self):
        """No expiry does not mean no control."""
        store = MemoryVaultStore(ttl_seconds=0)
        store.save("c1", Vault())
        store.delete("c1")
        assert store.load("c1") is None

    def test_it_says_so_in_describe(self):
        assert "retention is yours" in MemoryVaultStore(ttl_seconds=0).describe()

    def test_a_negative_value_is_refused(self):
        with pytest.raises(VaultError):
            MemoryVaultStore(ttl_seconds=-1)


class TestSerializedStore:
    def test_zero_is_passed_through_to_the_backend(self):
        """A cache's own "no expiry" is usually 0 or None, so the backend
        adapter decides — this store does not invent a huge TTL instead."""
        backend = DictBackend()
        SerializedVaultStore(backend, PlaintextCipher(), ttl_seconds=0).save("c1", Vault())
        assert set(backend.ttls.values()) == {0}

    def test_a_negative_value_is_refused(self):
        with pytest.raises(VaultError):
            SerializedVaultStore(DictBackend(), PlaintextCipher(), ttl_seconds=-5)

    def test_the_prefix_is_configurable(self):
        """A deployment with its own key convention should not have to fight
        this one."""
        backend = DictBackend()
        store = SerializedVaultStore(backend, PlaintextCipher(), prefix="acme:masked:")
        store.save("c1", Vault())
        assert all(key.startswith("acme:masked:") for key in backend.data)

    def test_an_empty_prefix_is_honoured(self):
        """Distinct from None, which means "use the default"."""
        backend = DictBackend()
        SerializedVaultStore(backend, PlaintextCipher(), prefix="").save("c1", Vault())
        assert "c1" in backend.data

    def test_a_custom_prefix_still_round_trips(self):
        backend = DictBackend()
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")
        store = SerializedVaultStore(backend, PlaintextCipher(), prefix="x:")
        store.save("c1", vault)
        assert anonymizer.restore(safe, store.load("c1")) == "email alice@acme.com"


class TestDatabaseStore:
    """The store this change exists for: retention in a database is usually
    managed with the rest of the schema."""

    def test_zero_keeps_a_row(self):
        connection = sqlite3.connect(":memory:")
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        store.save("c1", Vault())
        time.sleep(0.02)
        assert store.load("c1") is not None

    def test_purge_removes_nothing(self):
        """The row has an infinite deadline, so a cutoff comparison must not
        match it."""
        connection = sqlite3.connect(":memory:")
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        store.save("c1", Vault())
        assert store.purge() == 0
        assert store.load("c1") is not None

    def test_describe_does_not_ask_for_a_purge(self):
        """Because there is nothing for one to do."""
        connection = sqlite3.connect(":memory:")
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        assert "purge()" not in store.describe()
        assert "retention is yours" in store.describe()

    def test_describe_asks_for_one_when_rows_expire(self):
        connection = sqlite3.connect(":memory:")
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=60)
        assert "purge()" in store.describe()

    def test_a_negative_value_is_refused(self):
        with pytest.raises(VaultError):
            DatabaseVaultStore(sqlite3.connect(":memory:"), PlaintextCipher(), ttl_seconds=-1)

    def test_a_round_trip_works_with_no_expiry(self):
        connection = sqlite3.connect(":memory:")
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        store.save("c1", vault)
        assert anonymizer.restore(safe, store.load("c1")) == "email alice@acme.com"
