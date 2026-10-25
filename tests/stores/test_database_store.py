"""Holding vaults in a SQL table.

Tested against stdlib sqlite3, so the store is exercised for real without
adding a dependency. The statements use PEP 249 only, so a driver for
PostgreSQL or MySQL behaves the same — the one thing that differs between
them is the parameter marker, which is why it is an argument.

A database differs from a cache in one way that matters: there is no native
expiry. The lifetime is a column, filtered on read and reclaimed by
`purge()`. An unswept table of vaults is a growing pile of plaintext.
"""

from __future__ import annotations

import sqlite3
import time

import pytest

from maskvault import Anonymizer
from maskvault.ciphers import FernetCipher, PlaintextCipher
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault
from maskvault.stores import DatabaseVaultStore


@pytest.fixture
def connection():
    created = sqlite3.connect(":memory:")
    yield created
    created.close()


@pytest.fixture
def store(connection):
    built = DatabaseVaultStore(connection, PlaintextCipher())
    built.create_table()
    return built


@pytest.fixture
def vault():
    _, built = Anonymizer().anonymize("email alice@acme.com and ip 10.42.7.19")
    return built


class TestTheBasics:
    def test_a_saved_vault_comes_back(self, store, vault):
        store.save("c1", vault)
        assert store.load("c1") == vault

    def test_a_missing_key_returns_none(self, store):
        assert store.load("never-saved") is None

    def test_restoring_works_from_a_loaded_vault(self, store):
        anonymizer = Anonymizer()
        safe, built = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", built)
        assert anonymizer.restore(safe, store.load("c1")) == "email alice@acme.com"

    def test_saving_twice_replaces(self, store, vault):
        """Delete-then-insert rather than an upsert, because upsert syntax
        differs between dialects."""
        store.save("c1", vault)
        _, other = Anonymizer().anonymize("email bob@other.com")
        store.save("c1", other)
        assert store.load("c1") == other

    def test_delete_forgets_it(self, store, vault):
        store.save("c1", vault)
        store.delete("c1")
        assert store.load("c1") is None

    def test_contains_reports_presence(self, store, vault):
        assert "c1" not in store
        store.save("c1", vault)
        assert "c1" in store

    def test_two_keys_do_not_see_each_other(self, store):
        _, alice = Anonymizer().anonymize("email alice@acme.com")
        _, bob = Anonymizer().anonymize("email bob@other.com")
        store.save("alice", alice)
        store.save("bob", bob)
        assert "alice@acme.com" not in str(store.load("bob").snapshot())

    def test_create_table_is_idempotent(self, store):
        """So it can be called from a startup hook on every boot."""
        store.create_table()
        store.create_table()


class TestExpiry:
    def test_an_expired_row_is_not_returned(self, connection):
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        store.save("c1", Vault())
        time.sleep(0.01)
        assert store.load("c1") is None

    def test_loading_an_expired_row_also_deletes_it(self, connection):
        """A vault holds plaintext, so hiding the row is not enough."""
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        store.save("c1", Vault())
        time.sleep(0.01)
        store.load("c1")
        cursor = connection.cursor()
        cursor.execute("SELECT COUNT(*) FROM maskvault_vaults")
        assert cursor.fetchone()[0] == 0

    def test_purge_reclaims_rows_nobody_asked_for(self, connection):
        """A database has no expiry of its own, so without this the table
        grows and every expired row is plaintext nobody is using."""
        store = DatabaseVaultStore(connection, PlaintextCipher(), ttl_seconds=0)
        store.create_table()
        for index in range(5):
            store.save(f"c{index}", Vault())
        time.sleep(0.01)
        assert store.purge() == 5

    def test_purge_keeps_live_rows(self, store, vault):
        store.save("c1", vault)
        assert store.purge() == 0
        assert store.load("c1") is not None


class TestItRefusesAnUnsafeIdentifier:
    """A table name cannot be a bound parameter, so it is interpolated — and
    therefore validated rather than trusted."""

    @pytest.mark.parametrize(
        "name",
        [
            "vaults; DROP TABLE users",
            "vaults--",
            "vaults WHERE 1=1",
            'vaults" OR "1"="1',
            "vaults UNION SELECT * FROM secrets",
            "vaults/*comment*/",
            "vaults table",
            "1vaults",
            "",
        ],
    )
    def test_an_injection_attempt_is_refused(self, connection, name):
        with pytest.raises(VaultError, match="not a usable table name"):
            DatabaseVaultStore(connection, PlaintextCipher(), table=name)

    @pytest.mark.parametrize("name", ["maskvault_vaults", "vaults", "_v2", "Vault_Store_1"])
    def test_a_legitimate_name_is_accepted(self, connection, name):
        assert DatabaseVaultStore(connection, PlaintextCipher(), table=name)

    def test_a_custom_table_name_actually_works(self, connection):
        store = DatabaseVaultStore(connection, PlaintextCipher(), table="my_vaults")
        store.create_table()
        store.save("c1", Vault(values={"!|EMAIL_1|!": "me@acme.com"}))
        assert store.load("c1") is not None

    def test_an_unknown_paramstyle_is_refused(self, connection):
        with pytest.raises(VaultError, match="not supported"):
            DatabaseVaultStore(connection, PlaintextCipher(), paramstyle="pyformat")

    def test_the_message_names_the_valid_styles(self, connection):
        with pytest.raises(VaultError) as caught:
            DatabaseVaultStore(connection, PlaintextCipher(), paramstyle="nope")
        assert "qmark" in str(caught.value)
        assert "format" in str(caught.value)


class TestEncryptedRows:
    def test_the_row_does_not_contain_the_value(self, connection):
        store = DatabaseVaultStore(connection, FernetCipher(FernetCipher.generate_key()))
        store.create_table()
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email alice@acme.com")
        store.save("c1", vault)

        cursor = connection.cursor()
        cursor.execute("SELECT payload FROM maskvault_vaults")
        stored = bytes(cursor.fetchone()[0])
        assert b"alice@acme.com" not in stored
        assert anonymizer.restore(safe, store.load("c1")) == "email alice@acme.com"

    def test_a_wrong_key_reports_itself(self, connection):
        """Rather than looking like a cache miss."""
        store = DatabaseVaultStore(connection, FernetCipher(FernetCipher.generate_key()))
        store.create_table()
        store.save("c1", Vault(values={"!|EMAIL_1|!": "me@acme.com"}))

        other = DatabaseVaultStore(connection, FernetCipher(FernetCipher.generate_key()))
        with pytest.raises(VaultError, match="could not be decrypted"):
            other.load("c1")


class TestWhenTheDatabaseIsUnreachable:
    def test_a_driver_error_becomes_a_library_error(self, connection, vault):
        """Every driver raises its own exception type, so a caller cannot
        reasonably catch them all."""
        store = DatabaseVaultStore(connection, PlaintextCipher())
        store.create_table()
        connection.close()
        with pytest.raises(VaultError, match="could not reach its database"):
            store.save("c1", vault)

    def test_a_missing_table_is_reported_clearly(self, connection, vault):
        store = DatabaseVaultStore(connection, PlaintextCipher())
        with pytest.raises(VaultError, match="could not reach its database"):
            store.save("c1", vault)


class TestDescribe:
    def test_it_names_the_table_and_the_cipher(self, store):
        described = store.describe()
        assert "maskvault_vaults" in described
        assert "not encrypted" in described
        assert "purge()" in described


class TestACorruptRow:
    def test_unreadable_json_is_reported_not_swallowed(self, connection, store):
        """A corrupt row is a different event from a missing one. Reporting
        it as absence would hide the corruption behind every token coming
        back unrestored."""
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO maskvault_vaults (vault_key, payload, expires_at) VALUES (?, ?, ?)",
            ("c1", b"{not json", time.time() + 600),
        )
        connection.commit()
        with pytest.raises(VaultError, match="not readable JSON"):
            store.load("c1")

    def test_non_utf8_bytes_are_reported(self, connection, store):
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO maskvault_vaults (vault_key, payload, expires_at) VALUES (?, ?, ?)",
            ("c1", b"\xff\xfe", time.time() + 600),
        )
        connection.commit()
        with pytest.raises(VaultError, match="not readable JSON"):
            store.load("c1")
