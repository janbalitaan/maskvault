"""Holding vaults in a SQL database."""

from __future__ import annotations

import json
import re
import time
from typing import Any

from maskvault.ciphers.base import VaultCipher
from maskvault.constants import VAULT_TTL_SECONDS
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault

# A table or column name cannot be a bound parameter, so it is interpolated —
# and therefore has to be validated rather than trusted. Letters, digits and
# underscores only, which every SQL dialect accepts unquoted.
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# The two parameter markers that cover the drivers anyone is likely to use:
# sqlite3 and oracledb take `?`, while psycopg, mysqlclient, pymysql and
# asyncpg's sync wrappers take `%s`. PEP 249 calls these paramstyles.
_PLACEHOLDERS = {"qmark": "?", "format": "%s"}


class DatabaseVaultStore:
    """Puts vaults in a table, through any PEP 249 connection.

    For a deployment that already has a database and would rather not add a
    cache for this. Works with sqlite3, PostgreSQL, MySQL and anything else
    exposing a DB-API 2.0 connection:

        store = DatabaseVaultStore(connection, cipher=FernetCipher.from_env())
        store.create_table()                     # once, at deploy
        store.save(conversation_id, vault)        # on node 1
        vault = store.load(conversation_id)       # on node 2

    A database differs from a cache in one way that matters: there is no
    native expiry. So the lifetime is a column, filtered on every read and
    reclaimed by `purge()` — which has to be called by something, a cron or a
    startup hook. An unswept table of vaults is a growing pile of plaintext,
    which is the one failure this store can have that a cache cannot.
    """

    def __init__(
        self,
        connection: Any,
        cipher: VaultCipher,
        *,
        table: str = "maskvault_vaults",
        paramstyle: str = "qmark",
        ttl_seconds: float = VAULT_TTL_SECONDS,
    ) -> None:
        """Wrap a DB-API connection.

        `paramstyle` is the driver's parameter marker, as PEP 249 names it:
        "qmark" for sqlite3, "format" for psycopg and the MySQL drivers. It
        is not detected automatically because `connection.paramstyle` is a
        module attribute rather than a connection one, and guessing from the
        class name would break on a wrapper or a pool.
        """
        if not _IDENTIFIER.match(table):
            raise VaultError(
                f"{table!r} is not a usable table name. A name cannot be a "
                "bound parameter, so it is interpolated into the statement — "
                "letters, digits and underscores only."
            )
        if paramstyle not in _PLACEHOLDERS:
            raise VaultError(
                f"paramstyle {paramstyle!r} is not supported; expected one of "
                f"{', '.join(sorted(_PLACEHOLDERS))}. These are the PEP 249 "
                "names: sqlite3 uses 'qmark', psycopg and MySQL use 'format'."
            )
        self._connection = connection
        self._cipher = cipher
        self._table = table
        self._marker = _PLACEHOLDERS[paramstyle]
        self._ttl = ttl_seconds

    def create_table(self) -> None:
        """Create the table if it is absent.

        Offered so a deployment can call it from a startup hook rather than
        hand-writing DDL that has to match what this class queries. A project
        with real migrations should use them instead; the shape is two text
        columns and a float.
        """
        self._execute(
            f"CREATE TABLE IF NOT EXISTS {self._table} ("
            "vault_key TEXT PRIMARY KEY, "
            "payload BLOB NOT NULL, "
            "expires_at DOUBLE PRECISION NOT NULL)"
        )
        self._connection.commit()

    def save(self, key: str, vault: Vault) -> None:
        """Store a vault under `key`, replacing any vault already there."""
        payload = self._cipher.encrypt(json.dumps(vault.as_dict()).encode("utf-8"))
        expires_at = time.time() + self._ttl
        # Delete-then-insert rather than an upsert, because the upsert syntax
        # differs between dialects and this has to work on all of them.
        self._execute(f"DELETE FROM {self._table} WHERE vault_key = {self._marker}", (key,))
        self._execute(
            f"INSERT INTO {self._table} (vault_key, payload, expires_at) "
            f"VALUES ({self._marker}, {self._marker}, {self._marker})",
            (key, payload, expires_at),
        )
        self._connection.commit()

    def load(self, key: str) -> Vault | None:
        """Return the vault under `key`, or None if absent or expired."""
        cursor = self._execute(
            f"SELECT payload, expires_at FROM {self._table} WHERE vault_key = {self._marker}",
            (key,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        payload, expires_at = row[0], float(row[1])
        if expires_at < time.time():
            self.delete(key)
            return None
        serialized = self._cipher.decrypt(bytes(payload))
        try:
            return Vault.from_dict(json.loads(serialized.decode("utf-8")))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise VaultError(
                f"the stored vault under {key!r} is not readable JSON: {error}"
            ) from error

    def delete(self, key: str) -> None:
        """Forget the vault under `key`, whether or not one is there."""
        self._execute(f"DELETE FROM {self._table} WHERE vault_key = {self._marker}", (key,))
        self._connection.commit()

    def purge(self) -> int:
        """Delete every expired row and return how many went.

        Has to be called by something — a cron, a startup hook, a periodic
        task. A database has no expiry of its own, so without this the table
        grows and every expired row is plaintext nobody is using.
        """
        cursor = self._execute(
            f"DELETE FROM {self._table} WHERE expires_at < {self._marker}",
            (time.time(),),
        )
        self._connection.commit()
        # rowcount is -1 on drivers that do not report it, which is not an
        # error — the rows are gone either way.
        return max(cursor.rowcount, 0)

    def __contains__(self, key: str) -> bool:
        """Whether a live vault is stored under `key`."""
        return self.load(key) is not None

    def describe(self) -> str:
        """Summarize how this store protects what it holds, safe to log."""
        return (
            f"vault store: {self._table} table, {self._cipher.describes}, "
            f"rows expire after {self._ttl:.0f}s and need purge()"
        )

    def _execute(self, statement: str, parameters: tuple = ()) -> Any:
        """Run one statement, turning a driver error into a library one."""
        try:
            cursor = self._connection.cursor()
            cursor.execute(statement, parameters)
            return cursor
        except Exception as error:
            raise VaultError(
                f"the vault store could not reach its database: {error}"
            ) from error
