"""Holding vaults in a SQL database."""

from __future__ import annotations

from contextlib import AbstractContextManager, nullcontext, suppress
import json
import re
import threading
import time
from typing import Any

from maskvault.ciphers.base import VaultCipher
from maskvault.constants import VAULT_TTL_SECONDS
from maskvault.exceptions import VaultError
from maskvault.models.vault import Vault
from maskvault.stores.expiry import Expiry

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

    A database differs from a cache in two ways that matter.

    There is no native expiry, so the lifetime is a column — filtered on
    every read and reclaimed by `purge()`, which has to be called by
    something: a cron, a startup hook, a periodic task. An unswept table of
    vaults is a growing pile of plaintext, and that is the one failure this
    store can have which a cache cannot.

    **Correct before fast.** Every statement runs under a lock, so one
    connection shared by any number of threads gives the right answer rather
    than a driver error or, worse, a value from another caller. sqlite3 with
    sixteen threads on one connection loses about a quarter of its operations
    unserialized and none of them serialized. The cost is that concurrency is
    bounded by the store rather than by the database — which is the trade
    worth making here, because the alternative is a wrong answer about
    somebody's confidential data.

    `serialize=False` removes the lock for a driver that is already
    thread-safe, or a pool that hands out one connection per thread. redis-py
    and psycopg both qualify; see `docs/concurrency.md` for what each one
    guarantees, including the shared-transaction hazard that a lock does not
    fix.

    And retention here is usually already somebody's job. A nightly job, a
    partition drop, a policy the DBA owns — so `ttl_seconds=0` turns this
    store's expiry off entirely and leaves it to them. That is what zero
    means throughout: no expiry, not immediate expiry.
    """

    def __init__(
        self,
        connection: Any,
        cipher: VaultCipher,
        *,
        table: str = "maskvault_vaults",
        paramstyle: str = "qmark",
        ttl_seconds: float = VAULT_TTL_SECONDS,
        serialize: bool = True,
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
        self._expiry = Expiry(ttl_seconds)
        # A real lock by default, a no-op when the caller opts out. Branching
        # on a flag at every statement would put the decision in the hot path
        # and in every reader's way; choosing the object once does not.
        self._guard: AbstractContextManager = threading.Lock() if serialize else nullcontext()

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
        expires_at = self._expiry.deadline()
        # Delete-then-insert rather than an upsert, because the upsert syntax
        # differs between dialects and this has to work on all of them.
        # One lock across both statements and the commit. Delete-then-insert
        # is two steps, and a thread that inserted between them would have its
        # row deleted by this one — losing a vault that was saved
        # successfully, which the caller would only discover at restore time.
        with self._guard:
            self._execute(f"DELETE FROM {self._table} WHERE vault_key = {self._marker}", (key,))
            self._execute(
                f"INSERT INTO {self._table} (vault_key, payload, expires_at) "
                f"VALUES ({self._marker}, {self._marker}, {self._marker})",
                (key, payload, expires_at),
            )
            self._connection.commit()

    def load(self, key: str) -> Vault | None:
        """Return the vault under `key`, or None if absent or expired."""
        with self._guard:
            row = self._fetch_one(
                f"SELECT payload, expires_at FROM {self._table} "
                f"WHERE vault_key = {self._marker}",
                (key,),
            )
        if row is None:
            return None
        payload, expires_at = row[0], float(row[1])
        if self._expiry.expired(expires_at):
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
        with self._guard:
            self._execute(f"DELETE FROM {self._table} WHERE vault_key = {self._marker}", (key,))
            self._connection.commit()

    def purge(self) -> int:
        """Delete every expired row and return how many went.

        Has to be called by something — a cron, a startup hook, a periodic
        task. A database has no expiry of its own, so without this the table
        grows and every expired row is plaintext nobody is using.
        """
        if self._expiry.never:
            # Nothing was given a deadline, so there is nothing to reclaim.
            # Returning zero rather than deleting on a comparison that would
            # match every row.
            return 0
        with self._guard:
            swept = self._affected(
                f"DELETE FROM {self._table} WHERE expires_at < {self._marker}",
                (time.time(),),
            )
            self._connection.commit()
        return swept

    def __contains__(self, key: str) -> bool:
        """Whether a live vault is stored under `key`."""
        return self.load(key) is not None

    def describe(self) -> str:
        """Summarize how this store protects what it holds, safe to log."""
        sweeping = "" if self._expiry.never else " and need purge()"
        return (
            f"vault store: {self._table} table, {self._cipher.describes}, "
            f"{self._expiry.describe()}{sweeping}"
        )

    def _execute(self, statement: str, parameters: tuple = ()) -> None:
        """Run one statement that returns no rows."""
        self._run(statement, parameters)

    def _fetch_one(self, statement: str, parameters: tuple = ()) -> tuple | None:
        """Run one statement and return its first row, or None."""
        return self._run(statement, parameters, fetch=True)[0]

    def _affected(self, statement: str, parameters: tuple = ()) -> int:
        """Run one statement and return how many rows it changed.

        `rowcount` is -1 on drivers that do not report it, which is not an
        error — the rows are gone either way — so it is clamped at zero.
        """
        return max(self._run(statement, parameters, fetch=True)[1], 0)

    def _run(
        self, statement: str, parameters: tuple = (), fetch: bool = False
    ) -> tuple[tuple | None, int]:
        """Run one statement, always closing the cursor.

        The cursor is closed in a `finally` rather than left to the caller.
        sqlite3 tolerates an abandoned cursor; PostgreSQL and MySQL hold
        server-side state for one, so a long-running process doing this on
        every request accumulates them until the server refuses more.

        A driver error becomes a `VaultError`, so an application catches one
        exception type whichever driver it passed in.
        """
        cursor = None
        try:
            cursor = self._connection.cursor()
            cursor.execute(statement, parameters)
            row = cursor.fetchone() if fetch else None
            return row, getattr(cursor, "rowcount", -1)
        except Exception as error:
            raise VaultError(
                f"the vault store could not reach its database: {error}"
            ) from error
        finally:
            if cursor is not None:
                # A driver whose close() raises must not mask the real error,
                # and there is nothing useful to do about a failed close.
                with suppress(Exception):
                    cursor.close()
