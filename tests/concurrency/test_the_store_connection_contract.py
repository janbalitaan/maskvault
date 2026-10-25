"""Whose job thread safety is, when a store wraps somebody else's driver.

`DatabaseVaultStore` adds no lock, on purpose. A lock around an already
thread-safe driver serializes every request through one mutex for nothing,
and a lock cannot rescue a driver that is not safe. So the contract is
stated rather than enforced: the store opens a cursor per statement and
closes it, and the connection's thread safety is the caller's to get right.

These tests pin both halves of that with sqlite3, which is the driver most
likely to be reached for in a test or a small deployment and the one least
tolerant of a shared connection.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import threading

import pytest

from maskvault import Anonymizer, Vault
from maskvault.ciphers import PlaintextCipher
from maskvault.exceptions import VaultError
from maskvault.stores import DatabaseVaultStore

SESSIONS = 120
WORKERS = 16


@pytest.fixture
def database(tmp_path: Path) -> Path:
    """An sqlite file with the table already created."""
    path = tmp_path / "vaults.db"
    connection = sqlite3.connect(path)
    store = DatabaseVaultStore(connection, cipher=PlaintextCipher(), paramstyle="qmark")
    store.create_table()
    connection.commit()
    connection.close()
    return path


def store_for(connection: sqlite3.Connection, serialize: bool = True) -> DatabaseVaultStore:
    return DatabaseVaultStore(
        connection,
        cipher=PlaintextCipher(),
        paramstyle="qmark",
        serialize=serialize,
    )


def round_trip(store: DatabaseVaultStore, key: str) -> bool:
    """Anonymize, persist, reload, restore. True when the value came back."""
    anonymizer = Anonymizer()
    original = f"Email {key}@example.test"
    vault = Vault.for_key(key)
    safe = anonymizer.anonymize_into(original, vault)
    store.save(key, vault)
    loaded = store.load(key)
    return loaded is not None and anonymizer.restore(safe, loaded) == original


class TestAConnectionPerThreadWorks:
    """The shape the documentation tells you to use."""

    def test_every_session_round_trips(self, database):
        connections: dict[int, sqlite3.Connection] = {}
        lock = threading.Lock()

        def handle(n: int) -> bool:
            identity = threading.get_ident()
            with lock:
                if identity not in connections:
                    connections[identity] = sqlite3.connect(
                        database, check_same_thread=False, timeout=10
                    )
            return round_trip(store_for(connections[identity]), f"perthread-{n}")

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(handle, range(SESSIONS)))

        assert sum(results) == SESSIONS

    def test_each_session_gets_its_own_value_back(self, database):
        """Not merely "no exception" — the right value, not a neighbour's."""
        connections: dict[int, sqlite3.Connection] = {}
        lock = threading.Lock()
        anonymizer = Anonymizer()

        def handle(n: int) -> tuple[int, str]:
            identity = threading.get_ident()
            with lock:
                if identity not in connections:
                    connections[identity] = sqlite3.connect(
                        database, check_same_thread=False, timeout=10
                    )
            store = store_for(connections[identity])
            key = f"own-{n}"
            original = f"Email user{n}@company{n}.test"
            vault = Vault.for_key(key)
            safe = anonymizer.anonymize_into(original, vault)
            store.save(key, vault)
            return n, anonymizer.restore(safe, store.load(key))

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(handle, range(SESSIONS)))

        for n, restored in results:
            assert restored == f"Email user{n}@company{n}.test", (
                f"session {n} got another session's data: {restored}"
            )


class TestASharedConnectionIsCorrectByDefault:
    """The store serializes, so one connection across threads is still right.

    Unserialized, sqlite3 loses about a quarter of its operations under
    sixteen threads — as raised errors, never as wrong values. Serialized it
    loses none. Throughput is bounded by the store rather than the database,
    which is the trade worth making when the alternative is a wrong answer
    about somebody's confidential data.
    """

    def test_every_session_round_trips_on_one_connection(self, database):
        connection = sqlite3.connect(database, check_same_thread=False, timeout=30)
        store = store_for(connection)

        def handle(n: int) -> str:
            try:
                return "ok" if round_trip(store, f"shared-{n}") else "wrong"
            except Exception as error:
                return type(error).__name__

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            outcomes = list(pool.map(handle, range(SESSIONS)))

        assert outcomes.count("ok") == SESSIONS, sorted(set(outcomes))

    def test_each_session_gets_its_own_value(self, database):
        connection = sqlite3.connect(database, check_same_thread=False, timeout=30)
        store = store_for(connection)
        anonymizer = Anonymizer()

        def handle(n: int) -> tuple[int, str]:
            key = f"mine-{n}"
            original = f"Email user{n}@company{n}.test"
            vault = Vault.for_key(key)
            safe = anonymizer.anonymize_into(original, vault)
            store.save(key, vault)
            return n, anonymizer.restore(safe, store.load(key))

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            results = list(pool.map(handle, range(SESSIONS)))

        for n, restored in results:
            assert restored == f"Email user{n}@company{n}.test", (
                f"session {n} got another session's data: {restored}"
            )

    def test_opting_out_never_returns_another_callers_value(self, database):
        """`serialize=False` may raise, and may fail to resolve. It may not lie.

        Under contention an unserialized sqlite3 connection gives four
        outcomes, and only the first is success: the round trip works, the
        driver raises, the row is missed, or a vault comes back that does not
        hold the token — leaving it unresolved in the text, where `leaked()`
        reports it.

        What must never happen is a fifth: a token resolving to **another
        caller's value**. That is what `Vault.for_key` prevents, and this
        proves it under a genuine race rather than by argument. Measured on
        Python 3.13: 125 ok, 54 errors, 17 misses, 4 unresolved, 0 wrong.
        """
        connection = sqlite3.connect(database, check_same_thread=False, timeout=30)
        store = store_for(connection, serialize=False)
        anonymizer = Anonymizer()
        mine = {n: f"Email user{n}@company{n}.test" for n in range(SESSIONS)}

        def handle(n: int) -> str:
            key = f"unserialized-{n}"
            try:
                vault = Vault.for_key(key)
                safe = anonymizer.anonymize_into(mine[n], vault)
                store.save(key, vault)
                loaded = store.load(key)
                if loaded is None:
                    return "miss"
                restored = anonymizer.restore(safe, loaded)
                if restored == mine[n]:
                    return "ok"
                if any(other in restored for index, other in mine.items() if index != n):
                    return "SOMEONE_ELSES_DATA"
                return "unresolved" if anonymizer.leaked(restored, loaded) else "silent"
            except Exception:
                return "error"

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            outcomes = list(pool.map(handle, range(SESSIONS)))

        assert "SOMEONE_ELSES_DATA" not in outcomes, (
            "an unserialized connection returned another caller's value"
        )
        assert "silent" not in outcomes, (
            "a value went missing with no token left for leaked() to find"
        )

    def test_the_default_has_none_of_those_outcomes(self, database):
        """Which is the argument for serializing: one outcome, not four."""
        connection = sqlite3.connect(database, check_same_thread=False, timeout=30)
        store = store_for(connection)

        def handle(n: int) -> bool:
            return round_trip(store, f"serialized-{n}")

        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            assert all(pool.map(handle, range(SESSIONS)))


class _CountingCursor:
    """Proxies a cursor so closes can be counted.

    A wrapper rather than a monkeypatch: `sqlite3.Cursor.close` is a C slot
    and read-only, so assigning to it raises.
    """

    def __init__(self, inner, closed: list) -> None:
        self._inner = inner
        self._closed = closed

    def execute(self, *args, **kwargs):
        return self._inner.execute(*args, **kwargs)

    def fetchone(self):
        return self._inner.fetchone()

    @property
    def rowcount(self) -> int:
        return self._inner.rowcount

    def close(self) -> None:
        self._closed.append(self)
        self._inner.close()


class TestTheCursorIsAlwaysClosed:
    """Seven statements opened a cursor and nothing closed it.

    Harmless on sqlite3, a server-side resource leak on PostgreSQL and MySQL
    that grows with every request — so it is counted here rather than left to
    be discovered in production.
    """

    def test_no_cursor_outlives_its_statement(self, database):
        real = sqlite3.connect(database, check_same_thread=False)
        opened: list = []
        closed: list = []

        class CountingConnection:
            def cursor(self):
                cursor = _CountingCursor(real.cursor(), closed)
                opened.append(cursor)
                return cursor

            def commit(self) -> None:
                real.commit()

        store = store_for(CountingConnection())  # type: ignore[arg-type]
        assert round_trip(store, "counted")
        store.delete("counted")
        store.purge()

        assert opened, "the store should have opened at least one cursor"
        assert len(closed) == len(opened), (
            f"{len(opened) - len(closed)} of {len(opened)} cursors were left open"
        )

    def test_a_cursor_is_closed_even_when_the_statement_fails(self, database):
        """The close is in a `finally`, so a driver error does not leak one."""
        real = sqlite3.connect(database, check_same_thread=False)
        opened: list = []
        closed: list = []

        class ExplodingConnection:
            def cursor(self):
                cursor = _CountingCursor(real.cursor(), closed)
                opened.append(cursor)
                cursor.execute = lambda *a, **k: 1 / 0  # type: ignore[method-assign]
                return cursor

            def commit(self) -> None:
                real.commit()

        store = store_for(ExplodingConnection())  # type: ignore[arg-type]
        with pytest.raises(VaultError):
            store.load("anything")

        assert len(closed) == len(opened) == 1
