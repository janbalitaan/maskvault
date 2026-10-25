"""Holding vaults in this process."""

from __future__ import annotations

import threading
import time

from maskvault.constants import VAULT_TTL_SECONDS
from maskvault.models.vault import Vault
from maskvault.stores.expiry import Expiry


class MemoryVaultStore:
    """Keeps vaults in a dict, with a lifetime.

    Right for a single process: one node, a worker that handles a whole
    conversation, a test. Wrong for several nodes, because a vault saved here
    is reachable only from the process that saved it — which is the failure
    this store exists to make obvious rather than to hide.

    Entries expire by default. A vault holds plaintext originals, so its
    lifetime is the window in which they are exposed, and an unbounded dict of
    them is a leak that grows. Expiry is checked on access rather than swept
    on a timer: a background thread in a library is a thing a caller cannot
    see or stop, so `purge()` is offered instead.

    `ttl_seconds=0` turns expiry off, which is the caller's to choose — see
    `maskvault.stores.expiry` for why zero means never rather than
    immediately.
    """

    def describe(self) -> str:
        """Summarize how this store holds what it has, safe to log."""
        return f"vault store: in this process, {self._expiry.describe()}"

    def __init__(self, ttl_seconds: float = VAULT_TTL_SECONDS) -> None:
        """Set up a store whose entries live `ttl_seconds` from their save.

        Zero means no expiry, handing retention to the caller. See
        `maskvault.stores.expiry`.
        """
        self._expiry = Expiry(ttl_seconds)
        self._entries: dict[str, tuple[float, Vault]] = {}
        self._lock = threading.Lock()

    def save(self, key: str, vault: Vault) -> None:
        """Store a vault under `key`, replacing any vault already there."""
        with self._lock:
            self._entries[key] = (time.monotonic(), vault)

    def load(self, key: str) -> Vault | None:
        """Return the vault under `key`, or None if absent or expired."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            saved_at, vault = entry
            if self._expiry.elapsed_past(saved_at):
                del self._entries[key]
                return None
            return vault

    def delete(self, key: str) -> None:
        """Forget the vault under `key`, whether or not one is there."""
        with self._lock:
            self._entries.pop(key, None)

    def __contains__(self, key: str) -> bool:
        """Whether a live vault is stored under `key`."""
        return self.load(key) is not None

    def __len__(self) -> int:
        """How many vaults are held, expired ones included.

        Expiry is checked on access, so this counts what is occupying memory
        rather than what is still valid — which is the number that matters
        when the question is how much plaintext is being held.
        """
        with self._lock:
            return len(self._entries)

    def purge(self) -> int:
        """Drop every expired entry and return how many went.

        For a long-lived process that saves many vaults and loads few: without
        this, an entry nobody asks for again is never reclaimed.
        """
        if self._expiry.never:
            return 0
        with self._lock:
            stale = [
                key
                for key, (saved_at, _) in self._entries.items()
                if self._expiry.elapsed_past(saved_at)
            ]
            for key in stale:
                del self._entries[key]
        return len(stale)

    def clear(self) -> None:
        """Forget everything. Worth calling on shutdown."""
        with self._lock:
            self._entries.clear()
