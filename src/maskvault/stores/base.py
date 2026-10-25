"""What a vault store has to provide.

A Protocol rather than a base class, so a store is anything with the right
shape — including one a downstream project writes without importing from
here, and including a mock in a test.

Deliberately no backend is bundled. Three reasons:

**A dependency would undo the point.** This library has none, so it can be
read end to end in an afternoon. Pulling in a Redis client to hold values it
exists to protect is the wrong trade.

**There is no single right store.** Redis, Valkey, Memcached, DynamoDB,
Postgres, etcd, a signed cookie — each is correct somewhere, and the choice
depends on a deployment this library cannot see.

**It is a security decision.** A stored vault holds every original value in
plaintext. Where it goes, who can read it, and how long it lives are
questions for whoever owns the data, not defaults for a library to pick.

So the interface is four methods and the adapter is yours. `docs/` has one
for Redis in about ten lines.
"""

from __future__ import annotations

from typing import Protocol

from maskvault.models.vault import Vault


class VaultStore(Protocol):
    """Holds vaults between the request that made one and the one that uses it.

    Keys are the caller's to choose, and the choice matters: a key shared
    between two unrelated requests hands one caller's values to another. A
    conversation id or a request id is right; a user id usually is not,
    because the same user has more than one conversation.
    """

    def save(self, key: str, vault: Vault) -> None:
        """Store a vault under `key`, replacing any vault already there."""
        ...

    def load(self, key: str) -> Vault | None:
        """Return the vault stored under `key`, or None when there is none.

        None rather than an empty vault: an empty one restores nothing and is
        indistinguishable from a vault whose values were all absent, so a
        missing key would look like a working restore that found nothing.
        """
        ...

    def delete(self, key: str) -> None:
        """Forget the vault under `key`.

        Worth calling as soon as a conversation ends. A vault holds plaintext
        originals, so its lifetime is the window in which they are exposed.
        """
        ...

    def __contains__(self, key: str) -> bool:
        """Whether a vault is stored under `key`."""
        ...
