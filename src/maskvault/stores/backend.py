"""What a key-value backend has to provide.

Three methods, chosen to be the intersection of what every store already
does, so an adapter is short enough to read at a glance:

    class RedisBackend:
        def __init__(self, client):
            self._client = client

        def get(self, key):
            return self._client.get(key)

        def set(self, key, value, ttl_seconds):
            self._client.set(key, value, ex=int(ttl_seconds))

        def delete(self, key):
            self._client.delete(key)

That is the whole Redis integration. Memcached, DynamoDB and a SQL table are
the same shape.
"""

from __future__ import annotations

from typing import Protocol


class KeyValueBackend(Protocol):
    """Stores bytes under a string key, with an expiry.

    Bytes rather than str, because that is what every one of these stores
    natively holds — handing them a str means guessing an encoding somewhere,
    and the guess is usually invisible until a non-ASCII value arrives.
    """

    def get(self, key: str) -> bytes | None:
        """Return the bytes stored under `key`, or None when there are none."""
        ...

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        """Store `value` under `key`, to expire after `ttl_seconds`.

        The expiry is not optional. A vault holds plaintext originals, so an
        entry that never expires is an exposure with no end — and a backend
        that cannot expire should delete on read instead.
        """
        ...

    def delete(self, key: str) -> None:
        """Forget `key`, whether or not anything is stored under it."""
        ...
