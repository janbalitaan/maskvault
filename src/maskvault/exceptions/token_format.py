"""A token format that cannot be used."""

from __future__ import annotations

from maskvault.exceptions.base import MaskvaultError


class TokenFormatError(MaskvaultError, ValueError):
    """A token format is unusable.

    Raised at construction rather than at use, because a format whose pattern
    cannot match its own output would lose every value it replaced at restore
    time — with no error, and no way to recover the originals. Failing early
    is the only point at which that is fixable.

    Also a ValueError, so `except ValueError` keeps working for a caller who
    has not adopted these types. That is what the standard library does with
    `UnicodeDecodeError(ValueError, UnicodeError)`.
    """
