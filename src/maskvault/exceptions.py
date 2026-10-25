"""Everything this library raises.

One file rather than one per class, unlike `models/`. An exception hierarchy
is read as a hierarchy — a caller deciding what to catch wants to see the
whole tree at once, and each of these is two lines. Splitting them would mean
five files to answer one question.

Each also inherits from the built-in it replaces, so `except ValueError`
keeps working for a caller who has not adopted these yet. That is the same
thing the standard library does with `UnicodeDecodeError(ValueError,
UnicodeError)`, and it means adding a specific type is never a breaking
change.
"""

from __future__ import annotations


class MaskvaultError(Exception):
    """Base for everything this library raises.

    Catch this to handle any failure from maskvault without catching
    unrelated errors from elsewhere in a request.
    """


class TokenFormatError(MaskvaultError, ValueError):
    """A token format is unusable.

    Raised at construction rather than at use, because a format whose pattern
    cannot match its own output would lose every value it replaced at restore
    time — with no error, and no way to recover the originals. Failing early
    is the only point at which that is fixable.
    """


class DetectorError(MaskvaultError, ValueError):
    """A detector is malformed.

    Its pattern does not compile, or its `group` refers to a capture the
    pattern does not have.
    """


class WhitelistError(MaskvaultError, ValueError):
    """An allowlist cannot be built from what was given.

    Usually a regex in `patterns` that does not compile. Raised rather than
    skipped, because silently dropping a rule from an allowlist changes what
    gets replaced.
    """
