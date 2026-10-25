"""An allowlist that cannot be built."""

from __future__ import annotations

from maskvault.exceptions.base import MaskvaultError


class WhitelistError(MaskvaultError, ValueError):
    """An allowlist cannot be built from what was given.

    Usually a regex in `patterns` that does not compile. Raised rather than
    skipped, because silently dropping a rule from an allowlist changes what
    gets replaced and the caller would have no way to notice.
    """
