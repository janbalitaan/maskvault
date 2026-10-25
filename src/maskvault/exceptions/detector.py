"""A detector that is malformed."""

from __future__ import annotations

from maskvault.exceptions.base import MaskvaultError


class DetectorError(MaskvaultError, ValueError):
    """A detector is malformed.

    Its pattern does not compile, or its `group` refers to a capture the
    pattern does not have. The second case matters more than it looks:
    `value_of` falls back to the whole match when the group is missing, which
    looks like the detector working while the token quietly covers the
    keyword as well as the value.
    """
