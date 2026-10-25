"""The root of the hierarchy."""

from __future__ import annotations


class MaskvaultError(Exception):
    """Base for everything this library raises.

    Catch this to handle any failure from maskvault without catching
    unrelated errors from elsewhere in a request.
    """
