"""A vault could not be read back."""

from __future__ import annotations

from maskvault.exceptions.base import MaskvaultError


class VaultError(MaskvaultError, ValueError):
    """A payload is not a vault, or cannot be rebuilt into one.

    Raised rather than returning an empty vault, because an empty one
    restores nothing and looks identical to a vault whose values were all
    absent. A wiring mistake would then show up as every token coming back
    unrestored, which is a much harder thing to diagnose than a refusal at
    the point of loading.
    """
