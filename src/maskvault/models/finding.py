"""One thing a detector matched, and what would happen to it."""

from __future__ import annotations

from dataclasses import dataclass

from maskvault.models.action import Action


@dataclass(frozen=True)
class Finding:
    """One thing a detector matched, and what would happen to it.

    Returned by `Anonymizer.explain()` so a developer can see the policy's
    decisions before trusting it. `value` is the real matched text, so a
    Finding is not safe to log.
    """

    label: str
    value: str
    action: Action
    start: int
    end: int
    allowed: bool

    @property
    def replaced(self) -> bool:
        """Whether this value would actually be replaced."""
        return not self.allowed
