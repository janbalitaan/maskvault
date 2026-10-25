"""One replacement rule, bundled so the substitution call stays readable."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Substitution:
    """One replacement rule, bundled so _substitute takes fewer arguments."""

    label: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None
    # Which capture group holds the value; 0 means the whole match.
    group: int = 0

    def value_of(self, match: re.Match[str]) -> str:
        """Return the part of a match this rule treats as the value."""
        if self.group and self.group <= (match.re.groups or 0):
            return match.group(self.group) or ""
        return match.group(0)
