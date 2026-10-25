"""One kind of sensitive value, and what happens when it is found."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import re

from maskvault.models.action import Action


@dataclass(frozen=True)
class Detector:
    """One kind of sensitive value.

    `validate` exists because some of these are not really regular
    expressions. A phone number is "a run of digits and separators that is
    phone-shaped", and expressing "phone-shaped" in a pattern produced a
    regex that backtracked into partial matches — the one failure mode a
    privacy filter cannot have. So the pattern finds candidates generously
    and a function decides.
    """

    label: str
    pattern: re.Pattern[str]
    action: Action
    # Shown in place of a destroyed value, so the owner can see it happened.
    notice: str = "[removed]"
    validate: Callable[[str], bool] | None = None

    # Which capture group holds the value to replace. 0 replaces the whole
    # match, which is right when the match *is* the value. Keyword-led
    # patterns such as "passport: X123456" set this to 1 so the keyword
    # survives — "passport: [[PASSPORT_1]]" still reads, and whatever
    # consumes the text can tell what kind of value was removed.
    group: int = 0

    def matches(self, candidate: str) -> bool:
        """Whether a candidate passes this detector's validator, if it has one."""
        return self.validate is None or self.validate(candidate)

    def value_of(self, match: re.Match[str]) -> str:
        """Return the part of a match this detector treats as the sensitive value."""
        if self.group and self.group <= (match.re.groups or 0):
            return match.group(self.group) or ""
        return match.group(0)

    def span_of(self, match: re.Match[str]) -> tuple[int, int]:
        """Where in the text the sensitive value sits."""
        if self.group and self.group <= (match.re.groups or 0):
            return match.span(self.group)
        return match.span(0)
