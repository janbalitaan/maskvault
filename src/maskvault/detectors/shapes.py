"""Deciding whether a loose match really has the shape it appears to."""

from __future__ import annotations

import re

from maskvault.constants import PHONE_MAX_DIGITS, PHONE_MIN_DIGITS

# Dates and times are everywhere in a log and a CV, and none of them are
# phone numbers. Searched rather than anchored: an anchored pattern only
# rejects a date standing alone, so `2026-10-25 14:02:11` slipped through as
# a ten-digit run and a log line came back as `@@PHONE_1@@:02:11`.
_DATE_OR_TIME = re.compile(
    r"""
      \d{4}-\d{1,2}-\d{1,2}      # 2026-10-25
    | \d{1,2}:\d{2}              # 14:02
    | ^\d{4}-\d{1,2}$            # 2026-10
    """,
    re.VERBOSE,
)


class PhoneShape:
    """Decides whether a digit run is plausibly a phone number.

    A pattern strict enough to match every international format is strict
    enough to backtrack badly, and one loose enough to be safe also matches
    version strings and dates. So the pattern matches loosely and this makes
    the call — a judgement in code is easier to read, test and correct than
    another alternation inside a regular expression.
    """

    @staticmethod
    def looks_like_a_phone_number(candidate: str) -> bool:
        """Return whether a digit run is plausibly a phone number."""
        stripped = candidate.strip(" .,;:")
        if _DATE_OR_TIME.search(stripped):
            return False
        digits = sum(character.isdigit() for character in stripped)
        return PHONE_MIN_DIGITS <= digits <= PHONE_MAX_DIGITS
