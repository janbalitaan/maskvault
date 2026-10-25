"""Deciding whether a loose match really has the shape it appears to."""

from __future__ import annotations

from collections.abc import Callable
import re

from maskvault.constants import PHONE_MAX_DIGITS, PHONE_MIN_DIGITS
from maskvault.exceptions import DetectorError

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
    def looks_like_a_phone_number(
        candidate: str,
        minimum: int = PHONE_MIN_DIGITS,
        maximum: int = PHONE_MAX_DIGITS,
    ) -> bool:
        """Return whether a digit run is plausibly a phone number.

        The bounds are arguments rather than fixed, because they are regional.
        Seven to fifteen digits covers the ITU E.164 range and most national
        formats, but a four-digit short code and a six-digit internal
        extension are both real and both outside it.
        """
        stripped = candidate.strip(" .,;:")
        if _DATE_OR_TIME.search(stripped):
            return False
        digits = sum(character.isdigit() for character in stripped)
        return minimum <= digits <= maximum

    @staticmethod
    def bounded(minimum: int, maximum: int) -> Callable[[str], bool]:
        """Return a validator accepting digit runs of this length.

        For a region the default range does not fit, without rewriting the
        date-and-time exclusion that the validator exists for:

            Detector(
                label="phone",
                pattern=PHONE,
                action=Action.REVERSIBLE,
                validate=PhoneShape.bounded(6, 12),
            )

        Pass it through `Levels.detectors_for(replace={"phone": ...})` and the
        shipped ordering is kept.
        """
        if minimum < 1 or maximum < minimum:
            raise DetectorError(
                f"a phone number cannot have between {minimum} and {maximum} "
                "digits; expected 1 <= minimum <= maximum"
            )

        def validate(candidate: str) -> bool:
            return PhoneShape.looks_like_a_phone_number(candidate, minimum, maximum)

        return validate
