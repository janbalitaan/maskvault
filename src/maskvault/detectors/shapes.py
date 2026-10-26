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


# An ISBN-13 carries thirteen digits in hyphenated groups, which is exactly
# the shape of an international number. The `978`/`979` prefix is what tells
# them apart, and a bibliography should not come back tokenized.
_ISBN = re.compile(r"\b97[89][\d -]{10,14}\d\b")

# A run of nothing but digits, with no punctuation and no country prefix.
_BARE_DIGITS = re.compile(r"\d+")

# How many digits a bare run needs before it is treated as dialable.
_BARE_PHONE_MIN_DIGITS = 10


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
        bare_minimum: int | None = None,
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
        if _ISBN.search(stripped):
            return False
        digits = sum(character.isdigit() for character in stripped)
        if not minimum <= digits <= maximum:
            return False
        # A bare run of digits — no `+`, no separator — needs to be long
        # enough to be a number somebody could dial. `1048576` and `1000000`
        # are seven digits and were read as phone numbers; a file size and a
        # row count became reversible tokens, and the model lost the figures
        # it was being asked about.
        #
        # Ten is the bar because that is where national numbers start once a
        # trunk prefix or area code is included: `09175551234` and
        # `4155550132` still match, while a bare seven- to nine-digit integer
        # is far more often a count, a size or an identifier.
        if _BARE_DIGITS.fullmatch(stripped):
            # A caller who set the bounds themselves meant them: `bounded(6,
            # 12)` for a region with six-digit extensions should not then be
            # overruled by a default meant for international numbers. So the
            # bare bar follows explicit bounds and only applies the stricter
            # default when none were given.
            bar = _BARE_PHONE_MIN_DIGITS if bare_minimum is None else bare_minimum
            return digits >= bar
        return True

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
            # `bare_minimum=minimum`: a caller naming 6 digits accepts a bare
            # six-digit run, which is the whole point of widening the bounds.
            return PhoneShape.looks_like_a_phone_number(
                candidate, minimum, maximum, bare_minimum=minimum
            )

        return validate
