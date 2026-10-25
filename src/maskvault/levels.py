"""How much to replace.

The special-category vocabularies are the right default for a prompt about a
person, and wrong for a prompt about a codebase — "black" is in the origin
list and also half the CSS ever written. One default cannot serve both, so
strictness is a choice the caller makes once.

    MINIMAL    credentials only. Nothing reversible. For a pipeline where the
               only requirement is that a key never leaves.
    STANDARD   credentials, contact details, structured identifiers. The
               sensible default for most data.
    STRICT     everything, including the GDPR special categories. The right
               choice when the subject of the text is a person.
    PARANOID   STRICT plus the entropy net at a lower threshold, which trades
               false positives for coverage.

A level is a starting point, not a cage: pass `detectors` to replace the set
outright, or a `Whitelist` to let individual things back through.
"""

from __future__ import annotations

from maskvault.constants import PARANOID_MIN_LENGTH, PARANOID_RELAX_BY
from maskvault.detectors.entropy import EntropyDetector
from maskvault.detectors.general import DEFAULT_DETECTORS
from maskvault.detectors.identifiers import PERSONAL_DATA
from maskvault.detectors.vendor import VENDOR_CREDENTIALS
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.models.level import Level
from maskvault.personal import STRUCTURED_PERSONAL, SpecialCategories


class Levels:
    """Maps a strictness level to the detectors it implies.

    The levels are the main dial a caller turns, so what each one includes is
    the most important thing in this module to be able to read at a glance.
    """

    @staticmethod
    def detectors_for(level: Level | str = Level.STANDARD) -> tuple[Detector, ...]:
        """Build the detector set for a strictness level.

        Order matters throughout: specific formats before generic ones, and the
        entropy net last, so a known format is labeled rather than destroyed as
        an anonymous high-entropy blob.
        """
        level = Level(level) if isinstance(level, str) else level

        if level is Level.MINIMAL:
            return (*Levels._credentials_only(), EntropyDetector.build())

        contact = tuple(
            detector for detector in DEFAULT_DETECTORS if detector.action is Action.REVERSIBLE
        )
        # Order is the whole correctness story here, because the first detector
        # to match a span claims it.
        #
        # Precise before loose: `ip_address` has an exact shape while `phone`
        # matches any punctuated digit run and decides in code, so an address
        # like 10.42.7.19 is claimed by phone unless the precise one runs
        # first. Both are reversible, so the value survived either way — but
        # the label was wrong, and a caller whitelisting "ip_address" found it
        # had no effect.
        #
        # Then precise before keyword-led: an email address is unambiguous,
        # while the social-handle detector is "a platform name followed by
        # something", which would otherwise claim the domain half of one.
        standard = (
            VENDOR_CREDENTIALS
            + Levels._credentials_only()[len(VENDOR_CREDENTIALS) :]
            + PERSONAL_DATA
            + contact
            + STRUCTURED_PERSONAL
        )

        if level is Level.STANDARD:
            return (*standard, EntropyDetector.build())
        if level is Level.STRICT:
            return (
                standard
                + SpecialCategories.special_category_detectors()
                + (EntropyDetector.build(),)
            )
        return (
            standard
            + SpecialCategories.special_category_detectors()
            # A lower bar and a wider alphabet catch more real secrets, including
            # punctuated passwords, and more false positives. That is the trade
            # PARANOID exists to make.
            + (
                EntropyDetector.build(
                    min_length=PARANOID_MIN_LENGTH,
                    relax_by=PARANOID_RELAX_BY,
                    include_symbols=True,
                ),
            )
        )

    @staticmethod
    def _credentials_only() -> tuple[Detector, ...]:
        return VENDOR_CREDENTIALS + tuple(
            detector for detector in DEFAULT_DETECTORS if detector.action is Action.DESTROY
        )
