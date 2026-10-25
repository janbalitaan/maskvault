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

from enum import Enum

from maskvault.detectors import (
    DEFAULT_DETECTORS,
    PERSONAL_DATA,
    VENDOR_CREDENTIALS,
    Action,
    Detector,
    entropy_detector,
)
from maskvault.personal import STRUCTURED_PERSONAL, special_category_detectors


class Level(Enum):
    """How aggressively to replace."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"


def _credentials_only() -> tuple[Detector, ...]:
    return VENDOR_CREDENTIALS + tuple(
        detector for detector in DEFAULT_DETECTORS if detector.action is Action.DESTROY
    )


def detectors_for(level: Level | str = Level.STANDARD) -> tuple[Detector, ...]:
    """The detector set for a strictness level.

    Order matters throughout: specific formats before generic ones, and the
    entropy net last, so a known format is labelled rather than destroyed as
    an anonymous high-entropy blob.
    """
    level = Level(level) if isinstance(level, str) else level

    if level is Level.MINIMAL:
        return _credentials_only() + (entropy_detector(),)

    contact = tuple(
        detector for detector in DEFAULT_DETECTORS if detector.action is Action.REVERSIBLE
    )
    standard = (
        VENDOR_CREDENTIALS
        + _credentials_only()[len(VENDOR_CREDENTIALS) :]
        + PERSONAL_DATA
        + STRUCTURED_PERSONAL
        + contact
    )

    if level is Level.STANDARD:
        return standard + (entropy_detector(),)
    if level is Level.STRICT:
        return standard + special_category_detectors() + (entropy_detector(),)
    return (
        standard
        + special_category_detectors()
        # A lower bar and a wider alphabet catch more real secrets, including
        # punctuated passwords, and more false positives. That is the trade
        # PARANOID exists to make.
        + (entropy_detector(min_length=16, relax_by=0.5, include_symbols=True),)
    )
