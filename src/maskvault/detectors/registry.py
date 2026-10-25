"""Assembling the detectors into the order they must run in."""

from __future__ import annotations

from maskvault.detectors.entropy import EntropyDetector
from maskvault.detectors.general import DEFAULT_DETECTORS
from maskvault.detectors.identifiers import PERSONAL_DATA
from maskvault.detectors.vendor import VENDOR_CREDENTIALS
from maskvault.models.detector import Detector

# How many of the general detectors destroy rather than tokenize. Those have
# to run before the personal ones, so a password in an email-shaped string is
# destroyed rather than tokenized and handed back.
_DESTRUCTIVE_GENERAL = 4


class Registry:
    """Puts the detectors in the one order that gives correct results.

    Specific before generic, destructive before reversible, entropy last.
    Each of those is a correctness requirement rather than a preference:
    a credential matched first as a generic token would be restored into the
    answer, which is the failure this library exists to prevent.
    """

    @staticmethod
    def all_detectors(include_entropy: bool = True) -> tuple[Detector, ...]:
        """Return every detector, ordered so specific formats win."""
        detectors = (
            VENDOR_CREDENTIALS
            + DEFAULT_DETECTORS[:_DESTRUCTIVE_GENERAL]
            + PERSONAL_DATA
            + DEFAULT_DETECTORS[_DESTRUCTIVE_GENERAL:]
        )
        if include_entropy:
            detectors = (*detectors, EntropyDetector.build())
        return detectors
