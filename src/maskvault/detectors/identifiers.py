"""Personal identifiers, replaced reversibly.

Not secrets — a model may legitimately need to reason about an address or a
salary band — but not things to hand a provider either. These are tokenized
and restored, so the reader still gets a correct answer while the provider
never sees the value.
"""

from __future__ import annotations

from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.patterns import (
    DATE_OF_BIRTH,
    IBAN,
    IP_ADDRESS,
    IPV6_ADDRESS,
    MAC_ADDRESS,
    NATIONAL_ID,
    PASSPORT,
)

PERSONAL_DATA: tuple[Detector, ...] = (
    Detector(
        label="national_id",
        # US SSN shape. Other countries differ enough that a caller should add
        # their own, which is what `terms` and custom detectors are for.
        pattern=NATIONAL_ID,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="iban",
        pattern=IBAN,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="ipv6_address",
        # Before ip_address, so the more specific shape claims the span: an
        # IPv4-mapped address like ::ffff:10.0.0.1 contains an IPv4 address,
        # and the v4 detector would otherwise take the tail and leave the
        # prefix behind.
        pattern=IPV6_ADDRESS,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="ip_address",
        # Personal data under the GDPR, and it identifies a home or employer.
        pattern=IP_ADDRESS,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="mac_address",
        pattern=MAC_ADDRESS,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="passport",
        pattern=PASSPORT,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="date_of_birth",
        pattern=DATE_OF_BIRTH,
        action=Action.REVERSIBLE,
        group=1,
    ),
)
