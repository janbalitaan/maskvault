"""What to look for, and what to do when it is found.

Two actions, and the distinction matters more than any individual pattern:

    REVERSIBLE   identifying but legitimate — an employer, a phone number, an
                 address. Replaced with a token the provider never sees
                 through, then restored in the text your reader gets.

    DESTROY      must never reach a provider and must never come back — a
                 password, an API key, a card number. Replaced with a notice.
                 If one appears, something has gone wrong upstream, and
                 quietly restoring it would hide the mistake.

One module per family, so adding a pattern means editing the file that already
holds its neighbours:

    vendor        credential formats whose issuers publish their shape
    identifiers   personal identifiers, replaced reversibly
    general       patterns that apply to any text at all
    entropy       the net for secrets nobody anticipated
    shapes        validators, for when a pattern has to stay loose
    registry      the one order in which they give correct results
"""

from __future__ import annotations

from maskvault.detectors.entropy import EntropyDetector
from maskvault.detectors.general import DEFAULT_DETECTORS
from maskvault.detectors.identifiers import PERSONAL_DATA
from maskvault.detectors.registry import Registry
from maskvault.detectors.shapes import PhoneShape
from maskvault.detectors.vendor import VENDOR_CREDENTIALS

__all__ = [
    "DEFAULT_DETECTORS",
    "PERSONAL_DATA",
    "VENDOR_CREDENTIALS",
    "EntropyDetector",
    "PhoneShape",
    "Registry",
]
