"""The patterns that apply to any text, whatever it is about.

Order matters here more than anywhere else: the most specific patterns run
first, so an API key is not first matched as a generic long token and
destroyed under the wrong label.
"""

from __future__ import annotations

from maskvault.detectors.shapes import PhoneShape
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.patterns import (
    API_KEY,
    CARD_NUMBER,
    EMAIL,
    PASSWORD_ASSIGNMENT,
    PHONE,
    PRIVATE_KEY,
    URL,
)

# Order matters: the most specific patterns run first, so an API key is not
# first matched as a generic long token.
DEFAULT_DETECTORS: tuple[Detector, ...] = (
    # ---- destroy: never sent, never restored ----
    Detector(
        label="api_key",
        pattern=API_KEY,
        action=Action.DESTROY,
        notice="[an API key was removed before sending]",
    ),
    Detector(
        label="private_key",
        pattern=PRIVATE_KEY,
        action=Action.DESTROY,
        notice="[a private key was removed before sending]",
    ),
    Detector(
        label="password_assignment",
        pattern=PASSWORD_ASSIGNMENT,
        action=Action.DESTROY,
        notice="[a credential was removed before sending]",
    ),
    Detector(
        label="card_number",
        # Four groups of four, optionally separated. Deliberately loose: a
        # false positive costs a replaced number, a false negative sends one.
        pattern=CARD_NUMBER,
        action=Action.DESTROY,
        notice="[a card number was removed before sending]",
    ),
    # ---- reversible: pseudonymized, then restored ----
    Detector(
        label="email",
        pattern=EMAIL,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="phone",
        # Loose on purpose: is_phone_shaped makes the decision. Encoding the
        # grammar of digit groups here invites backtracking, which yields a
        # match covering only the middle of a number — and half a phone
        # number left in the text is worse than no match at all.
        pattern=PHONE,
        action=Action.REVERSIBLE,
        validate=PhoneShape.looks_like_a_phone_number,
    ),
    Detector(
        label="url",
        # The trailing character class excludes sentence punctuation. Without
        # that, "see https://example.com/me, then" matched the comma too, and
        # an exact whitelist entry for the URL no longer matched.
        pattern=URL,
        action=Action.REVERSIBLE,
    ),
)
