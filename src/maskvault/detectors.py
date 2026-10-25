"""What to look for, and what to do when it is found.

Two categories, and the distinction matters more than the patterns:

    REVERSIBLE   identifying but legitimate — an employer name, a phone
                 number, a client. Replaced with a token so the provider never
                 sees it, then restored in the answer the visitor reads.

    DESTROY      must never reach a provider and must never come back — a
                 password, an API key, a card number. Replaced with a notice.
                 If one of these appears, something has gone wrong upstream
                 and quietly restoring it would hide the mistake.
"""

from __future__ import annotations

import re

from maskvault.constants import PHONE_MAX_DIGITS, PHONE_MIN_DIGITS
from maskvault.entropy import (
    CANDIDATE,
    ENTROPY_MIN_LENGTH,
    candidate_pattern,
    looks_like_a_secret,
)
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.patterns import (
    API_KEY,
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    BASIC_AUTH_URL,
    BEARER_HEADER,
    CARD_NUMBER,
    CONNECTION_STRING,
    DATE_OF_BIRTH,
    EMAIL,
    ENV_ASSIGNMENT,
    IBAN,
    IP_ADDRESS,
    JWT,
    MAC_ADDRESS,
    NATIONAL_ID,
    NPM_TOKEN,
    PASSPORT,
    PASSWORD_ASSIGNMENT,
    PHONE,
    PRIVATE_KEY,
    PYPI_TOKEN,
    SENDGRID_KEY,
    SLACK_TOKEN,
    SSH_PUBLIC_KEY,
    STRIPE_KEY,
    TWILIO_KEY,
    URL,
)

# ISO-8601-ish dates are all over a CV and are not phone numbers.
_ISO_DATE = re.compile(r"^\d{4}-\d{1,2}(-\d{1,2})?$")


def is_phone_shaped(candidate: str) -> bool:
    """Whether a digit run is plausibly a phone number."""
    stripped = candidate.strip(" .,;:")
    if _ISO_DATE.match(stripped):
        return False
    digits = sum(character.isdigit() for character in stripped)
    return PHONE_MIN_DIGITS <= digits <= PHONE_MAX_DIGITS


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
        validate=is_phone_shaped,
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


# ---------------------------------------------------------------------------
# Known high-value formats
# ---------------------------------------------------------------------------
#
# Entropy catches secrets whose shape nobody anticipated, but it has a blind
# spot: a format drawn from a narrow alphabet scores low. An AWS access key id
# is uppercase and digits only, so it measures 3.68 bits and slips under the
# base64 threshold. Anything whose format is known and whose leak is expensive
# gets its own pattern, and entropy is the net behind them.

VENDOR_CREDENTIALS: tuple[Detector, ...] = (
    Detector(
        label="aws_access_key",
        pattern=AWS_ACCESS_KEY,
        action=Action.DESTROY,
        notice="[an AWS key was removed before sending]",
    ),
    Detector(
        label="aws_secret_key",
        # Only matched next to a naming hint: 40 base64 characters alone is
        # too common a shape to destroy on sight.
        pattern=AWS_SECRET_KEY,
        action=Action.DESTROY,
        notice="[an AWS secret was removed before sending]",
    ),
    Detector(
        label="slack_token",
        pattern=SLACK_TOKEN,
        action=Action.DESTROY,
        notice="[a Slack token was removed before sending]",
    ),
    Detector(
        label="stripe_key",
        pattern=STRIPE_KEY,
        action=Action.DESTROY,
        notice="[a Stripe key was removed before sending]",
    ),
    Detector(
        label="jwt",
        # Three dot-separated base64url segments, the middle one a payload.
        # A JWT often carries an identity and an expiry in readable form.
        pattern=JWT,
        action=Action.DESTROY,
        notice="[a token was removed before sending]",
    ),
    Detector(
        label="twilio_key",
        pattern=TWILIO_KEY,
        action=Action.DESTROY,
        notice="[a Twilio credential was removed before sending]",
    ),
    Detector(
        label="sendgrid_key",
        pattern=SENDGRID_KEY,
        action=Action.DESTROY,
        notice="[a SendGrid key was removed before sending]",
    ),
    Detector(
        label="npm_token",
        pattern=NPM_TOKEN,
        action=Action.DESTROY,
        notice="[an npm token was removed before sending]",
    ),
    Detector(
        label="pypi_token",
        pattern=PYPI_TOKEN,
        action=Action.DESTROY,
        notice="[a PyPI token was removed before sending]",
    ),
    Detector(
        label="ssh_public_key",
        pattern=SSH_PUBLIC_KEY,
        action=Action.DESTROY,
        notice="[an SSH key was removed before sending]",
    ),
    Detector(
        label="connection_string",
        # The credential-in-a-URL case, which is how a database password most
        # often ends up pasted into a prompt by accident.
        pattern=CONNECTION_STRING,
        action=Action.DESTROY,
        notice="[a connection string with credentials was removed before sending]",
    ),
    Detector(
        label="basic_auth_url",
        pattern=BASIC_AUTH_URL,
        action=Action.DESTROY,
        notice="[a URL with embedded credentials was removed before sending]",
    ),
    Detector(
        label="bearer_header",
        pattern=BEARER_HEADER,
        action=Action.DESTROY,
        notice="[an auth header was removed before sending]",
    ),
    Detector(
        label="env_assignment",
        # Any FOO_SECRET=, FOO_TOKEN=, FOO_KEY= style assignment. Catches the
        # vendor nobody has written a pattern for.
        pattern=ENV_ASSIGNMENT,
        action=Action.DESTROY,
        notice="[a credential was removed before sending]",
    ),
)


# ---------------------------------------------------------------------------
# Personal data, reversible
# ---------------------------------------------------------------------------
#
# Not secrets — a model may legitimately need to reason about these — but not
# things to hand a provider either. Tokenized and restored.

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


# Everything, in the order it must run: specific formats, then personal data,
# then the generic patterns, with entropy last as the net for the unknown.
def entropy_detector(
    min_length: int = 0, relax_by: float = 0.0, include_symbols: bool = False
) -> Detector:
    """Build the net for secrets whose format nobody anticipated.

    `relax_by` lowers every entropy threshold and `min_length` shortens the
    candidate. Both catch more real secrets at the cost of more false
    positives, which is the trade the PARANOID level exists to make.
    """
    pattern = (
        CANDIDATE
        if min_length <= 0 and not include_symbols
        else candidate_pattern(min_length or ENTROPY_MIN_LENGTH, include_symbols)
    )

    def validate(candidate: str) -> bool:
        return looks_like_a_secret(candidate, relax_by=relax_by, min_length=min_length)

    return Detector(
        label="high_entropy",
        pattern=pattern,
        action=Action.DESTROY,
        notice="[a value that looked like a secret was removed before sending]",
        validate=validate,
    )


def all_detectors(include_entropy: bool = True) -> tuple[Detector, ...]:
    """Every detector, ordered so specific formats win over generic ones."""
    detectors = (
        VENDOR_CREDENTIALS + DEFAULT_DETECTORS[:4] + PERSONAL_DATA + DEFAULT_DETECTORS[4:]
    )
    if include_entropy:
        detectors = (*detectors, entropy_detector())
    return detectors
