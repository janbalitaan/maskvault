"""Credential formats whose issuers publish their shape.

Entropy catches secrets nobody anticipated, but it has a blind spot: a format
drawn from a narrow alphabet scores low. An AWS access key id is uppercase and
digits only, so it measures 3.68 bits and slips under the base64 threshold.
Anything whose format is known and whose leak is expensive gets its own
pattern, and entropy is the net behind them.
"""

from __future__ import annotations

from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.patterns import (
    AWS_ACCESS_KEY,
    AWS_SECRET_KEY,
    BASIC_AUTH_URL,
    BEARER_HEADER,
    CONNECTION_STRING,
    ENV_ASSIGNMENT,
    JWT,
    NPM_TOKEN,
    PYPI_TOKEN,
    SENDGRID_KEY,
    SLACK_TOKEN,
    SSH_PUBLIC_KEY,
    STRIPE_KEY,
    TWILIO_KEY,
)

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
