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

from maskvault.entropy import (
    CANDIDATE,
    MIN_LENGTH,
    candidate_pattern,
    looks_like_a_secret,
)
from maskvault.models.action import Action
from maskvault.models.detector import Detector

# ISO-8601-ish dates are all over a CV and are not phone numbers.
_ISO_DATE = re.compile(r"^\d{4}-\d{1,2}(-\d{1,2})?$")

PHONE_MIN_DIGITS = 7
PHONE_MAX_DIGITS = 15  # E.164 maximum


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
        pattern=re.compile(
            r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AIza[A-Za-z0-9_\-]{30,}|gsk_[A-Za-z0-9_\-]{20,}"
            r"|xai-[A-Za-z0-9_\-]{20,}|r8_[A-Za-z0-9_\-]{20,}|hf_[A-Za-z0-9]{20,}"
            r"|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{16,})\b"
        ),
        action=Action.DESTROY,
        notice="[an API key was removed before sending]",
    ),
    Detector(
        label="private_key",
        pattern=re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
        ),
        action=Action.DESTROY,
        notice="[a private key was removed before sending]",
    ),
    Detector(
        label="password_assignment",
        pattern=re.compile(r"\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S{4,}", re.I),
        action=Action.DESTROY,
        notice="[a credential was removed before sending]",
    ),
    Detector(
        label="card_number",
        # Four groups of four, optionally separated. Deliberately loose: a
        # false positive costs a replaced number, a false negative sends one.
        pattern=re.compile(r"\b(?:\d{4}[ -]?){3}\d{3,4}\b"),
        action=Action.DESTROY,
        notice="[a card number was removed before sending]",
    ),
    # ---- reversible: pseudonymized, then restored ----
    Detector(
        label="email",
        pattern=re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="phone",
        # Loose on purpose: is_phone_shaped makes the decision. Encoding the
        # grammar of digit groups here invites backtracking, which yields a
        # match covering only the middle of a number — and half a phone
        # number left in the text is worse than no match at all.
        pattern=re.compile(r"(?<![\w.])\+?\d[\d\s().\-]{4,20}\d(?!\w)"),
        action=Action.REVERSIBLE,
        validate=is_phone_shaped,
    ),
    Detector(
        label="url",
        # The trailing character class excludes sentence punctuation. Without
        # that, "see https://example.com/me, then" matched the comma too, and
        # an exact whitelist entry for the URL no longer matched.
        pattern=re.compile(r"\bhttps?://[^\s<>\"')]*[^\s<>\"').,;:!?]"),
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
        pattern=re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        action=Action.DESTROY,
        notice="[an AWS key was removed before sending]",
    ),
    Detector(
        label="aws_secret_key",
        # Only matched next to a naming hint: 40 base64 characters alone is
        # too common a shape to destroy on sight.
        pattern=re.compile(
            r"(?i)\baws_?secret(?:_?access)?_?key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
        ),
        action=Action.DESTROY,
        notice="[an AWS secret was removed before sending]",
    ),
    Detector(
        label="slack_token",
        pattern=re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b"),
        action=Action.DESTROY,
        notice="[a Slack token was removed before sending]",
    ),
    Detector(
        label="stripe_key",
        pattern=re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b"),
        action=Action.DESTROY,
        notice="[a Stripe key was removed before sending]",
    ),
    Detector(
        label="jwt",
        # Three dot-separated base64url segments, the middle one a payload.
        # A JWT often carries an identity and an expiry in readable form.
        pattern=re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        action=Action.DESTROY,
        notice="[a token was removed before sending]",
    ),
    Detector(
        label="twilio_key",
        pattern=re.compile(r"\bSK[0-9a-fA-F]{32}\b|\bAC[0-9a-fA-F]{32}\b"),
        action=Action.DESTROY,
        notice="[a Twilio credential was removed before sending]",
    ),
    Detector(
        label="sendgrid_key",
        pattern=re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        action=Action.DESTROY,
        notice="[a SendGrid key was removed before sending]",
    ),
    Detector(
        label="npm_token",
        pattern=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        action=Action.DESTROY,
        notice="[an npm token was removed before sending]",
    ),
    Detector(
        label="pypi_token",
        pattern=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}\b"),
        action=Action.DESTROY,
        notice="[a PyPI token was removed before sending]",
    ),
    Detector(
        label="ssh_public_key",
        pattern=re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{32,}"),
        action=Action.DESTROY,
        notice="[an SSH key was removed before sending]",
    ),
    Detector(
        label="connection_string",
        # The credential-in-a-URL case, which is how a database password most
        # often ends up pasted into a prompt by accident.
        pattern=re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|sftp|"
            r"mssql|clickhouse|cassandra)://[^\s:@/]+:[^\s@/]+@[^\s]+"
        ),
        action=Action.DESTROY,
        notice="[a connection string with credentials was removed before sending]",
    ),
    Detector(
        label="basic_auth_url",
        pattern=re.compile(r"\bhttps?://[^\s:@/]+:[^\s@/]+@[^\s]+"),
        action=Action.DESTROY,
        notice="[a URL with embedded credentials was removed before sending]",
    ),
    Detector(
        label="bearer_header",
        pattern=re.compile(r"(?i)\b(?:authorization|x-api-key)\s*:\s*\S+"),
        action=Action.DESTROY,
        notice="[an auth header was removed before sending]",
    ),
    Detector(
        label="env_assignment",
        # Any FOO_SECRET=, FOO_TOKEN=, FOO_KEY= style assignment. Catches the
        # vendor nobody has written a pattern for.
        pattern=re.compile(
            r"(?i)\b[A-Z][A-Z0-9_]*_(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|APIKEY)\b"
            r"\s*[:=]\s*\S{6,}"
        ),
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
        pattern=re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="iban",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}\b"),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="ip_address",
        # Personal data under the GDPR, and it identifies a home or employer.
        pattern=re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="mac_address",
        pattern=re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="passport",
        pattern=re.compile(r"(?i)\bpassport\s*(?:no\.?|number|#)?\s*[:=]?\s*([A-Z0-9]{6,9})\b"),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="date_of_birth",
        pattern=re.compile(
            r"(?i)\b(?:date\s+of\s+birth|dob|born(?:\s+on)?)\s*[:=]?\s*"
            r"(\d{1,4}[-/]\d{1,2}[-/]\d{1,4})"
        ),
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
        else candidate_pattern(min_length or MIN_LENGTH, include_symbols)
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
