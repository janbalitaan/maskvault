"""Every expression this library matches, named.

A detector is a policy: a label, a pattern, an action, a notice. Keeping the
patterns here and the policy in the detector tables means each file has one
job — this is the list of *what* is recognized, and that is the list of what
happens when something is. For a library whose purpose is deciding what counts
as confidential, being able to read the first list on its own is worth the
indirection.

Two kinds of expression are deliberately not here. Alphabets and thresholds
live in `constants.py`, because they are numbers someone tunes rather than
expressions someone audits. And a regex that is one function's working detail
stays with that function: `_ISO_DATE` inside the phone validator is not
something this library matches, it is how one check avoids a false positive.
"""

from __future__ import annotations

import re

from maskvault.constants import TOKEN_REGEX

# -------------------------------------------------------------------------
# Credentials, and the generic contact patterns
# -------------------------------------------------------------------------

API_KEY = re.compile(
    r"\b(?:sk-[A-Za-z0-9_\-]{16,}|AIza[A-Za-z0-9_\-]{30,}|gsk_[A-Za-z0-9_\-]{20,}"
    r"|xai-[A-Za-z0-9_\-]{20,}|r8_[A-Za-z0-9_\-]{20,}|hf_[A-Za-z0-9]{20,}"
    r"|ghp_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{16,})\b"
)

PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
)

PASSWORD_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|pwd|secret|token)\s*[:=]\s*\S{4,}", re.I
)

CARD_NUMBER = re.compile(r"\b(?:\d{4}[ -]?){3}\d{3,4}\b")

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

PHONE = re.compile(r"(?<![\w.])\+?\d[\d\s().\-]{4,20}\d(?!\w)")

URL = re.compile(r"\bhttps?://[^\s<>\"')]*[^\s<>\"').,;:!?]")

AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")

AWS_SECRET_KEY = re.compile(
    r"(?i)\baws_?secret(?:_?access)?_?key\b\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
)

SLACK_TOKEN = re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")

STRIPE_KEY = re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")

JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")

TWILIO_KEY = re.compile(r"\bSK[0-9a-fA-F]{32}\b|\bAC[0-9a-fA-F]{32}\b")

SENDGRID_KEY = re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")

NPM_TOKEN = re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")

PYPI_TOKEN = re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{16,}\b")

SSH_PUBLIC_KEY = re.compile(r"\bssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{32,}")

CONNECTION_STRING = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|ftp|sftp|"
    r"mssql|clickhouse|cassandra)://[^\s:@/]+:[^\s@/]+@[^\s]+"
)

BASIC_AUTH_URL = re.compile(r"\bhttps?://[^\s:@/]+:[^\s@/]+@[^\s]+")

BEARER_HEADER = re.compile(r"(?i)\b(?:authorization|x-api-key)\s*:\s*\S+")

ENV_ASSIGNMENT = re.compile(
    r"(?i)\b[A-Z][A-Z0-9_]*_(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|APIKEY)\b"
    r"\s*[:=]\s*\S{6,}"
)

NATIONAL_ID = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}\b")

IP_ADDRESS = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

MAC_ADDRESS = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

PASSPORT = re.compile(r"(?i)\bpassport\s*(?:no\.?|number|#)?\s*[:=]?\s*([A-Z0-9]{6,9})\b")

DATE_OF_BIRTH = re.compile(
    r"(?i)\b(?:date\s+of\s+birth|dob|born(?:\s+on)?)\s*[:=]?\s*"
    r"(\d{1,4}[-/]\d{1,2}[-/]\d{1,4})"
)


# -------------------------------------------------------------------------
# Structured personal identifiers
# -------------------------------------------------------------------------

STREET_ADDRESS = re.compile(
    r"\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][\w'-]*\s+){0,3}"
    r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|"
    r"Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?|Terrace|Way|Close|Crescent|"
    r"Highway|Hwy\.?|Parkway|Circle|Square|Sq\.?)\b",
    re.I,
)

UNIT_NUMBER = re.compile(
    r"(?i)\b(?:apt|apartment|unit|suite|ste|flat|room|rm|blk|block|"
    r"floor|fl)\.?\s*#?\s*[\w-]{1,8}\b"
)

POSTAL_CODE = re.compile(
    r"(?i)\b(?:zip|zipcode|postal\s*code|postcode)\s*[:=]?\s*"
    r"([A-Z0-9][A-Z0-9 -]{2,9}[A-Z0-9])\b"
)

COORDINATES = re.compile(
    r"(?<![\w.])-?(?:[0-8]?\d|90)\.\d{3,}\s*,\s*-?(?:1[0-7]\d|[0-9]?\d|180)\.\d{3,}(?![\w.])"
)

DRIVERS_LICENSE = re.compile(
    r"(?i)\b(?:driver'?s?\s*(?:licen[cs]e|lic)|dl|licen[cs]e\s*(?:no|number|#))"
    r"\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{4,14})\b"
)

LICENSE_PLATE = re.compile(
    r"(?i)\b(?:plate|registration|reg\.?)\s*(?:no\.?|number|#)?\s*[:=]?\s*"
    r"([A-Z0-9]{2,4}[\s-]?[A-Z0-9]{2,4})\b"
)

TAX_ID = re.compile(
    r"(?i)\b(?:tax\s*id|tin|ein|vat\s*(?:no|number|id)|nino|"
    r"national\s*insurance|sss|tin\s*no)\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{5,15})\b"
)

BANK_ACCOUNT = re.compile(
    r"(?i)\b(?:account|acct|a/c|routing|sort\s*code|swift|bic)\s*"
    r"(?:no\.?|number|#)?\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{5,20})\b"
)

POLICY_NUMBER = re.compile(
    r"(?i)\b(?:policy|member|patient|medical\s*record|mrn|insurance|"
    r"medicare|medicaid|philhealth|nhs)\s*(?:no\.?|number|id|#)?\s*"
    r"[:=]?\s*([A-Z0-9][A-Z0-9 -]{4,18})\b"
)

EMPLOYEE_ID = re.compile(
    r"(?i)\b(?:employee|staff|student|badge|payroll)\s*(?:no\.?|number|id|#)?"
    r"\s*[:=]?\s*([A-Z0-9][A-Z0-9-]{3,14})\b"
)

SALARY = re.compile(
    r"(?i)(?:(?:salary|compensation|pay|rate|earn(?:s|ing|ed)?|income|"
    r"package|offer)\D{0,16})"
    r"(?:[$£€₱¥]|usd|eur|gbp|php|inr|sgd|aud)?\s?"
    r"\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?:\s?(?:k|per\s+\w+|/\w+|a\s+year|annually|pa))?"
)

SOCIAL_HANDLE = re.compile(
    # Platform names only, and none shorter than two characters. A
    # one-letter name such as "x" matches inside any address or path,
    # which costs far more than the handles it would catch.
    r"(?i)\b(?:twitter|instagram|telegram|tiktok|discord|signal|"
    r"whatsapp|wechat|viber|skype|facebook|mastodon|threads|bluesky)"
    # An optional noun and copula, so "telegram is x", "telegram
    # handle: x" and "telegram @x" all reach the value.
    r"(?:\s+(?:handle|username|user|account|id|profile))?"
    r"\s*(?:is|:|=|at)?\s*@?([\w.]{3,30})\b"
)

AGE = re.compile(r"(?i)\b(?:i\s*am|aged?|age\s*[:=]?)\s*(\d{1,3})\s*(?:years?\s*old)?\b")


# ---------------------------------------------------------------------------
# Placeholder tokens
# ---------------------------------------------------------------------------

# Matches tokens written in the default format, for counting them by kind.
# A Vault carries its own format, so this is the fallback for code holding
# none — a format's own pattern is derived from its delimiters.
TOKEN = re.compile(TOKEN_REGEX)
