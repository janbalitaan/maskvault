"""Criminal record and financial history.

Not a GDPR Article 9 category, but it behaves like one: a conviction or a
bankruptcy follows someone for years.

Matched case-insensitively and word-bounded, longest term first, so a
multi-word term wins over its parts and a short term does not match inside
a longer word.
"""

from __future__ import annotations

CRIMINAL_TERMS: frozenset[str] = frozenset(
    {
        "convicted",
        "conviction",
        "arrested",
        "arrest",
        "charged",
        "indicted",
        "felony",
        "felon",
        "misdemeanor",
        "misdemeanour",
        "criminal record",
        "probation",
        "parole",
        "incarcerated",
        "imprisoned",
        "jailed",
        "prison",
        "dui",
        "dwi",
        "expunged",
        "acquitted",
        "lawsuit",
        "sued",
        "settlement",
        "restraining order",
        "bankruptcy",
        "bankrupt",
        "foreclosure",
        "eviction",
        "garnishment",
        "default",
        "repossessed",
        "credit score",
        "debt collection",
    }
)
