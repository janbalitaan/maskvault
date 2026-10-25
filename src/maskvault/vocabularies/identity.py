"""Sexual orientation, gender identity and relationships.

Disclosure here can be dangerous rather than merely unwanted, and in some
countries it carries criminal risk.

Matched case-insensitively and word-bounded, longest term first, so a
multi-word term wins over its parts and a short term does not match inside
a longer word.
"""

from __future__ import annotations

IDENTITY_TERMS: frozenset[str] = frozenset(
    {
        "gay",
        "lesbian",
        "bisexual",
        "bi",
        "queer",
        "homosexual",
        "heterosexual",
        "straight",
        "asexual",
        "pansexual",
        "lgbt",
        "lgbtq",
        "lgbtqia",
        "transgender",
        "trans",
        "nonbinary",
        "non-binary",
        "genderqueer",
        "genderfluid",
        "intersex",
        "cisgender",
        "cis",
        "transitioning",
        "transitioned",
        "deadname",
        "pronouns",
        "coming out",
        "came out",
        "closeted",
        "in the closet",
        "partner",
        "husband",
        "wife",
        "spouse",
        "fiance",
        "fiancee",
        "divorced",
        "separated",
        "widowed",
        "single parent",
    }
)
