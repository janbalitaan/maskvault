"""Ethnic origin, nationality and immigration status.

Immigration status decides whether someone may work at all, and is
routinely used to exclude them.

Matched case-insensitively and word-bounded, longest term first, so a
multi-word term wins over its parts and a short term does not match inside
a longer word.
"""

from __future__ import annotations

ORIGIN_TERMS: frozenset[str] = frozenset(
    {
        "immigrant",
        "emigrant",
        "migrant",
        "expat",
        "expatriate",
        "refugee",
        "asylum",
        "asylum seeker",
        "undocumented",
        "illegal alien",
        "green card",
        "permanent resident",
        "naturalized",
        "naturalised",
        "visa",
        "work permit",
        "h1b",
        "h-1b",
        "tourist visa",
        "student visa",
        "deported",
        "deportation",
        "overstayed",
        "citizenship",
        "dual citizen",
        "stateless",
        "ethnic",
        "ethnicity",
        "indigenous",
        "aboriginal",
        "native",
        "black",
        "white",
        "asian",
        "hispanic",
        "latino",
        "latina",
        "latinx",
        "caucasian",
        "mixed race",
        "biracial",
        "minority",
    }
)
