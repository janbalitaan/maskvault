"""Political opinion and union membership.

Union membership is separately named in GDPR Article 9, for a historical
reason: it was used to blacklist workers.

Matched case-insensitively and word-bounded, longest term first, so a
multi-word term wins over its parts and a short term does not match inside
a longer word.
"""

from __future__ import annotations

POLITICS_TERMS: frozenset[str] = frozenset(
    {
        "conservative",
        "liberal",
        "libertarian",
        "socialist",
        "socialism",
        "communist",
        "communism",
        "marxist",
        "marxism",
        "anarchist",
        "anarchism",
        "democrat",
        "republican",
        "labour",
        "tory",
        "green party",
        "left wing",
        "right wing",
        "far left",
        "far right",
        "centrist",
        "moderate",
        "progressive",
        "reactionary",
        "populist",
        "nationalist",
        "nationalism",
        "feminist",
        "feminism",
        "activist",
        "activism",
        "dissident",
        "union member",
        "trade union",
        "shop steward",
        "collective bargaining",
        "strike",
        "picket",
        "unionized",
        "unionised",
        "voted for",
        "voting for",
        "i vote",
        "my vote",
        "party member",
    }
)
