"""How aggressively to replace.

The vocabularies that STRICT adds are right for text about a person and wrong
for a codebase, because words like "black" and "union" appear in both. One
default cannot serve both, so strictness is a choice the caller makes once.
"""

from __future__ import annotations

from enum import Enum


class Level(Enum):
    """How aggressively to replace."""

    MINIMAL = "minimal"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"
