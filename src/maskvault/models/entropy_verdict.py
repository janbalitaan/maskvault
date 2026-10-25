"""The result of judging whether a token looks like a secret."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EntropyVerdict:
    """Why a candidate was or was not treated as a secret."""

    value: str
    entropy: float
    character_classes: int
    alphabet: str
    is_secret: bool
    reason: str
