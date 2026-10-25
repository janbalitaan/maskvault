"""What to do with a detected value."""

from __future__ import annotations

from enum import Enum


class Action(Enum):
    """What to do with a detected value."""

    REVERSIBLE = "reversible"
    DESTROY = "destroy"
