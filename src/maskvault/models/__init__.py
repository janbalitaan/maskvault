"""The types this library passes around.

One per file, so a reader looking for what a Vault is finds a file called
vault.py rather than scrolling through the logic that uses it. Nothing here
imports from the modules above it, which keeps the dependency direction one
way: models know nothing about detection, detection depends on models.
"""

from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.models.entropy_verdict import EntropyVerdict
from maskvault.models.finding import Finding
from maskvault.models.level import Level
from maskvault.models.substitution import Substitution
from maskvault.models.vault import TOKEN_PATTERN, Vault
from maskvault.models.whitelist import (
    COMMON_SAFE_VALUES,
    TECHNICAL_HOMONYMS,
    Whitelist,
)

__all__ = [
    "COMMON_SAFE_VALUES",
    "TECHNICAL_HOMONYMS",
    "TOKEN_PATTERN",
    "Action",
    "Detector",
    "EntropyVerdict",
    "Finding",
    "Level",
    "Substitution",
    "Vault",
    "Whitelist",
]
