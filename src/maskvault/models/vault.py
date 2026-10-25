"""The mapping from token back to original value.

Never serialized into the text that leaves the process, never logged, never
returned over an API. It is held for the life of one operation, and
`summary()` is the only part of it that is safe to write down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from maskvault.models.token_format import TokenFormat


@dataclass
class Vault:
    """The mapping from token back to original value.

    Never serialized into a prompt, never logged, never returned over HTTP.
    Held only for the life of one request.
    """

    values: dict[str, str] = field(default_factory=dict)
    destroyed: list[str] = field(default_factory=list)

    # Which placeholder format these tokens are written in. Recorded here
    # because restoring needs it, and because the format is chosen per
    # operation to avoid whatever markup the input already contained.
    token_format: TokenFormat = field(default_factory=TokenFormat.default)

    @property
    def pattern(self) -> re.Pattern[str]:
        """Matches tokens in this vault's format."""
        return self.token_format.pattern

    @property
    def replaced(self) -> int:
        """How many distinct values were tokenized."""
        return len(self.values)

    def summary(self) -> str:
        """Describe what happened, with no values in it — safe to log."""
        kinds: dict[str, int] = {}
        pattern = self.pattern
        for token in self.values:
            match = pattern.match(token)
            if match:
                kinds[match.group(1)] = kinds.get(match.group(1), 0) + 1
        parts = [f"{count} {kind.lower()}" for kind, count in sorted(kinds.items())]
        if self.destroyed:
            parts.append(f"{len(self.destroyed)} destroyed")
        return ", ".join(parts) or "nothing replaced"
