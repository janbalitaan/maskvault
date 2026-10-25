"""The mapping from token back to original value.

Never serialized into the text that leaves the process, never logged, never
returned over an API. It is held for the life of one operation, and
`summary()` is the only part of it that is safe to write down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re

# Matches the tokens this library emits, for counting them by kind.
TOKEN_PATTERN = re.compile(r"\[\[([A-Z_]+)_(\d+)\]\]")


@dataclass
class Vault:
    """The mapping from token back to original value.

    Never serialized into a prompt, never logged, never returned over HTTP.
    Held only for the life of one request.
    """

    values: dict[str, str] = field(default_factory=dict)
    destroyed: list[str] = field(default_factory=list)

    @property
    def replaced(self) -> int:
        """How many distinct values were tokenized."""
        return len(self.values)

    def summary(self) -> str:
        """Describe what happened, with no values in it — safe to log."""
        kinds: dict[str, int] = {}
        for token in self.values:
            match = TOKEN_PATTERN.match(token)
            if match:
                kinds[match.group(1)] = kinds.get(match.group(1), 0) + 1
        parts = [f"{count} {kind.lower()}" for kind, count in sorted(kinds.items())]
        if self.destroyed:
            parts.append(f"{len(self.destroyed)} destroyed")
        return ", ".join(parts) or "nothing replaced"
