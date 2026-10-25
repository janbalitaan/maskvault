"""The mapping from token back to original value.

Never serialized into the text that leaves the process, never logged, never
returned over an API. It is held for the life of one operation, and
`summary()` is the only part of it that is safe to write down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import threading

from maskvault.models.token_format import TokenFormat


@dataclass
class Vault:
    """The mapping from token back to original value.

    Never serialized into a prompt, never logged, never returned over HTTP.
    Held only for the life of one request.
    """

    values: dict[str, str] = field(default_factory=dict)
    destroyed: list[str] = field(default_factory=list)

    # Guards the two collections above. A vault is normally per-request and
    # needs no guarding, but `anonymize_into` exists to accumulate into an
    # existing one — a conversation turn by turn, a structure field by field
    # — which invites sharing. Without this, two concurrent callers raised
    # "dictionary changed size during iteration" from inside the library and
    # lost most of what they recorded.
    #
    # Not part of the dataclass's identity: a lock is machinery, not data, so
    # it is excluded from comparison and repr.
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    # The next index per label, and the reverse mapping that gives a repeated
    # value its existing token. Both are derivable from `values`, and both are
    # kept here rather than rebuilt per call so that allocating a token is one
    # atomic step instead of a read followed by a write.
    _counters: dict[str, int] = field(default_factory=dict, repr=False, compare=False)
    _reverse: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    # Which placeholder format these tokens are written in. Recorded here
    # because restoring needs it, and because the format is chosen per
    # operation to avoid whatever markup the input already contained.
    token_format: TokenFormat = field(default_factory=TokenFormat.default)

    def mint(self, label: str, original: str) -> str:
        """Return the token standing for `original`, allocating one if needed.

        The whole allocation happens under one lock, and that is the point.
        Reading the next index, rendering the token and recording the mapping
        used to be three separate steps in the caller: two concurrent callers
        both read index 5, both minted token 6, and the second write replaced
        the first. The first caller's text still said token 6, so restoring it
        returned the *other* caller's value — a wrong answer rather than a
        missing one.

        The same value always gets the same token, so whatever reads the
        result can still tell two mentions refer to one thing.
        """
        with self._lock:
            existing = self._reverse.get(original)
            if existing is not None:
                return existing
            self._counters[label] = self._counters.get(label, 0) + 1
            token = self.token_format.render(
                self.token_format.label_for(label), self._counters[label]
            )
            self.values[token] = original
            self._reverse[original] = token
            return token

    def __post_init__(self) -> None:
        """Derive the counters and reverse mapping from any given values.

        A vault handed in with existing entries — loaded from a store, or
        written by `anonymize` and passed back to `anonymize_into` — has to
        resume numbering rather than restart it.
        """
        if self.values:
            self._rebuild()

    def _rebuild(self) -> None:
        """Recompute the counters and reverse mapping from `values`."""
        pattern = self.token_format.pattern
        for token, original in self.values.items():
            self._reverse.setdefault(original, token)
            match = pattern.fullmatch(token)
            if match:
                label, index = match.group(1), int(match.group(2))
                self._counters[label] = max(self._counters.get(label, 0), index)

    def destroy(self, label: str) -> None:
        """Note that a value under `label` was removed and will not come back."""
        with self._lock:
            self.destroyed.append(label)

    def snapshot(self) -> dict[str, str]:
        """Return a copy of the mapping, safe to iterate while others write.

        Every read inside this library goes through here. Iterating
        `values` directly is what raised "dictionary changed size during
        iteration" on a shared vault, and the traceback pointed at library
        internals rather than at the sharing that caused it.
        """
        with self._lock:
            return dict(self.values)

    @property
    def pattern(self) -> re.Pattern[str]:
        """Matches tokens in this vault's format."""
        return self.token_format.pattern

    @property
    def replaced(self) -> int:
        """How many distinct values were tokenized."""
        return len(self.snapshot())

    def summary(self) -> str:
        """Describe what happened, with no values in it — safe to log."""
        kinds: dict[str, int] = {}
        pattern = self.pattern
        for token in self.snapshot():
            match = pattern.match(token)
            if match:
                kinds[match.group(1)] = kinds.get(match.group(1), 0) + 1
        parts = [f"{count} {kind.lower()}" for kind, count in sorted(kinds.items())]
        with self._lock:
            destroyed = len(self.destroyed)
        if destroyed:
            parts.append(f"{destroyed} destroyed")
        return ", ".join(parts) or "nothing replaced"
