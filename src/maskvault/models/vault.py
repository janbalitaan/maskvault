"""The mapping from token back to original value.

Never serialized into the text that leaves the process, never logged, never
returned over an API. It is held for the life of one operation, and
`summary()` is the only part of it that is safe to write down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
import secrets
import string
import threading

from maskvault.constants import SCOPE_LETTERS
from maskvault.exceptions import VaultError
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
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False, init=False
    )

    # The next index per label, and the reverse mapping that gives a repeated
    # value its existing token. Both are derivable from `values`, and both are
    # kept here rather than rebuilt per call so that allocating a token is one
    # atomic step instead of a read followed by a write.
    _counters: dict[str, int] = field(
        default_factory=dict, repr=False, compare=False, init=False
    )
    _reverse: dict[str, str] = field(
        default_factory=dict, repr=False, compare=False, init=False
    )

    # Which placeholder format these tokens are written in. Recorded here
    # because restoring needs it, and because the format is chosen per
    # operation to avoid whatever markup the input already contained.
    token_format: TokenFormat = field(default_factory=TokenFormat.default)

    # An optional per-vault marker woven into every label, for the deployment
    # where anonymizing and restoring happen in different processes.
    #
    # Without it, two vaults independently mint the identical string
    # `@@EMAIL_1@@` for different values. If the wrong vault is used to
    # restore — a long-lived vault on another node, a cached one from an
    # earlier request — the token resolves to someone else's value, silently,
    # and `leaked()` sees nothing wrong because the token *is* in that vault.
    #
    # With it the tokens cannot collide, so a foreign token stays visible and
    # `leaked()` reports it. Off by default because it makes tokens longer,
    # and a longer token is one a model is more likely to reformat — trading
    # a silent wrong answer for a louder one is worth it only when the risk
    # is real. `Vault.scoped()` builds one.
    scope: str = ""

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
            scoped = f"{label}_{self.scope}" if self.scope else label
            self._counters[scoped] = self._counters.get(scoped, 0) + 1
            token = self.token_format.render(
                self.token_format.label_for(scoped), self._counters[scoped]
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

    @classmethod
    def scoped(cls, token_format: TokenFormat | None = None) -> Vault:
        """Build a vault whose tokens cannot collide with another vault's.

        For the deployment where anonymizing and restoring happen in
        different processes — two API nodes, a worker queue, a cache. The
        marker is random per vault, so a token minted here will not be found
        in a vault built anywhere else, and the mismatch shows up as an
        unrestored token rather than as another caller's value.
        """
        chosen = token_format or TokenFormat.default()
        return cls(token_format=chosen, scope=cls._new_scope())

    @staticmethod
    def _new_scope() -> str:
        """Generate a marker made only of letters.

        Letters rather than hex, because the scope goes into the *label* and
        the default `label_pattern` is `[A-Z_]+`. A hex marker like `C8A0`
        contains digits, so a scoped token stopped matching its own vault's
        pattern — restoring still worked, since that is a dictionary lookup,
        but `leaked()` could no longer see the token it was meant to report.
        Which would have removed the one benefit scoping exists for.
        """
        return "".join(secrets.choice(string.ascii_uppercase) for _ in range(SCOPE_LETTERS))

    def as_dict(self) -> dict:
        """Convert to plain JSON-serializable data, losing nothing.

        This is how a vault reaches another process: a store, a queue, a
        response body. Every field that restoring depends on is here —
        including the scope and the format's own patterns, which a
        hand-rolled version tends to drop. The CLI dropped both, so a scoped
        vault could not be restored from its own file and a custom format
        came back with the wrong label pattern.

        What is *not* here: the lock, which means nothing outside this
        process. `from_dict` makes a new one.

        The result contains every original value. It is as sensitive as the
        input was, and the choice of where to put it is a security decision —
        see `maskvault.stores`.
        """
        return {
            "values": self.snapshot(),
            "destroyed": list(self.destroyed),
            "scope": self.scope,
            "token_format": self.token_format.as_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Vault:
        """Rebuild a vault from `as_dict` output.

        Tolerant of a missing `destroyed`, `scope` or `token_format`, because
        a vault written by an older version will not have all three. Refuses
        a payload with no `values`: that is not a vault, and silently treating
        it as an empty one would turn a wiring mistake into every token
        coming back unrestored.
        """
        if not isinstance(data, dict) or "values" not in data:
            raise VaultError(
                'not a vault: no "values" key. A vault is written by '
                "Vault.as_dict(); a payload without it cannot restore anything."
            )
        stored = data.get("token_format")
        return cls(
            values=dict(data["values"]),
            destroyed=list(data.get("destroyed") or []),
            scope=str(data.get("scope") or ""),
            token_format=(TokenFormat.from_dict(stored) if stored else TokenFormat.default()),
        )

    def __getstate__(self) -> dict:
        """Drop the lock so a vault can be pickled.

        A lock cannot be pickled, and adding one made every vault
        unpicklable — which broke `ProcessPoolExecutor`, multiprocessing, and
        any cache or task queue that serializes with pickle. Those are exactly
        the places a vault travels for a multi-process deployment, so the
        guard has to not cost that.
        """
        state = self.__dict__.copy()
        del state["_lock"]
        return state

    def __setstate__(self, state: dict) -> None:
        """Restore a vault and give it a fresh lock.

        A new lock rather than the original: a lock means nothing across a
        process boundary, and the unpickled vault is a separate object with
        its own callers.
        """
        self.__dict__.update(state)
        self.__dict__["_lock"] = threading.Lock()

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
