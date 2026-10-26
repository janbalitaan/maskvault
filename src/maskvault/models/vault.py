"""The mapping from token back to original value.

Never serialized into the text that leaves the process, never logged, never
returned over an API. It is held for the life of one operation, and
`summary()` is the only part of it that is safe to write down.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import threading
import time

from maskvault.constants import SCOPE_LETTERS, WIPE_AFTER_SECONDS
from maskvault.exceptions import VaultError
from maskvault.models.token_format import TokenFormat
from maskvault.scopes import GENERATOR
from maskvault.utils.letters import LetterCode


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

    # When each token was minted, so `wipe()` can forget the values a
    # conversation has finished with while keeping the ones it still needs.
    #
    # Wall clock rather than monotonic, because a vault crosses process
    # boundaries — a store, a queue, another node — and monotonic clocks have
    # a different origin in every process. A monotonic timestamp survived
    # serialization as a meaningless number, and the vault that came back
    # treated every value as infinitely old and wiped all of them, which is
    # exactly the direction that breaks a request still in flight.
    #
    # The cost is sensitivity to a clock adjustment. A step backwards makes a
    # value look newer, so it is kept — safe. A step forwards makes it look
    # older, so it could be wiped early; NTP steps are milliseconds and a
    # large jump is rare, and keeping serialization correct matters more.
    _minted_at: dict[str, float] = field(
        default_factory=dict, repr=False, compare=False, init=False
    )

    # Which placeholder format these tokens are written in. Recorded here
    # because restoring needs it, and because the format is chosen per
    # operation to avoid whatever markup the input already contained.
    token_format: TokenFormat = field(default_factory=TokenFormat.default)

    # How to read text held in `bytes`. Carried here rather than passed to
    # both halves, because anonymizing with one encoding and restoring with
    # another would mangle every non-ASCII value — and a second parameter is
    # a second chance to disagree.
    #
    # UTF-8 by default because it refuses binary: a PNG raises
    # UnicodeDecodeError and is left alone. latin-1 and cp1252 decode *any*
    # byte sequence, so they cannot be tried as a fallback — an image would
    # decode "successfully" and be scanned as text, and one chance match
    # would corrupt it. A caller whose payload is in one of those says so.
    #
    # None scans no bytes at all, for a payload known to be binary.
    bytes_encoding: str | None = "utf-8"

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
            self._minted_at[token] = time.time()
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
    def scoped(
        cls, token_format: TokenFormat | None = None, letters: int = SCOPE_LETTERS
    ) -> Vault:
        """Build a vault whose tokens are very unlikely to collide with another's.

        For the deployment where anonymizing and restoring happen in
        different processes — two API nodes, a worker queue, a cache. The
        marker is random per vault, so a token minted here is not found in a
        vault built anywhere else, and the mismatch surfaces as an unrestored
        token that `leaked()` reports rather than as another caller's value.

        **Unlikely, not impossible.** Two vaults can draw the same marker,
        and a shared marker plus a mix-up is a silent wrong value again — so
        this is a safety net under correct vault handling, not a substitute
        for it. The default eight letters give about a 0.02% chance that any
        two of ten thousand concurrent vaults share a marker; `letters`
        raises it for a system with far more, at one character per letter.

        What actually guarantees the right value is keeping the vault with
        the request that produced it. See `docs/stores.md`.
        """
        chosen = token_format or TokenFormat.default()
        return cls(token_format=chosen, scope=cls._new_scope(letters))

    @classmethod
    def for_key(
        cls,
        key: str,
        token_format: TokenFormat | None = None,
        letters: int = SCOPE_LETTERS,
    ) -> Vault:
        """Build a vault whose marker is derived from an id you already have.

        `Vault.scoped()` draws a random marker, so two vaults can in
        principle draw the same one. If you already have something unique per
        conversation — a session id, a conversation id, a request id, the key
        you store the vault under — derive the marker from it and uniqueness
        stops being a matter of chance:

            vault = Vault.for_key(conversation_id)
            store.save(conversation_id, vault)

        Two consequences worth having. The marker is **deterministic**, so
        the same conversation always produces the same one — a retry, a
        replay or a second node reach the same answer. And loading the wrong
        conversation's vault is caught, because its marker is a function of
        the id you asked for: the tokens will not match and `leaked()` says
        so.

        Distinct keys give distinct markers unless the digest collides, which
        at twelve letters is about 1 in 200,000 across a million
        conversations. Raise `letters` for more.
        """
        chosen = token_format or TokenFormat.default()
        return cls(token_format=chosen, scope=cls._derive_scope(key, letters))

    @staticmethod
    def _derive_scope(key: str, letters: int = SCOPE_LETTERS) -> str:
        """Map a key onto a fixed-width marker of letters only.

        Letters rather than hex for the same reason the random marker uses
        them: the scope goes into the label, and the default `label_pattern`
        is `[A-Z_]+`, so a digit would stop a scoped token matching its own
        vault's pattern and `leaked()` would go blind to it.

        blake2b rather than a plain hash of the string, so the marker does
        not reveal the key: a session id is often a user identifier, and a
        marker that leaked it would put it in every token.
        """
        if not key:
            raise VaultError(
                "a derived scope needs a non-empty key; for a random marker "
                "use Vault.scoped() instead"
            )
        if letters < 1:
            raise VaultError(
                f"a scope needs at least one letter (got {letters}); "
                "for an unscoped vault use Vault() instead"
            )
        digest = hashlib.blake2b(key.encode("utf-8"), digest_size=32).digest()
        return LetterCode.encode(int.from_bytes(digest, "big"), letters)

    @staticmethod
    def _new_scope(letters: int = SCOPE_LETTERS) -> str:
        """Generate a marker that does not repeat within this process.

        A process prefix plus a counter, rather than letters drawn one at a
        time from the CSPRNG. Two markers from this process cannot agree,
        because the counter never repeats — arithmetic rather than
        probability — and the remaining risk is two *processes* drawing the
        same prefix, which is a far smaller population than two vaults
        drawing the same marker. See `maskvault.scopes`.
        """
        if letters < 1:
            raise VaultError(
                f"a scope needs at least one letter (got {letters}); "
                "for an unscoped vault use Vault() instead"
            )
        return GENERATOR.next_marker(letters)

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
            # Without these a revived vault cannot tell a value minted a
            # second ago from one minted an hour ago, and `wipe()` would
            # forget both.
            "minted_at": dict(self._minted_at),
            "bytes_encoding": self.bytes_encoding,
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
        vault = cls(
            values=dict(data["values"]),
            destroyed=list(data.get("destroyed") or []),
            scope=str(data.get("scope") or ""),
            token_format=(TokenFormat.from_dict(stored) if stored else TokenFormat.default()),
            # A vault written before this was recorded used UTF-8, which is
            # also the default, so the absent case needs no special handling.
            bytes_encoding=data.get("bytes_encoding", "utf-8"),
        )
        vault._adopt_mint_times(data.get("minted_at"))
        return vault

    def _adopt_mint_times(self, stored: object) -> None:
        """Take the recorded mint times, or treat the values as new.

        A vault written before these were recorded has none. Treating those
        values as *new* rather than as old is the deliberate choice: a wipe
        that forgets too little leaves data around a little longer, while one
        that forgets too much breaks a request still in flight. Between a
        privacy cost measured in minutes and a correctness failure, the
        correctness failure is worse.
        """
        now = time.time()
        times = stored if isinstance(stored, dict) else {}
        for token in self.values:
            recorded = times.get(token)
            self._minted_at[token] = (
                float(recorded) if isinstance(recorded, (int, float)) else now
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

    def wipe(self, older_than: float | None = None) -> int:
        """Forget values older than `older_than` seconds, returning how many went.

        A vault holds the originals in plaintext — that is its whole job —
        and `restore()` does not empty it, because a multi-turn conversation
        needs the same tokens to mean the same people on the next turn. So a
        vault outlives its use unless something ends it, and until then it is
        confidential data sitting in memory, in a cache, or in a table.

        **Selective by age**, because a long conversation keeps needing its
        recent values while the ones from twenty turns ago are finished:

            vault.wipe()            # anything older than 15 minutes
            vault.wipe(older_than=60)   # anything older than a minute
            vault.wipe(older_than=0)    # everything, finished or not

        The default matches the store TTL, so a vault in memory and a vault
        in a cache age out together rather than one outliving the other by
        accident. Pass `older_than=0` at the end of a single-turn request,
        where nothing is needed again.

        What survives is the scope, the token format, the counters and the
        list of destroyed labels — enough for `summary()` to still describe
        what happened, with no values in it. The counters survive
        deliberately: resetting them would let a later mint reuse `EMAIL_1`
        for a different person, so a token from before the wipe would resolve
        to the wrong value instead of to nothing.

        **This is not a secure erase.** Python strings are immutable and the
        interpreter may hold copies the process cannot reach, so this removes
        the reference, not every byte. For a stronger guarantee the value
        must never reach this process — see `docs/limitations.md`.
        """
        cutoff = WIPE_AFTER_SECONDS if older_than is None else older_than
        if cutoff < 0:
            raise VaultError(
                f"older_than cannot be negative (got {cutoff}); "
                "0 forgets everything and a larger value forgets less"
            )
        now = time.time()
        with self._lock:
            stale = [
                token
                for token in self.values
                # A token with no recorded time predates this field — from an
                # older serialized vault — and is treated as old, because the
                # safe assumption about data of unknown age is that it has
                # outlived its use.
                if now - self._minted_at.get(token, 0.0) >= cutoff
            ]
            for token in stale:
                original = self.values.pop(token)
                self._reverse.pop(original, None)
                self._minted_at.pop(token, None)
            return len(stale)

    @property
    def wiped(self) -> bool:
        """Whether this vault has been emptied of values.

        Distinct from never having held any: `summary()` still reports what
        was replaced, so a wiped vault can be logged without implying the
        request was clean.
        """
        return not self.values and bool(self._counters)

    def summary(self) -> str:
        """Describe what happened, with no values in it — safe to log.

        Counted from the counters rather than from the stored values, so a
        wiped vault still reports what it replaced. An audit line written
        after disposal would otherwise read "nothing replaced" for a request
        that handled somebody's data, which is the opposite of what an audit
        line is for.
        """
        with self._lock:
            kinds = {self._kind_of(scoped): count for scoped, count in self._counters.items()}
            destroyed = len(self.destroyed)
        parts = [f"{count} {kind.lower()}" for kind, count in sorted(kinds.items())]
        if destroyed:
            parts.append(f"{destroyed} destroyed")
        return ", ".join(parts) or "nothing replaced"

    def _kind_of(self, scoped_label: str) -> str:
        """Strip the scope marker back off a counter key.

        Counters are keyed by `LABEL_SCOPE` so two scopes cannot share a
        count, but a summary should say "email", not "email_qrmzvbdlkpwa".
        """
        if self.scope and scoped_label.endswith(f"_{self.scope}"):
            return scoped_label[: -len(self.scope) - 1]
        return scoped_label
