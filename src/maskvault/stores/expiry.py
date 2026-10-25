"""How long a stored vault lives."""

from __future__ import annotations

import time

from maskvault.exceptions import VaultError


class Expiry:
    """Decides whether a stored vault is still valid.

    One place for the rule, because three stores need it and a rule that
    disagrees between them would be worse than no rule.

    **Zero means no expiry.** That is the conventional meaning in a
    configuration value, and it is the one a developer wants from a database:
    retention there is managed with the rest of the schema — a nightly job, a
    partition drop, a policy the DBA already owns — and a library second-
    guessing it is a library fighting the deployment.

    A negative value raises rather than being treated as zero. A TTL is
    usually computed, and a computation that came out negative is a bug the
    caller wants to hear about, not a silent switch to keeping plaintext
    forever.
    """

    def __init__(self, ttl_seconds: float) -> None:
        """Set up an expiry rule, refusing a negative lifetime."""
        if ttl_seconds < 0:
            raise VaultError(
                f"ttl_seconds cannot be negative (got {ttl_seconds}). Use 0 "
                "for no expiry, which hands retention to you."
            )
        self._ttl = float(ttl_seconds)

    @property
    def never(self) -> bool:
        """Whether entries are kept until something else removes them."""
        return self._ttl == 0

    @property
    def seconds(self) -> float:
        """The configured lifetime. Zero when entries do not expire."""
        return self._ttl

    def deadline(self) -> float:
        """Return the wall-clock time an entry saved now should expire at.

        Returns infinity when nothing expires, so a store can write one
        comparable value either way rather than a nullable column.
        """
        return float("inf") if self.never else time.time() + self._ttl

    def expired(self, deadline: float) -> bool:
        """Whether a deadline from `deadline()` has passed."""
        return deadline < time.time()

    def elapsed_past(self, saved_at: float) -> bool:
        """Whether an entry saved at a monotonic `saved_at` has expired.

        Monotonic rather than wall-clock, for an in-process store: a clock
        adjustment would otherwise expire everything at once or nothing at
        all. A store that persists has to use `deadline` instead, because a
        monotonic value means nothing after a restart.
        """
        return not self.never and (time.monotonic() - saved_at) > self._ttl

    def describe(self) -> str:
        """Say how long entries live, for a line that is safe to log."""
        if self.never:
            return "entries do not expire; retention is yours to manage"
        return f"entries expire after {self._ttl:.0f}s"
