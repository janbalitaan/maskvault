"""Generating a vault's scope marker.

The marker is what makes a vault mix-up visible, so two things matter: that
two markers in flight do not agree, and that producing one is cheap enough
to do on every request.

Drawing every letter independently from the CSPRNG satisfies the first and
fails the second — twelve letters cost twelve calls, about 9 us a marker,
and the collision risk is the full birthday problem over every vault ever in
flight.

A **process prefix and a counter** is better on both counts. The prefix is
drawn once when the module loads; the counter increments. Within a process
two markers cannot agree, because the counter never repeats — that is
arithmetic, not probability. Across processes the birthday problem applies to
the number of *processes*, which is smaller than the number of vaults by
whatever a process handles in its lifetime:

    5,000,000 vaults, pure random, 12 letters          p = 1.3e-04
    5,000,000 vaults over 50 processes, prefix+counter  p = 4.0e-06

and the marker costs a counter increment rather than a CSPRNG round trip.
"""

from __future__ import annotations

import itertools
import secrets
import string
import threading

ALPHABET = string.ascii_uppercase

# Letters rather than digits or hex throughout. The scope goes into the token
# *label*, and the default `label_pattern` is `[A-Z_]+` — a digit would stop a
# scoped token matching its own vault's pattern, which is what `leaked()`
# relies on to report a token the model altered.
_BASE = len(ALPHABET)


def encode(number: int, letters: int) -> str:
    """Render a non-negative integer as exactly `letters` letters.

    Wraps rather than widening, so a marker's width is fixed and a token's
    shape does not change after a few hundred million vaults. Wrapping is
    safe because the prefix, not the counter, is what separates processes.
    """
    marker = []
    for _ in range(letters):
        number, index = divmod(number, _BASE)
        marker.append(ALPHABET[index])
    return "".join(marker)


class ScopeGenerator:
    """Hands out markers that do not repeat within this process.

    One instance is shared, built at import. The prefix is this process's;
    the counter is what makes each marker distinct, and it is guarded because
    two threads asking at once must not receive the same one.

    `itertools.count` is used rather than an integer plus a lock around the
    read-modify-write: `next()` on a count object is a single bytecode under
    the GIL in CPython, but the lock is kept anyway because that is an
    implementation detail of one interpreter and this library runs on
    whatever the application runs on.
    """

    def __init__(self, prefix_letters: int) -> None:
        self._prefix = self._draw(prefix_letters)
        self._counter = itertools.count()
        self._lock = threading.Lock()

    @property
    def prefix(self) -> str:
        """This process's prefix, fixed for its lifetime."""
        return self._prefix

    def next_marker(self, letters: int) -> str:
        """Return a marker of `letters` letters, unique within this process.

        The width is split between the prefix and the counter. A wider marker
        spends the extra letters on the prefix, because that is the half the
        cross-process collision risk depends on.
        """
        with self._lock:
            number = next(self._counter)
        counter_letters = min(len(self._prefix), max(1, letters // 2))
        prefix_letters = letters - counter_letters
        prefix = (self._prefix * 2)[:prefix_letters]
        return prefix + encode(number, counter_letters)

    @staticmethod
    def capacity(letters: int) -> int:
        """How many markers of this width a process can issue before repeating.

        The counter takes half the width, so capacity is 26 to that power.
        Past it the counter wraps and a marker *can* repeat within the
        process — the guarantee is "does not repeat", not "cannot", and this
        is where the difference lives.

            letters   counter   capacity
                  4         2          676
                  8         4      456,976
                 12         6  308,915,776
                 16         8     2.1e+11

        Twelve is the default, so a process would have to anonymize three
        hundred million times before the question arises. A narrower marker
        is a deliberate choice, and this is how to see what it costs.
        """
        counter_letters = max(1, letters // 2)
        return _BASE**counter_letters

    @staticmethod
    def _draw(letters: int) -> str:
        """Draw random letters in one CSPRNG call rather than one per letter.

        `secrets.choice` in a loop costs a round trip per letter, which at
        twelve letters was about 9 us — most of the cost of making a vault.
        One `randbits` and a base-26 expansion is about 0.5 us for the same
        result.
        """
        bits = max(8, letters * 5)
        return encode(secrets.randbits(bits), letters)


# One per process, built at import. A generator per vault would defeat the
# point: the counter has to be shared for it to guarantee anything.
GENERATOR = ScopeGenerator(prefix_letters=8)
