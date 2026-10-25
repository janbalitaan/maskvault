"""One anonymizer, many concurrent callers.

The shape nearly every web application takes: build an `Anonymizer` once at
module scope and use it from every request handler. If that is not safe, the
library is not usable for the thing it exists for.

It was not safe. The format chosen for an operation was stored on the
instance, so a second caller could overwrite it between the first caller's
write and its use. The first caller then minted tokens in the second caller's
delimiters while its own vault recorded the format it had asked for.

The visible damage was worse than a wrong field. `_counters_from` reads that
format to resume numbering, so a vault whose keys no longer match it restarts
from one — and `anonymize_into` mints `@@EMAIL_1@@` a second time, for a
different value. Two values, one token, and restore picks whichever was
written last.
"""

from __future__ import annotations

import threading

import pytest

from maskvault import Anonymizer, Level, anonymize_data, restore_data

# These choose different formats: the second already contains "@@", so the
# chooser avoids at-signs for it. That difference is what made the race
# observable rather than merely present.
TEXT_A = "write to " + " and ".join(f"alice{n}@acme.com" for n in range(40))
TEXT_B = "@@ here @@ " + " and ".join(f"bob{n}@other.com" for n in range(40))

ROUNDS = 300
THREADS = 6


def run_concurrently(work, arguments: list[tuple]) -> None:
    """Start every thread at once, so they overlap rather than queue."""
    barrier = threading.Barrier(len(arguments))

    def target(*passed):
        barrier.wait()
        work(*passed)

    threads = [threading.Thread(target=target, args=args) for args in arguments]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


class TestASharedAnonymizerIsSafe:
    def test_a_vault_always_agrees_with_its_own_format(self):
        """The invariant that was broken. Not cosmetic: `Vault.summary`,
        `leaked` and the counters all read this field."""
        shared = Anonymizer()
        wrong: list[tuple[str, list[str]]] = []

        def work(text: str) -> None:
            for _ in range(ROUNDS):
                _, vault = shared.anonymize(text)
                mismatched = [
                    token
                    for token in vault.values
                    if not vault.token_format.pattern.fullmatch(token)
                ]
                if mismatched:
                    wrong.append((vault.token_format.name, mismatched[:2]))

        run_concurrently(work, [(TEXT_A,), (TEXT_B,)] * (THREADS // 2))
        assert wrong == []

    def test_nothing_is_lost_on_restore(self):
        shared = Anonymizer()
        lost: list[str] = []

        def work(text: str, marker: str) -> None:
            for _ in range(ROUNDS):
                safe, vault = shared.anonymize(text)
                if marker not in shared.restore(safe, vault):
                    lost.append(marker)

        run_concurrently(
            work,
            [(TEXT_A, "alice0@acme.com"), (TEXT_B, "bob0@other.com")] * (THREADS // 2),
        )
        assert lost == []

    def test_no_value_ever_leaks_into_another_callers_output(self):
        """The failure a reader of this library would most fear: one
        caller's value appearing in another caller's text."""
        shared = Anonymizer()
        leaks: list[str] = []

        def work(text: str, forbidden: str) -> None:
            for _ in range(ROUNDS):
                safe, _ = shared.anonymize(text)
                if forbidden in safe:
                    leaks.append(forbidden)

        run_concurrently(
            work,
            [(TEXT_A, "bob0@other.com"), (TEXT_B, "alice0@acme.com")] * (THREADS // 2),
        )
        assert leaks == []

    def test_one_token_never_stands_for_two_values(self):
        """What the corrupted counters caused: numbering restarted, so a
        token was minted twice for different values."""
        shared = Anonymizer()
        collisions: list[tuple[str, str, str]] = []

        def work(text: str) -> None:
            for _ in range(ROUNDS):
                _, vault = shared.anonymize(text)
                seen: dict[str, str] = {}
                for token, original in vault.values.items():
                    if token in seen and seen[token] != original:
                        collisions.append((token, seen[token], original))
                    seen[token] = original

        run_concurrently(work, [(TEXT_A,), (TEXT_B,)] * (THREADS // 2))
        assert collisions == []


class TestConcurrencyAtEveryLevel:
    @pytest.mark.parametrize("level", list(Level), ids=lambda item: item.value)
    def test_a_shared_anonymizer_holds_up(self, level):
        shared = Anonymizer(level=level)
        failures: list[str] = []

        def work(text: str, marker: str) -> None:
            for _ in range(60):
                safe, vault = shared.anonymize(text)
                if marker not in shared.restore(safe, vault):
                    failures.append(marker)

        run_concurrently(work, [(TEXT_A, "alice0@acme.com"), (TEXT_B, "bob0@other.com")] * 2)
        assert failures == []


class TestConcurrentStructures:
    def test_walking_structures_concurrently_round_trips(self):
        """A structure is replaced field by field under one vault, so every
        leaf after the first depends on the format staying put."""
        shared = Anonymizer()
        failures: list[object] = []

        def work(seed: int) -> None:
            original = {
                "user": {"email": f"person{seed}@acme.com", "ip": f"10.0.{seed}.1"},
                "note": "@@ a marker @@" if seed % 2 else "plain",
            }
            for _ in range(80):
                safe, vault = anonymize_data(original, shared)
                if restore_data(safe, shared, vault) != original:
                    failures.append(original)

        run_concurrently(work, [(index,) for index in range(THREADS)])
        assert failures == []
