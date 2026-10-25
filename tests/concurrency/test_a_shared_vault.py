"""One vault, many concurrent callers accumulating into it.

`anonymize_into` exists to accumulate — a conversation turn by turn, a
structure field by field — so a caller sharing one vault is doing what the
method invites. Two failures followed, in increasing order of badness.

First a crash: `dictionary changed size during iteration`, raised from inside
the library with a traceback pointing at internals rather than at the sharing.

Then, once reads were snapshotted, something worse. Allocating a token was a
read of the counters followed by a write, and two callers both reading index
5 both minted token 6. The second write replaced the first, while the first
caller's *text* still said token 6 — so restoring it returned the other
caller's value. A wrong answer, not a missing one, and nothing said so.

The vault now allocates under its own lock, which makes the whole step atomic.
"""

from __future__ import annotations

import threading

import pytest

from maskvault import Anonymizer, Level
from maskvault.models.vault import Vault

THREADS = 6
ROUNDS = 150


def accumulate(anonymizer: Anonymizer, vault: Vault, threads: int, rounds: int):
    """Have several threads anonymize into one vault, and report what happened."""
    produced: list[tuple[str, str]] = []
    errors: list[str] = []
    barrier = threading.Barrier(threads)

    def work(seed: int) -> None:
        barrier.wait()
        try:
            for index in range(rounds):
                text = f"write to person{seed}-{index}@acme.com"
                produced.append((text, anonymizer.anonymize_into(text, vault)))
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")

    workers = [threading.Thread(target=work, args=(n,)) for n in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    return produced, errors


class TestASharedVaultIsSafe:
    def test_nothing_raises(self):
        """It used to raise `dictionary changed size during iteration` from
        inside the library."""
        _, errors = accumulate(Anonymizer(), Vault(), THREADS, ROUNDS)
        assert errors == []

    def test_every_value_is_recorded(self):
        """It recorded 780 of 1200 before, losing the rest to overwrites."""
        anonymizer = Anonymizer()
        vault = Vault()
        produced, _ = accumulate(anonymizer, vault, THREADS, ROUNDS)
        assert len(vault.snapshot()) == len(produced)

    def test_no_restore_returns_another_callers_value(self):
        """The failure that matters most: a wrong answer, not a missing one."""
        anonymizer = Anonymizer()
        vault = Vault()
        produced, _ = accumulate(anonymizer, vault, THREADS, ROUNDS)
        for original, safe in produced:
            assert anonymizer.restore(safe, vault) == original

    def test_no_token_stands_for_two_values(self):
        anonymizer = Anonymizer()
        vault = Vault()
        accumulate(anonymizer, vault, THREADS, ROUNDS)
        values = vault.snapshot()
        assert len(values) == len(set(values.values()))

    def test_a_repeated_value_keeps_one_token(self):
        """The property accumulation exists for, and it has to hold under
        concurrency too — otherwise a reader can no longer tell that two
        mentions refer to one thing."""
        anonymizer = Anonymizer()
        vault = Vault()
        barrier = threading.Barrier(THREADS)

        def work() -> None:
            barrier.wait()
            for _ in range(ROUNDS):
                anonymizer.anonymize_into("write to one@acme.com", vault)

        workers = [threading.Thread(target=work) for _ in range(THREADS)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        assert len(vault.snapshot()) == 1


class TestResumingFromExistingEntries:
    def test_a_vault_handed_back_resumes_numbering(self):
        """A vault from `anonymize` passed to `anonymize_into` must not
        restart at one and overwrite what the first call recorded."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("write to first@acme.com")
        anonymizer.anonymize_into("write to second@acme.com", vault)
        assert len(vault.snapshot()) == 2

    def test_a_vault_built_from_stored_values_resumes_too(self):
        """Loaded from a store or a file, which is how a vault survives a
        process boundary."""
        anonymizer = Anonymizer(token_format="at_signs")
        vault = Vault(values={"@@EMAIL_1@@": "first@acme.com"})
        anonymizer.anonymize_into("write to second@acme.com", vault)
        stored = vault.snapshot()
        assert len(stored) == 2
        assert "@@EMAIL_1@@" in stored
        assert stored["@@EMAIL_1@@"] == "first@acme.com"

    def test_a_value_already_in_a_loaded_vault_keeps_its_token(self):
        anonymizer = Anonymizer(token_format="at_signs")
        vault = Vault(values={"@@EMAIL_1@@": "first@acme.com"})
        safe = anonymizer.anonymize_into("write to first@acme.com", vault)
        assert "@@EMAIL_1@@" in safe
        assert len(vault.snapshot()) == 1


class TestTheLockIsNotPartOfTheData:
    def test_two_empty_vaults_compare_equal(self):
        """A lock is machinery. If it counted as data, no two vaults would
        ever be equal and a test comparing them would be unwritable."""
        assert Vault() == Vault()

    def test_the_repr_does_not_mention_it(self):
        assert "_lock" not in repr(Vault())

    @pytest.mark.parametrize("level", list(Level), ids=lambda item: item.value)
    def test_accumulating_holds_up_at_every_level(self, level):
        anonymizer = Anonymizer(level=level)
        vault = Vault()
        produced, errors = accumulate(anonymizer, vault, 4, 40)
        assert errors == []
        for original, safe in produced:
            assert anonymizer.restore(safe, vault) == original
