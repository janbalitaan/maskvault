"""Concurrency models other than threads: asyncio, and separate processes.

asyncio is the easier case and it is worth knowing why rather than trusting a
green test. This library contains no `await`, so on an event loop
`anonymize()` runs to completion before any other coroutine resumes — there
is no interleaving to protect against. `asyncio.to_thread` and a thread-pool
executor put the threaded case back, which is what the locks are for.

Separate processes are different again: a vault is an ordinary Python object,
so it travels only if it is serialized. Adding a lock made that impossible
and broke every pickle-based route — a process pool, multiprocessing, a task
queue — which are exactly where a vault needs to travel.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import importlib
import inspect
import pickle
import pkgutil
import random

import maskvault
from maskvault import Anonymizer
from maskvault.models.vault import Vault

# These push the format chooser different ways, which is what made the
# original race observable.
WITH_MARKER = "@@ marker @@ email person{n}@acme.com"
PLAIN = "email person{n}@acme.com"
CALLERS = 120


def question(caller: int) -> str:
    template = WITH_MARKER if caller % 2 == 0 else PLAIN
    return template.format(n=caller)


def anonymize_and_restore(caller: int) -> tuple[str, str]:
    """One whole operation, for running in a worker thread or process."""
    anonymizer = Anonymizer()
    text = question(caller)
    safe, vault = anonymizer.anonymize(text)
    return text, anonymizer.restore(safe, vault)


class TestTheLibraryIsSynchronous:
    def test_no_module_defines_a_coroutine(self):
        """The reason the async case needs no locking: with no await in the
        path, a coroutine cannot be interrupted part-way through it."""

        coroutines = []
        for info in pkgutil.walk_packages(maskvault.__path__, "maskvault."):
            if info.name.endswith("__main__"):
                continue
            module = importlib.import_module(info.name)
            coroutines += [
                f"{info.name}.{name}"
                for name, value in vars(module).items()
                if inspect.iscoroutinefunction(value)
            ]
        assert coroutines == []


class TestUnderAsyncio:
    def test_concurrent_requests_keep_their_own_values(self):
        """The web-app shape: one shared anonymizer, an await in the middle."""
        shared = Anonymizer()
        failures: list[int] = []

        async def provider(prompt: str) -> str:
            await asyncio.sleep(random.uniform(0, 0.001))
            return f"noted. {prompt}"

        async def handle(caller: int) -> None:
            text = question(caller)
            safe, vault = shared.anonymize(text)
            reply = await provider(safe)
            if f"person{caller}@acme.com" not in shared.restore(reply, vault):
                failures.append(caller)

        async def main() -> None:
            await asyncio.gather(*(handle(n) for n in range(CALLERS)))

        asyncio.run(main())
        assert failures == []

    def test_no_request_sees_another_requests_value(self):
        shared = Anonymizer()
        leaks: list[tuple[int, int]] = []

        async def handle(caller: int) -> None:
            safe, _ = shared.anonymize(question(caller))
            await asyncio.sleep(0)
            for other in range(CALLERS):
                if other != caller and f"person{other}@acme.com" in safe:
                    leaks.append((caller, other))

        async def main() -> None:
            await asyncio.gather(*(handle(n) for n in range(CALLERS)))

        asyncio.run(main())
        assert leaks == []

    def test_a_shared_vault_across_turns_holds_up(self):
        """One conversation, one vault, turns arriving concurrently."""
        shared = Anonymizer()
        conversation = Vault()
        failures: list[int] = []

        async def turn(index: int) -> None:
            text = f"turn {index}: email person{index}@acme.com"
            safe = shared.anonymize_into(text, conversation)
            await asyncio.sleep(random.uniform(0, 0.001))
            if shared.restore(safe, conversation) != text:
                failures.append(index)

        async def main() -> None:
            await asyncio.gather(*(turn(n) for n in range(CALLERS)))

        asyncio.run(main())
        assert failures == []
        assert len(conversation.snapshot()) == CALLERS


class TestUnderAThreadPool:
    def test_asyncio_to_thread_is_safe(self):
        """`to_thread` hands the work to a real thread, so this is the
        threaded case reached through async code."""
        failures: list[int] = []

        async def handle(caller: int) -> None:
            text, restored = await asyncio.to_thread(anonymize_and_restore, caller)
            if restored != text:
                failures.append(caller)

        async def main() -> None:
            await asyncio.gather(*(handle(n) for n in range(CALLERS)))

        asyncio.run(main())
        assert failures == []

    def test_a_thread_pool_executor_is_safe(self):
        """What a sync WSGI server does under the hood."""
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(anonymize_and_restore, range(CALLERS)))
        assert all(text == restored for text, restored in results)


class TestAcrossProcesses:
    def test_a_vault_survives_a_pickle_round_trip(self):
        """Adding a lock made every vault unpicklable, which broke a process
        pool, multiprocessing, and any task queue using pickle."""
        anonymizer = Anonymizer()
        safe, vault = anonymizer.anonymize("email me@acme.com")
        revived_safe, revived_vault = pickle.loads(pickle.dumps((safe, vault)))
        assert anonymizer.restore(revived_safe, revived_vault) == "email me@acme.com"

    def test_an_unpickled_vault_still_allocates_safely(self):
        """It gets a fresh lock: a lock means nothing across a process
        boundary, and the revived vault has its own callers."""
        revived = pickle.loads(pickle.dumps(Vault()))
        token = revived.mint("EMAIL", "me@acme.com")
        assert revived.snapshot() == {token: "me@acme.com"}

    def test_a_vault_crosses_a_process_boundary(self):
        with ProcessPoolExecutor(max_workers=2) as pool:
            text, restored = pool.submit(anonymize_and_restore, 1).result()
        assert text == restored

    def test_the_lock_is_not_part_of_the_pickled_state(self):
        assert "_lock" not in pickle.loads(pickle.dumps(Vault())).__getstate__()
