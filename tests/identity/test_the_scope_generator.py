"""Markers that do not repeat within a process.

Drawing every letter from the CSPRNG made each marker cost twelve round
trips, about 9 us, and left the full birthday problem over every vault ever
in flight. A process prefix plus a counter costs a counter increment, and
within a process two markers cannot agree — arithmetic, not probability.

What remains is two *processes* drawing the same prefix, which is a far
smaller population than two vaults drawing the same marker.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from maskvault.constants import SCOPE_LETTERS
from maskvault.scopes import ALPHABET, GENERATOR, ScopeGenerator, encode


class TestEncode:
    def test_it_produces_the_requested_width(self):
        assert len(encode(0, 6)) == 6
        assert len(encode(10**12, 6)) == 6

    def test_zero_is_the_first_letter_repeated(self):
        assert encode(0, 4) == ALPHABET[0] * 4

    def test_consecutive_numbers_differ(self):
        assert encode(1, 4) != encode(2, 4)

    def test_it_is_letters_only(self):
        """A digit would stop a scoped token matching its own vault's
        pattern, which is what `leaked()` relies on."""
        rendered = encode(123456789, 8)
        assert rendered.isalpha()
        assert rendered.isupper()

    def test_it_wraps_rather_than_widening(self):
        """A fixed width keeps a token's shape stable. Wrapping is safe
        because the prefix, not the counter, separates processes."""
        assert len(encode(len(ALPHABET) ** 4, 4)) == 4


class TestAGeneratorDoesNotRepeat:
    def test_consecutive_markers_differ(self):
        generator = ScopeGenerator(prefix_letters=8)
        assert generator.next_marker(12) != generator.next_marker(12)

    def test_a_hundred_thousand_are_distinct(self):
        generator = ScopeGenerator(prefix_letters=8)
        markers = {generator.next_marker(12) for _ in range(100_000)}
        assert len(markers) == 100_000

    def test_the_prefix_is_stable(self):
        """Fixed for the generator's lifetime, so it identifies the process."""
        generator = ScopeGenerator(prefix_letters=8)
        assert generator.prefix == generator.prefix
        assert len(generator.prefix) == 8

    def test_two_generators_draw_different_prefixes(self):
        """What stands in for two processes."""
        assert (
            ScopeGenerator(prefix_letters=8).prefix != ScopeGenerator(prefix_letters=8).prefix
        )

    @pytest.mark.parametrize("letters", [1, 2, 4, 8, 12, 16, 24])
    def test_any_width_is_honored(self, letters):
        generator = ScopeGenerator(prefix_letters=8)
        assert len(generator.next_marker(letters)) == letters

    @pytest.mark.parametrize("letters", [4, 12, 24])
    def test_markers_stay_distinct_within_capacity(self, letters):
        """Distinct up to the counter's capacity, which is what is claimed."""
        generator = ScopeGenerator(prefix_letters=8)
        draws = min(500, ScopeGenerator.capacity(letters))
        markers = {generator.next_marker(letters) for _ in range(draws)}
        assert len(markers) == draws


class TestTheCounterWraps:
    """The guarantee is "does not repeat", not "cannot repeat".

    The counter takes half the marker's width, so a narrow marker has a small
    capacity and a process that exceeds it sees a marker again. At the default
    twelve letters that is 308 million vaults from one process, so it is a
    caveat rather than a hazard — but it is a real one, and `capacity()`
    exists so nobody has to discover it.
    """

    @pytest.mark.parametrize(
        ("letters", "expected"),
        [(2, 26), (4, 676), (8, 456_976), (12, 308_915_776)],
    )
    def test_capacity_is_reported(self, letters, expected):
        assert ScopeGenerator.capacity(letters) == expected

    def test_a_narrow_marker_repeats_past_its_capacity(self):
        """Demonstrated rather than described, so the limit is not folklore."""
        generator = ScopeGenerator(prefix_letters=8)
        capacity = ScopeGenerator.capacity(2)
        markers = [generator.next_marker(2) for _ in range(capacity + 1)]
        assert len(set(markers)) == capacity
        assert markers[0] == markers[capacity]

    def test_the_default_capacity_is_beyond_any_process(self):
        assert ScopeGenerator.capacity(SCOPE_LETTERS) > 300_000_000


class TestTheCounterIsThreadSafe:
    def test_racing_threads_never_receive_the_same_marker(self):
        """Two threads asking at once must not get one marker between them."""
        generator = ScopeGenerator(prefix_letters=8)

        def batch(_: int) -> list[str]:
            return [generator.next_marker(12) for _ in range(2_000)]

        with ThreadPoolExecutor(max_workers=16) as pool:
            produced = [marker for chunk in pool.map(batch, range(16)) for marker in chunk]

        assert len(produced) == 32_000
        assert len(set(produced)) == 32_000


class TestTheSharedGenerator:
    def test_one_exists_for_the_process(self):
        assert isinstance(GENERATOR, ScopeGenerator)

    def test_it_has_a_prefix(self):
        """A generator per vault would defeat the point: the counter has to
        be shared for it to guarantee anything."""
        assert GENERATOR.prefix.isalpha()
