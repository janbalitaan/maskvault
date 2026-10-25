"""Changing a shipped detector set without waiting for a release.

A pattern in a library is a liability on a release cycle: a vendor changes a
key format, a region writes phone numbers differently, a detector fires on
something harmless in one codebase and nowhere else. None of those should
mean opening an issue and waiting.

Adding was always possible — pass `detectors=(*shipped, mine)`. Replacing one
of forty-one was not: it meant rebuilding the list by hand and keeping that
code in step with every future version. So the three operations live here,
applied by label:

    replace    a shipped detector is wrong or out of date
    without    a shipped detector is noise in this codebase
    add        something this codebase has that no library would know
    add_first  the same, but it has to win a span a shipped one would claim

A label rather than an index, because the order of a shipped list is an
implementation detail and pinning code to a position in it is a way to break
on an upgrade.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from maskvault.exceptions import DetectorError
from maskvault.models.detector import Detector


class Adjustments:
    """Applies a caller's replacements, removals and additions to a set.

    Order is preserved. A replacement takes the position of what it replaced,
    so the ordering guarantees the shipped set depends on — specific before
    generic, destructive before reversible, entropy last — still hold.

    `add` appends, which is right for a detector that catches what the
    shipped ones missed. `add_first` prepends, for one that has to *win* a
    span a shipped detector would otherwise claim — an internal identifier
    like `EMP-004212` is a punctuated digit run, so the phone detector takes
    it unless something runs earlier.
    """

    @staticmethod
    def apply(
        detectors: Sequence[Detector],
        *,
        replace: Mapping[str, Detector] | None = None,
        without: Iterable[str] | None = None,
        add: Iterable[Detector] | None = None,
        add_first: Iterable[Detector] | None = None,
    ) -> tuple[Detector, ...]:
        """Return `detectors` with the adjustments applied.

        A label in `replace` or `without` that is not in the set raises. That
        is deliberate: the usual cause is a typo or a label this version
        renamed, and silently doing nothing would leave a caller believing
        their replacement was in effect when the original was still running.
        """
        swaps = dict(replace or {})
        removals = set(without or ())
        Adjustments._check_labels(detectors, swaps, removals)

        kept = tuple(
            swaps.get(detector.label, detector)
            for detector in detectors
            if detector.label not in removals
        )
        return tuple(add_first or ()) + kept + tuple(add or ())

    @staticmethod
    def _check_labels(
        detectors: Sequence[Detector],
        swaps: Mapping[str, Detector],
        removals: set[str],
    ) -> None:
        """Raise when a named label is not in the set, listing what is."""
        available = {detector.label for detector in detectors}
        for operation, names in (("replace", set(swaps)), ("without", removals)):
            unknown = sorted(names - available)
            if not unknown:
                continue
            raise DetectorError(
                f"{operation} names a detector that is not in this set: "
                f"{', '.join(unknown)}. Available labels are: "
                f"{', '.join(sorted(available))}"
            )
