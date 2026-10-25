"""The bar a candidate has to clear to count as random."""

from __future__ import annotations

from dataclasses import dataclass

from maskvault.constants import (
    BASE64_THRESHOLD,
    HEX_THRESHOLD,
    MIN_CHARACTER_CLASSES,
    MIXED_THRESHOLD,
)
from maskvault.exceptions import DetectorError


@dataclass(frozen=True)
class EntropyThresholds:
    """Per-alphabet entropy bars, and the character-class minimum.

    These were constants, which made them adjustable only by editing the
    installed package or by shifting all three together with `relax_by`.
    Tuning a detector to one codebase's actual traffic is the most ordinary
    reason to reach into a library like this, and it should not need a
    release.

    One bar per alphabet because the maximum differs: hex tops out at 4 bits
    per character, base64 at 6, and an unconstrained alphabet higher still.
    A single number would be too strict for hex or too loose for everything
    else.

        EntropyThresholds(hex=2.8)              # catch shorter hex digests
        EntropyThresholds.relaxed_by(0.5)       # the PARANOID trade
        EntropyThresholds(minimum_classes=3)    # demand more variety
    """

    hex: float = HEX_THRESHOLD
    base64: float = BASE64_THRESHOLD
    mixed: float = MIXED_THRESHOLD
    minimum_classes: int = MIN_CHARACTER_CLASSES

    def __post_init__(self) -> None:
        """Reject a configuration that could never match anything."""
        for name, value in (
            ("hex", self.hex),
            ("base64", self.base64),
            ("mixed", self.mixed),
        ):
            if value < 0:
                raise DetectorError(
                    f"the {name} entropy threshold cannot be negative "
                    f"(got {value}); 0 accepts everything of the right shape"
                )
        if self.minimum_classes < 1:
            raise DetectorError(
                f"minimum_classes must be at least 1 (got {self.minimum_classes}); "
                "every non-empty candidate has one character class"
            )

    @classmethod
    def relaxed_by(cls, amount: float) -> EntropyThresholds:
        """Lower every bar by `amount`, catching more and misfiring more.

        What `PARANOID` does. Kept as a named constructor because "relax
        everything a bit" is a coherent intention, while picking three
        numbers independently usually is not.
        """
        return cls(
            hex=max(cls.hex - amount, 0.0),
            base64=max(cls.base64 - amount, 0.0),
            mixed=max(cls.mixed - amount, 0.0),
        )

    def for_alphabet(self, alphabet: str) -> float:
        """Return the bar for a named alphabet, falling back to `mixed`.

        An unknown name gets the mixed bar rather than raising: the alphabet
        is decided inside the classifier, so an unknown one would mean a bug
        here rather than bad input from a caller — and the strictest
        reasonable default is the safe response to it.
        """
        return {"hex": self.hex, "base64": self.base64}.get(alphabet, self.mixed)

    def describe(self) -> str:
        """Summarize the bars, for a line that is safe to log."""
        return (
            f"entropy bars: hex {self.hex}, base64 {self.base64}, "
            f"mixed {self.mixed}, at least {self.minimum_classes} character classes"
        )
