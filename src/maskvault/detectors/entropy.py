"""The net for secrets whose format nobody anticipated."""

from __future__ import annotations

from maskvault.entropy import CANDIDATE, ENTROPY_MIN_LENGTH, Entropy
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.models.entropy_thresholds import EntropyThresholds


class EntropyDetector:
    """Builds the detector that catches an unrecognized secret.

    Every other detector knows what it is looking for. This one does not: it
    measures how much a candidate looks like something generated rather than
    written, which is the only way to catch a credential whose issuer this
    library has never heard of.
    """

    @staticmethod
    def build(
        min_length: int = 0,
        relax_by: float = 0.0,
        include_symbols: bool = False,
        thresholds: EntropyThresholds | None = None,
    ) -> Detector:
        """Return a detector tuned by how eagerly it should fire.

        `relax_by` lowers every bar together and `min_length` shortens the
        candidate. Both catch more real secrets at the cost of more false
        positives, which is the trade the PARANOID level exists to make.

        `thresholds` sets the bars individually, for a codebase whose traffic
        the defaults suit badly — a repository full of hex digests, or one
        where every identifier looks generated. Tuning that should not need a
        release.
        """
        pattern = (
            CANDIDATE
            if min_length <= 0 and not include_symbols
            else Entropy.candidate_pattern(min_length or ENTROPY_MIN_LENGTH, include_symbols)
        )

        def validate(candidate: str) -> bool:
            return Entropy.looks_like_a_secret(
                candidate,
                relax_by=relax_by,
                min_length=min_length,
                thresholds=thresholds,
            )

        return Detector(
            label="high_entropy",
            pattern=pattern,
            action=Action.DESTROY,
            notice="[a value that looked like a secret was removed before sending]",
            validate=validate,
        )
