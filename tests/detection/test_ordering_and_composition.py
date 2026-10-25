"""TestOrderingAndComposition."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.detectors import Registry
from maskvault.levels import Levels

CREDENTIAL = "AKIAIOSFODNN7EXAMPLE"


CONTACT = "me@example.com"


class TestOrderingAndComposition:
    def test_levels_grow_monotonically(self):
        counts = [
            len(Levels.detectors_for(level))
            for level in (Level.MINIMAL, Level.STANDARD, Level.STRICT)
        ]
        assert counts == sorted(counts)

    def test_a_level_accepts_its_string_name(self):
        assert len(Levels.detectors_for("strict")) == len(Levels.detectors_for(Level.STRICT))

    def test_an_unknown_level_name_is_rejected(self):
        with pytest.raises(ValueError):
            Levels.detectors_for("extremely-strict")

    def test_a_known_format_keeps_its_label(self):
        """Specific detectors must run before the entropy net, or a vendor key
        is destroyed as an anonymous blob and the log loses what it was."""
        _, vault = Anonymizer(level=Level.STRICT).anonymize(f"key {CREDENTIAL}")
        assert "aws_access_key" in vault.destroyed
        assert "high_entropy" not in vault.destroyed

    def test_explicit_detectors_override_the_level(self):
        anonymizer = Anonymizer(level=Level.PARANOID, detectors=())
        safe, vault = anonymizer.anonymize(f"{CONTACT} {CREDENTIAL}")
        assert safe == f"{CONTACT} {CREDENTIAL}"
        assert vault.replaced == 0

    def test_the_level_is_reported(self):
        assert "strict" in Anonymizer(level=Level.STRICT).describe_policy()


class TestRegistryWithoutEntropy:
    """The net is optional, because a caller who has their own detectors may
    not want a generic one firing on their identifiers."""

    def test_entropy_is_included_by_default(self):
        assert any(detector.label == "high_entropy" for detector in Registry.all_detectors())

    def test_it_can_be_left_out(self):
        labels = [d.label for d in Registry.all_detectors(include_entropy=False)]
        assert "high_entropy" not in labels
        assert labels, "the rest of the detectors should still be there"
