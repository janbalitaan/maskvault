"""TestLevelsSection."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


class TestLevelsSection:
    @pytest.mark.parametrize(
        "level", [Level.MINIMAL, Level.STANDARD, Level.STRICT, Level.PARANOID]
    )
    def test_every_documented_level_exists(self, level):
        assert Anonymizer(level=level).level is level

    def test_strict_adds_the_special_categories(self):
        """README: STRICT adds health, religion, politics, identity, origin,
        criminal."""
        standard, _ = Anonymizer(level=Level.STANDARD).anonymize("I have diabetes")
        strict, _ = Anonymizer(level=Level.STRICT).anonymize("I have diabetes")
        assert "diabetes" in standard
        assert "diabetes" not in strict
