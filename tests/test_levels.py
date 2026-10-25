"""Each level must include what it claims and exclude what it does not.

A level that quietly includes more than documented surprises a caller with
false positives; one that includes less leaves data exposed. Both matter, so
each level is checked in both directions.
"""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level, detectors_for

CREDENTIAL = "AKIAIOSFODNN7EXAMPLE"
CONTACT = "me@example.com"
IDENTIFIER = "employee id EMP-4421"
SPECIAL = "I have diabetes"


class TestWhatEachLevelCovers:
    @pytest.mark.parametrize("level", list(Level))
    def test_every_level_stops_credentials(self, level):
        """No level is permissive about credentials."""
        safe, vault = Anonymizer(level=level).anonymize(f"key {CREDENTIAL}")
        assert CREDENTIAL not in safe
        assert vault.destroyed

    def test_minimal_leaves_contact_details(self):
        safe, _ = Anonymizer(level=Level.MINIMAL).anonymize(CONTACT)
        assert CONTACT in safe

    def test_standard_replaces_contact_details(self):
        safe, _ = Anonymizer(level=Level.STANDARD).anonymize(CONTACT)
        assert CONTACT not in safe

    def test_standard_leaves_special_categories(self):
        """'black' and 'union' are ordinary technical words, so the
        vocabularies are opt-in rather than on by default."""
        safe, _ = Anonymizer(level=Level.STANDARD).anonymize(SPECIAL)
        assert "diabetes" in safe

    def test_strict_replaces_special_categories(self):
        safe, _ = Anonymizer(level=Level.STRICT).anonymize(SPECIAL)
        assert "diabetes" not in safe

    def test_paranoid_catches_shorter_secrets(self):
        """A lower bar trades false positives for coverage."""
        short_secret = "k3yMaterial9xQ!zP"
        strict_safe, _ = Anonymizer(level=Level.STRICT).anonymize(f"token {short_secret}")
        paranoid_safe, _ = Anonymizer(level=Level.PARANOID).anonymize(f"token {short_secret}")
        assert short_secret in strict_safe
        assert short_secret not in paranoid_safe


class TestOrderingAndComposition:
    def test_levels_grow_monotonically(self):
        counts = [
            len(detectors_for(level)) for level in (Level.MINIMAL, Level.STANDARD, Level.STRICT)
        ]
        assert counts == sorted(counts)

    def test_a_level_accepts_its_string_name(self):
        assert len(detectors_for("strict")) == len(detectors_for(Level.STRICT))

    def test_an_unknown_level_name_is_rejected(self):
        with pytest.raises(ValueError):
            detectors_for("extremely-strict")

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
