"""TestWhatEachLevelCovers."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level

CREDENTIAL = "AKIAIOSFODNN7EXAMPLE"


CONTACT = "me@example.com"


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
