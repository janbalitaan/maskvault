"""TestInspectionSection."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestInspectionSection:
    def test_preview_reports_the_documented_shape(self):
        """README shows lines of 'state LABEL value' and a closing count."""
        anonymizer = Anonymizer(level=Level.STRICT)
        report = anonymizer.preview("me@example.com and key AKIAIOSFODNN7EXAMPLE")
        assert "findings at level strict" in report
        assert "EMAIL" in report
        assert "AWS_ACCESS_KEY" in report
        assert "would be replaced" in report

    def test_the_vault_summary_shape(self):
        """README: '1 age, 2 health, 1 salary, 1 street_address, 1 destroyed'."""
        anonymizer = Anonymizer(level=Level.STRICT)
        _, vault = anonymizer.anonymize("I have diabetes and a heart attack")
        assert "2 health" in vault.summary()

    def test_suggest_whitelist_is_usable_as_config(self):
        anonymizer = Anonymizer(level=Level.STRICT)
        draft = anonymizer.suggest_whitelist("me@example.com")
        relaxed = Anonymizer(level=Level.STRICT, whitelist=draft)
        assert "me@example.com" in relaxed.anonymize("me@example.com")[0]
