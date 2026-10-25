"""TestInspection."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level


@pytest.fixture
def strict() -> Anonymizer:
    return Anonymizer(level=Level.STRICT)


class TestInspection:
    def test_explain_reports_what_would_happen(self, strict):
        findings = strict.explain("me@example.com and key AKIAIOSFODNN7EXAMPLE")
        labels = {finding.label for finding in findings}
        assert "EMAIL" in labels
        assert "AWS_ACCESS_KEY" in labels

    def test_explain_marks_allowed_values(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        findings = anonymizer.explain("me@example.com")
        assert findings
        assert all(finding.allowed for finding in findings)

    def test_findings_are_in_text_order(self, strict):
        findings = strict.explain("first me@example.com then 10.0.0.1")
        positions = [finding.start for finding in findings]
        assert positions == sorted(positions)

    def test_preview_is_readable(self, strict):
        report = strict.preview("me@example.com")
        assert "EMAIL" in report
        assert "would be replaced" in report

    def test_preview_says_so_when_nothing_matches(self, strict):
        assert strict.preview("hello there") == "nothing would be replaced"

    def test_suggest_whitelist_omits_credentials(self, strict):
        """Allowing a credential through is almost never correct, so a
        generated draft must not propose it."""
        draft = strict.suggest_whitelist("me@example.com key AKIAIOSFODNN7EXAMPLE")
        assert "AKIAIOSFODNN7EXAMPLE" not in draft["values"]
        assert "me@example.com" in draft["values"]

    def test_suggest_whitelist_output_is_usable_as_config(self, strict):
        draft = strict.suggest_whitelist("me@example.com")
        relaxed = Anonymizer(level=Level.STRICT, whitelist=draft)
        safe, _ = relaxed.anonymize("me@example.com")
        assert "me@example.com" in safe

    def test_explain_does_not_mutate_the_text(self, strict):
        text = "me@example.com"
        strict.explain(text)
        assert text == "me@example.com"
