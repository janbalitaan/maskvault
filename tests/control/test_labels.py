"""TestLabels."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestLabels:
    def test_a_label_turns_a_detector_off(self):
        anonymizer = Anonymizer(whitelist={"labels": ["email"]})
        safe, _ = anonymizer.anonymize("write to me@example.com")
        assert "me@example.com" in safe

    def test_other_detectors_still_run(self):
        anonymizer = Anonymizer(whitelist={"labels": ["email"]})
        safe, _ = anonymizer.anonymize("me@example.com and 10.0.0.1")
        assert "10.0.0.1" not in safe

    def test_a_category_turns_a_vocabulary_off(self):
        anonymizer = Anonymizer(level=Level.STRICT, whitelist={"categories": ["health"]})
        safe, _ = anonymizer.anonymize("I have diabetes")
        assert "diabetes" in safe
