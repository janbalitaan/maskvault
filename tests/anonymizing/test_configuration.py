"""TestConfiguration."""

from __future__ import annotations

import re

import pytest

from maskvault import Action, Anonymizer, Detector


@pytest.fixture
def anonymizer() -> Anonymizer:
    return Anonymizer(terms={"ORG": ["Acme Corporation", "Acme", "Initech"]})


class TestConfiguration:
    def test_it_can_be_switched_off(self):
        anonymizer = Anonymizer(terms={"ORG": ["Acme"]}, enabled=False)
        safe, vault = anonymizer.anonymize("Acme and a@b.com")
        assert safe == "Acme and a@b.com"
        assert vault.replaced == 0

    def test_custom_detectors_replace_the_defaults(self):
        detector = Detector(
            label="employee_id",
            pattern=re.compile(r"\bEMP-\d{4}\b"),
            action=Action.REVERSIBLE,
        )
        anonymizer = Anonymizer(detectors=(detector,))
        safe, vault = anonymizer.anonymize("EMP-1234 wrote a@b.com")
        assert vault.token_format.render("EMPLOYEE_ID", 1) in safe
        assert "a@b.com" in safe, "only the given detectors should apply"
        assert anonymizer.restore(safe, vault) == "EMP-1234 wrote a@b.com"

    def test_empty_input_is_safe(self, anonymizer):
        safe, vault = anonymizer.anonymize("")
        assert safe == ""
        assert vault.replaced == 0

    def test_restoring_without_a_vault_is_a_no_op(self, anonymizer):
        _, vault = anonymizer.anonymize("nothing here")
        assert anonymizer.restore("some answer", vault) == "some answer"
