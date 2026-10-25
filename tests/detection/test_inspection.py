"""TestInspection."""

from __future__ import annotations

import pytest

from maskvault import Anonymizer, Level
from maskvault.models.vault import Vault


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


class TestCallerSuppliedTerms:
    """A term behaves exactly like a reversible detector, and is reported
    through the same path — so `explain` shows it rather than leaving the
    caller to wonder whether their term took effect."""

    def test_a_term_is_replaced(self):
        anonymizer = Anonymizer(terms={"employer": ["Initech"]})
        safe, vault = anonymizer.anonymize("I work at Initech")
        assert "Initech" not in safe
        assert vault.replaced == 1

    def test_a_term_appears_in_explain(self):
        """Upper-cased, because that is how it appears in a token — the report
        and the output agree."""
        anonymizer = Anonymizer(terms={"employer": ["Initech"]})
        labels = [finding.label for finding in anonymizer.explain("I work at Initech")]
        assert "EMPLOYER" in labels

    def test_a_term_round_trips(self):
        anonymizer = Anonymizer(terms={"employer": ["Initech"]})
        safe, vault = anonymizer.anonymize("I work at Initech")
        assert anonymizer.restore(safe, vault) == "I work at Initech"


class TestSuggestWhitelistScope:
    """`only_reversible` is the default because a destroyed value is a
    credential, and suggesting a credential for the allowlist is the one
    suggestion this must not make."""

    def test_by_default_a_credential_is_not_suggested(self):
        key = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        draft = Anonymizer().suggest_whitelist(f"email me@acme.com key={key}")
        assert not any(key in value for value in draft["values"])

    def test_a_reversible_value_is_suggested(self):
        draft = Anonymizer().suggest_whitelist("write to me@acme.com")
        assert "me@acme.com" in draft["values"]

    def test_destroyed_values_can_be_included_deliberately(self):
        """For reviewing everything the policy touched, which is a different
        job from building an allowlist."""
        key = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        draft = Anonymizer().suggest_whitelist(
            f"email me@acme.com key={key}", only_reversible=False
        )
        assert len(draft["values"]) > 1

    def test_the_draft_carries_a_warning_note(self):
        """It is a draft, and acting on it without reading it would allow
        whatever the policy happened to find."""
        draft = Anonymizer().suggest_whitelist("write to me@acme.com")
        assert "draft" in draft["note"]


class TestRestoringACountFromAVault:
    def test_counters_resume_from_an_existing_vault(self):
        """`anonymize_into` accumulates, so the second call must not restart
        numbering and overwrite the first call's tokens."""
        anonymizer = Anonymizer()
        _, vault = anonymizer.anonymize("write to me@acme.com")
        anonymizer.anonymize_into("and to you@acme.com", vault)
        assert len(vault.values) == 2

    def test_a_vault_holding_a_foreign_token_does_not_break_resuming(self):
        """A vault round-tripped through a different format may hold a key
        this format cannot parse. Skipping it beats refusing to continue."""

        vault = Vault(values={"not-a-token": "value"})
        anonymizer = Anonymizer()
        anonymizer.anonymize_into("write to me@acme.com", vault)
        assert len(vault.values) == 2
