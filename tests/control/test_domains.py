"""TestDomains."""

from __future__ import annotations

from maskvault import Anonymizer


class TestDomains:
    def test_a_domain_allows_its_addresses(self):
        anonymizer = Anonymizer(whitelist={"domains": ["example.com"]})
        safe, _ = anonymizer.anonymize("me@example.com")
        assert "me@example.com" in safe

    def test_a_domain_allows_subdomains(self):
        """Listing a company domain means the company, not one host."""
        anonymizer = Anonymizer(whitelist={"domains": ["example.com"]})
        safe, _ = anonymizer.anonymize("me@mail.example.com")
        assert "me@mail.example.com" in safe

    def test_a_domain_does_not_allow_a_lookalike(self):
        anonymizer = Anonymizer(whitelist={"domains": ["example.com"]})
        safe, _ = anonymizer.anonymize("me@notexample.com")
        assert "notexample.com" not in safe

    def test_a_domain_allows_urls_too(self):
        anonymizer = Anonymizer(whitelist={"domains": ["example.com"]})
        safe, _ = anonymizer.anonymize("https://example.com/page")
        assert "example.com/page" in safe
