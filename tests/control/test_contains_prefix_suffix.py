"""TestContainsPrefixSuffix."""

from __future__ import annotations

from maskvault import Anonymizer


class TestContainsPrefixSuffix:
    def test_contains_allows_a_family(self):
        anonymizer = Anonymizer(whitelist={"contains": ["github.com"]})
        safe, _ = anonymizer.anonymize("https://github.com/anyone/repo")
        assert "github.com" in safe

    def test_a_prefix_allows_a_family(self):
        anonymizer = Anonymizer(whitelist={"prefixes": ["https://mysite.dev/"]})
        safe, _ = anonymizer.anonymize("https://mysite.dev/about")
        assert "mysite.dev/about" in safe

    def test_a_prefix_does_not_allow_another_host(self):
        anonymizer = Anonymizer(whitelist={"prefixes": ["https://mysite.dev/"]})
        safe, _ = anonymizer.anonymize("https://elsewhere.dev/about")
        assert "elsewhere.dev" not in safe

    def test_a_suffix_allows_a_family(self):
        anonymizer = Anonymizer(whitelist={"suffixes": ["@mycompany.com"]})
        safe, _ = anonymizer.anonymize("write to anyone@mycompany.com")
        assert "anyone@mycompany.com" in safe
