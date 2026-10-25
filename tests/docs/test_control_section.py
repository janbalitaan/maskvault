"""TestControlSection."""

from __future__ import annotations

from maskvault import Anonymizer, Level


class TestControlSection:
    def test_every_documented_whitelist_key_is_honored(self):
        """README lists nine keys. Each has to actually do something."""
        anonymizer = Anonymizer(
            level=Level.STRICT,
            whitelist={
                "labels": ["url", "age"],
                "categories": ["identity"],
                "values": ["Python", "FastAPI"],
                "words": ["black", "native"],
                "contains": ["github.com"],
                "prefixes": ["https://mysite.dev/"],
                "suffixes": ["@mycompany.com"],
                "domains": ["mycompany.com"],
                "patterns": [r"^EMP-\d{4}$"],
            },
        )
        whitelist = anonymizer.whitelist
        assert whitelist.allows_label("url")
        assert whitelist.allows_label("identity")
        assert whitelist.allows_value("Python")
        assert whitelist.allows_value("black")
        assert whitelist.allows_value("https://github.com/x")
        assert whitelist.allows_value("https://mysite.dev/about")
        assert whitelist.allows_value("me@mycompany.com")
        assert whitelist.allows_value("EMP-1234")

    def test_nothing_is_allowed_by_default(self):
        """README: 'Nothing is allowed through by default'."""
        assert Anonymizer().whitelist.describe() == "nothing allowed through"
