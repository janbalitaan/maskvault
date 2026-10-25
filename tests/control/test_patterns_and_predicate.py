"""TestPatternsAndPredicate."""

from __future__ import annotations

from maskvault import Anonymizer, Whitelist


class TestPatternsAndPredicate:
    def test_a_pattern_allows_matches(self):
        anonymizer = Anonymizer(whitelist={"patterns": [r"@example\.com$"]})
        safe, _ = anonymizer.anonymize("me@example.com")
        assert "me@example.com" in safe

    def test_a_predicate_allows_whatever_it_says(self):
        whitelist = Whitelist(predicate=lambda value: value.endswith("example.com"))
        anonymizer = Anonymizer(whitelist=whitelist)
        safe, _ = anonymizer.anonymize("me@example.com and me@other.com")
        assert "me@example.com" in safe
        assert "me@other.com" not in safe

    def test_a_predicate_has_no_json_form(self):
        """A config file must not be able to introduce executable code."""
        assert Whitelist.from_dict({"predicate": "lambda v: True"}).predicate is None
