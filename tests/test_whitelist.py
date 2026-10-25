"""The allowlist is the control surface, so each mechanism needs its own test.

Every test here pairs an allowed case with a denied one. A whitelist that
allows too much silently removes the protection the library exists to
provide, and that failure is invisible without the negative case.
"""

from __future__ import annotations

import re

import pytest

from maskvault import Anonymizer, Level, Whitelist
from maskvault.whitelist import COMMON_SAFE_VALUES, TECHNICAL_HOMONYMS


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


class TestValues:
    def test_an_exact_value_passes_through(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        safe, _ = anonymizer.anonymize("write to me@example.com")
        assert "me@example.com" in safe

    def test_case_does_not_matter(self):
        anonymizer = Anonymizer(whitelist={"values": ["ME@EXAMPLE.COM"]})
        safe, _ = anonymizer.anonymize("write to me@example.com")
        assert "me@example.com" in safe

    def test_a_different_value_is_still_replaced(self):
        anonymizer = Anonymizer(whitelist={"values": ["me@example.com"]})
        safe, _ = anonymizer.anonymize("write to other@example.com")
        assert "other@example.com" not in safe

    def test_trailing_punctuation_does_not_defeat_a_value(self):
        """A detector may hand over the match with sentence punctuation
        attached, which an exact entry would otherwise fail to match."""
        anonymizer = Anonymizer(whitelist={"values": ["https://example.com/me"]})
        safe, _ = anonymizer.anonymize("see https://example.com/me, then go")
        assert "https://example.com/me" in safe


class TestWords:
    def test_a_word_passes_through(self):
        anonymizer = Anonymizer(level=Level.STRICT, whitelist={"words": ["black"]})
        safe, _ = anonymizer.anonymize("the black formatter")
        assert "black" in safe

    def test_a_word_entry_does_not_allow_a_longer_match(self):
        anonymizer = Anonymizer(level=Level.STRICT, whitelist={"words": ["bi"]})
        safe, _ = anonymizer.anonymize("I am bisexual")
        assert "bisexual" not in safe


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


class TestConfig:
    def test_it_round_trips_through_json(self):
        original = Whitelist(
            labels={"url"},
            values={"Python"},
            words={"black"},
            domains={"example.com"},
            prefixes=("https://a/",),
            patterns=(re.compile(r"^X\d+$"),),
        )
        assert Whitelist.from_dict(original.as_dict()).as_dict() == original.as_dict()

    def test_empty_config_allows_nothing(self):
        whitelist = Whitelist.from_dict(None)
        assert not whitelist.allows_value("me@example.com")
        assert whitelist.describe() == "nothing allowed through"

    def test_merge_combines_two_policies(self):
        base = Whitelist(values={"Python"})
        extra = Whitelist(values={"FastAPI"}, labels={"url"})
        merged = base.merge(extra)
        assert merged.allows_value("python")
        assert merged.allows_value("fastapi")
        assert merged.allows_label("url")

    def test_as_dict_omits_empty_fields(self):
        assert Whitelist(values={"Python"}).as_dict() == {"values": ["Python"]}

    def test_describe_is_safe_to_log(self):
        """The summary goes in logs, so it must not contain the values."""
        whitelist = Whitelist(values={"secret-project-name"})
        assert "secret-project-name" not in whitelist.describe()


class TestCuratedLists:
    @pytest.mark.parametrize("name", ["python", "fastapi", "postgresql", "kubernetes"])
    def test_common_safe_values_covers_the_obvious(self, name):
        assert name in COMMON_SAFE_VALUES

    @pytest.mark.parametrize("word", ["black", "native", "union", "terminal"])
    def test_homonyms_lists_words_with_technical_meanings(self, word):
        assert word in TECHNICAL_HOMONYMS

    def test_the_curated_lists_work_as_a_whitelist(self):
        anonymizer = Anonymizer(
            level=Level.STRICT,
            whitelist={
                "words": sorted(TECHNICAL_HOMONYMS),
                "values": sorted(COMMON_SAFE_VALUES),
            },
        )
        safe, _ = anonymizer.anonymize("I use black and Python on a native terminal")
        for word in ("black", "Python", "native", "terminal"):
            assert word in safe
