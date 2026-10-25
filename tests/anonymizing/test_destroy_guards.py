"""What stops a destructive detector from destroying the wrong thing.

A destroyed value is not coming back, so the two guards in front of that
decision matter more than the ones in front of a reversible replacement: a
mistake here loses data permanently rather than tokenizing it.
"""

from __future__ import annotations

from maskvault import Anonymizer, Level, Whitelist, restore_data
from maskvault.structured import anonymize_data

API_KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"


class TestAWhitelistStopsDestruction:
    def test_an_exact_value_spares_the_detector_that_matched_it(self):
        """`values` is compared against the whole match, so it spares the
        detector whose span is exactly the value."""
        anonymizer = Anonymizer(whitelist={"values": [API_KEY]})
        safe, _ = anonymizer.anonymize(f"the key is {API_KEY} okay")
        assert API_KEY in safe

    def test_an_exact_value_does_not_spare_a_wider_match(self):
        """Worth knowing rather than discovering: the entropy detector takes
        the whole assignment `key=sk_live_...`, so an exact entry for the key
        alone does not match what it claimed. `contains` or `patterns` is the
        answer when another detector may take a wider span."""
        anonymizer = Anonymizer(whitelist={"values": [API_KEY]})
        safe, _ = anonymizer.anonymize(f"key={API_KEY}")
        assert API_KEY not in safe

    def test_contains_spares_it_whatever_the_span(self):
        anonymizer = Anonymizer(whitelist={"contains": [API_KEY]})
        safe, vault = anonymizer.anonymize(f"key={API_KEY}")
        assert API_KEY in safe
        assert vault.destroyed == []

    def test_a_pattern_spares_it_too(self):
        anonymizer = Anonymizer(whitelist={"patterns": [r"sk_live_\w+"]})
        safe, _ = anonymizer.anonymize(f"key={API_KEY}")
        assert API_KEY in safe

    def test_an_unwhitelisted_one_still_goes(self):
        safe, vault = Anonymizer().anonymize(f"key={API_KEY}")
        assert API_KEY not in safe
        assert vault.destroyed

    def test_a_predicate_can_spare_it(self):
        anonymizer = Anonymizer(
            whitelist=Whitelist(predicate=lambda value: value.endswith("dp7dc"))
        )
        safe, _ = anonymizer.anonymize(f"key={API_KEY}")
        assert API_KEY in safe


class TestAValidatorStopsDestruction:
    def test_a_candidate_the_validator_rejects_survives(self):
        """The entropy detector destroys, and its validator is what separates
        a real secret from a long identifier. A rejected candidate has to come
        back untouched rather than be destroyed on the pattern alone."""
        text = "the build ran at commit abcdefabcdefabcdefabcdef"
        safe, _ = Anonymizer(level=Level.STANDARD).anonymize(text)
        assert "the build ran at commit" in safe


class TestRestoringNeedsNothingToRestore:
    def test_an_empty_vault_returns_the_data_unchanged(self):
        """The short-circuit matters for a structure: walking a large one to
        replace nothing is pure cost."""
        anonymizer = Anonymizer()
        data = {"host": "db.internal", "port": 5432}
        safe, vault = anonymize_data(data, anonymizer)
        assert vault.values == {}
        assert restore_data(safe, anonymizer, vault) == data

    def test_an_unrecognized_leaf_type_is_returned_as_is(self):
        """A restorer meets whatever the caller's structure holds, and an
        object it has no rule for must pass through rather than vanish."""
        anonymizer = Anonymizer()
        _, vault = anonymize_data({"x": "me@acme.com"}, anonymizer)
        sentinel = object()
        assert restore_data({"odd": sentinel}, anonymizer, vault)["odd"] is sentinel
