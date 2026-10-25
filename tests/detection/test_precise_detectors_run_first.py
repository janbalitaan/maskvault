"""The first detector to match a span claims it, so order is correctness.

Two assemblies used to disagree about this: `Registry.all_detectors` put the
precise identifiers before the loose contact patterns, and
`Levels.detectors_for` did the opposite. The second is the one the Anonymizer
uses, so an IP address was labelled as a phone number.
"""

from __future__ import annotations

from maskvault import Anonymizer, Level
from maskvault.detectors import Registry
from maskvault.levels import Levels


def labels(detectors) -> list[str]:
    return [detector.label for detector in detectors]


class TestPreciseBeforeLoose:
    def test_ip_address_is_checked_before_phone(self):
        """`phone` matches any punctuated digit run, so it would otherwise
        claim 10.42.7.19 first."""
        order = labels(Levels.detectors_for(Level.STANDARD))
        assert order.index("ip_address") < order.index("phone")

    def test_an_ip_address_gets_the_right_label(self):
        """Both are reversible, so the value survived either way — but a
        caller whitelisting "ip_address" found it had no effect."""
        _, vault = Anonymizer().anonymize("request from 10.42.7.19")
        assert any("IP_ADDRESS" in token for token in vault.values)
        assert not any("PHONE" in token for token in vault.values)

    def test_whitelisting_one_label_leaves_a_looser_one_matching(self):
        """Worth knowing rather than surprising: a label turns one detector
        off, and a value matching two patterns is then claimed by the other.
        An IP is also a punctuated digit run, so `phone` takes it."""
        anonymizer = Anonymizer(whitelist={"labels": ["ip_address"]})
        safe, _ = anonymizer.anonymize("request from 10.42.7.19")
        assert "@@PHONE_1@@" in safe

    def test_whitelisting_the_value_keeps_it_whatever_matches(self):
        """Which is why `values` exists: it allows the text through rather
        than turning off one of the detectors that could claim it."""
        anonymizer = Anonymizer(whitelist={"values": ["10.42.7.19"]})
        safe, _ = anonymizer.anonymize("request from 10.42.7.19")
        assert "10.42.7.19" in safe

    def test_a_pattern_also_keeps_it(self):
        anonymizer = Anonymizer(whitelist={"patterns": [r"10\.\d+\.\d+\.\d+"]})
        safe, _ = anonymizer.anonymize("request from 10.42.7.19")
        assert "10.42.7.19" in safe

    def test_email_is_checked_before_social_handle(self):
        """The handle detector is "a platform name followed by something",
        which would claim the domain half of an address."""
        order = labels(Levels.detectors_for(Level.STANDARD))
        assert order.index("email") < order.index("social_handle")

    def test_the_two_assemblies_agree_about_ordering(self):
        """They disagreed once, and the one nobody read was the one in use."""
        registry = labels(Registry.all_detectors())
        levels = labels(Levels.detectors_for(Level.STANDARD))
        shared = [label for label in registry if label in levels]
        in_levels = [label for label in levels if label in registry]
        assert shared == in_levels
