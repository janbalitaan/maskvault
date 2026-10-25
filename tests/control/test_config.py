"""TestConfig."""

from __future__ import annotations

import re

from maskvault import Whitelist


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
