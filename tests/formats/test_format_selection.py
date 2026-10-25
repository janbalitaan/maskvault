"""TestFormatSelection."""

from __future__ import annotations

from maskvault.models.token_format import (
    ANGLES,
    AT_SIGNS,
    BRACKETS,
    DEFAULT_FORMATS,
    MATH_BRACKETS,
    choose_format,
)


class TestFormatSelection:
    def test_plain_text_gets_the_markup_safe_format(self):
        """The default has to be safe where the OUTPUT goes, which
        collision avoidance cannot see. At-signs are claimed by no
        common markup; double brackets are wikilinks everywhere."""
        assert choose_format("ordinary prose about work") is AT_SIGNS

    def test_the_default_is_unaffected_by_wikilinks_in_the_input(self):
        """At-signs do not collide with wikilinks, so nothing changes."""
        assert choose_format("see [[Meeting Notes]]") is AT_SIGNS

    def test_each_collision_falls_through(self):
        assert choose_format("@@b@@ already here") is MATH_BRACKETS
        assert choose_format("@@b@@ and \u27e6c\u27e7") is BRACKETS
        assert choose_format("@@b@@ \u27e6c\u27e7 [[d]]") is ANGLES

    def test_it_never_returns_nothing(self):
        """Even text containing every delimiter gets a format."""
        hostile = "[[a]] @@b@@ <<c>> ⟦d⟧"
        assert choose_format(hostile) is DEFAULT_FORMATS[-1]

    def test_only_the_opening_delimiter_decides(self):
        """A stray closing delimiter is harmless on its own, and rejecting it
        would switch formats more often than necessary."""
        assert choose_format("a closing @@ is still a collision") is MATH_BRACKETS
        assert choose_format("a closing ]] alone") is AT_SIGNS
