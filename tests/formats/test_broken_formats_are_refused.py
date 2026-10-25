"""A format whose pattern does not match its own output would lose every"""

from __future__ import annotations

import pytest

from maskvault.models.token_format import (
    DEFAULT_FORMATS,
    TokenFormat,
    choose_format,
)


class TestBrokenFormatsAreRefused:
    """A format whose pattern does not match its own output would lose every
    value at restore time, with no error. So it is refused at construction."""

    def test_a_missing_delimiter_is_refused(self):
        with pytest.raises(ValueError, match="delimiter"):
            TokenFormat(name="bad", opening="[[", closing="")

    def test_a_pattern_that_cannot_match_its_output_is_refused(self):
        with pytest.raises(ValueError, match="cannot match its own output"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern=r"\d+")

    def test_an_uncompilable_pattern_is_refused(self):
        with pytest.raises(ValueError, match="does not compile"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_pattern="[unclosed")

    def test_an_unknown_label_case_is_refused(self):
        with pytest.raises(ValueError, match="label_case"):
            TokenFormat(name="bad", opening="[[", closing="]]", label_case="title")

    def test_choosing_from_no_candidates_is_refused(self):
        with pytest.raises(ValueError, match="at least one"):
            choose_format("text", ())

    def test_every_built_in_format_is_valid(self):
        """The validation applies to the library's own formats too."""
        for token_format in DEFAULT_FORMATS:
            assert token_format.pattern.fullmatch(token_format.render("LABEL", 1))
