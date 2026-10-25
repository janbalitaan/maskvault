"""Choosing a format the text does not already use.

Two collisions matter and only one is detectable. Selection handles the
input: it tries each candidate until one finds no occurrence of its opening
delimiter. It cannot handle the *destination* — a token is clean in the input
and still breaks when the output is pasted into a wiki — which is why the
order of the candidates matters as much as the mechanism.
"""

from __future__ import annotations

from maskvault.formats import (
    ANGLES,
    AT_SIGNS,
    BRACKETS,
    DEFAULT_FORMATS,
    MATH_BRACKETS,
    PIPE_BANG,
    PIPE_BRACKETS,
    TokenFormats,
)


class TestTheDefault:
    def test_plain_text_gets_the_first_candidate(self):
        assert TokenFormats.choose_format("ordinary prose about work") is PIPE_BANG

    def test_the_default_claims_nothing_common(self):
        """The property the whole order is built on. Each of these is a thing
        people paste into a model, and the default survives all of them."""
        for text in (
            "@@ -1,5 +1,5 @@",  # unified diff
            "see [[Meeting Notes]] and [[another]]",  # wikilinks
            "[![PyPI](https://img.shields.io/pypi/v/x)](url)",  # README badge
            "> [!NOTE] something useful",  # GitHub alert
            "{{ user.name }} and {% if x %}",  # Jinja
            "<div id='a'>text</div>",  # HTML
            "key: &anchor *ref <<: merge |block",  # YAML
            "WHERE a LIKE '%%x%%' AND b::text = c",  # SQL
            'echo "$@" a|b ${x} $(cmd) 2>&1',  # shell
            "#[derive(Debug)] a |= 1",  # Rust
            "<|endoftext|> [INST]",  # model specials
        ):
            assert TokenFormats.choose_format(text) is PIPE_BANG, text


class TestFallingThrough:
    def test_each_collision_moves_to_the_next(self):
        assert TokenFormats.choose_format("!|b|! already here") is PIPE_BRACKETS
        assert TokenFormats.choose_format("!|b|! and [|c|]") is AT_SIGNS
        assert TokenFormats.choose_format("!|b|! [|c|] @@d@@") is MATH_BRACKETS
        assert TokenFormats.choose_format("!|b|! [|c|] @@d@@ ⟦e⟧") is BRACKETS
        assert TokenFormats.choose_format("!|b|! [|c|] @@d@@ ⟦e⟧ [[f]]") is ANGLES

    def test_it_never_returns_nothing(self):
        """Text containing every delimiter still gets a format: the last
        candidate, because returning None would leave the caller with no way
        to anonymize at all."""
        hostile = "!|a|! [|b|] @@c@@ ⟦d⟧ [[e]] <<f>>"
        assert TokenFormats.choose_format(hostile) is DEFAULT_FORMATS[-1]

    def test_only_the_opening_delimiter_decides(self):
        """A stray closing delimiter is harmless on its own, and rejecting it
        would switch formats more often than necessary."""
        assert TokenFormats.choose_format("a closing |! alone") is PIPE_BANG
        assert TokenFormats.choose_format("a closing ]] alone") is PIPE_BANG

    def test_a_caller_can_supply_their_own_candidates(self):
        """ "Pick one that fits the text" must not mean "pick one of ours"."""
        assert TokenFormats.choose_format("prose", (BRACKETS, ANGLES)) is BRACKETS
        assert TokenFormats.choose_format("[[x]]", (BRACKETS, ANGLES)) is ANGLES


class TestTheOrderIsDeliberate:
    def test_the_default_is_first_and_ascii(self):
        """ASCII because a model reproduces it more reliably than an
        unusual codepoint, which is the failure selection cannot fix."""
        assert DEFAULT_FORMATS[0] is PIPE_BANG
        assert (PIPE_BANG.opening + PIPE_BANG.closing).isascii()

    def test_the_non_ascii_option_is_not_first(self):
        """Math brackets collide with nothing at all, which would make them
        the obvious default — but a non-ASCII token is one a model is more
        likely to normalize or drop."""
        assert MATH_BRACKETS is not DEFAULT_FORMATS[0]
        assert MATH_BRACKETS in DEFAULT_FORMATS

    def test_wikilinks_are_available_but_late(self):
        """The most legible to a model, and claimed by every wiki — so a
        caller who controls the whole pipeline can ask for it by name."""
        assert DEFAULT_FORMATS.index(BRACKETS) > DEFAULT_FORMATS.index(PIPE_BANG)

    def test_every_candidate_reads_back_its_own_output(self):
        """A format that cannot would lose every value at restore time."""
        for token_format in DEFAULT_FORMATS:
            assert token_format.pattern.fullmatch(token_format.example)

    def test_no_candidate_uses_the_special_token_convention(self):
        """`<|...|>` is how a model marks its own control tokens, so a
        delimiter pair resembling it is the one thing to avoid."""
        for token_format in DEFAULT_FORMATS:
            assert (token_format.opening, token_format.closing) != ("<|", "|>")
