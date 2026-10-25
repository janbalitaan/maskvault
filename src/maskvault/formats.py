"""How a placeholder is written.

No delimiter is safe everywhere, which is the whole reason this is
configurable rather than fixed. Two things can go wrong, and only the first
is detectable:

**Collision with the input.** The text already contains the delimiter, so a
replacement nests inside it or a legitimate occurrence is mistaken for a
token. This one is avoidable: a format is chosen per operation by trying each
candidate until one finds no occurrence of its opening delimiter in the text,
and the choice is recorded in the Vault so restoring never has to be told.

**Collision with the output's destination.** The text is clean, but the
*result* is pasted into a wiki, rendered as Markdown, or fed to a template
engine — where the token means something. Selection cannot help, because it
inspects the input and knows nothing about where the output goes. Only the
default can protect against this, by being a pair that nothing claims.

So the default is the one pair tested against what people actually paste into
a model and found in none of it:

    !|LABEL_1|!   nothing claims it

The alternatives, and what claims each:

    [|X|]    Haskell and Idris quasi-quotation. Rare, and more legible than
             the default, so it is available by name.
    @@X@@    unified diff hunk headers — `@@ -1,5 +1,5 @@`. Common, because
             pasting a diff into a model is an ordinary thing to do.
    [[X]]    wikilinks: Obsidian, Roam, Logseq, MediaWiki, Dendron, Foam.
             Also the most legible to a language model, which is the trade.
    [!X!]    GitHub alerts (`> [!NOTE]`), and `[![` is a linked image — the
             badge syntax at the top of most READMEs.
    {{X}}    templates: Jinja, Handlebars, Mustache, Vue, Angular, Liquid.
    {|X|}    MediaWiki tables, and LaTeX.
    <<X>>    AsciiDoc cross-references.
    %%X%%    Obsidian comments, SQL LIKE patterns, printf.
    ((X))    Roam block references.
    (|X|)    Haskell idiom brackets, and the Elixir and OCaml pipe operator.
    <|X|>    the convention for a model's own special tokens, which is the
             one pair that must never be used.

A note on what the default does *not* fix: a model that reformats a token
breaks restoring whatever the delimiters are, and `!|EMAIL_1|` is rejected
exactly as `@@EMAIL_1@` was. `Anonymizer.leaked()` is what reports that, and
no choice of delimiter removes the need for it.
"""

from __future__ import annotations

import secrets
import string

from maskvault.exceptions import TokenFormatError
from maskvault.models.token_format import TokenFormat

# The candidates, in the order they are tried. Order is by what markup claims
# the delimiter, not by how it reads — the module docstring lists each.

# The default. Tested against diffs, Markdown, wikilinks, README badges,
# GitHub alerts, Jinja, Handlebars, Mustache, ERB, Velocity, HTML, YAML, SQL,
# shell, Makefiles, regex, LaTeX, CI logs, PowerShell, Haskell, Nim, OCaml,
# Perl, MATLAB, Rust attributes and the `<|...|>` special-token convention,
# and found in none of them.
PIPE_BANG = TokenFormat.default()

# More legible than the default and claimed only by Haskell and Idris
# quasi-quotation, which is rare enough that this sits second rather than
# being hidden behind a name.
PIPE_BRACKETS = TokenFormat(name="pipe_brackets", opening="[|", closing="|]")

# The previous default. Unified diff uses `@@` in hunk headers, and pasting a
# diff into a model is an ordinary thing to do.
AT_SIGNS = TokenFormat(name="at_signs", opening="@@", closing="@@")

# Mathematical white square brackets. Essentially never typed by hand, so
# this collides with nothing at all; the cost is that it is non-ASCII, which
# some pipelines still mishandle.
MATH_BRACKETS = TokenFormat(name="math_brackets", opening="\u27e6", closing="\u27e7")

# The most legible to a language model, and claimed by every wiki. Available
# by name for callers who control the whole pipeline.
BRACKETS = TokenFormat(name="brackets", opening="[[", closing="]]")

# A last resort, after the three above. AsciiDoc uses this for cross
# references, so it is not a good default either.
ANGLES = TokenFormat(name="angles", opening="<<", closing=">>")

DEFAULT_FORMATS: tuple[TokenFormat, ...] = (
    PIPE_BANG,
    PIPE_BRACKETS,
    AT_SIGNS,
    MATH_BRACKETS,
    BRACKETS,
    ANGLES,
)

FORMATS_BY_NAME: dict[str, TokenFormat] = {
    token_format.name: token_format for token_format in DEFAULT_FORMATS
}


class TokenFormats:
    """Builds the token format a run will use.

    Static methods: a format is derived from its arguments and the text it has
    to survive, with no state to carry between calls. Grouping them means a
    reader looking for "how do I get a format" has one place to look.
    """

    @staticmethod
    def random_format(name: str = "random", length: int = 6) -> TokenFormat:
        """Generate a format with unguessable delimiters.

        Two reasons to want this. A delimiter nobody can predict will not collide
        with anything in the text, whatever markup it uses. And when the text is
        going somewhere that might try to inject content back — a model
        processing untrusted input, for instance — text that cannot guess the
        delimiter cannot forge a token that restore would expand.

        The delimiters are not secret in any cryptographic sense; they are
        unpredictable, which is a different and weaker property. It raises the
        cost of forging a token; it does not make it impossible.
        """
        alphabet = string.ascii_uppercase + string.digits
        marker = "".join(secrets.choice(alphabet) for _ in range(length))
        return TokenFormat(name=name, opening=f"<{marker}:", closing=f":{marker}>")

    @staticmethod
    def format_from_dict(data: dict) -> TokenFormat:
        """Build a format from plain JSON.

        Kept as the documented entry point; the construction itself lives on
        TokenFormat, beside `as_dict`, so that a Vault can rebuild its own
        format without importing this module.
        """
        return TokenFormat.from_dict(data)

    @staticmethod
    def choose_format(
        text: str, candidates: tuple[TokenFormat, ...] = DEFAULT_FORMATS
    ) -> TokenFormat:
        """Pick the first candidate whose delimiters are absent from the text.

        `candidates` is yours to supply: pass your own formats, in your own order
        of preference, and the first one that fits the text is used. Falls back to
        the last candidate when every one collides — with the built-in list that
        means the text already contains characters almost nobody types, and a
        caller worried about even that case should pass `TokenFormats.random_format()`.
        """
        if not candidates:
            raise TokenFormatError("choose_format needs at least one candidate format")
        for candidate in candidates:
            if not candidate.collides_with(text):
                return candidate
        return candidates[-1]
