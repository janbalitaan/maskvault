"""How a placeholder is written.

No delimiter is safe everywhere, which is the whole reason this is
configurable rather than fixed.

`[[LABEL_1]]` reads most clearly to a language model, and that matters — a
model that recognizes a placeholder leaves it alone. But double square
brackets are wikilink syntax in Obsidian, Roam, Logseq and MediaWiki, which
causes three problems:

**Nesting.** A value already inside a wikilink produces `[[[[ORG_1]]]]`.
Renderers and models both mishandle that.

**False leak reports.** A legitimate link to a page named `[[API_2]]` has the
exact shape of a token, so leak detection flags it.

**Rendering.** Even when the input contains no wikilinks, the *output* may be
pasted into a wiki, where `[[ORG_1]]` renders as a broken link.

That third problem is the one collision avoidance cannot solve, because it
inspects the input and knows nothing about where the output goes. So the
default is `@@LABEL_1@@`, which no common markup claims, and brackets are
available by name for a caller who controls the whole pipeline.

On top of that, a format is chosen per operation by trying each candidate
until one finds no existing occurrence of its opening delimiter in the text.
The choice is recorded in the Vault, because restoring requires knowing which
format was used — a caller never has to track it.
"""

from __future__ import annotations

import secrets
import string

from maskvault.exceptions import TokenFormatError
from maskvault.models.token_format import TokenFormat

# The candidates, in the order they are tried.
#
# Order is by what markup already claims the delimiter, not by how it reads.
# Collision avoidance can only inspect the text it is given; it cannot know
# that the output will later be rendered as Markdown, pasted into a wiki, or
# fed to a template engine. So the default has to be safe in those places
# without being told about them.
#
#   [[X]]   wikilinks: Obsidian, Roam, Logseq, MediaWiki, Dendron, Foam
#   {{X}}   templates: Jinja, Handlebars, Mustache, Vue, Angular, Liquid
#   <<X>>   AsciiDoc cross-references
#   %%X%%   Obsidian comments
#   ((X))   Roam block references
#   @@X@@   nothing in general prose. Unified diff uses @@ in hunk headers,
#           which only appear at the start of a line in a diff.
#
# Hence at-signs first. Double square brackets read more clearly to a
# language model, and a caller who wants that can ask for it by name — but it
# is the wrong thing to hand someone who has not thought about where their
# output goes.

# Safe in Markdown, wiki markup, HTML and the common template languages.
AT_SIGNS = TokenFormat.default()

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

DEFAULT_FORMATS: tuple[TokenFormat, ...] = (AT_SIGNS, MATH_BRACKETS, BRACKETS, ANGLES)

FORMATS_BY_NAME: dict[str, TokenFormat] = {
    token_format.name: token_format for token_format in DEFAULT_FORMATS
}


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


def format_from_dict(data: dict) -> TokenFormat:
    r"""Build a format from plain JSON, so it can live in a config file.

    {
      "name": "mine",
      "opening": "<%|",
      "closing": "|%>",
      "label_pattern": "[A-Z_]+",
      "index_pattern": "\\d+"
    }
    """
    try:
        return TokenFormat(
            name=str(data["name"]),
            opening=str(data["opening"]),
            closing=str(data["closing"]),
            label_pattern=str(data.get("label_pattern", r"[A-Z_]+")),
            index_pattern=str(data.get("index_pattern", r"\d+")),
            label_case=str(data.get("label_case", "upper")),
        )
    except KeyError as error:
        raise TokenFormatError(f"a token format needs {error.args[0]!r}") from error


def choose_format(
    text: str, candidates: tuple[TokenFormat, ...] = DEFAULT_FORMATS
) -> TokenFormat:
    """Pick the first candidate whose delimiters are absent from the text.

    `candidates` is yours to supply: pass your own formats, in your own order
    of preference, and the first one that fits the text is used. Falls back to
    the last candidate when every one collides — with the built-in list that
    means the text already contains characters almost nobody types, and a
    caller worried about even that case should pass `random_format()`.
    """
    if not candidates:
        raise TokenFormatError("choose_format needs at least one candidate format")
    for candidate in candidates:
        if not candidate.collides_with(text):
            return candidate
    return candidates[-1]
