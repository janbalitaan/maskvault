"""How a placeholder is written.

No delimiter is safe everywhere, which is the whole reason this is
configurable rather than fixed.

`[[LABEL_1]]` reads clearly to a language model, and that matters — a model
that understands a placeholder is a placeholder leaves it alone. But double
square brackets are wikilink syntax in Obsidian, Roam, Logseq and MediaWiki,
which causes two distinct problems:

**Nesting.** A value already inside a wikilink produces `[[[[ORG_1]]]]`.
Renderers and models both mishandle that.

**False leak reports.** A legitimate link to a page named `[[API_2]]` has the
exact shape of a token, so leak detection flags it.

So a format is chosen per operation, by trying each candidate until one finds
no existing occurrence of its opening delimiter in the text. The choice is
recorded in the Vault, because restoring requires knowing which format was
used — a caller never has to track it.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import secrets
import string


@dataclass(frozen=True)
class TokenFormat:
    """One way of writing a placeholder.

    Every part is yours to change. The built-in formats are starting points,
    not a fixed vocabulary — define whatever suits the text you are passing
    through, including something deliberately unlike anything else:

        TokenFormat(
            name="mine",
            opening="<%|",
            closing="|%>",
            label_pattern=r"[a-z]+",
        )

    `label_pattern` describes what a label looks like so the matching regex is
    derived from it, rather than written twice and kept in sync by hand. That
    is also what makes validation possible: the format is checked at
    construction to confirm its pattern matches its own output, because a
    format that fails that test would lose every value it replaced at restore
    time, silently.
    """

    name: str
    opening: str
    closing: str
    label_pattern: str = r"[A-Z_]+"
    index_pattern: str = r"\d+"

    # How a detector's label is cased in the token. Uppercase by default
    # because it reads as a placeholder rather than a word, which is what
    # makes a model leave it alone. Set "lower" or "keep" if your
    # label_pattern expects something else — the two are validated together,
    # so they cannot drift apart.
    label_case: str = "upper"

    def __post_init__(self) -> None:
        """Reject a format that cannot read back what it writes."""
        if not self.opening or not self.closing:
            raise ValueError(
                f"token format {self.name!r} needs both an opening and a closing "
                "delimiter, or tokens would not be distinguishable from prose"
            )
        try:
            pattern = self.pattern
        except re.error as error:
            raise ValueError(f"token format {self.name!r} does not compile: {error}") from error

        if self.label_case not in {"upper", "lower", "keep"}:
            raise ValueError(
                f"token format {self.name!r} has label_case={self.label_case!r}; "
                'expected "upper", "lower" or "keep"'
            )

        sample = self.render(self.label_for("Label"), 1)
        if not pattern.fullmatch(sample):
            raise ValueError(
                f"token format {self.name!r} cannot match its own output "
                f"({sample!r}). With label_case={self.label_case!r}, "
                f"label_pattern={self.label_pattern!r} has to match "
                f"{self.label_for('Label')!r} and index_pattern has to match a number."
            )

    @property
    def example(self) -> str:
        """What a token looks like in this format, for documentation."""
        return self.render("LABEL", 1)

    @property
    def pattern(self) -> re.Pattern[str]:
        """Matches tokens written in this format."""
        return re.compile(
            re.escape(self.opening)
            + f"({self.label_pattern})_({self.index_pattern})"
            + re.escape(self.closing)
        )

    def label_for(self, label: str) -> str:
        """Apply this format's casing to a detector label."""
        if self.label_case == "upper":
            return label.upper()
        if self.label_case == "lower":
            return label.lower()
        return label

    def render(self, label: str, index: int) -> str:
        """Write one token.

        Built by concatenation rather than str.format, because a delimiter
        containing braces would otherwise be eaten as format escaping: a
        "{{" opening renders as a single "{".
        """
        return f"{self.opening}{label}_{index}{self.closing}"

    def as_dict(self) -> dict:
        """Round-trips with format_from_dict, for writing a config back out."""
        return {
            "name": self.name,
            "opening": self.opening,
            "closing": self.closing,
            "label_pattern": self.label_pattern,
            "index_pattern": self.index_pattern,
            "label_case": self.label_case,
        }

    def collides_with(self, text: str) -> bool:
        """Whether this format's delimiters already appear in the text.

        Checked against the opening delimiter only. A closing delimiter alone
        is harmless, and requiring both absent would reject more text than
        necessary.
        """
        return self.opening in text


# The candidates, in the order they are tried.
#
# Brackets come first because they are the most legible to a language model,
# which is the common case and the one where comprehension matters most. Each
# fallback trades a little of that legibility for a delimiter that is
# meaningless in one more markup language.
BRACKETS = TokenFormat(name="brackets", opening="[[", closing="]]")

# Safe in Markdown, wiki markup, HTML and the common template languages.
AT_SIGNS = TokenFormat(name="at_signs", opening="@@", closing="@@")

# For text that already contains both of the above.
ANGLES = TokenFormat(name="angles", opening="<<", closing=">>")

# Mathematical white square brackets. Essentially never written by hand, so
# this is the last resort that will not collide with anything.
MATH_BRACKETS = TokenFormat(name="math_brackets", opening="⟦", closing="⟧")

DEFAULT_FORMATS: tuple[TokenFormat, ...] = (BRACKETS, AT_SIGNS, ANGLES, MATH_BRACKETS)

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
        raise ValueError(f"a token format needs {error.args[0]!r}") from error


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
        raise ValueError("choose_format needs at least one candidate format")
    for candidate in candidates:
        if not candidate.collides_with(text):
            return candidate
    return candidates[-1]
