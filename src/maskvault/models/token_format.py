"""How a placeholder is written.

Every part is the caller's to change. The built-in formats and the
selection logic live in `maskvault.formats`; this is the type they are
instances of.

A format is validated at construction, because one whose pattern cannot
match its own output would lose every value it replaced at restore time,
silently.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from maskvault.exceptions import TokenFormatError


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
            raise TokenFormatError(
                f"token format {self.name!r} needs both an opening and a closing "
                "delimiter, or tokens would not be distinguishable from prose"
            )
        try:
            pattern = self.pattern
        except re.error as error:
            raise TokenFormatError(
                f"token format {self.name!r} does not compile: {error}"
            ) from error

        if self.label_case not in {"upper", "lower", "keep"}:
            raise TokenFormatError(
                f"token format {self.name!r} has label_case={self.label_case!r}; "
                'expected "upper", "lower" or "keep"'
            )

        sample = self.render(self.label_for("Label"), 1)
        if not pattern.fullmatch(sample):
            raise TokenFormatError(
                f"token format {self.name!r} cannot match its own output "
                f"({sample!r}). With label_case={self.label_case!r}, "
                f"label_pattern={self.label_pattern!r} has to match "
                f"{self.label_for('Label')!r} and index_pattern has to match a number."
            )

    @property
    def example(self) -> str:
        """What a token looks like in this format, for documentation.

        Composed the same way a real token is — `label_for` then `render` —
        because `render` writes exactly what it is given. Skipping the casing
        here advertised `<LABEL_1>` for a format whose tokens were actually
        `<label_1>`, which is the one thing an example must not do.
        """
        return self.render(self.label_for("LABEL"), 1)

    @property
    def pattern(self) -> re.Pattern[str]:
        """Matches tokens written in this format."""
        return re.compile(
            re.escape(self.opening)
            + f"({self.label_pattern})_({self.index_pattern})"
            + re.escape(self.closing)
        )

    @classmethod
    def default(cls) -> TokenFormat:
        """Build the format used when a caller has not chosen one.

        `!|LABEL_1|!`, which is the one delimiter pair tested against the
        things people actually paste into a model that claims none of them:
        diffs, Markdown, wikilinks, README badges, GitHub alerts, Jinja,
        Handlebars, HTML, YAML, SQL, shell, Haskell quasi-quotes, Rust
        attributes, and the `<|...|>` convention for a model's own special
        tokens. The reasoning for each is in `maskvault.formats`.

        Defined here rather than imported from `maskvault.formats` so that a
        model never depends on a module above it — `Vault` needs a default,
        and reaching upward for one would make the import graph circular.
        """
        return cls(name="pipe_bang", opening="!|", closing="|!")

    def label_for(self, label: str) -> str:
        """Apply this format's casing to a detector label."""
        if self.label_case == "upper":
            return label.upper()
        if self.label_case == "lower":
            return label.lower()
        return label

    def render(self, label: str, index: int) -> str:
        """Write one token, with the label exactly as given.

        Casing is `label_for`'s job, and a caller composes the two:
        `render(label_for(label), index)`. Kept apart so a caller who has
        already cased a label does not get it cased twice, and so this stays
        a primitive that does one thing.

        Built by concatenation rather than str.format, because a delimiter
        containing braces would otherwise be eaten as format escaping: a
        "{{" opening renders as a single "{".
        """
        return f"{self.opening}{label}_{index}{self.closing}"

    @classmethod
    def from_dict(cls, data: dict) -> TokenFormat:
        r"""Build a format from plain JSON, so it can live in a config file.

            {
              "name": "mine",
              "opening": "<%|",
              "closing": "|%>",
              "label_pattern": "[A-Z_]+",
              "index_pattern": "\\d+",
              "label_case": "upper"
            }

        Paired with `as_dict` here rather than in `maskvault.formats`, because
        a Vault needs to rebuild its own format when it is loaded from a store
        — and a model reaching upward for that would make the import graph
        circular.
        """
        try:
            return cls(
                name=str(data["name"]),
                opening=str(data["opening"]),
                closing=str(data["closing"]),
                label_pattern=str(data.get("label_pattern", r"[A-Z_]+")),
                index_pattern=str(data.get("index_pattern", r"\d+")),
                label_case=str(data.get("label_case", "upper")),
            )
        except KeyError as error:
            raise TokenFormatError(f"a token format needs {error.args[0]!r}") from error

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
