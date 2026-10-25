"""What is allowed through unchanged.

The default posture is deny: the detectors for the chosen level all run, and
anything that looks confidential is replaced. That is the safe default, but on
its own it is too blunt. A prompt about someone's career legitimately contains
their public GitHub URL, the name of a framework, a city, a published article.
Replacing those costs answer quality and buys no privacy, because they are
already public.

So strictness is paired with explicit control, in the order checked:

    labels      turn a whole detector off           {"url", "age"}
    categories  turn a special category off         {"identity"}
    values      exact strings, case-insensitive     {"Python", "FastAPI"}
    words       single words, word-bounded          {"black", "native"}
    contains    substring anywhere in the match     {"github.com"}
    prefixes    the match starts with this          {"https://mysite.dev/"}
    suffixes    the match ends with this            {"@mycompany.com"}
    domains     email or URL on this domain         {"mycompany.com"}
    patterns    regexes                             (re.compile(...),)
    predicate   any callable, for whatever is left

Deciding what belongs here is the one judgment the library cannot make, which
is why nothing is allowed by default. `Anonymizer.explain()` exists to make
that decision cheap: it reports what *would* be replaced, so a developer can
look at the list and allow the harmless entries rather than guessing up front.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
import re

# Stripped from both ends before a comparison, because a detector may hand
# over "https://example.com/me," with the sentence comma attached.
_TRAILING_PUNCTUATION = " .,;:!?\"'()[]{}<>"

# Pulls the host out of an email address or a URL.
_HOST = re.compile(r"(?:@|https?://)([^\s/:@]+)", re.I)


@dataclass
class Whitelist:
    """Values, labels and patterns that bypass replacement.

    Checked before any detector acts, so an allowed value is never tokenized
    and never needs restoring.
    """

    labels: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    values: set[str] = field(default_factory=set)
    words: set[str] = field(default_factory=set)
    contains: set[str] = field(default_factory=set)
    prefixes: tuple[str, ...] = ()
    suffixes: tuple[str, ...] = ()
    domains: set[str] = field(default_factory=set)
    patterns: tuple[re.Pattern[str], ...] = ()

    # The escape hatch: arbitrary logic for whatever the fields above cannot
    # express. Called with the matched text and must return True to allow it.
    predicate: Callable[[str], bool] | None = None

    def __post_init__(self) -> None:
        """Normalize the inputs once, so each check is a set lookup."""
        # Normalized once, so the hot path is a set lookup rather than a scan.
        self._labels = _lower_set(self.labels) | _lower_set(self.categories)
        self._values = _lower_set(self.values)
        self._words = _lower_set(self.words)
        self._contains = _lower_set(self.contains)
        self._prefixes = tuple(prefix.lower() for prefix in self.prefixes if prefix)
        self._suffixes = tuple(suffix.lower() for suffix in self.suffixes if suffix)
        self._domains = {domain.lower().lstrip("@.") for domain in self.domains if domain}
        self._word_pattern = _word_alternation(self._words)

    # -- the checks --------------------------------------------------------

    def allows_label(self, label: str) -> bool:
        """Whether a whole detector is switched off."""
        return label.strip().lower() in self._labels

    def allows_value(self, value: str) -> bool:
        """Whether a specific matched value may pass through unchanged.

        Trailing punctuation is stripped before comparing, because a detector
        may hand over "https://example.com/me," with the sentence comma
        attached and an exact entry would not match it otherwise.
        """
        candidate = value.strip()
        if not candidate:
            return True
        trimmed = candidate.strip(_TRAILING_PUNCTUATION)
        lowered, trimmed_lower = candidate.lower(), trimmed.lower()

        # Each mechanism as one condition, so adding another does not grow a
        # chain of early returns.
        return any(
            (
                lowered in self._values,
                trimmed_lower in self._values,
                self._word_pattern is not None and bool(self._word_pattern.fullmatch(trimmed)),
                any(fragment in lowered for fragment in self._contains),
                bool(self._prefixes) and trimmed_lower.startswith(self._prefixes),
                bool(self._suffixes) and trimmed_lower.endswith(self._suffixes),
                self._allows_host(trimmed),
                any(
                    pattern.search(candidate) or pattern.search(trimmed)
                    for pattern in self.patterns
                ),
                bool(self.predicate and self.predicate(candidate)),
            )
        )

    def _allows_host(self, candidate: str) -> bool:
        """Whether the host in an email or URL is an allowed domain.

        Subdomains count: allowing "example.com" allows "docs.example.com",
        because a developer listing a company domain means the company.
        """
        if not self._domains:
            return False
        found = _HOST.search(candidate)
        if not found:
            return False
        host = found.group(1).lower().rstrip(".")
        return any(host == domain or host.endswith(f".{domain}") for domain in self._domains)

    # -- config ------------------------------------------------------------

    @classmethod
    def from_dict(cls, data: dict | None) -> Whitelist:
        r"""Build one from plain JSON, so a policy can live in a config file.

            {
              "labels": ["url", "age"],
              "categories": ["identity"],
              "values": ["Python", "FastAPI"],
              "words": ["black", "native"],
              "domains": ["mycompany.com"],
              "prefixes": ["https://github.com/me"],
              "patterns": ["^EMP-\\\\d{4}$"]
            }

        `predicate` has no JSON form, by design — a config file should not be
        able to introduce executable code.
        """
        if not data:
            return cls()
        return cls(
            labels=set(data.get("labels") or []),
            categories=set(data.get("categories") or []),
            values=set(data.get("values") or []),
            words=set(data.get("words") or []),
            contains=set(data.get("contains") or []),
            prefixes=tuple(data.get("prefixes") or []),
            suffixes=tuple(data.get("suffixes") or []),
            domains=set(data.get("domains") or []),
            patterns=tuple(re.compile(pattern, re.I) for pattern in data.get("patterns") or []),
        )

    def as_dict(self) -> dict:
        """Round-trips with from_dict, for writing a policy back out."""
        return {
            key: value
            for key, value in (
                ("labels", sorted(self.labels)),
                ("categories", sorted(self.categories)),
                ("values", sorted(self.values)),
                ("words", sorted(self.words)),
                ("contains", sorted(self.contains)),
                ("prefixes", list(self.prefixes)),
                ("suffixes", list(self.suffixes)),
                ("domains", sorted(self.domains)),
                ("patterns", [pattern.pattern for pattern in self.patterns]),
            )
            if value
        }

    def merge(self, other: Whitelist) -> Whitelist:
        """Combine two policies, for a shared base plus per-project additions."""
        return Whitelist(
            labels=self.labels | other.labels,
            categories=self.categories | other.categories,
            values=self.values | other.values,
            words=self.words | other.words,
            contains=self.contains | other.contains,
            prefixes=self.prefixes + other.prefixes,
            suffixes=self.suffixes + other.suffixes,
            domains=self.domains | other.domains,
            patterns=self.patterns + other.patterns,
            predicate=self.predicate or other.predicate,
        )

    def describe(self) -> str:
        """Summarize this policy in one line, safe to log."""
        counts = (
            (len(self._labels), "labels off"),
            (len(self._values), "values"),
            (len(self._words), "words"),
            (len(self._contains), "substrings"),
            (len(self._prefixes), "prefixes"),
            (len(self._suffixes), "suffixes"),
            (len(self._domains), "domains"),
            (len(self.patterns), "patterns"),
        )
        parts = [f"{count} {name}" for count, name in counts if count]
        if self.predicate:
            parts.append("a predicate")
        return ", ".join(parts) or "nothing allowed through"


def _lower_set(values: Iterable[str]) -> set[str]:
    return {value.strip().lower() for value in values if value and value.strip()}


def _word_alternation(words: set[str]) -> re.Pattern[str] | None:
    """One pattern for all allowed words, so the check is a single match."""
    if not words:
        return None
    ordered = sorted(words, key=len, reverse=True)
    return re.compile("|".join(re.escape(word) for word in ordered), re.I)


# Public technology names, which carry no privacy risk and whose replacement
# would make a prompt about someone's work unanswerable. A starting point
# rather than a default, because only the caller knows what is public.
COMMON_SAFE_VALUES: frozenset[str] = frozenset(
    {
        "python",
        "javascript",
        "typescript",
        "java",
        "php",
        "perl",
        "go",
        "rust",
        "ruby",
        "kotlin",
        "swift",
        "c",
        "c#",
        "c++",
        "sql",
        "bash",
        "scala",
        "elixir",
        "fastapi",
        "django",
        "flask",
        "react",
        "next.js",
        "vue",
        "svelte",
        "angular",
        "node.js",
        "express",
        "spring",
        "laravel",
        "rails",
        "android",
        "flutter",
        "postgresql",
        "postgres",
        "mysql",
        "mongodb",
        "redis",
        "sqlite",
        "oracle",
        "elasticsearch",
        "kafka",
        "rabbitmq",
        "influxdb",
        "clickhouse",
        "cassandra",
        "aws",
        "gcp",
        "azure",
        "vercel",
        "openshift",
        "kubernetes",
        "docker",
        "terraform",
        "ansible",
        "jenkins",
        "github",
        "gitlab",
        "git",
        "grafana",
        "linux",
        "ubuntu",
        "debian",
        "windows",
        "macos",
        "nginx",
        "apache",
    }
)

# Words in the special-category vocabularies that are also ordinary technical
# vocabulary. Offered so a developer running STRICT over code or documentation
# does not have to discover each one from a false positive.
TECHNICAL_HOMONYMS: frozenset[str] = frozenset(
    {
        "black",  # the formatter, and a color
        "white",  # whitelist, and a color
        "native",  # native code, native app
        "straight",  # straight-through processing
        "partner",  # partner API, partner integration
        "single",  # single sign-on, singleton
        "default",  # a value, not a loan default
        "migration",  # a schema migration
        "transplant",
        "chronic",
        "terminal",  # a terminal emulator
        "bi",  # business intelligence
        "trans",  # transaction, transform
        "cis",  # CIS benchmarks
        "x",  # the variable, and the platform
        "strike",  # a strike price, a strikethrough
        "union",  # a SQL UNION, a C union
        "green party",
        "block",  # a code block
        "dl",  # a definition list
    }
)
