"""Replacing sensitive values before a prompt leaves the process.

The reason this exists separately from redaction: redaction is one-way and
protects the *owner's* key. This is reversible and protects the *owner's
privacy* from the provider.

An owner can have a bot that answers "who do you work for?" correctly while
the provider only ever sees "[[ORG_1]]". The mapping stays in this process,
is never sent anywhere, and is applied to the answer on the way back.

    anonymizer = Anonymizer(terms={"ORG": ["Acme Corp", "Initech"]})
    safe, vault = anonymizer.anonymize(prompt)
    reply = model(safe)                       # provider sees tokens only
    answer = anonymizer.restore(reply, vault)  # visitor sees real names
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
import re

from maskvault.detectors import Action, Detector
from maskvault.levels import Level, detectors_for
from maskvault.whitelist import Whitelist

# Tokens a model is unlikely to mangle: no spaces, no markdown meaning, and a
# shape that survives being quoted or reformatted.
# A placeholder format, not a credential — bandit flags any name containing
# "TOKEN", and renaming it to something vaguer would read worse.
TOKEN_TEMPLATE = "[[{label}_{index}]]"  # noqa: S105
TOKEN_PATTERN = re.compile(r"\[\[([A-Z_]+)_(\d+)\]\]")


@dataclass(frozen=True)
class Finding:
    """One thing a detector matched, and what would happen to it.

    Returned by `Anonymizer.explain()` so a developer can see the policy's
    decisions before trusting it. `value` is the real matched text, so a
    Finding is not safe to log.
    """

    label: str
    value: str
    action: Action
    start: int
    end: int
    allowed: bool

    @property
    def replaced(self) -> bool:
        return not self.allowed


@dataclass(frozen=True)
class _Substitution:
    """One replacement rule, bundled so _substitute takes fewer arguments."""

    label: str
    pattern: re.Pattern[str]
    validator: Callable[[str], bool] | None = None


@dataclass
class Vault:
    """The mapping from token back to original value.

    Never serialized into a prompt, never logged, never returned over HTTP.
    Held only for the life of one request.
    """

    values: dict[str, str] = field(default_factory=dict)
    destroyed: list[str] = field(default_factory=list)

    @property
    def replaced(self) -> int:
        """How many distinct values were tokenized."""
        return len(self.values)

    def summary(self) -> str:
        """Describe what happened, with no values in it — safe to log."""
        kinds: dict[str, int] = {}
        for token in self.values:
            match = TOKEN_PATTERN.match(token)
            if match:
                kinds[match.group(1)] = kinds.get(match.group(1), 0) + 1
        parts = [f"{count} {kind.lower()}" for kind, count in sorted(kinds.items())]
        if self.destroyed:
            parts.append(f"{len(self.destroyed)} destroyed")
        return ", ".join(parts) or "nothing replaced"


class Anonymizer:
    """Substitutes sensitive values for tokens, and puts them back.

    Every detector runs by default — vendor credentials, personal data,
    generic patterns and an entropy net for formats nobody anticipated. That
    is deliberate: the value that leaks is the one nobody thought to
    configure. `whitelist` is how you let something back through.

    `terms` lets a caller name things no pattern could find — employers,
    client names, product names, a village they grew up in. That is the part
    that actually matters for a CV: patterns catch emails, but only the owner
    knows which company name they would rather a provider never logged.
    """

    def __init__(
        self,
        level: Level | str = Level.STANDARD,
        detectors: tuple[Detector, ...] | None = None,
        terms: dict[str, list[str]] | None = None,
        whitelist: Whitelist | dict | None = None,
        enabled: bool = True,
    ) -> None:
        # Default-deny within the chosen level: every detector it includes
        # runs unless the whitelist says otherwise. Deny is the safe default,
        # because the value that leaks is the one nobody thought to configure.
        self._whitelist = (
            whitelist if isinstance(whitelist, Whitelist) else Whitelist.from_dict(whitelist)
        )
        self._level = Level(level) if isinstance(level, str) else level
        chosen = detectors_for(self._level) if detectors is None else detectors
        self._detectors = tuple(
            detector for detector in chosen if not self._whitelist.allows_label(detector.label)
        )
        self._enabled = enabled
        self._terms = self._compile_terms(terms or {})

    @staticmethod
    def _compile_terms(terms: dict[str, list[str]]) -> list[tuple[str, re.Pattern[str]]]:
        """Owner-supplied literals, longest first.

        Longest first so "Acme Corporation" is matched before "Acme", which
        would otherwise leave "Corporation" dangling next to a token.
        """
        compiled = []
        for label, values in terms.items():
            for value in sorted(
                {v.strip() for v in values if v.strip()}, key=len, reverse=True
            ):
                compiled.append((label.upper(), re.compile(rf"\b{re.escape(value)}\b", re.I)))
        return compiled

    # ------------------------------------------------------------------

    def anonymize(self, text: str) -> tuple[str, Vault]:
        """Return text safe to send, plus the vault needed to restore it."""
        vault = Vault()
        if not self._enabled or not text:
            return text, vault

        counters: dict[str, int] = {}
        # Caller-supplied terms first: they are the most specific and the most
        # sensitive, and a literal must win over a generic pattern.
        for label, pattern in self._terms:
            text = self._substitute(text, _Substitution(label, pattern), counters, vault)
        for detector in self._detectors:
            if detector.action is Action.DESTROY:
                text = self._destroy(text, detector, vault)
            else:
                text = self._substitute(
                    text,
                    _Substitution(detector.label.upper(), detector.pattern, detector.validate),
                    counters,
                    vault,
                )
        return text, vault

    def _substitute(
        self,
        text: str,
        rule: _Substitution,
        counters: dict[str, int],
        vault: Vault,
    ) -> str:
        """Replace each distinct match with a stable token.

        The same value gets the same token throughout, so a model can still
        tell that two mentions refer to one thing.
        """
        seen: dict[str, str] = {}

        def swap(match: re.Match[str]) -> str:
            original = match.group(0)
            if self._whitelist.allows_value(original):
                return original
            if rule.validator is not None and not rule.validator(original):
                return original
            if original in seen:
                return seen[original]
            counters[rule.label] = counters.get(rule.label, 0) + 1
            token = TOKEN_TEMPLATE.format(label=rule.label, index=counters[rule.label])
            seen[original] = token
            vault.values[token] = original
            return token

        return rule.pattern.sub(swap, text)

    def _destroy(self, text: str, detector: Detector, vault: Vault) -> str:
        """Remove a value that must never be sent or restored."""

        def swap(match: re.Match[str]) -> str:
            original = match.group(0)
            if self._whitelist.allows_value(original):
                return original
            if detector.validate is not None and not detector.validate(original):
                return original
            vault.destroyed.append(detector.label)
            return detector.notice

        return detector.pattern.sub(swap, text)

    # ------------------------------------------------------------------

    def restore(self, text: str, vault: Vault) -> str:
        """Put the real values back into a model's answer.

        Only tokens present in this vault are restored, so a model that
        invents `[[ORG_9]]` leaves it visible rather than resolving to
        something unrelated — a visible oddity beats a silent wrong answer.
        """
        if not vault.values or not text:
            return text
        for token, original in vault.values.items():
            text = text.replace(token, original)
        return text

    # -- inspection --------------------------------------------------------

    def explain(self, text: str) -> list[Finding]:
        """What this anonymizer would do to the text, and why.

        The point of this is to make configuration cheap. Rather than guessing
        a whitelist up front, run real input through it, read the findings, and
        allow the entries that turn out to be harmless. `suggest_whitelist`
        turns that reading straight into config.

        Findings include values the whitelist already allows, marked as such,
        so a developer can see the policy working rather than inferring it.
        """
        findings: list[Finding] = []
        for label, pattern in self._terms:
            findings.extend(self._find(text, label, pattern, Action.REVERSIBLE, None))
        for detector in self._detectors:
            findings.extend(
                self._find(
                    text,
                    detector.label.upper(),
                    detector.pattern,
                    detector.action,
                    detector.validate,
                )
            )
        # Earliest first, so the report reads in the order of the text.
        findings.sort(key=lambda finding: (finding.start, finding.label))
        return findings

    def _find(
        self,
        text: str,
        label: str,
        pattern: re.Pattern[str],
        action: Action,
        validator: Callable[[str], bool] | None,
    ) -> list[Finding]:
        found = []
        for match in pattern.finditer(text):
            value = match.group(0)
            if validator is not None and not validator(value):
                continue
            found.append(
                Finding(
                    label=label,
                    value=value,
                    action=action,
                    start=match.start(),
                    end=match.end(),
                    allowed=self._whitelist.allows_value(value),
                )
            )
        return found

    def preview(self, text: str) -> str:
        """A readable report of what would happen. For a terminal, not a log.

        This prints real values, which is the whole point — a developer
        deciding what to allow has to see what was found. It is not safe to
        log; `Vault.summary()` is what goes in a log.
        """
        findings = self.explain(text)
        if not findings:
            return "nothing would be replaced"

        lines = [f"{len(findings)} findings at level {self._level.value}:"]
        for finding in findings:
            state = "allowed" if finding.allowed else finding.action.value
            lines.append(f"  {state:11} {finding.label:18} {finding.value[:48]}")
        remaining = sum(1 for finding in findings if not finding.allowed)
        lines.append(
            f"{remaining} would be replaced, {len(findings) - remaining} allowed through"
        )
        return "\n".join(lines)

    def suggest_whitelist(self, text: str, *, only_reversible: bool = True) -> dict:
        """A whitelist draft covering everything found, ready to edit.

        Deliberately a *draft*. It allows everything, which is not a policy
        anyone should ship — the intended use is to delete the lines that
        should stay protected and keep the rest. Credentials are left out
        entirely by default, because allowing one is almost never correct.
        """
        findings = [finding for finding in self.explain(text) if not finding.allowed]
        if only_reversible:
            findings = [finding for finding in findings if finding.action is Action.REVERSIBLE]
        return {
            "values": sorted({finding.value.strip() for finding in findings}),
            "labels": [],
            "note": "a draft: remove anything that should stay protected",
        }

    @property
    def level(self) -> Level:
        """The strictness level in force."""
        return self._level

    @property
    def whitelist(self) -> Whitelist:
        """The allowlist in force, for logging what the policy was."""
        return self._whitelist

    def describe_policy(self) -> str:
        """What this anonymizer will do, safe to log at startup."""
        state = "on" if self._enabled else "OFF"
        return (
            f"anonymizer {state} at {self._level.value}: {len(self._detectors)} detectors, "
            f"{len(self._terms)} terms, {self._whitelist.describe()}"
        )

    def leaked(self, text: str, vault: Vault) -> list[str]:
        """Tokens still in the text after restoring.

        A model that mangled a token leaves one behind. Checking lets the
        caller fall back to a deterministic answer rather than show
        "[[ORG_2]]" to a recruiter.
        """
        restored = self.restore(text, vault)
        return [match.group(0) for match in TOKEN_PATTERN.finditer(restored)]
