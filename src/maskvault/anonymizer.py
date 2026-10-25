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

import re

from maskvault.formats import DEFAULT_FORMATS, FORMATS_BY_NAME, choose_format
from maskvault.levels import detectors_for
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.models.finding import Finding
from maskvault.models.level import Level
from maskvault.models.substitution import Substitution
from maskvault.models.token_format import TokenFormat
from maskvault.models.vault import Vault
from maskvault.models.whitelist import Whitelist


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
        *,
        detectors: tuple[Detector, ...] | None = None,
        terms: dict[str, list[str]] | None = None,
        whitelist: Whitelist | dict | None = None,
        token_format: TokenFormat | str | None = None,
        format_candidates: tuple[TokenFormat, ...] | None = None,
        enabled: bool = True,
    ) -> None:
        """Build an anonymizer.

        Everything after `level` is keyword-only. There is no sensible
        positional order for four independent options, and a caller who
        passed `terms` where `detectors` was expected would get silent
        under-protection rather than an error.
        """
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
        # None means choose per operation, which avoids a collision with
        # whatever markup the text already uses. A named or explicit format
        # pins it, for a caller who needs the same delimiters every time.
        self._fixed_format = (
            FORMATS_BY_NAME[token_format] if isinstance(token_format, str) else token_format
        )
        # The candidates auto-selection tries, in preference order. A caller
        # can supply their own, so "pick one that fits the text" does not
        # mean "pick one of ours".
        self._candidates = format_candidates or DEFAULT_FORMATS
        self._active_format = self._fixed_format or self._candidates[0]

    def anonymize(self, text: str) -> tuple[str, Vault]:
        """Return text safe to send, plus the vault needed to restore it."""
        token_format = self._fixed_format or choose_format(text, self._candidates)
        vault = Vault(token_format=token_format)
        return self.anonymize_into(text, vault), vault

    def anonymize_into(self, text: str, vault: Vault) -> str:
        """Replace values in one string, accumulating into an existing vault.

        This is what lets a caller anonymize many strings under one vault — a
        structure walked field by field, or a conversation turn by turn. A
        value appearing in two of them keeps one token, so whatever reads the
        result can still tell the mentions refer to the same thing.
        """
        if not self._enabled or not text:
            return text

        self._active_format = vault.token_format
        counters = self._counters_from(vault)

        # Caller-supplied terms first: they are the most specific and the most
        # sensitive, and a literal must win over a generic pattern.
        for label, pattern in self._terms:
            text = self._substitute(text, Substitution(label, pattern), counters, vault)
        for detector in self._detectors:
            if detector.action is Action.DESTROY:
                text = self._destroy(text, detector, vault)
            else:
                text = self._substitute(
                    text,
                    Substitution(
                        detector.label.upper(),
                        detector.pattern,
                        detector.validate,
                        detector.group,
                    ),
                    counters,
                    vault,
                )
        return text

    @staticmethod
    def _counters_from(vault: Vault) -> dict[str, int]:
        """Return the highest index already used per label in this vault.

        Needed so a second call does not restart numbering and overwrite what
        the first call recorded.
        """
        counters: dict[str, int] = {}
        for token in vault.values:
            match = vault.token_format.pattern.fullmatch(token)
            if match:
                label, index = match.group(1), int(match.group(2))
                counters[label] = max(counters.get(label, 0), index)
        return counters

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
        """Report what this anonymizer would do to the text, and why.

        The point of this is to make configuration cheap. Rather than guessing
        a whitelist up front, run real input through it, read the findings, and
        allow the entries that turn out to be harmless. `suggest_whitelist`
        turns that reading straight into config.

        Findings include values the whitelist already allows, marked as such,
        so a developer can see the policy working rather than inferring it.
        """
        findings: list[Finding] = []
        for label, pattern in self._terms:
            # A caller-supplied term behaves exactly like a reversible
            # detector, so it is reported through the same path.
            findings.extend(
                self._find(
                    text, Detector(label=label, pattern=pattern, action=Action.REVERSIBLE)
                )
            )
        for detector in self._detectors:
            findings.extend(self._find(text, detector))
        # Earliest first, so the report reads in the order of the text.
        findings.sort(key=lambda finding: (finding.start, finding.label))
        return findings

    def preview(self, text: str) -> str:
        """Render what would happen. For a terminal, not a log.

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
        """Draft a whitelist covering everything found, ready to edit.

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
    def token_format(self) -> TokenFormat | None:
        """The pinned format, or None when one is chosen per operation."""
        return self._fixed_format

    @property
    def format_candidates(self) -> tuple[TokenFormat, ...]:
        """The formats auto-selection will try, in preference order."""
        return self._candidates

    @property
    def level(self) -> Level:
        """The strictness level in force."""
        return self._level

    @property
    def whitelist(self) -> Whitelist:
        """The allowlist in force, for logging what the policy was."""
        return self._whitelist

    def describe_policy(self) -> str:
        """Summarize what this anonymizer will do, safe to log at startup."""
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
        # The vault's own pattern, so a token written in one format is not
        # judged against another — and so a wikilink in text that used a
        # different format is not mistaken for a mangled token.
        return [match.group(0) for match in vault.pattern.finditer(restored)]

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

    def _substitute(
        self,
        text: str,
        rule: Substitution,
        counters: dict[str, int],
        vault: Vault,
    ) -> str:
        """Replace each distinct match with a stable token.

        The same value gets the same token throughout, so a model can still
        tell that two mentions refer to one thing.
        """
        # Seeded from the vault so a value already tokenized by an earlier
        # call keeps its token. Without this, one value spread across several
        # strings would mint a new token each time and whatever reads the
        # result could no longer tell the mentions refer to one thing.
        seen: dict[str, str] = {original: token for token, original in vault.values.items()}

        def swap(match: re.Match[str]) -> str:
            whole = match.group(0)
            original = rule.value_of(match)
            if not original or self._whitelist.allows_value(original):
                return whole
            if rule.validator is not None and not rule.validator(original):
                return whole
            if original in seen:
                token = seen[original]
            else:
                counters[rule.label] = counters.get(rule.label, 0) + 1
                token = self._active_format.render(
                    self._active_format.label_for(rule.label),
                    counters[rule.label],
                )
                seen[original] = token
                vault.values[token] = original
            # Replace only the value, so a keyword-led match keeps its keyword.
            return whole.replace(original, token, 1)

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

    def _find(self, text: str, detector: Detector) -> list[Finding]:
        """Every match of one detector, as reportable findings."""
        label = detector.label.upper()
        found = []
        for match in detector.pattern.finditer(text):
            value = detector.value_of(match)
            if not value or not detector.matches(value):
                continue
            start, end = detector.span_of(match)
            found.append(
                Finding(
                    label=label,
                    value=value,
                    action=detector.action,
                    start=start,
                    end=end,
                    allowed=self._whitelist.allows_value(value),
                )
            )
        return found
