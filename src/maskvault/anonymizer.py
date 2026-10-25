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

from maskvault.formats import DEFAULT_FORMATS, FORMATS_BY_NAME, TokenFormats
from maskvault.levels import Levels
from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.models.finding import Finding
from maskvault.models.level import Level
from maskvault.models.substitution import Substitution
from maskvault.models.token_format import TokenFormat
from maskvault.models.vault import Vault
from maskvault.models.whitelist import Whitelist
from maskvault.patterns import NOTICE as _NOTICE


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
        chosen = Levels.detectors_for(self._level) if detectors is None else detectors
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

    def anonymize(self, text: str) -> tuple[str, Vault]:
        """Return text safe to send, plus the vault needed to restore it."""
        token_format = self._fixed_format or TokenFormats.choose_format(text, self._candidates)
        vault = Vault(token_format=token_format)
        return self.anonymize_into(text, vault), vault

    def anonymize_into(self, text: str, vault: Vault) -> str:
        """Replace values in one string, accumulating into an existing vault.

        Nothing about the operation is stored on this object, which is what
        makes one anonymizer safe to share across concurrent callers — the
        shape nearly every web application takes. The format and the counters
        both live on the vault, and the vault belongs to the caller.

        This is what lets a caller anonymize many strings under one vault — a
        structure walked field by field, or a conversation turn by turn. A
        value appearing in two of them keeps one token, so whatever reads the
        result can still tell the mentions refer to the same thing.
        """
        if not self._enabled or not text:
            return text

        # Caller-supplied terms first: they are the most specific and the most
        # sensitive, and a literal must win over a generic pattern.
        for label, pattern in self._terms:
            text = self._substitute(text, Substitution(label, pattern), vault)
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
                    vault,
                )
        return text

    def restore(self, text: str, vault: Vault) -> str:
        """Put the real values back into a model's answer.

        Only tokens present in this vault are restored, so a model that
        invents `[[ORG_9]]` leaves it visible rather than resolving to
        something unrelated — a visible oddity beats a silent wrong answer.
        """
        if not vault.values or not text:
            return text
        for token, original in vault.snapshot().items():
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

        Overlaps are resolved the way `anonymize` resolves them, so the two
        agree. Reporting every detector's matches independently counted a
        value twice whenever two patterns claimed the same span — an IP
        address is also a punctuated digit run, so `explain` said nine where
        `anonymize` replaced six, and the number a developer read was not the
        number they would get.
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
        return self._resolve_overlaps(findings)

    @staticmethod
    def _resolve_overlaps(findings: list[Finding]) -> list[Finding]:
        """Keep one finding per span, picking the same winner substitution does.

        Substitution runs each detector over the text in turn, so the one
        earliest in the detector list claims a span — not the one that starts
        earliest in the text. `findings` arrives in detector order, so walking
        it in that order and skipping anything overlapping an earlier claim
        gives the same answer.

        Getting this backwards is subtle: sorting by position first reports
        `high_entropy` for a Stripe key, because the entropy candidate starts
        a few characters earlier while `stripe_key` is the detector that
        actually replaces it.
        """
        kept: list[Finding] = []
        claimed: list[tuple[int, int]] = []
        for finding in findings:
            overlaps = any(
                finding.start < end and start < finding.end for start, end in claimed
            )
            if overlaps:
                continue
            kept.append(finding)
            claimed.append((finding.start, finding.end))
        # Earliest first, so the report reads in the order of the text.
        kept.sort(key=lambda finding: (finding.start, finding.label))
        return kept

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
        """Tokens still in the text after restoring, in any shape.

        The check to run on every model reply. A model that altered a token
        leaves one behind, and restoring cannot match it — so without this the
        reply has quietly lost a value and nothing says so.

        Catches both well-formed tokens this vault does not know and tokens
        the model changed: inner spaces, dropped or swapped delimiters, a
        lower-cased label, one broken over a line break.

        **Over-reports rather than under-reports, deliberately.** A reply
        discussing a column literally named `EMAIL_1` is flagged, which costs
        a fallback on a request that was fine. The alternative is a value
        silently missing from an answer somebody acts on, and between those
        two the choice is not close.
        """
        restored = self.restore(text, vault)
        # Two kinds of leftover, and the second is the common one.
        #
        # A well-formed token this vault does not know: the model invented
        # `!|EMAIL_9|!`, or the wrong vault was used. Found by the vault's own
        # pattern, so a token written in one format is not judged against
        # another.
        found = {match.group(0) for match in vault.pattern.finditer(restored)}
        # A token the model *altered*, which restoring could not match and
        # the pattern cannot see: `!| EMAIL_1 |!`, `EMAIL_1`, `[EMAIL_1]`,
        # `!|email_1|!`, one split across a line break. Checking only for
        # well-formed tokens reported nothing for any of those, so a reply
        # that had silently lost its value looked clean.
        found.update(self._mangled(restored, vault))
        return sorted(found)

    def resolved(self, text: str, vault: Vault) -> list[str]:
        """Which of this vault's tokens appear intact in the text.

        For the question `leaked()` does not answer. Three values go out and
        a reply comes back mentioning two of them: that is normal — a reply
        need not repeat everything it was given — so nothing is wrong and
        `leaked()` is correctly silent.

        But *whether* it is normal is the application's call, not this
        library's. A summarizer mentioning two of three contacts is fine; a
        form-filler returning two of three fields is a failure. So the counts
        are reported rather than judged:

            sent = anonymizer.resolved(reply, vault)
            if len(sent) < len(vault.values):
                ...  # some values were not referred to

        Combined with `leaked()` the three outcomes separate cleanly:

            resolved 3, leaked 0   everything came back
            resolved 2, leaked 0   one was not mentioned — usually fine
            resolved 2, leaked 1   one was mangled — do not trust the reply

        Tokens for destroyed values are never in the vault, so they cannot
        appear here. A destroyed value has no token to return.
        """
        return sorted(token for token in vault.values if token in text)

    def unresolved(self, text: str, vault: Vault) -> list[str]:
        """Which of this vault's tokens do not appear intact in the text.

        The complement of `resolved`. Includes both the values a reply simply
        did not mention and the ones it mangled — `leaked()` is what tells
        those two apart, and only the second is a reason to distrust a reply.
        """
        return sorted(token for token in vault.values if token not in text)

    @staticmethod
    def _mangled(text: str, vault: Vault) -> set[str]:
        """Find label-and-index cores from this vault that survived in the text.

        The delimiters are what a model changes; the `LABEL_1` core is what it
        tends to keep. So the core is what to look for, case-insensitively and
        tolerating whitespace where the model may have broken a line.

        Reported as the core rather than as whatever surrounds it, because the
        caller's question is "did a token fail to restore", not "what exactly
        did the model write".
        """
        cores = set()
        pattern = vault.token_format.pattern
        for token in vault.snapshot():
            match = pattern.fullmatch(token)
            if match:
                cores.add(f"{match.group(1)}_{match.group(2)}")
        if not cores:
            return set()
        # Whitespace-tolerant, so a core broken over a line break is still
        # recognized: "EMAIL\n_1" is the same failure as "EMAIL_1".
        alternation = "|".join(
            re.escape(core).replace("_", r"\s*_\s*") for core in sorted(cores)
        )
        return {
            re.sub(r"\s+", "", match.group(0)).upper()
            for match in re.finditer(alternation, text, re.IGNORECASE)
        }

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
        vault: Vault,
    ) -> str:
        """Replace each distinct match with a stable token.

        The same value gets the same token throughout, so a model can still
        tell that two mentions refer to one thing.
        """

        def swap(match: re.Match[str]) -> str:
            whole = match.group(0)
            original = rule.value_of(match)
            if self._is_own_output(original, vault.token_format):
                return whole
            if not original or self._whitelist.allows_value(original):
                return whole
            if rule.validator is not None and not rule.validator(original):
                return whole
            # The vault allocates: it holds the counters and the reverse
            # mapping, so giving a repeated value its existing token and
            # minting a new one are one atomic step rather than two.
            token = vault.mint(rule.label, original)
            # Replace only the value, so a keyword-led match keeps its keyword.
            return whole.replace(original, token, 1)

        return rule.pattern.sub(swap, text)

    def _is_own_output(self, candidate: str, token_format: TokenFormat) -> bool:
        """Whether a candidate is something this anonymizer already inserted.

        Detectors run one after another over progressively replaced text, so a
        later detector sees the tokens and notices the earlier ones left
        behind. At PARANOID — a lower entropy bar and symbols in the alphabet
        — `@@IP_ADDRESS_1@@` measures as a high-entropy value and was
        destroyed, which lost the original permanently and left a vault whose
        tokens no longer appeared in the text. Restoring could never work.

        Checked before the whitelist, because this is not a policy decision a
        caller should have to make: replacing a replacement is never what
        anyone wanted.
        """
        if not candidate:
            return False
        # Searched, not fullmatched. A candidate often *contains* a token
        # rather than equalling one: the paranoid entropy pattern took
        # `user=@@EMAIL_1@@` as a single run, so an exact comparison let it
        # through and the token inside was destroyed with the rest.
        if token_format.pattern.search(candidate):
            return True
        # The core without its delimiters. A detector reading already-replaced
        # text does not always get the whole token: the entropy net's
        # candidate pattern stops at `!|`, so it sees `EMAIL_QRMZVB_1` on its
        # own. With a wide random scope that core measures as a secret, and at
        # twelve letters 11% of tokens were destroyed — the value lost and the
        # vault left holding a token no longer in the text.
        #
        # Fullmatched, not searched, so a real secret that happens to contain
        # something token-shaped is still judged on its own merits.
        if token_format.core_pattern.fullmatch(candidate):
            return True
        # A notice is prose in brackets, and the only prose this library puts
        # into the text. Matching the shape rather than the exact strings
        # keeps a caller's custom notice covered too.
        return bool(_NOTICE.search(candidate))

    def _destroy(self, text: str, detector: Detector, vault: Vault) -> str:
        """Remove a value that must never be sent or restored."""

        def swap(match: re.Match[str]) -> str:
            original = match.group(0)
            if self._is_own_output(original, vault.token_format):
                return original
            if self._whitelist.allows_value(original):
                return original
            if detector.validate is not None and not detector.validate(original):
                return original
            vault.destroy(detector.label)
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
