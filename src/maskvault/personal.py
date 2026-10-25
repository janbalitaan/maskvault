"""Personal details, beyond the obvious identifiers.

An email address and a phone number are the easy cases. The details that do
real harm when they leak are the ones that are hard to take back: a health
condition, a home address, a salary, an immigration status, a religion. Those
decide whether someone gets a job, a loan or an apartment, and none of them
belongs in a third party's logs.

Two kinds here, because they need different handling:

**Structured identifiers** have a shape, so a pattern finds them — a license
number, a plate, coordinates, a policy number, a postcode.

**Special categories** do not. "I have type 2 diabetes" has no format; the
sensitive part is a *word*, and the word only matters in context. For those
there is a curated vocabulary, and the term itself is tokenized. That keeps
the sentence usable — a model reading "I was diagnosed with [[HEALTH_1]] in
2019" can still answer sensibly, and the reader gets the real word back.

The categories follow GDPR Article 9, which is a better organizing principle
than intuition: racial or ethnic origin, political opinions, religious or
philosophical beliefs, trade union membership, genetic and biometric data,
health, and sex life or sexual orientation. Those are the ones European law
treats as needing explicit consent, and that list has held up well as a
general description of what people do not want shared.

A vocabulary is not detection. It will miss a condition nobody listed and
will match a word used innocently. It is a floor, not a guarantee, and the
`terms` option exists for whatever matters to a particular caller.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import re

from maskvault.models.action import Action
from maskvault.models.detector import Detector
from maskvault.patterns import (
    AGE,
    BANK_ACCOUNT,
    COORDINATES,
    DRIVERS_LICENSE,
    EMPLOYEE_ID,
    LICENSE_PLATE,
    POLICY_NUMBER,
    POSTAL_CODE,
    SALARY,
    SOCIAL_HANDLE,
    STREET_ADDRESS,
    TAX_ID,
    UNIT_NUMBER,
)
from maskvault.vocabularies import SPECIAL_CATEGORIES

# ---------------------------------------------------------------------------
# Structured identifiers
# ---------------------------------------------------------------------------

STRUCTURED_PERSONAL: tuple[Detector, ...] = (
    Detector(
        label="street_address",
        # A number followed by a street word. Deliberately conservative: it
        # wants the street type, because "12 years" is not an address.
        pattern=STREET_ADDRESS,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="unit_number",
        pattern=UNIT_NUMBER,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="postal_code",
        # Several national formats. Matched only after a locality hint, so a
        # bare four-digit number is not mistaken for a postcode.
        pattern=POSTAL_CODE,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="coordinates",
        # A home is findable from one of these to within a few metres.
        pattern=COORDINATES,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="drivers_license",
        pattern=DRIVERS_LICENSE,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="license_plate",
        pattern=LICENSE_PLATE,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="tax_id",
        pattern=TAX_ID,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="bank_account",
        pattern=BANK_ACCOUNT,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="policy_number",
        pattern=POLICY_NUMBER,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="employee_id",
        pattern=EMPLOYEE_ID,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="salary",
        # Compensation is one of the most consequential things to leak, and
        # the figure is what matters, not the currency.
        pattern=SALARY,
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="social_handle",
        pattern=SOCIAL_HANDLE,
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="age",
        pattern=AGE,
        action=Action.REVERSIBLE,
        group=1,
    ),
)


# ---------------------------------------------------------------------------
# Special categories (GDPR Article 9)
# ---------------------------------------------------------------------------
#
# A vocabulary, not detection. Each term is tokenized where it appears, which
# keeps the surrounding sentence usable while the word itself stays private.


class SpecialCategories:
    """Builds detectors for the GDPR Article 9 special categories.

    Health, religion, politics, identity and origin, plus criminal and
    financial history. These are vocabulary-driven rather than pattern-driven:
    there is no shape to a religion, only a list of words.
    """

    @staticmethod
    def category_detector(category: str, terms: frozenset[str]) -> Detector:
        """Build one detector that matches any term in a category.

        Terms are sorted longest first so "heart attack" wins over "heart", and
        each is word-bounded so "bi" does not match inside "big".
        """
        ordered = sorted(terms, key=len, reverse=True)
        alternation = "|".join(re.escape(term) for term in ordered)
        return Detector(
            label=category,
            pattern=re.compile(rf"\b(?:{alternation})\b", re.I),
            action=Action.REVERSIBLE,
        )

    @staticmethod
    def vocabularies(
        extra: Mapping[str, Iterable[str]] | None = None,
    ) -> dict[str, frozenset[str]]:
        """Return the shipped vocabularies, merged with `extra`.

        A name already shipped is *extended*, not replaced — the shipped
        terms stay. A name that is not becomes a new category. Both are the
        things people actually want:

            # a term the health list misses
            vocabularies({"health": ["long covid", "neuropathy"]})

            # a category of your own
            vocabularies({"diagnosis": ["fibromyalgia"]})

        Extending rather than replacing is deliberate. A caller adding one
        term almost never means "and discard the other hundred", and the
        version that silently did would be a privacy regression dressed as a
        convenience. To replace a category, pass your own set to
        `category_detector` directly.

        Terms are lower-cased, because matching is case-insensitive and a
        capitalized entry would otherwise look like it worked while matching
        nothing extra.
        """
        merged = {name: set(terms) for name, terms in SPECIAL_CATEGORIES.items()}
        for name, terms in (extra or {}).items():
            merged.setdefault(name, set()).update(
                term.strip().lower() for term in terms if term.strip()
            )
        return {name: frozenset(terms) for name, terms in merged.items()}

    @staticmethod
    def special_category_detectors(
        categories: tuple[str, ...] | None = None,
        extra: Mapping[str, Iterable[str]] | None = None,
    ) -> tuple[Detector, ...]:
        """Detectors for the special categories, all of them by default.

        `extra` adds terms or whole categories; see `vocabularies`. A name in
        `categories` that neither ships nor appears in `extra` is skipped
        rather than raising, so a caller can name a category they expect a
        future version to add.
        """
        available = SpecialCategories.vocabularies(extra)
        chosen = categories or tuple(available)
        return tuple(
            SpecialCategories.category_detector(name, available[name])
            for name in chosen
            if name in available
        )
