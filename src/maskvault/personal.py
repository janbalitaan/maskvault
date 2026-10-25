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

import re

from maskvault.models.action import Action
from maskvault.models.detector import Detector

# ---------------------------------------------------------------------------
# Structured identifiers
# ---------------------------------------------------------------------------

STRUCTURED_PERSONAL: tuple[Detector, ...] = (
    Detector(
        label="street_address",
        # A number followed by a street word. Deliberately conservative: it
        # wants the street type, because "12 years" is not an address.
        pattern=re.compile(
            r"\b\d{1,5}[A-Za-z]?\s+(?:[A-Z][\w'-]*\s+){0,3}"
            r"(?:Street|St\.?|Avenue|Ave\.?|Road|Rd\.?|Boulevard|Blvd\.?|Lane|Ln\.?|"
            r"Drive|Dr\.?|Court|Ct\.?|Place|Pl\.?|Terrace|Way|Close|Crescent|"
            r"Highway|Hwy\.?|Parkway|Circle|Square|Sq\.?)\b",
            re.I,
        ),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="unit_number",
        pattern=re.compile(
            r"(?i)\b(?:apt|apartment|unit|suite|ste|flat|room|rm|blk|block|"
            r"floor|fl)\.?\s*#?\s*[\w-]{1,8}\b"
        ),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="postal_code",
        # Several national formats. Matched only after a locality hint, so a
        # bare four-digit number is not mistaken for a postcode.
        pattern=re.compile(
            r"(?i)\b(?:zip|zipcode|postal\s*code|postcode)\s*[:=]?\s*"
            r"([A-Z0-9][A-Z0-9 -]{2,9}[A-Z0-9])\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="coordinates",
        # A home is findable from one of these to within a few metres.
        pattern=re.compile(
            r"(?<![\w.])-?(?:[0-8]?\d|90)\.\d{3,}\s*,\s*-?(?:1[0-7]\d|[0-9]?\d|180)\.\d{3,}(?![\w.])"
        ),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="drivers_license",
        pattern=re.compile(
            r"(?i)\b(?:driver'?s?\s*(?:licen[cs]e|lic)|dl|licen[cs]e\s*(?:no|number|#))"
            r"\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{4,14})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="license_plate",
        pattern=re.compile(
            r"(?i)\b(?:plate|registration|reg\.?)\s*(?:no\.?|number|#)?\s*[:=]?\s*"
            r"([A-Z0-9]{2,4}[\s-]?[A-Z0-9]{2,4})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="tax_id",
        pattern=re.compile(
            r"(?i)\b(?:tax\s*id|tin|ein|vat\s*(?:no|number|id)|nino|"
            r"national\s*insurance|sss|tin\s*no)\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{5,15})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="bank_account",
        pattern=re.compile(
            r"(?i)\b(?:account|acct|a/c|routing|sort\s*code|swift|bic)\s*"
            r"(?:no\.?|number|#)?\s*[:=]?\s*([A-Z0-9][A-Z0-9 -]{5,20})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="policy_number",
        pattern=re.compile(
            r"(?i)\b(?:policy|member|patient|medical\s*record|mrn|insurance|"
            r"medicare|medicaid|philhealth|nhs)\s*(?:no\.?|number|id|#)?\s*"
            r"[:=]?\s*([A-Z0-9][A-Z0-9 -]{4,18})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="employee_id",
        pattern=re.compile(
            r"(?i)\b(?:employee|staff|student|badge|payroll)\s*(?:no\.?|number|id|#)?"
            r"\s*[:=]?\s*([A-Z0-9][A-Z0-9-]{3,14})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="salary",
        # Compensation is one of the most consequential things to leak, and
        # the figure is what matters, not the currency.
        pattern=re.compile(
            r"(?i)(?:(?:salary|compensation|pay|rate|earn(?:s|ing|ed)?|income|"
            r"package|offer)\D{0,16})"
            r"(?:[$£€₱¥]|usd|eur|gbp|php|inr|sgd|aud)?\s?"
            r"\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?:\s?(?:k|per\s+\w+|/\w+|a\s+year|annually|pa))?"
        ),
        action=Action.REVERSIBLE,
    ),
    Detector(
        label="social_handle",
        pattern=re.compile(
            # Platform names only, and none shorter than two characters. A
            # one-letter name such as "x" matches inside any address or path,
            # which costs far more than the handles it would catch.
            r"(?i)\b(?:twitter|instagram|telegram|tiktok|discord|signal|"
            r"whatsapp|wechat|viber|skype|facebook|mastodon|threads|bluesky)"
            # An optional noun and copula, so "telegram is x", "telegram
            # handle: x" and "telegram @x" all reach the value.
            r"(?:\s+(?:handle|username|user|account|id|profile))?"
            r"\s*(?:is|:|=|at)?\s*@?([\w.]{3,30})\b"
        ),
        action=Action.REVERSIBLE,
        group=1,
    ),
    Detector(
        label="age",
        pattern=re.compile(
            r"(?i)\b(?:i\s*am|aged?|age\s*[:=]?)\s*(\d{1,3})\s*(?:years?\s*old)?\b"
        ),
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

HEALTH_TERMS: frozenset[str] = frozenset(
    {
        "diabetes",
        "diabetic",
        "cancer",
        "carcinoma",
        "leukemia",
        "leukaemia",
        "tumor",
        "tumour",
        "hiv",
        "aids",
        "hepatitis",
        "tuberculosis",
        "epilepsy",
        "epileptic",
        "asthma",
        "asthmatic",
        "depression",
        "depressed",
        "anxiety",
        "bipolar",
        "schizophrenia",
        "schizophrenic",
        "ptsd",
        "adhd",
        "autism",
        "autistic",
        "ocd",
        "dyslexia",
        "dyslexic",
        "alzheimer",
        "alzheimers",
        "dementia",
        "parkinson",
        "parkinsons",
        "arthritis",
        "lupus",
        "fibromyalgia",
        "crohn",
        "crohns",
        "colitis",
        "ibs",
        "hypertension",
        "hypertensive",
        "cholesterol",
        "stroke",
        "aneurysm",
        "heart attack",
        "cardiac arrest",
        "heart failure",
        "angina",
        "arrhythmia",
        "kidney failure",
        "dialysis",
        "transplant",
        "cirrhosis",
        "chemotherapy",
        "chemo",
        "radiotherapy",
        "immunotherapy",
        "remission",
        "disability",
        "disabled",
        "wheelchair",
        "amputee",
        "prosthetic",
        "blind",
        "deaf",
        "paralysis",
        "paralyzed",
        "paraplegic",
        "quadriplegic",
        "miscarriage",
        "stillbirth",
        "infertility",
        "ivf",
        "abortion",
        "addiction",
        "alcoholism",
        "alcoholic",
        "rehab",
        "overdose",
        "relapse",
        "suicidal",
        "self-harm",
        "eating disorder",
        "anorexia",
        "bulimia",
        "covid",
        "long covid",
        "chronic fatigue",
        "migraine",
        "insomnia",
        "pregnant",
        "pregnancy",
        "menopause",
        "hysterectomy",
        "antidepressant",
        "antipsychotic",
        "insulin",
        "chemo drugs",
        "medication",
        "diagnosis",
        "diagnosed",
        "prognosis",
        "biopsy",
        "chronic",
        "terminal",
    }
)

RELIGION_TERMS: frozenset[str] = frozenset(
    {
        "christian",
        "christianity",
        "catholic",
        "catholicism",
        "protestant",
        "evangelical",
        "baptist",
        "methodist",
        "lutheran",
        "presbyterian",
        "pentecostal",
        "anglican",
        "orthodox",
        "mormon",
        "jehovah",
        "adventist",
        "quaker",
        "muslim",
        "islam",
        "islamic",
        "sunni",
        "shia",
        "shiite",
        "sufi",
        "jewish",
        "judaism",
        "jew",
        "hasidic",
        "orthodox jew",
        "zionist",
        "hindu",
        "hinduism",
        "buddhist",
        "buddhism",
        "sikh",
        "sikhism",
        "jain",
        "jainism",
        "baha'i",
        "bahai",
        "zoroastrian",
        "shinto",
        "taoist",
        "taoism",
        "confucian",
        "atheist",
        "atheism",
        "agnostic",
        "agnosticism",
        "humanist",
        "secular",
        "pagan",
        "wiccan",
        "animist",
        "spiritualist",
        "born again",
        "practicing",
        "devout",
        "observant",
        "halal",
        "kosher",
        "ramadan",
        "lent",
        "sabbath",
        "shabbat",
        "hajj",
        "baptism",
        "confirmation",
    }
)

POLITICS_TERMS: frozenset[str] = frozenset(
    {
        "conservative",
        "liberal",
        "libertarian",
        "socialist",
        "socialism",
        "communist",
        "communism",
        "marxist",
        "marxism",
        "anarchist",
        "anarchism",
        "democrat",
        "republican",
        "labour",
        "tory",
        "green party",
        "left wing",
        "right wing",
        "far left",
        "far right",
        "centrist",
        "moderate",
        "progressive",
        "reactionary",
        "populist",
        "nationalist",
        "nationalism",
        "feminist",
        "feminism",
        "activist",
        "activism",
        "dissident",
        "union member",
        "trade union",
        "shop steward",
        "collective bargaining",
        "strike",
        "picket",
        "unionized",
        "unionised",
        "voted for",
        "voting for",
        "i vote",
        "my vote",
        "party member",
    }
)

IDENTITY_TERMS: frozenset[str] = frozenset(
    {
        "gay",
        "lesbian",
        "bisexual",
        "bi",
        "queer",
        "homosexual",
        "heterosexual",
        "straight",
        "asexual",
        "pansexual",
        "lgbt",
        "lgbtq",
        "lgbtqia",
        "transgender",
        "trans",
        "nonbinary",
        "non-binary",
        "genderqueer",
        "genderfluid",
        "intersex",
        "cisgender",
        "cis",
        "transitioning",
        "transitioned",
        "deadname",
        "pronouns",
        "coming out",
        "came out",
        "closeted",
        "in the closet",
        "partner",
        "husband",
        "wife",
        "spouse",
        "fiance",
        "fiancee",
        "divorced",
        "separated",
        "widowed",
        "single parent",
    }
)

ORIGIN_TERMS: frozenset[str] = frozenset(
    {
        "immigrant",
        "emigrant",
        "migrant",
        "expat",
        "expatriate",
        "refugee",
        "asylum",
        "asylum seeker",
        "undocumented",
        "illegal alien",
        "green card",
        "permanent resident",
        "naturalized",
        "naturalised",
        "visa",
        "work permit",
        "h1b",
        "h-1b",
        "tourist visa",
        "student visa",
        "deported",
        "deportation",
        "overstayed",
        "citizenship",
        "dual citizen",
        "stateless",
        "ethnic",
        "ethnicity",
        "indigenous",
        "aboriginal",
        "native",
        "black",
        "white",
        "asian",
        "hispanic",
        "latino",
        "latina",
        "latinx",
        "caucasian",
        "mixed race",
        "biracial",
        "minority",
    }
)

CRIMINAL_TERMS: frozenset[str] = frozenset(
    {
        "convicted",
        "conviction",
        "arrested",
        "arrest",
        "charged",
        "indicted",
        "felony",
        "felon",
        "misdemeanor",
        "misdemeanour",
        "criminal record",
        "probation",
        "parole",
        "incarcerated",
        "imprisoned",
        "jailed",
        "prison",
        "dui",
        "dwi",
        "expunged",
        "acquitted",
        "lawsuit",
        "sued",
        "settlement",
        "restraining order",
        "bankruptcy",
        "bankrupt",
        "foreclosure",
        "eviction",
        "garnishment",
        "default",
        "repossessed",
        "credit score",
        "debt collection",
    }
)

# The categories, keyed by the label their tokens carry.
SPECIAL_CATEGORIES: dict[str, frozenset[str]] = {
    "health": HEALTH_TERMS,
    "religion": RELIGION_TERMS,
    "politics": POLITICS_TERMS,
    "identity": IDENTITY_TERMS,
    "origin": ORIGIN_TERMS,
    "criminal": CRIMINAL_TERMS,
}


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


def special_category_detectors(
    categories: tuple[str, ...] | None = None,
) -> tuple[Detector, ...]:
    """Detectors for the special categories, all of them by default."""
    chosen = categories or tuple(SPECIAL_CATEGORIES)
    return tuple(
        category_detector(name, SPECIAL_CATEGORIES[name])
        for name in chosen
        if name in SPECIAL_CATEGORIES
    )
