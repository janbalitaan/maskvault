"""Religious and philosophical belief.

A protected characteristic in most jurisdictions, and a basis for
discrimination in all of them.

Matched case-insensitively and word-bounded, longest term first, so a
multi-word term wins over its parts and a short term does not match inside
a longer word.
"""

from __future__ import annotations

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
