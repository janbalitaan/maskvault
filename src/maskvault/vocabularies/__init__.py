"""The word lists, one file per category.

These are data, not logic, and they are the part of the library most likely
to be edited — by someone adding a language, a condition the lists miss, or a
term their own domain cares about. Keeping each in its own file means such a
change touches one small file whose entire contents are the thing being
changed.

The categories follow GDPR Article 9, which is a better organizing principle
than intuition: it names racial or ethnic origin, political opinion, religious
or philosophical belief, trade union membership, genetic and biometric data,
health, and sex life or sexual orientation as needing explicit consent. That
list has held up well as a description of what people do not want shared.
Criminal and financial history is added because it behaves the same way.

A vocabulary is not detection. It misses what nobody listed and matches words
used innocently. It is a floor, not a guarantee.
"""

from collections.abc import Mapping
from types import MappingProxyType

from maskvault.vocabularies.criminal import CRIMINAL_TERMS
from maskvault.vocabularies.health import HEALTH_TERMS
from maskvault.vocabularies.homonyms import TECHNICAL_HOMONYMS
from maskvault.vocabularies.identity import IDENTITY_TERMS
from maskvault.vocabularies.origin import ORIGIN_TERMS
from maskvault.vocabularies.politics import POLITICS_TERMS
from maskvault.vocabularies.religion import RELIGION_TERMS
from maskvault.vocabularies.safe_values import COMMON_SAFE_VALUES

# The categories, keyed by the label their tokens carry. Adding a language
# means adding a file and one line here.
# Read-only. A plain dict here meant a caller — or a library deeper in the
# stack — could assign to it and silently disable a category for every user in
# the process. In a library whose job is to not miss things, detection turning
# itself off is the worst available failure.
#
# Extending is still supported, and is the first thing people want: a domain
# vocabulary, or a language these lists do not cover. See
# `SpecialCategories.special_category_detectors(extra=...)`, which merges
# without touching this.
SPECIAL_CATEGORIES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "health": HEALTH_TERMS,
        "religion": RELIGION_TERMS,
        "politics": POLITICS_TERMS,
        "identity": IDENTITY_TERMS,
        "origin": ORIGIN_TERMS,
        "criminal": CRIMINAL_TERMS,
    }
)

__all__ = [
    "COMMON_SAFE_VALUES",
    "CRIMINAL_TERMS",
    "HEALTH_TERMS",
    "IDENTITY_TERMS",
    "ORIGIN_TERMS",
    "POLITICS_TERMS",
    "RELIGION_TERMS",
    "SPECIAL_CATEGORIES",
    "TECHNICAL_HOMONYMS",
]
