"""Fixing a pattern without waiting for a release.

A pattern in a library is a liability on someone else's release cycle. So
every shipped detector, vocabulary and threshold can be replaced, removed or
extended by label.

    python examples/07_extending.py
"""

import re

from maskvault import (
    Action,
    Anonymizer,
    Detector,
    EntropyDetector,
    EntropyThresholds,
    Level,
    Levels,
    PhoneShape,
    SpecialCategories,
)
from maskvault.exceptions import DetectorError
from maskvault.patterns import PHONE

# A vendor added a key prefix the shipped pattern does not know.
BETTER_AWS = Detector(
    label="aws_access_key",
    pattern=re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    action=Action.DESTROY,
    notice="[an AWS key was removed]",
)

# This region writes six-digit internal extensions.
REGIONAL_PHONE = Detector(
    label="phone",
    pattern=PHONE,
    action=Action.REVERSIBLE,
    validate=PhoneShape.bounded(6, 12),
)

# This codebase is full of hex digests, so the default bar misfires.
TUNED_ENTROPY = EntropyDetector.build(thresholds=EntropyThresholds(hex=2.0))

# And an identifier no library would know about.
INTERNAL_ID = Detector(
    label="internal_id",
    pattern=re.compile(r"\bEMP-\d{6}\b"),
    action=Action.REVERSIBLE,
)

detectors = Levels.detectors_for(
    Level.STRICT,
    replace={
        "aws_access_key": BETTER_AWS,
        "phone": REGIONAL_PHONE,
        "high_entropy": TUNED_ENTROPY,
    },
    without=("age", "salary"),  # noise here
    # add_first, not add: an internal id is a punctuated digit run, so the
    # widened phone detector would claim it otherwise.
    add_first=(INTERNAL_ID,),
    extra_terms={"health": ["long covid", "neuropathy"]},
)

anonymizer = Anonymizer(detectors=detectors)

print(f"{len(detectors)} detectors after adjustment")
print(f"policy: {anonymizer.describe_policy()}\n")

for text in (
    "key AROAIOSFODNN7EXAMPLE",
    "call 555123 today",
    "see EMP-004212",
    "recovering from long covid",
    "I am 34 years old",
):
    print(f"  {text:34} -> {anonymizer.anonymize(text)[0]}")

print()
print("a typo is refused rather than silently ignored:")
try:
    Levels.detectors_for(Level.STANDARD, without=("aws_acces_key",))
except DetectorError as error:
    print(f"  {str(error).split('.')[0]}")

print()
print("and a vocabulary extension keeps what shipped:")
vocab = SpecialCategories.vocabularies({"health": ["neuropathy"]})
print(
    f"  health terms: {len(vocab['health'])}, 'diabetes' still present: "
    f"{'diabetes' in vocab['health']}"
)
