"""Build a policy from real text rather than guessing at one.

Nothing is allowed by default, which is the safe direction — and would make
configuring a whitelist a guessing game. So it is not: run real input
through, read what was found, and keep the entries that are harmless.

    python examples/03_what_would_be_replaced.py
"""

import json

from maskvault import Anonymizer, Level

text = (
    "I'm a backend engineer at Initech. I use Python and FastAPI. "
    "Reach me at alice@acme.com. I was treated for diabetes in 2019."
)

anonymizer = Anonymizer(level=Level.STRICT)

print("what would happen, and why:")
for finding in anonymizer.explain(text):
    state = "allowed" if finding.allowed else finding.action.value
    print(f"  {state:11} {finding.label:12} {finding.value}")

print()
print("a draft whitelist, for you to edit down:")
print(json.dumps(anonymizer.suggest_whitelist(text), indent=2))

print()
print("with Python and FastAPI allowed:")
relaxed = Anonymizer(
    level=Level.STRICT,
    whitelist={"values": ["Python", "FastAPI"]},
)
print(f"  {relaxed.anonymize(text)[0]}")

# `explain` and `preview` print real values, which is the point — you cannot
# decide what to allow without seeing it. Neither is safe to log.
