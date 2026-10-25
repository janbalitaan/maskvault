"""One vault across a conversation, so one person keeps one token.

Without this, each turn mints a new token for the same address and the model
can no longer tell that two mentions are the same person.

    python examples/05_a_multi_turn_chat.py
"""

from maskvault import Anonymizer
from maskvault.models.vault import Vault

anonymizer = Anonymizer()

# One vault for the whole conversation. Safe to use from concurrent callers:
# it allocates tokens under its own lock.
conversation = Vault()

turns = [
    "Who owns invoice 8842-1193? It was raised by alice@acme.com.",
    "Ask alice@acme.com to confirm, and cc bob@acme.com.",
    "Has alice@acme.com replied?",
]

for number, turn in enumerate(turns, start=1):
    safe = anonymizer.anonymize_into(turn, conversation)
    print(f"turn {number}: {safe}")

print()
print(f"distinct values across three turns: {len(conversation.snapshot())}")
print("alice kept one token throughout, so the model can follow the thread.")

print()
reply = "Yes — !|EMAIL_1|! confirmed it this morning."
print(f"model says: {reply}")
print(f"reader sees: {anonymizer.restore(reply, conversation)}")

print()
print("To restore in a different request or process, the vault has to travel.")
print("See examples/06_a_store.py.")
