"""The whole library in twenty lines: anonymize, send, restore.

python examples/01_round_trip.py
"""

from maskvault import Anonymizer

# One anonymizer, built once. It holds no per-operation state, so this is
# safe at module scope in a web application shared by every request.
anonymizer = Anonymizer()

question = (
    "Draft a reply to alice@acme.com about invoice 8842-1193. "
    "She can be reached on +63 917 555 1234."
)

safe, vault = anonymizer.anonymize(question)
print("sent to the provider:")
print(f"  {safe}\n")

# Whatever a provider returns, with the tokens it was given.
reply = f"I have drafted a note to {next(iter(vault.snapshot()))} about the invoice."

answer = anonymizer.restore(reply, vault)
print("shown to the reader:")
print(f"  {answer}\n")

# What is safe to write in a log. The vault itself never is.
print(f"log line: {vault.summary()}")
