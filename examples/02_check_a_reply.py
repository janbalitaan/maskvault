"""Never trust a model to hand a token back unchanged.

A model is not a function. It reformats placeholders, wraps them in Markdown
and breaks them over lines — none of which is a bug, and all of which stops a
token being restored. `leaked()` is how you find out before a reader does.

    python examples/02_check_a_reply.py
"""

from maskvault import Anonymizer

anonymizer = Anonymizer()
safe, vault = anonymizer.anonymize("reply to alice@acme.com")
token = next(iter(vault.snapshot()))

REPLIES = {
    "echoes the token": f"I will email {token}.",
    "wraps it in markdown": f"I will email **{token}**.",
    "adds inner spaces": "I will email !| EMAIL_1 |!.",
    "drops the delimiters": "I will email EMAIL_1.",
    "invents a token": "I will email !|EMAIL_9|!.",
}

for description, reply in REPLIES.items():
    restored = anonymizer.restore(reply, vault)
    problems = anonymizer.leaked(reply, vault)
    verdict = "fall back" if problems else "serve it"
    print(f"{description:22} -> {verdict:10} {problems or ''}")

print()
print("In a request handler that becomes:")
print("""
    answer = anonymizer.restore(reply, vault)
    if anonymizer.leaked(answer, vault):
        return deterministic_answer()
    return answer
""")
