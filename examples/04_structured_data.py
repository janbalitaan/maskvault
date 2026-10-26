"""A request body rather than a sentence.

What you actually want to pass somewhere is usually nested: a payload, a log
record, a config dump. Flattening it to text and back loses the structure.

    python examples/04_structured_data.py
"""

import json

from maskvault import Anonymizer, anonymize_data, restore_data

anonymizer = Anonymizer()

payload = {
    "request_id": "req-7742",
    "user": {"email": "alice@acme.com", "ip": "10.42.7.19"},
    "contacts": ["bob@acme.com", "carol@acme.com"],
    "retries": 3,
    "trace": None,
}

safe, vault = anonymize_data(payload, anonymizer)
print("safe to send:")
print(json.dumps(safe, indent=2))

print()
print(f"restores exactly: {restore_data(safe, anonymizer, vault) == payload}")
print(f"log line:         {vault.summary()}")

print()
print("note what was left alone:")
print("  'retries' and 'trace' — a number and None have nothing to tokenize")
print()
print("keys are scanned too, because a key can be the data:")
by_email, _ = anonymize_data({"alice@acme.com": "owner"}, anonymizer)
print(f"  a map keyed by email   -> {by_email}")
schema_keys, _ = anonymize_data({"email": "bob@acme.com", "name": "Bob"}, anonymizer)
print(f"  schema keys untouched  -> {schema_keys}")
literal, _ = anonymize_data({"alice@acme.com": "owner"}, anonymizer, include_keys=False)
print(f"  include_keys=False     -> {literal}")
print()
print("numbers stay numbers unless you ask otherwise:")
numbers, _ = anonymize_data({"account": 4111111111111111}, anonymizer, stringify_numbers=True)
print(f"  stringify_numbers=True -> {numbers}")
