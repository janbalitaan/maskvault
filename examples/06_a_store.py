"""Restoring somewhere other than where you anonymized.

The common case needs none of this: anonymize, call the provider and restore
in one handler, and the vault is a local variable. A store is for when the
vault has to outlive the request.

What a store holds is the plaintext, so it takes a required cipher.

    pip install 'maskvault[encryption]'
    python examples/06_a_store.py
"""

from maskvault import Anonymizer
from maskvault.ciphers import FernetCipher, PlaintextCipher
from maskvault.stores import MemoryVaultStore, SerializedVaultStore


class DictBackend:
    """Stands in for Redis. A real adapter is these four methods."""

    def __init__(self) -> None:
        self.data: dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        return self.data.get(key)

    def set(self, key: str, value: bytes, ttl_seconds: float) -> None:
        self.data[key] = value

    def delete(self, key: str) -> None:
        self.data.pop(key, None)


anonymizer = Anonymizer()

# --- node 1: anonymize and store -----------------------------------------
backend = DictBackend()
key = FernetCipher.generate_key()  # once at deployment, shared by every node
store = SerializedVaultStore(backend, FernetCipher(key))

safe, vault = anonymizer.anonymize("reply to alice@acme.com")
store.save("conversation-7", vault)

print(f"sent to the provider: {safe}")
print(f"what the store holds: {next(iter(backend.data.values()))[:48]}...")
print(f"  contains the address: {b'alice@acme.com' in next(iter(backend.data.values()))}")

# --- node 2: load and restore --------------------------------------------
elsewhere = SerializedVaultStore(backend, FernetCipher(key))
loaded = elsewhere.load("conversation-7")
reply = f"I emailed {next(iter(loaded.snapshot()))}."
print(f"\nrestored on another node: {anonymizer.restore(reply, loaded)}")

# --- what each store tells you about itself -------------------------------
print()
for described in (
    SerializedVaultStore(backend, FernetCipher(key)),
    SerializedVaultStore(backend, PlaintextCipher()),
    MemoryVaultStore(ttl_seconds=0),
):
    print(f"  {described.describe()}")

print()
print("Opting out of encryption is a name you have to type, so it shows in")
print("review. And ttl_seconds=0 means no expiry — retention is yours.")
