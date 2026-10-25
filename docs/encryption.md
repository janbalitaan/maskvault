# Encryption

## What is encrypted, and what is not

**A stored vault: yes.** It holds every original value, and it goes somewhere
with wider access than the application — a shared cache, a table, a backup of
either — while the key stays in the application. Those are different trust
domains, which is what makes encrypting worth doing here.

**A value in memory: no.** To decrypt you need the key, and the key would
live in the same process as the ciphertext. An attacker who can read your
process memory reads both. That version looks like security and is not, so
this library does not offer it. See [limitations](limitations.md).

## Who does which part

| | Who |
| --- | --- |
| Deciding when to encrypt | maskvault — always, before bytes reach the backend |
| The cipher implementation | `cryptography`'s Fernet — **not maskvault** |
| The key | **you** |
| Which cipher | you, at the call site |

maskvault writes no cryptographic primitive. The only cipher here delegates:

```python
return self._fernet.encrypt(plaintext)
```

There is a test asserting that stays true.

## A cipher is required, not defaulted

A store refuses to be built without one:

```python
SerializedVaultStore(backend, FernetCipher.from_env())   # encrypted
SerializedVaultStore(backend, PlaintextCipher())          # opt out, visibly
SerializedVaultStore(backend)                             # TypeError
```

There is no secure value to default to. A key cannot be invented — a random
one per process would leave the node that restores unable to decrypt what the
node that anonymized wrote, which is the case a store exists to serve. And
defaulting to plaintext would mean a store that looks encrypted to anyone who
did not read the signature.

So `PlaintextCipher` is a name you have to type. It is sometimes the right
choice — a store only the application can reach, a test — but it should show
in review.

## Setting it up

```bash
pip install 'maskvault[encryption]'
```

```python
key = FernetCipher.generate_key()   # once, at deployment. Keep it somewhere safe.
```

Then in every node:

```python
cipher = FernetCipher(key)
cipher = FernetCipher.from_env()         # MASKVAULT_VAULT_KEY
cipher = FernetCipher.from_env("MY_KEY")
```

The **same** key has to reach every node that restores. `from_env` raises
when the variable is unset rather than falling back to plaintext: a
deployment that forgot to inject the key should fail at startup, not store
readable vaults until someone notices.

## Authentication matters as much as secrecy

Fernet is AES-128-CBC with an HMAC-SHA256 tag. The tag is the part people
overlook: a vault a store operator can **modify** is one whose tokens can be
pointed at values of their choosing, so the answer your reader sees becomes
the answer the attacker wrote. Secrecy alone would not prevent that.

```python
cipher.decrypt(tampered)
# VaultError: could not be decrypted: the key is wrong, or the stored bytes
# were modified
```

Reported as itself rather than as an absent vault, because a wrong key and a
cache miss are different events.

## Or own it entirely

`VaultCipher` is a Protocol, so a cipher where the key never reaches your
process needs no import from here:

```python
class KmsCipher:
    def __init__(self, client, key_id):
        self._client, self._key_id = client, key_id

    def encrypt(self, plaintext):
        return self._client.encrypt(
            KeyId=self._key_id, Plaintext=plaintext
        )["CiphertextBlob"]

    def decrypt(self, ciphertext):
        return self._client.decrypt(CiphertextBlob=ciphertext)["Plaintext"]

    @property
    def describes(self):
        return f"aws kms, key {self._key_id}"
```

```python
SerializedVaultStore(backend, KmsCipher(boto3.client("kms"), "alias/prod"))
```

`store.describe()` then reports `aws kms, key alias/prod`, so the choice is
visible in a startup log. An HSM or a Vault transit backend fit the same way.

## The key never appears in anything this library writes

Checked on nine surfaces: the cipher's repr, `describes`, the store's repr,
`describe()`, the vault's repr, `as_dict()`, `summary()`, the stored bytes,
and the anonymized text.

```python
repr(FernetCipher(key))
# "FernetCipher(fernet (AES-128-CBC with an HMAC-SHA256 tag))"
```

That repr is explicit rather than inherited. The default happened to be safe
only because `FernetCipher` is a plain class — adding `@dataclass` later
would have started printing the key into every traceback and test failure.

## Your own cipher

`VaultCipher` is a Protocol, so a cipher is anything with `encrypt`,
`decrypt` and `describes`. Nothing to inherit, nothing to register:

```python
class HmacStreamCipher:
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...

    @property
    def describes(self) -> str:
        return "hmac-stream"

SerializedVaultStore(backend, cipher=HmacStreamCipher(key))
```

That is how a KMS client, an HSM, a Vault transit backend or an algorithm
your organization mandates drops in. `KeyValueBackend` is a Protocol too, so
the storage half is equally open — see
[`examples/08_your_own_cipher.py`](../examples/08_your_own_cipher.py), which
writes both from the standard library.

Three things a custom cipher owes its caller:

**Authenticate, do not only encrypt.** A vault an attacker can modify is a
vault whose tokens can be pointed at values of their choosing, so the answer
your reader sees becomes the one the attacker wrote. `encrypt` that returns
ciphertext with no tag leaves that open. Fernet does this for you; a stream
cipher does not.

**Raise on failure.** `decrypt` must raise when the key is wrong or the
ciphertext was altered. The store lets that propagate rather than turning it
into `None`, because a silent `None` reads as "no vault for this session" and
the caller carries on holding tokens it cannot resolve.

**Keep the key out of `describes`.** It goes into logs and `describe()`
output. Name the algorithm, never the key.

The contract is tested against a cipher that inherits nothing from this
library, in `tests/stores/test_a_third_party_cipher.py` — a Protocol is only
open as long as nothing on the path does an `isinstance` check, and that is
worth verifying rather than assuming.
