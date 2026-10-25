# Getting started

## Install

```bash
pip install maskvault                    # or: uv add maskvault
pip install 'maskvault[encryption]'      # only if you store vaults
```

Python 3.10 or newer. No required dependencies.

## A first round trip

```python
from maskvault import Anonymizer

anonymizer = Anonymizer()

safe, vault = anonymizer.anonymize(
    "I work at Initech, email alice@acme.com, phone +63 917 555 1234"
)
print(safe)
# I work at Initech, email !|EMAIL_1|!, phone !|PHONE_1|!

print(anonymizer.restore(safe, vault))
# I work at Initech, email alice@acme.com, phone +63 917 555 1234
```

Two things to notice. "Initech" survived — an employer name is not something
a pattern can recognize, so you name it yourself (see
[whitelisting](whitelisting.md) and `terms`). And `vault` came back to you
rather than being kept, which is what makes everything in
[stores](stores.md) optional.

## What it found, before you trust it

```python
for finding in anonymizer.explain("email alice@acme.com key=sk_live_NOTAREALKEYEXAMPLE"):
    print(finding.label, finding.action.value, finding.value)
```

```
EMAIL       reversible   alice@acme.com
STRIPE_KEY  destroy      sk_live_NOTAREALKEYEXAMPLE
```

`explain()` reports exactly what `anonymize()` will do — same count, same
labels. It prints real values, which is the point: deciding what to allow
means seeing what was found. **It is not safe to log.** `Vault.summary()` is
what goes in a log:

```python
safe, vault = anonymizer.anonymize("email alice@acme.com key=sk_live_NOTAREALKEYEXAMPLE")
vault.summary()
# "1 email, 1 destroyed"
```

## Destroyed values do not come back

```python
safe, vault = anonymizer.anonymize("my key is sk_live_NOTAREALKEYEXAMPLE")
print(safe)
# my key is [a Stripe key was removed before sending]

print(anonymizer.restore(safe, vault))
# my key is [a Stripe key was removed before sending]
```

A credential that came back would mean this library handed it to a provider
and then handed it onward. If one appears, something upstream is wrong, and
the notice is there so you can see it.

## Wiring it into a request

```python
from maskvault import Anonymizer

# Module scope. One instance is safe to share — see docs/concurrency.md.
anonymizer = Anonymizer()


def answer(question: str) -> str:
    safe, vault = anonymizer.anonymize(question)
    reply = provider.complete(safe)

    answer = anonymizer.restore(reply, vault)
    if leftover := anonymizer.leaked(answer, vault):
        # A model that reformatted a token leaves one behind. Better to fall
        # back than to show "!|EMAIL_1|!" to a person.
        logger.warning("unrestored tokens: %s", leftover)
        return fallback()
    return answer
```

That is the whole integration. The vault is a local variable that never
leaves the function, so this works unchanged on fifty nodes.

## Turning the dial up

```python
from maskvault import Anonymizer, Level

Anonymizer(level=Level.MINIMAL)    # credentials only
Anonymizer(level=Level.STANDARD)   # the default
Anonymizer(level=Level.STRICT)     # adds health, religion, politics, identity
Anonymizer(level=Level.PARANOID)   # a lower entropy bar, more false positives
```

See [levels](levels.md) for what each one includes.

## Where next

- Something was replaced that should not have been: [whitelisting](whitelisting.md)
- A dict or a JSON body rather than a string: [structured data](structured-data.md)
- Restoring in a different request or process: [stores](stores.md)
- Cleaning a file from the shell: [command line](cli.md)
