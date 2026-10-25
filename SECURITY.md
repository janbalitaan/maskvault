# Security policy

## Reporting a vulnerability

Open a [security advisory](https://github.com/janbalitaan/maskvault/security/advisories/new)
rather than a public issue.

If you are not sure whether something qualifies, open the advisory anyway. A
report that turns out to be a non-issue costs a short conversation; a
vulnerability discussed in a public issue cannot be taken back.

Expect an acknowledgement within a week.

## What is in scope

This library holds confidential values in order to put them back, so the
interesting failures are about what escapes and what comes back wrong.

**In scope:**

- A value reaching somewhere it should not: a log line, a `repr`, a
  `summary()`, a `describe()`, an exception message, or the anonymized text
  itself.
- A destroyed value being restored. A credential coming back would mean this
  library handed it to a provider and then handed it onward.
- A token resolving to the wrong value — one caller's token answering with
  another caller's data.
- An encryption key appearing anywhere this library writes.
- A stored vault that can be modified undetected, which lets a store
  operator point a token at a value of their choosing.
- Anything that makes `leaked()` miss a token it should report, since that
  is the check a caller relies on to fail safely.
- Resource exhaustion through crafted input: catastrophic backtracking,
  unbounded recursion, unbounded memory.
- SQL injection or path traversal through a store's configuration.

**Out of scope**, and documented as such in
[docs/limitations.md](docs/limitations.md):

- A resolved value being plaintext in process memory. Python offers no
  reliable way to pin or wipe a string, and
  [docs/encryption.md](docs/encryption.md) explains why encrypting it in
  place would protect nothing.
- Detection missing a value with no recognizable shape under no recognizable
  key. Worth a normal issue so a pattern can be added — the detector list is
  meant to grow — but it is a known boundary rather than a vulnerability.
- A whitelist that allows too much. That is a policy you wrote, and
  `explain()` exists to show you what it does.
- A vault stored without a cipher. A store refuses to be built without one
  being chosen, so plaintext there is a decision rather than an accident.
- A model reformatting a token so it cannot be restored. No delimiter choice
  prevents it; `leaked()` is the answer.

## The threat model

[docs/security.md](docs/security.md) states what someone in each position can
do — reading the provider's logs, reading your vault store, reading your
process memory, controlling the text, supplying the whitelist.

The failures an earlier version had are kept as tests, each one a bug that
was real:

| | |
| --- | --- |
| `tests/concurrency/` | a shared anonymizer minting a token that stood for two values |
| `tests/anonymizing/test_never_replaces_own_output.py` | the entropy net destroying the library's own tokens, losing the originals permanently |
| `tests/detection/test_explain_matches_reality.py` | `explain()` reporting a different count from what `anonymize()` did |
| `tests/stores/test_who_owns_the_encryption.py` | the key reachable through a repr |

## Supported versions

Pre-1.0, only the latest release is supported. A security fix goes out as a
patch release on the current minor version.
