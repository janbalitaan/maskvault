# Changelog

This project follows [semantic versioning](https://semver.org). Until 1.0.0
the public API may change in a minor release; anything that would break a
caller is listed under **Changed** with what to do about it.

## [Unreleased]

## [0.1.0] — 2026-10-26

First release.

### Added

- Reversible anonymization with a vault. Values are replaced with tokens and
  restored afterwards, so a third party never sees them while your reader
  still gets a correct answer.
- Credentials are destroyed rather than tokenized, and never restored. An
  exact round trip therefore holds only when nothing was destroyed.
- Four strictness levels: `MINIMAL`, `STANDARD`, `STRICT`, `PARANOID`.
- Around 20 vendor credential formats, connection strings with embedded
  credentials, and auth headers.
- Structured personal identifiers: addresses, salaries, coordinates,
  licences, policy and account numbers, tax IDs, social handles, ages.
- Vocabularies for the GDPR Article 9 special categories — health, religion,
  politics, identity, origin — plus criminal and financial history, with
  `TECHNICAL_HOMONYMS` to blunt the words that mean something else in a
  technical sentence.
- A Shannon-entropy net for secrets whose format nobody anticipated, gated
  on four conditions rather than entropy alone — because "the quick brown fox
  jumps" scores above 4 bits.
- Default-deny allowlisting with nine mechanisms (labels, categories, values,
  words, substrings, prefixes, suffixes, domains, regexes) and a `predicate`
  escape hatch for anything else. An unrecognized key raises with a mapped
  suggestion, so a typo cannot leave a whitelist silently unapplied.
- `explain()`, `preview()` and `suggest_whitelist()`, so a policy can be
  built from real input instead of guesswork. `explain()` reports exactly
  what `anonymize()` will do — same count, same labels.
- `anonymize_data` and `restore_data`, which walk dicts, lists, sets and JSON
  rather than only strings. One vault covers the whole structure.
- Every shipped pattern, bound and word list is replaceable at runtime, so a
  vendor format this version does not know, a region whose phone numbers are
  shorter, or a term the health vocabulary misses does not mean waiting for a
  release. `Levels.detectors_for` and `Registry.all_detectors` take `replace`,
  `without`, `add` and `add_first` — by label, because the order of a shipped
  list is an implementation detail. A label that is not in the set raises
  rather than doing nothing, since the usual cause is a typo and silence
  would leave a caller believing their replacement was in effect.
- `add_first` for a detector that has to win a span a shipped one would
  claim. An internal identifier like `EMP-004212` is a punctuated digit run,
  so the phone detector takes it unless something runs earlier.
- `EntropyThresholds`, so the entropy bars can be tuned per alphabet instead
  of only moving together through `relax_by`. One bar each for hex, base64
  and mixed, because the maximum differs: hex tops out at 4 bits per
  character and base64 at 6.
- `PhoneShape.bounded(minimum, maximum)` for a region the default seven-to-
  fifteen-digit range does not fit, keeping the date-and-time exclusion the
  validator exists for.
- `SpecialCategories.vocabularies(extra=)` and `special_category_detectors`,
  which extend a shipped vocabulary rather than replacing it — a caller
  adding one term almost never means "and discard the other hundred".
- `leaked()` now detects a token a model altered — changed case, inserted
  whitespace, a broken delimiter — not only an intact one. Measured against
  ten model behaviours it caught one of six failure modes before and six of
  six after. It over-reports deliberately: a column named `EMAIL_1` is
  flagged, which is the right direction for a check whose job is to stop a
  confidential value being sent on.
- The shipped lookup tables are `MappingProxyType`. Assigning to one would
  change behaviour for every user in the process, including a library that
  never asked, and detection turning itself off is the worst failure
  available here.
- A vault cipher is a Protocol, so an application can supply its own — a KMS
  client, an HSM, a Vault transit backend, or an algorithm an organization
  mandates. The storage backend is a Protocol for the same reason. Both are
  tested against implementations that inherit nothing from this library,
  because a Protocol is only open as long as nothing on the path does an
  `isinstance` check.
- `Vault.for_key(conversation_id)`, which derives a token marker from an id
  the caller already has unique. A token is an index into one vault, so two
  independent vaults both mint `EMAIL_1` and restoring with the wrong one
  returns another caller's value silently. Deriving the marker makes
  uniqueness inherited rather than probabilistic, makes it deterministic
  across retries and nodes, and makes loading the wrong conversation's vault
  visible to `leaked()`.
- `Vault.scoped()` markers widened from four letters to twelve, and the width
  is now a parameter. Four letters is 456,976 markers: by the birthday bound
  two of a thousand concurrent vaults shared one about 66% of the time, which
  the docstring described as impossible.
- `DatabaseVaultStore` closes every cursor. Seven statements opened one and
  nothing closed it — survivable on sqlite3, a server-side resource leak on
  PostgreSQL and MySQL, growing with every request.
- `docs/extending.md`, `examples/07_extending.py` and
  `examples/08_your_own_cipher.py`.
- `Anonymizer.anonymize_into`, which accumulates into an existing vault so
  many strings — a conversation turn by turn — can share one.
- Configurable token formats, chosen per operation to avoid colliding with
  markup already in the text, and validated at construction so a format that
  cannot read back its own output is refused. The default is `!|LABEL_1|!`,
  picked by testing each candidate against what people actually paste into a
  model: diffs, Markdown, wikilinks, README badges, GitHub alerts, Jinja,
  HTML, YAML, SQL, shell, Haskell, Rust attributes and the `<|...|>`
  special-token convention. `random_format()` gives unguessable delimiters.
- A command line: `maskvault explain`, `anonymize`, `restore` and `policy`.
  `explain` prints labels, actions and positions and **no values**, so it is
  safe in CI, and exits 1 when something is found.
- Vault stores for when a vault must outlive the request:
  `MemoryVaultStore` for one process, `SerializedVaultStore` for any
  key-value backend, `DatabaseVaultStore` for any PEP 249 connection. The
  `VaultStore` and `KeyValueBackend` ports keep Redis, Memcached and the
  database drivers out of this package.
- Encryption for a stored vault, through the `encryption` extra:
  `FernetCipher` for authenticated encryption, `PlaintextCipher` as an
  explicit opt-out, `VaultCipher` as the port for a KMS or an HSM. A store
  refuses to be built without a cipher being chosen, because there is no
  secure default — a key cannot be invented.
- `Vault.scoped()`, for the deployment where anonymizing and restoring happen
  in different processes. A random marker in every label means two vaults
  cannot mint the same token, so the wrong vault leaves a token visible
  rather than resolving it to another caller's value.
- `Vault.as_dict()` and `Vault.from_dict()`, a lossless JSON round trip —
  values, destroyed labels, scope and the format's own patterns. JSON rather
  than pickle, because a pickled payload is executable on load.
- `ttl_seconds=0` means no expiry, handing retention to the caller. A
  negative value raises rather than being read as zero, because a computed
  TTL that came out negative is a bug rather than a request to keep
  plaintext forever.
- One `Anonymizer` is safe to share across concurrent callers, and so is one
  `Vault`. Covered by `tests/concurrency/` under threads, asyncio, a thread
  pool and separate processes.
- Full documentation in `docs/`, and a test that keeps it honest: every link
  resolves, every page is reachable, every name in the API reference is
  importable, and every import in a code block works.
- No required dependencies. Python 3.10 and newer, fully typed, with
  `py.typed`.
