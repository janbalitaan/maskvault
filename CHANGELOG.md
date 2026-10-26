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
- `anonymize_data` scans dict keys by default. A key is usually schema, and a
  schema key matches no detector — but `{"alice@acme.com": {...}}` is how a
  map of users by email address looks and `{"10.42.7.19": "primary"}` is how
  a host map looks. Those keys are the data, so leaving keys unexamined meant
  the structure most likely to be keyed by an identifier was the one that
  leaked it. `include_keys=False` restores the old behaviour for a
  downstream system that matches on the literal key; `skip_keys` names
  individual keys rather than all of them.
- A structure deeper than the walk limit now raises `StructureError` instead
  of being returned unchanged. The old behaviour was a silent leak: a
  structure eighty levels deep had every value below sixty-four pass through
  in the clear, with an empty vault and a successful return. `max_depth` on
  `anonymize_data` raises the limit for a structure that is genuinely that
  deep.
- A structure that refers to itself is detected and refused, naming the
  problem. At the depth limit a cycle put a reference to the *original
  object* into the output — real values and all. The same object appearing
  twice side by side is still walked, because only the current path is
  tracked.
- Text inside `bytes` and `bytearray` is anonymized and restored. Bytes had
  no handler, so a request body read in binary mode carried its email
  addresses out in the clear while the strings beside it were masked. Bytes
  that do not decode as UTF-8 are left alone, being binary rather than text.
- Four false positives fixed, found by measuring ordinary engineering prose
  rather than by reading the patterns. Over-masking costs what under-masking
  does: a value replaced by a token is one the model cannot reason about.
  - A bare seven-digit integer was read as a phone number, so `1048576 bytes`
    and `1000000 entries` became reversible tokens. A bare run now needs ten
    digits, which is where national numbers start once a trunk prefix or area
    code is included; `09175551234` and `4155550132` still match, and an
    explicit `PhoneShape.bounded()` still governs.
  - An ISBN-13 was read as an international number. The 978/979 prefix is
    what separates the two shapes.
  - `policy allows 3 retries` was read as a policy number: `(?i)` covered the
    value class as well as the keyword, so `[A-Z0-9 -]` matched lowercase and
    everything after a common English word matched. The value is now
    case-sensitive and must contain a digit.
  - `Policy No: 9988776655` was labelled PHONE. Protected, but a caller
    whitelisting `policy_number` found it had no effect. The keyword-led
    identifiers now run before the contact details, as
    `KEYWORD_IDENTIFIERS`; `social_handle` and `age` stay after them as
    `LOOSE_PERSONAL`, because putting `social_handle` first claims
    `telegram.org` out of `me@telegram.org`.
- IPv6 detection. `IP_ADDRESS` is IPv4 only, so there was no IPv6 pattern to
  miss with — an IPv6 host went out in the clear at every level and nothing
  failed. Covers the compressed forms and the IPv4-embedded ones, where a
  hex-only match would have taken `::ffff:10` and left `.0.0.1` in the text.
  Runs before the IPv4 detector so the more specific shape claims the span.
- The salary pattern matches a plainly written amount. `\d{1,3}(?:,\d{3})+`
  made the comma group mandatory, so `salary is 95000 USD` matched nothing
  while `salary of $95,000` matched — and the plain integer is the common
  form. A currency marker may now sit on either side of the amount.
- `Vault.wipe(older_than=...)`, which forgets the values a vault has
  finished with and reports how many went. Selective by age rather than
  all-or-nothing, because a long conversation keeps needing its recent values
  while the ones from twenty turns ago are done — an all-or-nothing wipe
  forces a choice between leaving plaintext around and breaking a request
  still in flight. The default is fifteen minutes, matching the store TTL;
  `older_than=0` forgets everything, for a single-turn request. Mint times
  travel with the vault, so a wipe after a trip through a cache or a table
  still forgets the right things. `restore()` deliberately does not empty a vault, because a
  multi-turn conversation needs the same tokens to mean the same people next
  turn — so a vault outlives its use unless something ends it, and until
  then it is plaintext in memory or in a store. Retention is still governed
  by the TTL; this is the option for ending one early. The counters survive a
  wipe, so a token minted later cannot reuse an index and resolve to a
  different person, and `summary()` still describes what was replaced so an
  audit line written after disposal is not blank.
- `Anonymizer.resolved()` and `.unresolved()`, for the question `leaked()`
  does not answer. Three values go out and a reply mentions two: that is
  ordinary, and whether it is acceptable is the application's call. Together
  with `leaked()` the three outcomes separate — everything came back, one was
  not mentioned, one was mangled — and the middle two have the same resolved
  count, which is why `leaked()` is not optional.
- `DatabaseVaultStore` serializes every statement by default, so one
  connection shared across threads is correct rather than merely usual.
  sqlite3 with sixteen threads on one connection lost about a quarter of its
  operations unserialized and none serialized. `serialize=False` opts out for
  a driver that is already thread-safe or a pool that hands out one
  connection per thread.
- Scope markers now come from a process prefix and a counter rather than from
  a per-letter CSPRNG draw. Two markers from one process cannot agree, which
  is arithmetic rather than probability, and the remaining risk is two
  processes drawing the same prefix — a far smaller population. Also 12x
  faster: 9.4 us a marker to 0.8. `ScopeGenerator.capacity()` reports where
  the counter wraps, which at the default width is 308 million vaults.
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
