# API reference

Everything importable from `maskvault`, plus the two subpackages. Nothing
else is public.

```python
from maskvault import (
    # the main entry point
    Anonymizer, Level, Vault,
    # structured data
    anonymize_data, restore_data,
    # control
    Whitelist, COMMON_SAFE_VALUES, TECHNICAL_HOMONYMS,
    # inspection
    Finding, Action, Detector, EntropyVerdict, EntropyThresholds,
    # detection internals, for composing your own
    Registry, Levels, Entropy, EntropyDetector, PhoneShape, SpecialCategories,
    DEFAULT_DETECTORS, PERSONAL_DATA, STRUCTURED_PERSONAL, VENDOR_CREDENTIALS,
    SPECIAL_CATEGORIES, PHONE_MIN_DIGITS, PHONE_MAX_DIGITS,
    # token formats
    TokenFormat, TokenFormats, DEFAULT_FORMATS,
    PIPE_BANG, PIPE_BRACKETS, AT_SIGNS, MATH_BRACKETS, BRACKETS, ANGLES,
    # version
    __version__,
)
from maskvault.ciphers import FernetCipher, PlaintextCipher, VaultCipher
from maskvault.stores import (
    DatabaseVaultStore, KeyValueBackend, MemoryVaultStore,
    SerializedVaultStore, VaultStore,
)
from maskvault.exceptions import (
    MaskvaultError, DetectorError, TokenFormatError, VaultError, WhitelistError,
)
```

## `Anonymizer`

```python
Anonymizer(
    level=Level.STANDARD,
    *,
    detectors=None,          # tuple[Detector, ...] — replaces the level's set
    terms=None,              # dict[str, list[str]] — literals you name
    whitelist=None,          # Whitelist | dict
    token_format=None,       # TokenFormat | str — None chooses per operation
    format_candidates=None,  # tuple[TokenFormat, ...]
    enabled=True,            # False passes text through untouched
)
```

Immutable after construction, and holds no per-operation state — so one
instance is safe to share across concurrent callers.

| Method | Returns | |
| --- | --- | --- |
| `.anonymize(text)` | `(str, Vault)` | replace, and hand back the vault |
| `.anonymize_into(text, vault)` | `str` | accumulate into an existing vault |
| `.restore(text, vault)` | `str` | put the originals back |
| `.leaked(text, vault)` | `list[str]` | tokens still present after restoring |
| `.resolved(text, vault)` | `list[str]` | this vault's tokens that came back intact |
| `.unresolved(text, vault)` | `list[str]` | this vault's tokens that did not |
| `.explain(text)` | `list[Finding]` | what would happen. **Carries values.** |
| `.preview(text)` | `str` | the same, rendered. **For a terminal, not a log.** |
| `.suggest_whitelist(text, *, only_reversible=True)` | `dict` | a draft allowlist |
| `.describe_policy()` | `str` | safe to log at startup |
| `.level` / `.whitelist` / `.token_format` / `.format_candidates` | | the configuration |

`enabled=False` is for a kill switch: the anonymizer returns text untouched
rather than the caller needing a branch at every call site.

## `Vault`

```python
Vault(values={}, destroyed=[], token_format=..., scope="")
Vault.scoped()          # tokens carry a random marker; see docs/stores.md
Vault.for_key(id)       # marker derived from an id you already have unique
vault.wipe(older_than=…)  # forget values past that age; 0 for all
vault.wiped             # whether it has been emptied
```

| Member | Returns | |
| --- | --- | --- |
| `.snapshot()` | `dict[str, str]` | a copy, safe to iterate while others write |
| `.mint(label, original)` | `str` | allocate or reuse a token. Atomic. |
| `.destroy(label)` | `None` | note a value that will not come back |
| `.replaced` | `int` | how many distinct values were tokenized |
| `.destroyed` | `list[str]` | labels of values removed for good |
| `.summary()` | `str` | **safe to log** — counts, no values |
| `.pattern` | `re.Pattern` | matches tokens in this vault's format |
| `.as_dict()` / `Vault.from_dict(data)` | | lossless JSON round trip |

Never log a vault itself. `summary()` is the part that is safe.

## Structured data

```python
anonymize_data(
    data, anonymizer, *,
    include_keys=False,       # keys are schema, not data
    stringify_numbers=False,  # a bare integer may be an account number
    skip_keys=None,           # frozenset[str] — a subtree to leave alone
) -> tuple[Any, Vault]

restore_data(data, anonymizer, vault) -> Any
```

See [structured data](structured-data.md).

## `Whitelist`

```python
Whitelist(
    labels=set(), categories=set(), values=set(), words=set(),
    contains=set(), prefixes=(), suffixes=(), domains=set(),
    patterns=(), predicate=None,
)
Whitelist.from_dict(data)     # the JSON form; refuses an unknown key
```

| Method | |
| --- | --- |
| `.allows_label(label)` / `.allows_value(value)` | the two questions it answers |
| `.merge(other)` | combine two policies |
| `.describe()` | safe to log |
| `.as_dict()` | the JSON form back out |

See [whitelisting](whitelisting.md).

## `Finding` and `Action`

```python
Finding(label, value, action, start, end, allowed)
```

`.value` is the **real matched text**, so a Finding is not safe to log.
`.replaced` is `True` when the whitelist does not allow it.

```python
Action.REVERSIBLE   # tokenized, restored
Action.DESTROY      # replaced with a notice, never restored
```

## `Detector`

```python
Detector(
    label, pattern, action,
    notice="[removed]",   # what replaces a destroyed value
    validate=None,        # a callable deciding a loose match
    group=0,              # which capture is the value
    terms=None,
)
```

A `group` larger than the pattern has is refused at construction.

| Method | |
| --- | --- |
| `.matches(candidate)` | whether the validator accepts it |
| `.value_of(match)` / `.span_of(match)` | the part treated as the value |

## Detection internals

```python
Registry.all_detectors(
    include_entropy=True, *, replace=None, without=None, add=None, add_first=None
) -> tuple[Detector, ...]

Levels.detectors_for(
    level, *, replace=None, without=None, add=None, add_first=None,
    extra_terms=None
) -> tuple[Detector, ...]

EntropyDetector.build(
    min_length=0, relax_by=0.0, include_symbols=False, thresholds=None
) -> Detector

SpecialCategories.special_category_detectors(categories=None, extra=None)
SpecialCategories.vocabularies(extra=None) -> dict[str, frozenset[str]]
SpecialCategories.category_detector(category, terms)

PhoneShape.looks_like_a_phone_number(candidate, minimum=7, maximum=15) -> bool
PhoneShape.bounded(minimum, maximum) -> Callable[[str], bool]
```

`replace`, `without`, `add` and `add_first` adjust a shipped set by label, so a pattern
that is wrong for one codebase does not wait for a release. A label that is
not in the set raises rather than doing nothing — see
[extending](extending.md).

## `EntropyThresholds`

```python
EntropyThresholds(hex=3.0, base64=4.0, mixed=3.5, minimum_classes=2)
EntropyThresholds().relaxed_by(0.5)
```

| Member | |
| --- | --- |
| `.for_alphabet(name)` | the bar for "hex", "base64" or anything else |
| `.describe()` | safe to log |

One bar per alphabet because the maximum differs: hex tops out at 4 bits per
character, base64 at 6. A single number would be too strict for one or too
loose for the other.

```python
Entropy.classify(candidate, relax_by=0.0, min_length=20) -> EntropyVerdict
Entropy.find_secrets(text) -> list[EntropyVerdict]      # confirmed only
Entropy.looks_like_a_secret(candidate, ...) -> bool
Entropy.shannon_entropy(text) -> float
Entropy.character_classes(text) -> int
Entropy.candidate_pattern(min_length=20, include_symbols=False)
```

`find_secrets` returns only secrets — the name is the contract. `classify`
explains any candidate, which is the one to use when adjusting a threshold.

## Token formats

```python
TokenFormat(name, opening, closing,
            label_pattern=r"[A-Z_]+", index_pattern=r"\d+", label_case="upper")
TokenFormat.default()
TokenFormat.from_dict(data)
```

| Member | |
| --- | --- |
| `.render(label, index)` | write a token, label exactly as given |
| `.label_for(label)` | apply this format's casing |
| `.example` | what a token looks like, composed the same way |
| `.pattern` | matches tokens in this format |
| `.collides_with(text)` | whether the opening delimiter appears |
| `.as_dict()` | the JSON form |

```python
TokenFormats.choose_format(text, candidates=DEFAULT_FORMATS)
TokenFormats.random_format(name="random", length=6)
TokenFormats.format_from_dict(data)
```

See [token formats](token-formats.md).

## Ciphers

```python
FernetCipher(key)                 # needs maskvault[encryption]
FernetCipher.generate_key()
FernetCipher.from_env(variable=None)   # MASKVAULT_VAULT_KEY
PlaintextCipher()                 # the explicit opt-out
```

Each provides `.encrypt(bytes)`, `.decrypt(bytes)` and `.describes`.
`VaultCipher` is the Protocol. See [encryption](encryption.md).

## Stores

```python
MemoryVaultStore(ttl_seconds=900)
SerializedVaultStore(backend, cipher, ttl_seconds=900, prefix=None)
DatabaseVaultStore(connection, cipher, *, table="maskvault_vaults",
                   paramstyle="qmark", ttl_seconds=900)
```

All provide `.save(key, vault)`, `.load(key)`, `.delete(key)`, `key in store`
and `.describe()`. `MemoryVaultStore` and `DatabaseVaultStore` also provide
`.purge()`. `ttl_seconds=0` means no expiry.

`VaultStore` and `KeyValueBackend` are the Protocols. See [stores](stores.md).

## Errors

```
MaskvaultError                 everything below
├── DetectorError              a pattern or capture group is wrong
├── TokenFormatError           a format cannot read back its own output
├── VaultError                 a payload is not a vault, or will not decrypt
└── WhitelistError             an allowlist rule will not compile
```

Each also inherits `ValueError`, so `except ValueError` keeps working for a
caller who has not adopted these — what the standard library does with
`UnicodeDecodeError`.

## Command line

```bash
maskvault explain   [FILE] [--level L] [--json]
maskvault anonymize [FILE] [--level L] [--vault FILE]
maskvault restore   [FILE] --vault FILE
maskvault policy    [--level L]
```

See [command line](cli.md).
