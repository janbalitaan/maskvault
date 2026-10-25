# Security

## What this protects

Values you would rather a third party did not see. The text goes out with
tokens in place of them, and comes back with the originals restored — so the
provider never holds the value while your reader still gets a correct answer.

That is the only guarantee. Everything below is about its edges.

## Design commitments

These do not change between versions:

1. **Default deny.** Within a level, every detector runs unless the
   whitelist says otherwise. The value that leaks is the one nobody thought
   to configure.
2. **A destroyed value never returns.** Not by a setting, not by a flag. A
   credential coming back would mean this library handed it to a provider
   and then handed it onward.
3. **Nothing that carries a value is logged.** `Vault.summary()`,
   `Whitelist.describe()`, `Anonymizer.describe_policy()` and every store's
   `describe()` are safe. `explain()` and `preview()` carry real values and
   say so.
4. **A key never appears in anything this library writes.** Checked on nine
   surfaces, including every repr.
5. **No required dependencies.** A privacy filter that pulls in a dependency
   tree is one nobody can audit.

## What an attacker in each position can do

### Someone reading the provider's logs

Sees tokens. That is the whole point.

What they still see: the *shape* of your text, how many values of each kind
it held, and anything a detector missed. Token labels are deliberately
descriptive — `!|EMAIL_1|!` tells a model it is an address, which is what
makes the answer useful — so the categories are visible even when the values
are not.

### Someone reading your vault store

Sees every original value, unless you encrypted it. This is why a store takes
a required cipher rather than a defaulted one, and why
[encryption](encryption.md) exists.

With `FernetCipher` they see ciphertext and cannot modify it undetected. The
second half matters: a vault an operator can **edit** is one whose tokens can
be pointed at values of their choosing, so your reader's answer becomes the
one they wrote.

### Someone who can read your process memory

Sees everything: the resolved values, the vault, the key. Nothing here
defends against that, and a library claiming to would be lying — see
[limitations](limitations.md).

### Someone who controls the text being anonymized

Can try to smuggle a value past the detectors. This is the limit worth being
clearest about: **detection is a check against carelessness, not against
determination.** A value split across two fields, base64-encoded, or in a
format no pattern covers goes through.

They can also feed text containing something token-shaped. A detector will
not claim it — the library never replaces text it inserted — and a token from
a previous pass is left alone, so a second pass is a no-op rather than a
nesting.

### Someone who can supply a whitelist

Can turn detection off. A whitelist is a policy, so it belongs with your
code rather than with user input. `Whitelist.from_dict` refuses an unknown
key and refuses `predicate` outright, because a config file should not be
able to introduce executable code — but it cannot stop a config that
deliberately allows everything.

## Implementation notes

**The anonymizer never replaces its own output.** Detectors run one after
another over progressively replaced text, so a later one sees what an earlier
one left. At `PARANOID` the entropy net measured `!|IP_ADDRESS_1|!` as a
high-entropy value and destroyed it — losing the original permanently and
leaving a vault whose tokens no longer appeared in the text, so restoring
could never work. Guarded now, and the guard searches rather than compares
exactly, because a candidate often *contains* a token rather than equalling
one.

**Token allocation is atomic.** The counter and the mapping live on the vault
under one lock, so two concurrent callers cannot both mint the same token for
different values. They could before, and restoring then returned the other
caller's value.

**A vault carries its own format.** Restoring needs to know which delimiters
were used, and a vault whose recorded format disagreed with its keys broke
`summary()`, `leaked()` and the numbering.

**A vault is serialized as JSON, never pickle.** A pickled payload is
executable on load, so a store an attacker can write would be code execution
in every process that reads it.

**SQL identifiers are validated, not trusted.** A table name cannot be a
bound parameter, so `DatabaseVaultStore` checks it against
`^[A-Za-z_][A-Za-z0-9_]*$` and binds every value.

## Reporting a vulnerability

Open a security advisory rather than a public issue, and if you are unsure
whether something qualifies, open it anyway. The full policy is in
[SECURITY.md](../SECURITY.md).

## What is out of scope

Named here so a report is not wasted:

- A value in memory being plaintext. See [limitations](limitations.md).
- Detection missing something with no recognizable shape under no
  recognizable key. Worth an issue so a pattern can be added, but it is a
  known boundary rather than a vulnerability.
- A whitelist that allows too much. That is a policy you wrote.
- A vault stored without a cipher by explicit choice.
