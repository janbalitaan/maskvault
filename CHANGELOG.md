# Changelog

This project follows [semantic versioning](https://semver.org). Until 1.0.0
the public API may change in a minor release; anything that would break a
caller is listed under **Changed** with what to do about it.

## [Unreleased]

### Added

- `anonymize_data` and `restore_data`, which walk dicts, lists and JSON rather
  than only strings. One vault covers the whole structure.
- `Anonymizer.anonymize_into`, which accumulates into an existing vault so
  many strings can share one.

### Changed

- The default token format is now `@@LABEL_1@@` rather than `[[LABEL_1]]`.
  Collision avoidance can only inspect the text it is given, so it cannot know
  that the output will later be rendered as Markdown or pasted into a wiki —
  where double square brackets are a link. At-signs are claimed by no common
  markup. Pass `token_format="brackets"` to keep the old behavior.

## [0.1.0]

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
- Structured personal identifiers: addresses, salaries, coordinates, licenses,
  policy and account numbers, tax IDs, social handles, ages.
- Vocabularies for the GDPR Article 9 special categories — health, religion,
  politics, identity, origin — plus criminal and financial history.
- A Shannon-entropy net for secrets whose format nobody anticipated.
- Default-deny allowlisting with nine mechanisms (labels, categories, values,
  words, substrings, prefixes, suffixes, domains, regexes) and a `predicate`
  escape hatch for anything else.
- `explain()`, `preview()` and `suggest_whitelist()`, so a policy can be built
  from real input instead of guesswork.
- Configurable token formats, chosen per operation to avoid colliding with
  wikilink or template syntax already in the text, and validated at
  construction so a format that cannot read back its own output is refused.
- `random_format()` for unguessable delimiters.
- No dependencies.
