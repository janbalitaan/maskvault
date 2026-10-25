"""Words in the sensitive vocabularies that are also ordinary technical terms.

"black" is a formatter and a color. "union" is a SQL clause. "native" is
native code. Each appears in a special-category vocabulary for a good reason
and in a codebase for an unrelated one.

This list exists so a developer running STRICT over code or documentation
does not have to discover each collision from a false positive. It is a
mitigation, not a fix: the underlying limitation is that a word list cannot
read context.
"""

from __future__ import annotations

TECHNICAL_HOMONYMS: frozenset[str] = frozenset(
    {
        "black",  # the formatter, and a color
        "white",  # whitelist, and a color
        "native",  # native code, native app
        "straight",  # straight-through processing
        "partner",  # partner API, partner integration
        "single",  # single sign-on, singleton
        "default",  # a value, not a loan default
        "migration",  # a schema migration
        "transplant",
        "chronic",
        "terminal",  # a terminal emulator
        "bi",  # business intelligence
        "trans",  # transaction, transform
        "cis",  # CIS benchmarks
        "x",  # the variable, and the platform
        "strike",  # a strike price, a strikethrough
        "union",  # a SQL UNION, a C union
        "green party",
        "block",  # a code block
        "dl",  # a definition list
    }
)
