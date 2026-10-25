# Token formats

The default is `!|LABEL_1|!`. Two collisions can break a token and only one
of them is detectable.

## Collision with the input

The text already contains the delimiter, so a replacement nests inside it or
a real occurrence is mistaken for a token. This one is handled: a format is
chosen per operation by trying each candidate until one is absent from the
text, and the choice is recorded in the vault so restoring needs no
bookkeeping from you.

```python
safe, vault = anonymizer.anonymize("a note mentioning !|EXISTING|!")
vault.token_format.name   # "pipe_brackets", since the default was taken
```

Only the *opening* delimiter decides. A stray closing one is harmless on its
own, and rejecting it would switch formats more often than necessary.

## Collision with wherever the output goes

The input is clean, but the *result* is pasted into a wiki, rendered as
Markdown, or fed to a template engine — where the token means something.
Selection cannot help: it sees the text it is given and knows nothing about
the destination. Only the default can protect against this, by being a pair
nothing claims.

So the default was picked by testing each candidate against what people
actually paste into a model:

| | Claimed by |
| --- | --- |
| `!\|X\|!` | **nothing** — the default |
| `[\|X\|]` | Haskell and Idris quasi-quotation. Rare, more legible, so it is second |
| `@@X@@` | unified diff hunk headers, `@@ -1,5 +1,5 @@` |
| `[[X]]` | wikilinks — Obsidian, Roam, Logseq, MediaWiki, Dendron, Foam |
| `[!X!]` | GitHub alerts, `> [!NOTE]`. And `[![` is a linked image — the badge syntax at the top of most READMEs |
| `{{X}}` | templates — Jinja, Handlebars, Mustache, Vue, Angular, Liquid |
| `{\|X\|}` | MediaWiki tables, and LaTeX |
| `<<X>>` | AsciiDoc cross-references |
| `%%X%%` | Obsidian comments, SQL `LIKE`, `printf` |
| `((X))` | Roam block references |
| `(\|X\|)` | Haskell idiom brackets, the Elixir and OCaml pipe operator |
| `<\|X\|>` | a model's own special tokens — the one pair to never use |

The last row matters more than it looks. `<|endoftext|>` and `<|im_start|>`
are how a model marks its own control tokens, so a delimiter pair resembling
one is the thing to avoid outright.

ASCII, deliberately. `⟦X⟧` collides with nothing at all, which would make it
the obvious default — but a non-ASCII token is one a model is more likely to
normalize or drop. It is second-to-last instead, as the fallback when the
ASCII candidates are all taken.

## What the default does not fix

A model that reformats a token breaks restoring whatever the delimiters are.
`!|EMAIL_1|` is rejected exactly as `@@EMAIL_1@` was — neither is silently
restored, which is the important part:

```python
answer = anonymizer.restore(reply, vault)
if leftover := anonymizer.leaked(answer, vault):
    return fallback()
```

No choice of delimiter removes the need for that check.

## Asking for one by name

```python
Anonymizer(token_format="brackets")        # -> [[ORG_1]]
Anonymizer(token_format="pipe_bang")       # pin the default
```

`brackets` is the most legible to a model, and claimed by every wiki. Right
when you control the whole pipeline, which is why it is available by name
rather than by default.

## Defining your own

```python
from maskvault import Anonymizer, TokenFormat

Anonymizer(token_format=TokenFormat(
    name="mine",
    opening="<%|",
    closing="|%>",
    label_pattern=r"[a-z_]+",
    label_case="lower",
))   # -> <%|org_1|%>
```

A format is validated at construction against its own output. One that cannot
read back what it writes would lose every value at restore time, silently:

```python
TokenFormat(name="broken", opening="", closing=">")
# TokenFormatError: needs both an opening and a closing delimiter

TokenFormat(name="mismatched", opening="<", closing=">",
            label_pattern=r"[a-z]+", label_case="keep")
# TokenFormatError: cannot match its own output ('<Label_1>')
```

`label_pattern` and `label_case` are validated *together*, so they cannot
drift apart.

Casing is a separate step from rendering, so a caller who already cased a
label does not get it cased twice:

```python
token_format.render(token_format.label_for("email"), 1)
```

`example` composes the two the same way, so what it advertises is what a real
token looks like.

## Unguessable delimiters

```python
from maskvault import TokenFormats

Anonymizer(token_format=TokenFormats.random_format())
```

For a pipeline where a token's shape should not be predictable from the
outside.

## Your own candidate list

"Pick one that fits the text" should not mean "pick one of ours":

```python
from maskvault import BRACKETS, ANGLES

Anonymizer(format_candidates=(BRACKETS, ANGLES))
```
