# Command line

The library is for a program that calls a provider. The command line is for
the moment before that: a log you are about to paste into a chat window, a
config you are about to attach to a ticket, a dump you are about to send to
support.

```bash
maskvault explain app.log              # is there anything in here?
maskvault anonymize app.log            # print it with the values replaced
kubectl logs pod | maskvault anonymize # the same, from a pipe
maskvault policy                       # what each level detects
```

Reading standard input is the common case rather than a convenience. The
point is to clean something on its way somewhere, and requiring a file first
would mean writing the sensitive thing to disk on the way past.

## `explain` — and it reveals nothing

```bash
$ maskvault explain app.log
  IP_ADDRESS     reversible  at 39-49
  EMAIL          reversible  at 55-71
  STRIPE_KEY     destroy     at 225-257

3 findings: 1 EMAIL, 1 IP_ADDRESS, 1 STRIPE_KEY
```

Labels, actions and positions — **no values**. A tool that printed the secret
it found, to warn you about the secret it found, would put the value into
your terminal scrollback and your CI log.

| exit | means |
| --- | --- |
| `0` | nothing sensitive |
| `1` | something was found |
| `2` | could not run — no such file, bad arguments, an unreadable vault |

The last two are separate so a pipeline can tell "your text has a secret in
it" from "this tool was used wrongly".

```yaml
- run: pip install maskvault
- run: maskvault explain config/production.yaml
```

```bash
maskvault explain app.log --json       # for a tool
maskvault explain app.log --level strict
```

## `anonymize` — and `restore`

```bash
$ maskvault anonymize message.txt
write to !|EMAIL_1|! or call !|PHONE_1|!
[1 email, 1 phone]
```

The text goes to standard output and the summary to standard error, so
redirecting stdout captures the text alone.

Without `--vault` the replacements cannot be undone, which is the right
default for "clean this before I paste it somewhere": there is nothing to
restore and nothing to leak.

```bash
maskvault anonymize message.txt --vault vault.json > masked.txt
maskvault restore masked.txt --vault vault.json
```

The vault file is created `0600`. It holds every original value, so it is as
sensitive as the input was — the umask default would often make it
group-readable, which would undo the point of the exercise.

Restoring reports what it could not do rather than leaving it silent:

```
[1 token(s) could not be restored: !|EMAIL_9|!]
[1 destroyed value(s) were not restored, which is deliberate]
```

A model that reformatted a token leaves one behind, and a reader would
otherwise see `!|EMAIL_9|!` with no explanation.

## `policy` — what a level actually does

```bash
$ maskvault policy --level minimal
minimal: 19 detectors
  destroyed   (19): aws_access_key, aws_secret_key, slack_token, ...
  reversible  (0):
  anonymizer on at minimal: 19 detectors, 0 terms, nothing allowed
```

The level is the main dial, and "what does STRICT actually add" is a question
the name alone cannot answer. With no `--level` it prints all four.

## Also

```bash
python -m maskvault policy
```

For when the console script is not on `PATH`, which is common in a container.
