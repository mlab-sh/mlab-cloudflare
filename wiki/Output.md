# Output

Two rules, and everything follows from them.

**1. stdout carries the result. stderr carries everything else.**

Progress spinners, status lines, warnings and prompts all go to stderr. So this
works while a spinner is running:

```bash
mlab-cloudflare zones -o json | jq '.[] | select(.paused) | .name'
```

**2. `-o json` prints exactly what the API returned.**

Nothing is humanized, reordered or annotated in JSON mode. A pipeline always
sees the API's own field names and values, so a script written against
Cloudflare's documentation works without a translation layer.

## Human mode

The default. Two-space indent, dimmed labels, one blank line around each block,
and columns that only appear when they carry data — a table never shows an
empty column just because the schema has the field.

Statuses are tinted by meaning rather than by field: `active` and `true` read
green, `pending` amber, `deactivated` red, `false` dimmed. `false` is dimmed
rather than red on purpose — a list of unproxied records must not read as a wall
of errors.

A few numbers get a unit in human mode only. A DNS TTL of `1` renders as
`1 (auto)` rather than as a duration, because that is what it means.

## Choosing

In order of precedence:

```bash
mlab-cloudflare zones -o json          # flag
CLOUDFLARE_OUTPUT=json mlab-cloudflare zones   # environment
```

or `"output": "json"` in a profile, for a profile you always script against.

## Quiet

`-q` silences everything this tool writes to stderr: progress, status lines and
warnings. The result on stdout is unaffected.

Progress is also suppressed automatically when stderr is not a terminal, or
when `CI` is set, so logs stay free of escape sequences without anyone passing a
flag. `MLAB_CLOUDFLARE_NO_PROGRESS` forces it off.

Nothing is drawn at all for work that finishes in under 250 ms — the flash of a
spinner appearing and vanishing reads as a glitch rather than as feedback, and
most calls to `api.cloudflare.com` land inside that window.

## Exit codes

`0` on success, `1` on any error, with the message on stderr:

```
  ✖ API error 403 [9109]: Zone not owned by this account
hint: the credential is valid but lacks the permission for this endpoint, or the
account/zone is out of its scope
```

Which makes every command usable as a check:

```bash
mlab-cloudflare ping -q -o json >/dev/null || echo "credential is broken"
```
