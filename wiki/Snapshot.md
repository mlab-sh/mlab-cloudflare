# `mlab-cloudflare snapshot` and `diff`

One dated record of what the account looks like, and what changed between two
of them.

```bash
mlab-cloudflare snapshot
mlab-cloudflare snapshot --out weekly/2026-09-06.json
mlab-cloudflare diff before.json after.json
mlab-cloudflare diff before.json after.json --full
```

Configuration drift is the finding no single read can produce, and the [audit
log](Activity)'s retention horizon is the argument for recording **before** the
answer is needed rather than after.

## What a snapshot holds

The **responses**, not this tool's reading of them. Two reasons, both about the
record still being worth something later:

1. A check written next month can be run against a snapshot taken today,
   because the file is not shaped like the checks that existed when it was
   written.
2. A diff over responses says what Cloudflare changed. A diff over findings
   would say what this tool concluded, which is a different and much less useful
   sentence when the two disagree.

`snapshot` runs every plane's collector and keeps what the API said on the way
past. It sits on the same path as the [cache](Cache), so it captures exactly the
configuration reads and never the liveness checks — a snapshot containing "the
token was valid at 14:02" would be recording the weather. The audit log is out
for the same reason: it is a window, not a state.

```
  ✔ wrote mlab-cloudflare-a1b2c3d4-2026-09-06.json

  reads                 592
  size                  569 kB
  credentials redacted  0
```

A plane that fails outright is noted and does not stop the rest: a snapshot of
eight planes is worth more than none.

## Refusals are part of the record

A read that was refused is stored as a refusal rather than dropped. A diff where
a `403` becomes a body is a **permission that was granted** — exactly the kind
of change a snapshot exists to catch, and one no findings-shaped record could
express.

## Credentials never reach the file

Everything goes through the same [redaction list](Secrets) every other
persisting path uses, so a field cannot be masked in one place and stored in
another. Each value is replaced by its length, which keeps the record auditable
without carrying the secret:

```json
"token": "<redacted:36>"
```

A snapshot is a file people copy between machines, which makes it the last place
for a live credential.

## Reading a diff

```
  2026-09-06T09:50:26Z → 2026-09-13T09:00:00Z

  LIST /zones account.id=a1b2c3d4…
      [example.com].paused: false → true
      [newly-added.example] added
  LIST /zones/1a2b3c4d…/settings
      [min_tls_version].value: 1.0 → 1.2
      [ssl].value: flexible → strict

  37 changed reads
```

**Lists are matched by identity, not by position.** A zone inserted at the front
of a list would otherwise shift every element after it and report the whole list
as changed, burying the one thing that happened. The match is on a stable key —
`id` where there is one — and the *display* uses the name somebody chose, so a
rename reads as a change rather than as an addition and a removal.

A list whose elements do not all share an identifying key falls back to
position. Half-matching by name and half by index would be worse than either.

Four changes are reported at the level of the read rather than the value:

| | |
| --- | --- |
| `read added` | this endpoint was not read before |
| `no longer read` | it is not read now |
| `became readable` | it was refused before and answers now |
| `no longer readable` | the reverse — a permission or entitlement went away |

A read whose whole body changed prints its first eight lines and a count;
`--full` prints all of them.

## The format

`format: 1`, with the tool version, the instant, the account, how many reads and
how many redactions. `diff` refuses a file whose version it does not know rather
than guessing at it.

## See also

- [Cache](Cache) — the same path, which is why the two agree on what is
  configuration
- [Secrets](Secrets) — the list applied on the way to disk
