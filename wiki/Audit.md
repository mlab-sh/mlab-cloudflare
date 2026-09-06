# `mlab-cloudflare audit`

Every plane, one graded report, one exit code.

```bash
mlab-cloudflare audit
mlab-cloudflare audit --full
mlab-cloudflare audit --fail-on high
mlab-cloudflare audit -o json
```

The other commands each answer a question about one part of an account. This
one answers the question somebody actually asks: **is anything wrong here, and
what.**

It runs [`identity`](Identity), [`dns`](Dns), [`posture`](Posture),
[`tls`](Tls), [`platform`](Platform), [`zerotrust`](Zerotrust),
[`egress`](Egress) and [`network`](Network), sorts every finding worst-first,
and says what it could not look at.

## The exit code

```bash
mlab-cloudflare audit --fail-on high || echo "the gate tripped"
```

| Code | Meaning |
| --- | --- |
| `0` | nothing reached the threshold |
| `2` | a finding reached it |
| `1` | the tool failed — a bad credential, no network, an unreadable config |

`2` rather than `1` on purpose: a gate that cannot tell *the audit found things*
from *the tool broke* will eventually be switched off, and the second is the
case that needs a human.

`--fail-on` is **at or above**: `--fail-on medium` trips on a high finding too.
The default is `never`, so the command reports and succeeds unless you ask it
not to.

## The short view

By default it prints the worst five of each severity and drops `info`
altogether — that is context for a finding above it, and forty lines of context
ahead of two high findings is how a report stops being read.

```
  › showing 15 of 40 findings; --full prints the rest
```

`--full` prints everything, in the same order.

## What was not read is part of the answer

Every plane reads through the same client, and the same recorder a
[snapshot](Snapshot) uses collects every refusal. So no plane can quietly
contribute an empty finding list because its reads were denied:

```
  Not read

  ENDPOINT                                     READS  CAUSE       WHY
  GET /zones/{id}/logs/control/retention/flag  19     permission  401 Unauthorized
  LIST /zones/{id}/custom_certificates         19     plan        400 Plan level does not allow…
  LIST /zones/{id}/logpush/jobs                19     permission  403 Authentication error

  ! 12 endpoints were refused; those areas are unaudited, not clean
  › 1 more endpoint is not included in this account's plan
```

Two things make that section usable rather than noise.

**Object ids are generalised.** Nineteen zones refusing the same read are one
gap in the audit, not nineteen, and a report that lists them separately buries
every other gap underneath. The `READS` column says how many objects each row
covers, and the list is sorted by it.

**The plan and the credential are separated.** A refusal because the account
does not have the product is not a gap somebody can close; a refusal because the
token lacks a permission is. That distinction is only claimed where the API says
so in as many words — guessing at it from a status code would turn "you cannot
look" into "you do not have this", which is the more comfortable of the two and
the wrong one to assume.

## A plane that fails outright

Is named and does not stop the rest. Seven planes reported is worth more than
none:

```
  ! 1 plane could not run at all: network: several accounts are in scope…
```

## In CI

```yaml
- run: mlab-cloudflare audit --fail-on high -o json > audit.json
  env:
    CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}
    CLOUDFLARE_ACCOUNT_ID: ${{ vars.CLOUDFLARE_ACCOUNT_ID }}
```

The JSON carries `findings`, `counts`, `unread` (each row tagged `plan` or
`permission`), `planesFailed` and `exitCode`, so a job can gate on the code and
still publish the document.

```bash
mlab-cloudflare audit -o json | jq -r '.findings[] | select(.severity=="high") | .finding'
```

## Cost

Every plane, once: around 600 calls on a 19-zone account, 85 seconds cold and
under a second warm. See [Cache](Cache) — and note that a `--fail-on` gate in CI
runs cold every time unless the cache directory is preserved between jobs.

## See also

- [Snapshot](Snapshot) — the same reads, kept rather than judged
- [Errors](Errors) — why a refusal has more than one meaning
