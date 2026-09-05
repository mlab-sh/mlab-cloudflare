# `mlab-cloudflare zones`

The zones of the account being scanned.

```bash
mlab-cloudflare zones
mlab-cloudflare zones --status pending
mlab-cloudflare zones --all-accounts
mlab-cloudflare zones -a acme-labs
```

| Flag | Meaning |
| --- | --- |
| `--all-accounts` | Every zone the credential reaches, across all accounts |
| `--status STATUS` | `initializing`, `pending`, `active`, `moved`, `deleted`, `deactivated` |
| `--limit N` | A single page of that size instead of everything |

```
  Zones of acme-corp

  NAME             STATUS   PLAN  TYPE  PAUSED  ID
  example.com      active   Pro   full  false   1a2b3c4d5e6f708192a3b4c5d6e7f809
  example.net      active   Free  full  true    2b3c4d5e6f708192a3b4c5d6e7f809a1
  staging.example  pending  Free  full  false   3c4d5e6f708192a3b4c5d6e7f809a1b2

  3 zones

  ! paused, so nothing configured on them is enforced: example.net
  ! never delegated, so Cloudflare serves no traffic for them: staging.example
```

## One account at a time

**A scan covers one account.** That is the unit the whole tool works in: an
audit report is about an account, its zones and its configuration, and mixing
several into one report produces findings nobody owns.

So `zones` is scoped to [the resolved account](Configuration) by default, and
the heading names it — because the useful question about a scan is not "did it
run" but "did it run on the thing I meant".

`--all-accounts` opts out. That is the inventory question rather than the scan
question: which accounts hold what, so you know which one to scan next. The
table swaps its `TYPE` column for `ACCOUNT` when you ask for it, since the
owner is then the point.

## Choosing the account

With one account reachable, it is used. With several and none chosen, the
command stops and shows you the choice rather than guessing:

```
  ✖ several accounts are in scope, and a scan covers one account.

    acme-corp  a1b2c3d4e5f60718293a4b5c6d7e8f90
    acme-labs  b2c3d4e5f60718293a4b5c6d7e8f90a1

Pass --account <NAME|ID> for a single run, or save it as this profile's default with:

    mlab-cloudflare login --account <NAME|ID>
```

Save it once and nothing asks again. `-a`/`--account` takes a name or an id, and
overrides the saved default for one run.

## The two warnings

Both are states that look configured and enforce nothing, and both come back on
this listing, so neither costs a request.

**`paused: true`** — the zone is not proxied. The WAF rules, rate limits and bot
policies on it are inert, and the origin is exposed directly. A normal debugging
state and a bad steady state.

**`status: pending`** — the nameservers were never pointed at Cloudflare. The
zone's entire configuration is inert while everybody believes it is protecting
something. This is the one that survives longest, because the dashboard shows a
fully configured zone.

## See also

- [Accounts](Accounts) — how to find out which account to scan
- [Configuration](Configuration) — where the default account is stored
