# `mlab-cloudflare activity`

What was actually done to this account, and by whom.

```bash
mlab-cloudflare activity
mlab-cloudflare activity --days 90
mlab-cloudflare activity --failed
mlab-cloudflare activity --by-token
mlab-cloudflare activity --destructive --days 180
mlab-cloudflare activity --actor someone@example.com
```

Aliases: `audit-log`, `log`.

| Flag | Meaning |
| --- | --- |
| `--days N` | How far back to look (default 30) |
| `--failed` | Only actions that failed |
| `--by-token` | Only changes made by a token or by the system, not by a person |
| `--destructive` | Only deletions and revocations |
| `--actor EMAIL` | Only actions by this address |
| `--limit N` | Stop after this many entries |

```
  Activity, last 30 days

  WHEN                  ACTOR              BY             ACTION         RESULT  RESOURCE    IP
  2026-09-05T21:05:55Z  ops@example.com    user           token_revoke   ok      account     203.0.113.4
  2026-09-03T09:18:53Z  4b1e2f0a6c8d3e5f…  account_token  delete         ok      dns.record  198.51.100.9
  2026-09-03T06:25:19Z                     system         backup_issued  ok      certificate_pack

  3 entries

  › 2 of 3 changes in the last 30 days were made by a token or by the system rather than by a person
  › 1 deletion or revocation in the last 30 days — delete
  › changes came from 2 distinct addresses — 203.0.113.4, 198.51.100.9
```

The system's own actor id is the literal `1`, which identifies nothing, so the
`ACTOR` column is left empty for it — the `BY` column already says the change
was internal.

## Why it matters

The audit log is the only record of what a setting used to be. Its retention is
plan-dependent, which makes it two things at once: the way to answer "who
changed this", and the clock on how far back any incident can be reconstructed
at all. That is the argument for snapshotting on a schedule rather than
trusting the log to still hold the answer.

## What it observes

The findings are computed over the **whole window**, not over the filtered
view, so a narrowed listing still reports the shape of everything in it. The
line under the table says how many entries the filters hid.

- **Failed actions.** A run of failures is what a credential being tried looks
  like from this side.
- **Changes not made by a person.** `actor.type` of `account_token`,
  `user_token` or `system`. Normal in an account with a pipeline, and worth
  seeing in one without.
- **Deletions and revocations**, with the distinct action types behind the
  count.
- **Distinct source addresses.** The cheapest form of "did this come from where
  it usually comes from" without a baseline to compare against.

## Filters the API does not offer

`--failed`, `--by-token` and `--destructive` are applied locally, because the
v1 audit log does not filter on them. `--actor` and `--days` are sent to the
API. That means the local filters cost nothing extra but only see what the
window fetched.

## See also

- [Identity](Identity) — who *could* make these changes
- [Api](Api) — the v2 audit log (`/accounts/{account}/logs/audit`), which
  filters far more richly and pages by cursor
