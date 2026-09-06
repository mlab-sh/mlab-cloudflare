# mlab-cloudflare

**A CLI over the Cloudflare API, built as a base for read-only account and zone
audit.**

It talks to `api.cloudflare.com/client/v4` with a scoped API token, and a
profile in `$HOME/.mlab/cloudflare.conf` says which credential to use and which
account and zone to default to.

It reads. Every command in this repository is a GET, and no data leaves your
machine unless a command says it does and you pass the flag that allows it.

Made to be driven by a token created from the **Read all resources** template,
or something narrower.

## First run

Create a token at **dash.cloudflare.com → My Profile → API Tokens**, then:

```bash
mlab-cloudflare login
mlab-cloudflare whoami
mlab-cloudflare zones
```

`login` prompts for the token without echoing it, verifies it, picks the
account, and writes the config file with mode 0600 in a 0700 directory.

### Two kinds of token

Cloudflare keeps user-owned and account-owned tokens in separate namespaces
that cannot see each other, and the store that does not hold a token answers
`1000 Invalid API Token` — the same thing a mistyped credential gets.

- **My Profile → API Tokens** creates a *user* token. It is tied to you and is
  removed when you leave the account.
- **Manage account → Account API tokens** creates an *account* token, which is
  also where the R2 credentials are now handed out. It belongs to the account,
  outlives its creator's membership, and can only be verified against its own
  account — so it needs an account id:

  ```bash
  mlab-cloudflare login --account <ACCOUNT ID>
  ```

  The id is the 32 hex characters in the dashboard URL, `dash.cloudflare.com/<id>`.

`login` tries both stores, asks for the account id when it needs one, and
records which store answered so later commands go straight to it.

In CI there is usually nothing to set up: the tool reads `CLOUDFLARE_API_TOKEN`
(and `CF_API_TOKEN`, and `CLOUDFLARE_ACCOUNT_ID`) straight from the environment,
which is where wrangler and the Terraform provider already put them.

## Commands

| Command | What it does |
| --- | --- |
| `login` | Create or update a profile, prove the credential works, save it. |
| `whoami` | What this credential is, and exactly what it may do. Start here. |
| `ping` | Check that the current profile reaches the API. |
| `accounts` | Accounts this credential reaches. |
| `zones` | Zones of the account being scanned, and which of them enforce nothing. |
| `dns` | What the zones point at, and what points nowhere. Graded findings. |
| `posture` | What the edge enforces, and what is carved out of it. Graded findings. |
| `tls` | What browsers are served, and whether the origin will talk to anyone. Graded findings. |
| `identity` | Who can change this account, and with what. Graded findings. |
| `activity` | What was actually done to this account, and by whom. |
| `api` | Raw request against any endpoint, for everything not wrapped yet. |
| `profile` | List, show, select and delete saved profiles. |
| `config` | Where the config file is, and what is in it. |
| `cache` | What the response cache holds, and how to empty it. |

Every command renders to the terminal by default and to raw JSON with
`-o json`.

## One account at a time

A scan covers **one account**. `accounts` shows what the credential reaches so
you can pick; everything else runs inside the account resolved from
`--account`, the environment, or the profile. Save a preferred one once:

```bash
mlab-cloudflare login --account <NAME|ID>
```

## Caching

Configuration reads are cached on disk under `~/.mlab/cache/cloudflare`, so the
several commands of one audit share them. `dns`, `posture`, `tls` and `identity`
over a 19-zone account are 54 seconds cold and under a second warm.

Refusals are remembered too, which is most of that: a free zone answering `404`
on a phase its plan does not have is a fact rather than a moment, and re-asking
it on every zone on every run was the entire warm cost. A `429` and any `5xx`
are never stored.

Liveness checks — `ping`, `whoami`'s verification, `activity` — are never cached.
`--no-cache` bypasses reads while still refreshing; `--cache-ttl 0` turns it off
entirely.

## Why `whoami` comes first

Cloudflare's API answers `403` both for "this is not configured" and for "you
may not look", and the two are opposite findings. `whoami` settles which one
you are about to get: it reports the token's policies, the scope each policy
covers, whether any granted permission group is a write rather than a read,
whether the token carries an expiry and a source-IP condition, and which
accounts and zones it can actually see.

A Global API Key works too, and the tool says clearly what it thinks of that:
it carries every permission its user has, on every account they can reach, it
cannot be scoped or expired, and revoking it breaks every other integration
that shares it.

## Credentials

The config file is a credential store: it holds the token in cleartext, at mode
0600 in a 0700 directory, and the tool warns when the permissions have drifted.
Anything that prints a profile masks the credential to its last four characters.

Several readable Cloudflare endpoints hand back a live secret — a Cloudflare
Tunnel's connector token, a Turnstile widget's server-side key, an Access
identity provider's OIDC client secret, the TSIG key of a secondary DNS peer.
`api --redact` replaces each of them with its length before printing, which is
what makes the output safe to paste into a ticket.

## Layout

```
src/
  main.rs        entry point
  cli/           the clap surface, and the context a command runs in
  commands/      one file per command
  cf/            the HTTP client, the response cache, profiles, scope, redaction
  audit.rs       the graded checks, as pure functions over fetched data
  providers.rs   the hostname suffixes behind the takeover check
  ui/            the terminal render and the progress rules
```

## Status

Early. The credential handling, the HTTP layer and the base commands are in
place; the graded checks, the snapshot and the diff are not written yet. See
the audit surface analysis for what is worth reading and why.
