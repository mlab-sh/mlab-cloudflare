# mlab-cloudflare

**A CLI over the Cloudflare API, built as a base for read-only account and zone
audit.**

mlab-cloudflare talks to `api.cloudflare.com/client/v4` with a scoped API token,
and a profile in `$HOME/.mlab/cloudflare.conf` says which credential to use and
which account and zone to default to.

It reads. Every command in the tool is a GET, and no data leaves your machine
unless a command says it does and you pass the flag that allows it.

---

## The commands

| Command | What it does |
| --- | --- |
| [`whoami`](Whoami) | What this credential is, and exactly what it may do. Start here. |
| [`login`](Login) | Create or update a profile, prove the credential works, save it. |
| [`ping`](Ping) | Check that the current profile reaches the API. |
| [`accounts`](Accounts) | Accounts this credential reaches. |
| [`zones`](Zones) | Zones of the account being scanned, and which of them enforce nothing. |
| [`dns`](Dns) | What the zones point at, and what points nowhere. Graded. |
| [`posture`](Posture) | What the edge enforces, and what is carved out of it. Graded. |
| [`identity`](Identity) | Who can change this account, and with what. Graded. |
| [`activity`](Activity) | What was actually done to this account, and by whom. |
| [`api`](Api) | Raw request against any endpoint, for everything not wrapped yet. |
| [`profile`](Configuration) | List, show, select and delete saved profiles. |
| [`config`](Configuration) | Where the config file is, and what is in it. |
| [`cache`](Cache) | What the response cache holds, and how to empty it. |

## One account at a time

A scan covers **one account**. That is the unit the tool works in: an audit
report is about an account, its zones and its configuration, and mixing several
into one report produces findings nobody owns.

[`accounts`](Accounts) is how you see what is reachable and pick. Everything
else runs inside the account resolved from `--account`, the environment, or the
profile — and saving a preferred one with `login --account <NAME|ID>` means
nothing asks again.

## Key concepts

- **[Tokens](Tokens)** — Cloudflare keeps user-owned and account-owned tokens in
  two namespaces that cannot see each other. Which one holds yours decides which
  endpoint verifies it, and whether it survives your leaving the account. This is
  the page to read before anything else.
- **[Configuration](Configuration)** — profiles, the precedence between flags,
  environment and file, and where credentials live.
- **[Output](Output)** — a terminal render by default, raw JSON with `-o json`,
  and the rules that keep the two from mixing.
- **[Cache](Cache)** — configuration reads are cached on disk so the several
  commands of one audit share them. What is never cached, and why.
- **[Errors](Errors)** — the envelope, the three meanings of `403`, the rate
  ceiling, and what the tool retries on your behalf.
- **[Secrets](Secrets)** — several readable endpoints hand back live
  credentials. What the tool does about that, and what you should.
- **[Audit surface](Audit-Surface)** — the catalogue of what is worth reading
  across the 1,696 readable operations, and the finding each one produces.
- **[Roadmap](Roadmap)** — what is built, what is next, in order.

## Getting started

```bash
git clone https://github.com/mlab-sh/mlab-cloudflare.git
cd mlab-cloudflare && cargo build --release

mlab-cloudflare login
mlab-cloudflare whoami
mlab-cloudflare zones
```

See [Install](Install) for the details, and [Login](Login) for what the wizard
asks and why.

## About the examples in this wiki

Every identifier, account name, hostname and address on these pages is
invented. Ids follow an obviously patterned scheme
(`a1b2c3d4e5f60718293a4b5c6d7e8f90`), hostnames use the RFC 2606 reserved
domains, and addresses use the RFC 5737 test ranges. Nothing here is a capture
of a real account.

## Scope and stability

The v4 API is documented, versioned and stable, and Cloudflare publishes an
OpenAPI description of it. There is no undocumented surface to fall back on
here, and nothing in this tool depends on one — which makes it a quieter
proposition than the other mlab CLIs, and means a command that breaks is a
change in the product rather than a change in an internal route.

What is not stable is the **entitlement** behind an endpoint. Page Shield, API
Shield, Bot Management, Log Retention, DLP and Zero Trust all answer `403` or
`404` on plans that do not include them, and that is indistinguishable from a
permission your token lacks. See [Errors](Errors).
