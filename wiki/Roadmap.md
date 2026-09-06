# Roadmap

Ordered by finding-per-call rather than by how much surface each phase covers.
See [Audit surface](Audit-Surface) for what each phase would read and why.

## Phase 1 — the base — **done**

Credential handling, the HTTP layer, and the commands that establish what you
are holding and what it reaches.

- `login`, `profile`, `config` — profiles at `$HOME/.mlab/cloudflare.conf`,
  0600 in a 0700 directory, credentials masked wherever they are printed
- Both credential kinds, and both [token stores](Tokens), with the store
  discovered once and remembered
- `whoami` — policies, scope shape, read-vs-write, expiry, IP condition, reach
- `ping`, `accounts`, `zones`
- `api` — the raw handler, with paging, cursor paging and `--redact`
- Envelope checking, bounded retry on `429`/`5xx`, no redirect following

## Phase 2 — identity — **done**

The graded-check engine (`audit.rs`: severities, findings, the pure functions
over fetched data) plus the two commands that use it.

- [`identity`](Identity) — members and their privileges as the union across
  their roles, tokens from both stores graded for writes, expiry, blanket
  scope and use, and SSO/SCIM coverage including directory users who were
  deactivated and still hold access
- [`activity`](Activity) — the audit log, with the queries that matter
- **Not read is not clean**: every refused read is listed, and never counted as
  a pass

## Phase 3 — DNS and the namespace — **done**

[`dns`](Dns), with `takeover`, `exposure`, `mail`, `records` and `domains`.

- A provider suffix table graded by how claimable an unclaimed name is, matched
  on a label boundary
- Unproxied records that publish an address also sitting behind the proxy —
  computable from one listing, because a proxied record still reports its real
  target
- Private space in public DNS, wildcards, DNSSEC stuck `pending`, missing zone
  holds
- Mail posture from the zone's own records, with no SPF split by whether the
  zone actually receives mail
- Registrar expiry, auto-renew and transfer lock

## Phase 4 — zone posture — **done**

[`posture`](Posture), with `settings`, `rules` and `edge`.

- The settings blob, one call for a dozen checks: SSL mode graded by which leg
  it leaves open, minimum TLS, HSTS read for its shape rather than its switch,
  development mode, 0-RTT
- The ruleset phase entry points, which are the only view that returns rules in
  execution order — and the only store, since the deprecated `/firewall/rules`
  is a second view of the same rules rather than a second engine
- Skip rules naming exactly which phases and products they turn off
- Managed rulesets weakened by an override, with OWASP paranoia levels excluded
  as tuning rather than bypass
- Spectrum applications graded by port, worker routes, snippets
- **Entitlement awareness**: a free zone answers 404 on the managed and
  rate-limit phases, and reporting that as unconfigured would have produced 36
  false findings on a 19-zone account

## Phase 5 — certificates and origin trust — **done**

[`tls`](Tls), with `origin`, `certs` and `hostnames`.

- The composite finding the plane exists for: an origin published in DNS *and*
  Authenticated Origin Pulls off, which is what turns an address from an
  information disclosure into a way in. Both planes share one implementation of
  "which records publish an origin", so they cannot disagree
- Origin pulls on with hostnames excluded, where the zone reads as covered
- Certificate expiry in two tiers, packs stalled before active, client
  certificates with no end date, certificate transparency unwatched
- The Gateway CA on its own clock, since replacing it is a fleet rollout
- A refused read is reported neither way — `None` is not evidence

## Phase 6 — the developer platform — **done**

[`platform`](Platform), with `workers`, `storage` and `pages`.

- The `workers.dev` exposure, split by whether the script also serves a zone
  route — a bypass and a design respectively — with the bindings named, since
  the point is that the unprotected door reaches the same data
- R2 buckets served anonymously on `r2.dev`, Pages previews sharing production
  bindings, Hyperdrive naming the database estate
- Stores nothing reaches, with buckets served over HTTP and dead-letter queues
  excluded, because neither is neglect
- Six reads in flight at once: one at a time was a minute of round trips for
  forty scripts

## Phase 7 — Zero Trust — **done**

[`zerotrust`](Zerotrust) (alias `zt`), with `access`, `gateway`, `devices` and
`tunnels`.

- Access policies graded by what admits and what requires: `everyone`,
  `bypass`, an address with no second factor, a one-time-PIN provider
- Gateway configured with no policy at all, allow rules above the first block,
  inspection and logging switched off
- Split-tunnel exclusions that send *routable* traffic around Gateway — the
  default list is special-purpose space, and flagging it produced eight false
  findings before the distinction went in
- Posture rules no Access policy references
- Tunnel ingress as the internal exposure map, with a locally-configured tunnel
  reported as unread rather than as publishing nothing
- `/cfd_tunnel/{id}/token` is never called: not reading a live credential is
  stronger than redacting it
- An account without Zero Trust gets two lines, not a wall of findings

## Phase 8 — egress, logging and alerting — **done**

[`egress`](Egress) with `jobs` and `retention`, and [`alerts`](Egress) with
`coverage`, `policies` and `destinations`.

- Logpush jobs shipping headers, cookies or client addresses; disabled and
  failing jobs; destinations shown as scheme and host only, since the rest of
  the string carries an access key
- Raw log retention per zone, stated as what it decides: whether a question
  asked next month has an answer
- Alert coverage grouped by **the question nobody answers** rather than by
  identifier, gated on what the account can actually receive
- Webhooks failing more recently than they succeeded, disabled policies,
  standing silences
- The plane most likely to be entirely unreadable, so it prints what it could
  not read and says the plane is unaudited rather than clean

## Phase 9 — network — **done**

[`network`](Network), with `magic`, `addressing` and `balancing`.

- Tunnels permitting a null cipher, health checks off, replay protection off
  where the setting exists
- Site ACLs pairing two whole LANs on every protocol, where an empty list means
  "all" rather than "none"
- Static routes covering the same space at one priority, with containment
  computed rather than string-matched
- Advertised prefixes nothing is bound to, and RPKI states other than valid
- Pools whose monitor is absent *or* dangling, balancers with no fallback
- The one plane that could not be exercised live: the account it was built
  against routes nothing through Cloudflare, so the tests carry it and the
  empty case is what was verified end to end

## Phase 10 — snapshot and diff

Everything above, redacted and written to one dated file, then compared.
Configuration drift is the finding no single read can produce, and the audit
log's retention horizon is the argument for recording before it is needed.

Needs every earlier phase to expose its reads as data rather than only as
rendering, which is why each one keeps its gather step separate from its
report.

## Phase 11 — the whole report, and shipping it

One `audit` command across every plane, entitlement-aware so a plan gap never
reads as a misconfiguration, with an exit code a CI gate can act on and the
unread list as a first-class section of the output.

Then release: the `.deb` and `.rpm` metadata already in `Cargo.toml` wired to a
pipeline, a Homebrew formula, checksummed tarballs per target. The wiki sync is
already running.

## Not planned

- Anything that writes. The `api` command will pass a `POST` because refusing
  to would be dishonest about what it is, but no wrapped command will.
- Active probing. Confirming that a dangling CNAME target is really
  deprovisioned needs a resolution against the outside world; if that is ever
  added it goes behind an explicit flag and is documented as active.
