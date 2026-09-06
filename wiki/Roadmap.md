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

## Phase 6 — the developer platform

Workers and their bindings, the `workers.dev` exposure that bypasses every
zone-level rule, Pages preview configurations holding production bindings, R2
buckets served publicly on `r2.dev`, Hyperdrive connection details, Turnstile
widgets. The first phase where the rate ceiling shapes the design.

## Phase 7 — Zero Trust

Access policies, Gateway rules, split-tunnel exclusions, tunnel ingress. The
largest read, and the one that has to degrade cleanly when the entitlement is
absent — which is most accounts. Redaction is mandatory here: a tunnel's token
endpoint returns a live connector credential.

## Phase 8 — egress, logging and alerting

Where request data goes and whether anyone is told when something breaks:
Logpush destinations and their field lists, notification policies against the
available alert types, silences never restored, webhook destinations failing
since months, log retention and data residency.

## Phase 9 — network

Only on accounts that bought Magic Transit or WAN: site ACLs, tunnels, static
routes, BYOIP prefixes, DNS Firewall clusters, load balancer pools.

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
