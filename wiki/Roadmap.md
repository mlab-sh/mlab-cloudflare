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

## Phase 3 — DNS and the namespace

The densest findings on the platform, and the phase that most benefits from
covering a whole portfolio rather than one domain: dangling records pointing at
deprovisioned cloud resources, unproxied records publishing the origin, DNSSEC
stuck `pending`, mail authentication on zones that send no mail, registrar
expiry and lock state.

One list call per zone.

## Phase 4 — zone posture

`/zones/{id}/settings` is one call and answers a dozen checks: SSL mode,
minimum TLS, HSTS, development mode, security level, caching. Paired with the
ruleset phase entrypoints and the legacy firewall surfaces, to establish what
actually executes and in what order — which is not what the dashboard shows
when rules exist in both engines.

## Phase 5 — certificates and origin trust

Small, and it turns a DNS finding into an exposure: without Authenticated
Origin Pulls, every leaked origin address is a way in rather than an
information disclosure. Plus the certificate inventory and its expiries.

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
