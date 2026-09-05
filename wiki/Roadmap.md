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

## Phase 2 — identity

The token inventory across both stores, members and roles with their
two-factor state, pending invitations, account-owned tokens, SSO and SCIM
coverage, resource shares, and the audit-log queries that matter (failed
actions, deletes, changes made by a token rather than a person).

Bounded, high value, and it needs no zone iteration.

## Phase 3 — DNS

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

## Phase 5 — the developer platform

Workers and their bindings, the `workers.dev` exposure that bypasses every
zone-level rule, Pages preview configurations holding production bindings, R2
buckets served publicly on `r2.dev`.

## Phase 6 — Zero Trust

Access policies, Gateway rules, split-tunnel exclusions, tunnel ingress. The
largest read, and the one that has to degrade cleanly when the entitlement is
absent — which is most accounts.

## Phase 7 — snapshot and diff

Everything above, redacted and written to one dated file, then compared.
Configuration drift is the finding no single read can produce, and the audit
log's retention horizon is the argument for recording before it is needed.

## Not planned

- Anything that writes. The `api` command will pass a `POST` because refusing
  to would be dishonest about what it is, but no wrapped command will.
- Active probing. Confirming that a dangling CNAME target is really
  deprovisioned needs a resolution against the outside world; if that is ever
  added it goes behind an explicit flag and is documented as active.
