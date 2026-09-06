# `mlab-cloudflare posture`

What the edge is configured to do, and what has been carved out of it.

```bash
mlab-cloudflare posture
mlab-cloudflare posture -z example.com
mlab-cloudflare posture settings
mlab-cloudflare posture rules
mlab-cloudflare posture edge
```

The question is never "is there a WAF" — there is. It is whether the rules run,
in which order, and what has been exempted from them.

## Where the truth is

Cloudflare exposes the same custom firewall rules through two surfaces: the
deprecated `/zones/{id}/firewall/rules`, and the ruleset phase entry point.
**On a current account they are one store with two views**, not two engines, so
this command reads only the entry point — reading both would report every rule
twice.

The entry point is also the only view that returns the rules **in the order
they execute**, which is what a broad rule near the top makes decisive.

Four phases are read:

| Phase | Why |
| --- | --- |
| `http_request_firewall_custom` | where the `skip` rules live |
| `http_request_firewall_managed` | what they skip |
| `http_ratelimit` | usually empty, and that is the finding |
| `http_config_settings` | can change a zone setting per request, which makes the settings blob a default rather than the truth |

Page rules are read separately, because those genuinely *are* a second engine,
evaluated before the rulesets.

## What it checks

### Transport

One call returns all 56 settings, so this is a dozen checks for the price of one.

- **SSL mode**, graded by which leg it leaves open. `off` and `flexible` send
  cleartext to the origin while the browser sees a padlock — **high**. `full`
  encrypts both legs and validates no certificate, so anyone who can intercept
  the origin leg can present anything — **medium**. Only `strict` is what people
  assume they have.
- `min_tls_version` of `1.0` or `1.1`.
- **HSTS read for its shape, not only its switch**: off; on but with a max-age
  under six months; on but without `includeSubDomains`, which leaves every
  subdomain unprotected.
- `always_use_https` off.
- `0rtt` on, which permits replay of early data on any endpoint that is not
  idempotent.

A setting the API did not return is reported as unknown, not as off — the blob
differs by plan.

### Enforcement

- **Skip rules**, the flagship finding. Each one names exactly what it turns
  off for the requests it matches, read from its action parameters:

  ```
  example.com: "webhook bypass" skips phases http_ratelimit+http_request_firewall_managed,
  the rest of this ruleset
  ```

- **Managed rulesets weakened by an override**: deployed but disabled, set to
  `log` rather than block, categories switched off, individual rules turned
  down. **OWASP paranoia levels are excluded** — choosing not to run levels 2 to
  4 is how that ruleset is meant to be tuned, and reporting it would bury the
  overrides that really do switch protection off.
- Development mode on, which bypasses the cache and relaxes the edge.
- Security level at `essentially_off`.
- No managed ruleset, and no rate limit rule — **only where the plan allows one**.
- Custom rules left at `log`, and disabled rules.
- Page rules, which are the separate engine.

### Edge

- **Spectrum applications**, graded by port. An application on 22, 3389, 3306,
  5432, 6379 or 27017 publishes remote administration or a database to the
  internet with none of the HTTP security stack in front of it — and it appears
  in no review that only looks at web traffic.
- Worker routes, including any route whose script is gone.
- Snippets: code running at the edge, outside the rule engine.

## A plan gap is not a gap in configuration

This is the trap the phase exists to avoid. A **free** zone answers `404 could
not find entrypoint rules` on the managed and rate-limit phases: the free
managed ruleset runs automatically and cannot be tuned, and rate limiting rules
cannot be created at all. Reporting those as unconfigured turns a price list
into a wall of findings — on a 19-zone account, 36 of them.

So the two plan-gated checks fire only where the plan allows the thing, and the
zones they skipped are **named** rather than left silent:

```
  info  enforcement  18 zones are on a free plan, where the managed ruleset applies
                     automatically and cannot be tuned, and rate limiting rules are
                     not available
```

Everything else — SSL mode, HSTS, minimum TLS, development mode — is
configurable on every plan and is checked everywhere.

Page Shield is treated the same way: off on a paid zone is a finding, off on a
free zone is the price list.

## Subcommands

`posture settings` prints the matrix:

```
  ZONE         PLAN          SSL       MIN TLS  HSTS  HTTPS  SECURITY  DEV MODE
  example.com  Pro Website   flexible  1.0      off   on     medium    off
  example.net  Free Website  full      1.2      365d  on     medium    off
```

`posture rules` prints each phase's rules **numbered in execution order**, with
the expression, so the order argument can actually be made.

`posture edge` lists Spectrum applications, worker routes and snippets together
— everything that handles a request outside the rule engine.

## Cost

Nine reads per zone, issued together, and all cached. A 19-zone account is about
17 seconds cold and under a second warm. See [Cache](Cache).

## Not read here

Bot management settings, API Shield discovery and the certificate surfaces.
Certificates are [phase 5](Roadmap); the other two are entitlement-heavy and
belong with a pass that can say what a plan includes rather than guessing.

## See also

- [Dns](Dns) — the origin exposure this sits in front of
- [Cache](Cache) — why the second run is instant
