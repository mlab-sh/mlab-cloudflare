# Audit surface

Cloudflare's v4 API publishes **2,154 paths** and **1,696 GET operations**.
Strip the Radar endpoints, which describe the internet rather than your
account, and roughly **1,230** of them read some part of a configuration you
own.

The full analysis — 77 concrete checks across eight planes, each with the
endpoint, what it exposes and the finding it produces — lives in a separate
document:

> **[Cloudflare Audit Surface](https://claude.ai/code/artifact/5c192a3b-12f3-4968-b4c3-f1a79ee7b3cb)**

## The eight planes

| Plane | GET ops | The question it answers |
| --- | --- | --- |
| Identity | 113 | Who can change things, and with what credential |
| DNS & namespace | 62 | What points where, and what points nowhere |
| Edge & traffic | 144 | Whether the rules run, in what order, and what was carved out |
| TLS & certificates | 39 | What browsers see, and whether the origin talks to anyone |
| Zero Trust | 214 | Who reaches internal systems, and is fleet traffic inspected |
| Developer platform | 312 | What developers provisioned without a change ticket |
| Observability | 215 | Is anyone told, and where does the request data go |
| Network | 131 | The routed estate, where the account has one |

Counts are a classification of the published OpenAPI description by path
family, and exclude 278 Radar operations and 188 not assigned to a plane.

## The shape of the findings

Three patterns account for most of what is worth reporting, and none of them is
"a setting is missing":

**Configured and inert.** A zone whose nameservers were never delegated. A
paused zone. A WAF ruleset deployed and then exempted rule by rule. A DLP
profile no Gateway rule references. Each reads as protection in the dashboard
and enforces nothing.

**A door beside the door.** An unproxied DNS record publishing the origin that
every WAF rule is meant to sit in front of. A Worker also answering on
`workers.dev`, past the zone entirely. A split-tunnel exclusion that routes
traffic around Gateway. The control is real; the path around it is also real.

**A credential nobody owns.** An account-owned token that outlived its creator.
An Access service token with no expiry. A client certificate issued to a partner
who left. None of these appear in an offboarding checklist.

## The boundary

Worth stating in any report, because one that does not say where it stopped
looking reads as though it looked everywhere:

- Cloudflare knows the origin address; it does not know whether the origin's
  firewall accepts connections from anywhere else.
- The API says a CNAME points at a provider hostname. Confirming the resource
  behind it was deprovisioned needs a resolution against the outside world.
- Secret values are not readable, by design.
- Configuration history exists only as far back as the audit log's retention.
- Anything below the plan line answers the same way as a missing permission.
  See [Errors](Errors).

## See also

- [Roadmap](Roadmap) — the order these get built in
- [Api](Api) — reading any of them today, before they are wrapped
