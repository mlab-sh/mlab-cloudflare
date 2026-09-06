# `mlab-cloudflare network`

The routed estate, where an account has one.

```bash
mlab-cloudflare network
mlab-cloudflare network magic
mlab-cloudflare network addressing
mlab-cloudflare network balancing
```

Magic Transit and Magic WAN move an organisation's actual routing into
Cloudflare: tunnels, static routes, site LANs and ACLs, BGP. The failures here
are the ordinary failures of network engineering — overlapping prefixes,
permissive ACLs, health checks nobody turned on — with the difference that a
mistake applies to every site at once.

## Most accounts have none of this

It is the plane most likely to be entirely absent, so that case is handled first
and plainly:

```
  Network
  › no Magic tunnel, static route, announced prefix, DNS Firewall cluster or load balancer
  › this account does not route through Cloudflare, which is not a finding
```

## What it checks

### Tunnels and sites

- **A tunnel permitting a null cipher.** It authenticates the peer and sends the
  traffic in clear, which is the one thing everyone assumes an IPsec tunnel does
  not do. **High.**
- **A site rule pairing two whole LANs on every protocol** — a flat network
  wearing a segmentation diagram. It is invisible from either site's own
  configuration; only the ACL shows it. **High.**

  An empty protocol list means *every* protocol, and an ACL side with no
  subnets, ports or port ranges means the whole LAN. Reading either as "nothing"
  inverts the finding.
- Tunnels with health checks off, so failover has nothing to act on.
- IPsec tunnels with replay protection off. GRE has no such setting, and its
  absence is not read as "off".

### Static routes

**Two routes covering the same space at the same priority** is a decision made
per packet rather than by the design — and neither route's own definition shows
it, only the pair does.

Containment is computed rather than string-matched: `10.0.0.0/8` covers
`10.4.0.0/16`, and a default route covers everything. IPv4 only — a wrong answer
about routing is worse than no answer, and the overlaps that bite in practice
are v4.

Routes with the same next hop are not a clash, and different priorities mean the
design has already decided.

### Announced address space

- **A prefix advertised with nothing bound to it** — address space announced on
  your behalf for no reason. A prefix that is not advertised is not idle, it is
  simply not in use yet.
- **An RPKI validation state other than valid**, so the announcement can be
  dropped by validating networks.

### DNS Firewall

Clusters, the upstream resolvers they forward to — a resolver that is no longer
yours, still being forwarded to, is a resolution path outside the organisation —
and clusters with no rate limit, which pass a flood straight through.

### Load balancing

- **A pool with no working monitor**, which covers both "no monitor set" and
  "monitor set to one that no longer exists". Either way it never marks an
  origin unhealthy, so it never fails over.
- A balancer with **no fallback pool**, so traffic is dropped rather than shed
  when every pool is unhealthy.
- Disabled origins still listed in a pool, as a record of infrastructure that
  may still be listening.

## A note on validation

This plane could not be exercised against a live account during development —
the account it was built against routes nothing through Cloudflare. Every check
is written against the published schema and covered by unit tests over recorded
shapes, and the empty case is the one that was verified end to end.

If you run this against an account that *does* use Magic Transit and something
reads wrong, that is the most likely place in the tool for it.

## See also

- [Audit surface](Audit-Surface) — the rest of the network plane
