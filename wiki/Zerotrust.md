# `mlab-cloudflare zerotrust`

Who reaches internal systems, and whether fleet traffic is inspected at all.

```bash
mlab-cloudflare zerotrust
mlab-cloudflare zt access
mlab-cloudflare zt gateway
mlab-cloudflare zt devices
mlab-cloudflare zt tunnels
```

Where an account has this, it is usually the plane with the highest blast
radius. Four layers, each of which can undo the one before it:

- **Access policies** are the perimeter.
- **Gateway policies** are the egress control.
- The **device profile** decides which traffic ever reaches Gateway.
- The **tunnels** decide what internal surface is reachable in the first place.

## One endpoint is never called

`/accounts/{id}/cfd_tunnel/{id}/token` returns a live connector credential —
enough to run a connector for that tunnel. An audit has no use for the value,
so it is not read at all. **Not reading it is a stronger guarantee than
redacting it**, because it never reaches the [cache](Cache) either.

## An absent plane is not a finding

Zero Trust is absent from most accounts. When there is no application, no
Gateway policy, no tunnel and no device profile, the command says so in two
lines and stops, rather than producing a wall of findings about a product
nobody bought.

## What it checks

### Access

- A policy with `include: [{everyone: {}}]` and `decision: allow` — **the
  application is public**. High.
- A policy with `decision: bypass` — Access is off for that path **while the
  application still reads as protected** in the list. High.
- An application admitting on an **address alone**: an `email` or
  `email_domain` include with no `require` clause at all. Anyone with a company
  address, from any device, with no second factor.
- An application whose allowed providers include a **one-time-PIN** provider,
  where an email inbox is the only factor.
- Sessions of a day or more. The value is a Go duration, where the units stop
  at hours and **`m` is minutes, not months** — a week is `168h`, and reading
  `m` as a month would report the shortest session available as the longest.
- **Service tokens**, which bypass interactive authentication entirely: no
  expiry within the year, or never used.
- Identity providers **without SCIM**, so removing someone from the directory
  does not remove their Access.

### Gateway

- **Configured with no policy at all** — it inspects traffic and decides
  nothing about it. High, and the first thing to say, because the product reads
  as present in the dashboard.
- Allow rules sitting **above the first block**, which decide everything they
  match before any block is reached.
- TLS inspection off, so an HTTP policy sees hostnames and nothing else.
- The activity log off, so no decision can be reviewed later.
- Rule types logging **only what was blocked** — allowed traffic leaves no
  record, and no later investigation is possible.

### Devices

- **Split-tunnel exclusions that send routable traffic around Gateway.** In
  exclude mode everything on the list leaves the device without passing through
  the egress control.

  The default list is almost entirely special-purpose space — private,
  loopback, link-local, multicast, and a dozen ranges from the IANA registry
  including `240.0.0.0/4`, `192.0.0.0/24` and `198.18.0.0/15`. Excluding those
  is the intended configuration, so the check only names an exclusion **a
  service could actually be reached on**. Flagging the defaults turned a
  correct setup into eight findings before that distinction went in.
- A profile that lets a user switch WARP off without a lock, which turns the
  fleet's egress control into an opt-in.
- A profile that does not auto-update the client.
- **Posture rules referenced by no Access policy.** They are only controls if a
  policy consumes them; a populated list nothing references is the most
  polished form of theatre on the platform, and the cross-reference is
  mechanical.

### Tunnels

- **The ingress rules, listed** — that is the authoritative record of what the
  internet can reach inside the network, hostname by hostname and port by port.
- A **catch-all that reaches something** rather than refusing, so a request for
  an unlisted hostname still lands inside.
- Ingress rules with `noTLSVerify`.
- Tunnels with no healthy connector: configured paths waiting rather than
  serving.
- Private ranges advertised to every enrolled device at a **/16 or wider**.
- A tunnel **configured on the connector** rather than in Cloudflare reports
  `source: "local"` and no ingress. That is reported as unread, not as
  publishing nothing — the API cannot see a file on someone's machine.

## Cost

Fifteen account-level reads plus one per tunnel, all cached. Two seconds cold on
an account with six applications and three tunnels.

## See also

- [Identity](Identity) — the dashboard side of who can change things
- [Platform](Platform) — Access applications often protect Worker preview URLs,
  which is where the two planes meet
