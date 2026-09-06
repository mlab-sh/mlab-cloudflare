# `mlab-cloudflare tls`

What browsers are served, and whether the origin will talk to anyone who finds
it.

```bash
mlab-cloudflare tls
mlab-cloudflare tls -z example.com
mlab-cloudflare tls origin
mlab-cloudflare tls certs
mlab-cloudflare tls hostnames
```

## The argument

Two questions get conflated here. The browser-facing half is mostly inventory
and expiry, and Cloudflare manages most of it.

The origin-facing half is the one that matters, and it has nothing to do with
certificates being valid. **Encrypting the origin leg protects the transport
and says nothing about who may open the connection.** Authenticated Origin
Pulls is the control that makes the origin refuse a request that did not come
through Cloudflare. Without it, `full (strict)` protects the wire while anyone
who learns the origin address is talking to the application.

Which is why this command also reads the DNS records. [`dns`](Dns) finds the
addresses a zone publishes; this finds whether the origin checks who is calling.
Neither is the finding on its own — together they are:

```
  high  origin  5 zones publish an origin address in DNS and do not require Cloudflare's
                client certificate at the origin, so that address is a way in rather
                than an information disclosure
                example.com (5 published, ssl flexible); example.net (1 published, ssl flexible)
```

`tls origin` prints that as a matrix:

```
  ZONE              SSL       ORIGIN PULLS  PUBLISHED  ORIGIN
  example.com       flexible  off           5          reachable
  example.net       full      off           0
  quiet.example     strict    on            0
```

`PUBLISHED` counts the DNS records naming an address the proxy also fronts for.
`ORIGIN` says `reachable` when both halves are true.

## What it checks

### Origin trust

- **The chain**: an origin published in DNS *and* origin pulls off — **high**.
- Origin pulls off with nothing published — **medium**. Still worth saying:
  nothing at the origin distinguishes Cloudflare from anyone else who learns
  the address, and the next unproxied record completes it.
- Origin pulls **on with hostnames excluded** — the zone reads as covered and
  the gap is the finding.
- Universal SSL off with no certificate uploaded, so the hostnames covered by
  neither are served nothing.

A setting the API refused is reported **neither way**. `None` is a refused read,
not evidence that the control is missing, and this is the plane's headline
finding — the worst place to guess.

### Certificates

- Expiring **within two weeks** — high. Inside that there is no time for a
  renewal that needs a DNS change or a purchase, so it outranks the rest of the
  report. Within thirty days — medium.
- Packs that **never reached active**, reported with the state they stalled in.
  The hostnames they cover are not being served by them.
- Client certificates with **no end date**, which is an unrotatable credential
  outside the token system.
- Nobody subscribed to **certificate transparency alerts**, so a certificate
  issued for the domain by anyone else goes unnoticed.
- Account-level mTLS certificates, and the **Gateway CA separately**: it is
  trusted by every managed device, so replacing it is a fleet rollout rather
  than a certificate renewal. It gets a year of warning rather than a month.

### Customer hostnames

On a SaaS zone this is the tenant list. A hostname that never finished
verification is the same dangling shape as a stale DNS record — with the added
property that the zone owner is serving it. Custom origin servers are listed
as context.

Empty is the normal state for a zone that serves its own traffic, and the
command says so rather than leaving a blank table.

## Entitlement

`/zones/{id}/custom_certificates` answers **`400 [1011] Plan level does not
allow custom certificates`** on plans below Business — a `400`, not a `403` or
a `404`. That is a third shape for the same fact, which is why nothing in this
command treats a status code as the signal: a read that failed contributes
nothing, and a read that succeeded is the only thing checked.

## Cost

Ten reads per zone, issued together and all cached. The DNS records and the
settings blob are usually already warm from [`dns`](Dns) and
[`posture`](Posture), so in a full audit this plane costs eight new calls per
zone rather than ten. See [Cache](Cache).

## See also

- [Dns](Dns) — the addresses this plane decides the meaning of
- [Posture](Posture) — the SSL mode, checked there and reused here
