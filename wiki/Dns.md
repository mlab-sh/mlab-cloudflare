# `mlab-cloudflare dns`

What the account's zones point at, and what points nowhere.

```bash
mlab-cloudflare dns
mlab-cloudflare dns -z example.com
mlab-cloudflare dns takeover
mlab-cloudflare dns exposure
mlab-cloudflare dns mail
mlab-cloudflare dns records
mlab-cloudflare dns domains
```

With no subcommand it runs every check across every zone of the account being
scanned and prints the graded report. With `-z` it narrows to one zone.

This is the densest plane on the platform, and the one that most benefits from
covering a whole account rather than one domain: a dangling record is invisible
in the zone it sits in and obvious across a portfolio.

## The report

```
  DNS across 19 zones

  zones    19
  records  148
  signed   2 of 19

  Findings

  high    exposure   16 unproxied records publish an address that also sits behind the proxy,
                     so the origin can be reached by name and every rule on the zone is bypassed
                     direct.example.com → 198.18.0.9, api.example.net → 198.18.0.9
  medium  mail       8 parked zones have neither MX nor SPF, so anyone can send mail as them;
                     a domain that sends no mail should say so with a null MX and v=spf1 -all
                     example.org, example.net
  low     namespace  DNSSEC is off on 17 zones
                     …
```

## What it checks

### Takeover

Every `CNAME` whose target ends in a known third-party suffix, graded by how
claimable an unclaimed name on that platform is:

| Grade | Meaning |
| --- | --- |
| **High** | The platform hands out names first-come — GitHub Pages, Heroku, S3, Azure App Service. If the resource was deprovisioned the name is claimable by anyone today. |
| **Medium** | The platform verifies domain ownership before serving — Shopify, Netlify, Statuspage. A dangling record is a dead reference rather than an open door. |
| **Info** | A Cloudflare resource — `r2.dev`, `pages.dev`, `workers.dev`. Nobody else can claim it; it says something in *this* account is published under the name. |

The suffix match is on a label boundary, so a hostname inside a zone you control
that merely ends with the letters of a suffix is not a candidate. The longest
matching suffix wins.

**The API can only do half of this check.** It says a record points at a
provider hostname; whether the resource behind it still exists needs a
resolution against the outside world, which is an active step. The report says
so once rather than pretending otherwise, and only where it is actually the
open question — a record pointing at your own R2 bucket needs no outside look.

### Exposure

- **The sharp one.** An unproxied `A`/`AAAA` whose address also sits behind a
  proxied record. A proxied record still reports its real target in `content` —
  the proxy hides the origin from a resolver, not from the API — so this is
  computable from one listing. The origin can then be reached by name, and every
  WAF rule, rate limit and bot policy on the zone is bypassed.
- **Unproxied proxiable records** generally, which publish an address directly.
  Records Cloudflare could not proxy are skipped: those are not a choice anybody
  made.
- **Private or reserved space in public DNS** — `10.0.0.0/8`, `192.168.0.0/16`,
  link-local, carrier-grade NAT — which describes the internal network to
  anyone who asks. Reported whether proxied or not, because the address is
  published either way.
- **Wildcards**, so every unregistered name under them resolves.

`100::` and the documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) are the conventional filler for a name that should only ever
be reached through the proxy, and are never reported as exposed origins.

### Mail

Read from the zone's own records, so it costs no extra request: `MX`, the `TXT`
at the apex, and the `TXT` at `_dmarc`. Long records split across several quoted
strings are joined the way a resolver joins them.

- SPF ending in `+all` or `?all` — **high**, it authorises every sender on the
  internet.
- More than one SPF record — a resolver treats that as no SPF at all.
- **No SPF, split two ways**, because the remedy differs: a zone that carries MX
  is in use for mail and needs a real policy; a zone with none is parked and
  wants a null MX with `v=spf1 -all`.
- No DMARC record, so a receiver has no instruction for mail that fails
  authentication.
- DMARC at `p=none`, which reports failures and rejects nothing.

`dns mail` prints the matrix rather than the findings:

```
  ZONE                MX  SPF   DMARC
  example.com         6   ~all  p=none
  parked.example      0   none  none
```

### Namespace

- **DNSSEC `pending`** — the zone is signed and the DS record was never added at
  the registrar, so nothing is validated. It reads as enabled in the dashboard,
  which is why it survives.
- DNSSEC off.
- **No zone hold**, so the domain can be added to another Cloudflare account by
  whoever controls its DNS next.

A zone whose signing state could not be read is reported neither way — `None`
means the read was refused, which is not evidence.

### Registrar

`dns domains` reads Cloudflare Registrar: expiry within 60 days, auto-renew off,
transfer lock off. An expiry is a full outage followed by a hostile
registration, and no edge setting mitigates it.

An empty list is not a finding — most domains are registered elsewhere, and this
endpoint only knows about Cloudflare Registrar. The command says so.

## Cost

One record listing per zone answers takeover, exposure and the whole of mail.
The graded report adds two calls per zone for DNSSEC and the hold; the listing
views do not pay for them.

The three per-zone reads are issued together, so a zone costs about one round
trip rather than three — roughly 18 seconds for 19 zones against 34 sequential.

## JSON

```bash
mlab-cloudflare dns -o json | jq '.findings[] | select(.severity=="high")'
```

## See also

- [Zones](Zones) — the inventory this runs over
- [Audit surface](Audit-Surface) — the rest of the DNS plane
