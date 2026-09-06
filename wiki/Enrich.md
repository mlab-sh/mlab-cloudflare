# `mlab-cloudflare enrich`

The same account, seen from outside it.

```bash
mlab-cloudflare enrich plan
mlab-cloudflare enrich
mlab-cloudflare enrich zones
mlab-cloudflare enrich origins
mlab-cloudflare enrich --budget 10
mlab-cloudflare enrich zones -z example.com
```

Every other command in this tool reads Cloudflare's record of the account. That
record is authoritative about *intent* and silent about *effect*: it says which
names the account publishes, not which names answer; which address an origin is,
not what kind of address that is.

`enrich` asks [mlab.sh](https://mlab.sh) those second questions and puts the two
answers side by side. Every finding it produces has the same shape — **the
inside and the outside disagree** — and none of them can be reached through the
Cloudflare API at all.

## Why it is a separate command

It is the only command that talks to a service other than Cloudflare, the only
one that leaves the machine on the user's behalf, and the only one that spends a
quota. All three are reasons not to fold it into `audit` silently.

`audit --enrich` includes the findings, but reads **only results `enrich` has
already fetched**, and reports the rest as not looked up. Running the ordinary
report never draws down a daily limit as a side effect.

## Setting the key

`enrich` needs an mlab.sh API key, which is available on a Pro plan or above.
It is stored beside the Cloudflare credential and redacted the same way.

```bash
mlab-cloudflare login --mlab-key mlk_…
export MLAB_API_KEY=mlk_…
mlab-cloudflare enrich --mlab-key mlk_…
```

Precedence is the usual one: flag, then `MLAB_API_KEY` (or `MLAB_KEY`), then the
profile. It has a name of its own rather than reusing `CLOUDFLARE_API_TOKEN`,
because it is a key for a different service — putting one in the other's slot is
a category error the config should not let you make quietly.

## Spending, and not spending

Quotas are per day and shared across an organisation. A Pro plan allows 25
domain lookups and 50 address lookups a day, and an account with 26 zones
therefore cannot be swept in one day. Four things follow.

**Nothing is looked up twice.** Results are held for seven days, which is how
long mlab keeps its own. A second run inside that week costs nothing.

**Results are held apart from the Cloudflare cache.** They live in
`$HOME/.mlab/cache/cloudflare/mlab/`, so `cache clear` cannot throw away a week
of paid lookups to refresh fifteen minutes of free ones. `cache clear --all`
removes them deliberately.

**`--no-cache` does not apply here.** Bypassing a cache that stands between you
and a daily limit is not a debugging convenience. `--refresh` exists for when it
is genuinely wanted.

**The budget is a ceiling, not a target.** `--budget N` caps how many lookups a
run may spend, default 20. Targets past it are printed under **Not looked up** —
never as clean, which is the same rule the refused-read handling follows
everywhere else in the tool.

Two orderings make a truncated run useful. The namespace goes before the
origins, because a hostname the account does not know about is the finding this
command exists for. Within the origins, exposed addresses go first: a budget
that runs out should run out on the addresses the proxy already hides.

### Seeing the cost first

```bash
mlab-cloudflare enrich plan
mlab-cloudflare enrich --dry-run
```

`plan` lists every target, which quota it comes out of, and whether it is
already held. It sends nothing.

```
  What a full run would look up

  TARGET           QUOTA   STATE
  example.com      domain  held
  example.net      domain  would be looked up
  example.org      domain  would be looked up
  198.18.0.9       ip      would be looked up
  198.18.12.4      ip      would be looked up

  5 targets

  › 2 domain lookups to spend
  › 2 ip lookups to spend
  › results are held for 7 days, which is how long mlab keeps its own
```

`--dry-run` goes further: it runs the real report on whatever is held and lists
everything else as not looked up. It is the honest way to see what a week-old
cache still covers.

## `enrich zones`

One domain lookup per zone. What the world resolves for the name, what
certificates exist for it in the public logs, and what its live mail policy is.

```
  Namespace, as the internet sees it

  high    shadow               2 hostnames resolve and the Cloudflare zone holds no record for them
                               assets.example.com, legacy.example.com
  medium  shadow               7 hostnames are known publicly and have no record in the Cloudflare zone
                               beta.example.com, demo.example.com, staging.example.com, …
  medium  live mail            1 live DMARC policy is p=none, which reports and rejects nothing
                               example.com
  low     shadow               2 public hostnames name an internal environment
                               db.example.com ("db"), prod.example.com ("prod")
  info    public certificates  4 certificate authorities have issued for these names
                               …
```

### Shadow names

A hostname that answers from outside and has no record in the Cloudflare zone is
served by a nameserver, a delegation, or a wildcard **this account does not
control**. Nothing in the account will ever mention it, which is exactly why the
Cloudflare API cannot find it.

Three grades, by how strong the evidence is:

| Grade | Evidence |
| --- | --- |
| **High** | The scan resolved it. The name answers today and the zone has no record for it. |
| **Medium** | The name is known publicly — passive DNS, or a certificate in a transparency log — and the zone has no record for it. |
| **Low** | A public hostname names an internal environment (`prod`, `db`, `staging`). Not a defect on its own; it tells an attacker where to look. |

Each name is reported once, under the strongest evidence there is for it.

> **What this check deliberately does not say.** A scan's `resolve` list covers
> the names it got answers for, and it is not exhaustive over the names it
> discovered — on a real zone, two hostnames that plainly answer were missing
> from it. So absence from that list means *not shown to resolve*, never *does
> not resolve*, and no finding here claims a name is dead. An earlier version
> did, and reported fifteen live hostnames as resolving to nothing.

Wildcard certificates are judged as the name they wrap: `*.staging.example.com`
is evidence about `staging.example.com`. Cloudflare's own universal
certificates, issued under a hashed `*.sni.cloudflaressl.com` name, are
Cloudflare's rather than the zone's and are skipped.

### Drift

A hostname whose public answer is **not** in Cloudflare's address space is
answering from the origin directly. Whatever the zone's rules say, they are not
in the path for that name.

### Live mail

The DNS plane reports a zone with no SPF or no DMARC. This check answers a
question that plane cannot: whether what is *in the zone* is what the world
actually gets.

| In the zone | Live | Meaning |
| --- | --- | --- |
| yes | no | The record enforces nothing. Something else is answering for the name. |
| no | yes | The same conclusion from the other direction, and the more alarming of the two: a policy is being served that this account did not publish. |

Then two facts about the live policy itself: a DMARC of `p=none` reports and
rejects nothing, and an SPF containing `+all` or `?all` authorises every sender
on the internet.

### Public certificates

The `tls` command reads what Cloudflare issued. This reads what **any** CA
issued for these names, which is the only way to see a certificate somebody
obtained outside the account. The issuer list is the finding: an authority
nobody recognises is the signal.

> The report deliberately does not say "authorities other than Cloudflare".
> Cloudflare's own universal certificates are issued by Google Trust Services
> and Let's Encrypt, so an issuer string cannot tell a Cloudflare certificate
> from one somebody obtained independently, and a claim the data cannot support
> does not belong in an audit.

Expiry is judged on the **newest** certificate for each name only. A
transparency log holds every certificate ever issued, so counting all of them
reported six imminent expiries on a zone whose live certificates were all months
away. `--expiring-within` sets the window, default 30 days.

## `enrich origins`

One address lookup per published address. Cloudflare will tell you an origin is
`198.18.0.9`; it will not tell you that the address is a residential line, a
mobile network, a Tor exit, or a block with no abuse contact — and each of those
changes what an exposed origin costs.

```
  Origins, as the internet sees them

  high    origins  1 exposed origin sits on a consumer connection rather than in a datacenter
                   direct.example.com → 198.18.0.9 (An ISP)
  low     origins  1 origin address has a reverse name that does not resolve back
                   mail.example.com → 198.18.12.4 (host.isp.example)
  info    origins  origins sit in 2 countries
                   France: …; Canada: …
```

| Check | Grade | Why it matters |
| --- | --- | --- |
| Consumer connection | High | Not a datacenter: the origin is somebody's home or office line, and the address is the household's too. |
| Mobile network | High | The origin address is not stable and is shared with a carrier's subscribers. |
| Tor exit node | High | Traffic to the address is attributable to anyone. |
| Behind a VPN or proxy | Medium | The origin's real location is not where the address says, and the provider is in the path. |
| Reserved space | Medium | A published record points somewhere that resolves for nobody. |
| Peer-to-peer observations | Low | Activity is attributed to the address; it is shared or residential, and its abuse contact will hear about it. |
| Reverse name that does not resolve back | Low | Forward-confirmed reverse DNS is what receiving mail servers check. |
| No reverse name | Info | — |
| No abuse contact in the block | Info | Nobody to report to when the address is the problem. |
| More than one country | Info | Not a defect; the first question a data-residency review asks. |

**What counts as exposed.** An address is an exposed origin when Cloudflare
proxies for it *and* a record publishes a route around the proxy. An address
Cloudflare never fronts for is just an address — a mail server, a stray host —
and calling it an exposed origin would flag every unproxied record in the
account. The network checks in the table above apply only to exposed addresses,
because an origin the proxy genuinely hides is not exposed by the network it
sits on. Tor, reserved space and reputation are facts about the address itself,
so they are judged on every published address.

Addresses that would teach nothing are never looked up, because each would spend
a unit of a daily quota: documentation space (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), the IPv6 discard prefix (`100::/64`), and private, loopback,
link-local and carrier-grade NAT ranges. One address serving four names is one
lookup, not four, merged across zones.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--budget N` | `20` | Most lookups this run may spend. |
| `--dry-run` | off | Report on held results only; look nothing up. |
| `--refresh` | off | Look targets up again even when a held result would do. |
| `--expiring-within DAYS` | `30` | Certificate expiry window. |
| `--mlab-key KEY` | — | Prefer `MLAB_API_KEY`; a command line is visible to other users. |
| `-z, --zone` | — | Narrow to one zone, as everywhere else. |

## Exit codes

`enrich` reports; it does not judge. It exits `0` unless something went wrong.
To gate on these findings, use `audit --enrich --fail-on high`.

## See also

- [dns](Dns) — the same namespace from the inside
- [tls](Tls) — the certificates this account issued
- [audit](Audit) — `--enrich` folds these findings in, without spending quota
- [cache](Cache) — where the results are held, and how to keep them
