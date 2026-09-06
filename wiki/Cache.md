# Cache

Configuration reads are cached on disk. The point is the rate ceiling.

## Why

**1,200 requests per five minutes, per credential**, shared with wrangler,
Terraform and every CI job using the same token. A DNS sweep over twenty zones
is around sixty calls, and running `dns`, then `dns mail`, then `dns takeover`
in one sitting fetches the same records three times over.

Configuration does not change between those, so it is read once:

| Command | Cold | Warm |
| --- | --- | --- |
| `dns` (19 zones) | 16.6 s | 0.2 s |
| `posture` | 17.3 s | 0.2 s |
| `tls` | 16.0 s | 0.2 s |
| `identity` | 3.7 s | 0.2 s |

The four together are 54 seconds cold and under a second warm — and the second
of those four is already cheaper than the first, because the planes share reads:
`tls` needs the DNS records and the settings blob that `dns` and `posture`
already fetched, so it makes 134 new calls rather than 190.

## What is cached, and what never is

Two rules decide, and both are about not lying.

**Only configuration, never liveness.** [`ping`](Ping) and [`whoami`](Whoami)
exist to say whether a credential works *now*; a cached answer would have them
report a revoked token as active. Their verification call is never cached, and
neither is [`activity`](Activity), where staleness is the bug rather than the
saving. That is why `whoami` stays around half a second warm and `identity`
around 0.7 — the residue is the calls that are deliberately live.

**Keyed by credential.** Two profiles with different scopes get different
answers to the same request, so the credential is part of the key. It is hashed
rather than stored, and a rotated token therefore misses on everything it used
to hold, which is correct.

**Refusals are remembered, most of them.** This one changed after measuring.
Before it, the second run of `posture` cost the same as the first: about 90 of
its reads are refusals — a free zone answering `404` on the managed-ruleset
phase, `custom_certificates` answering `400` below Business — and re-asking
them was the entire warm cost.

Those are facts about a plan or a token, not about a moment. A free zone will
still answer `404` in a second. So a `4xx` is stored and replayed with its own
status and message, and it ages out on the same TTL as everything else: an area
reads as unread for at most fifteen minutes after a permission is granted, which
is the same staleness the rest of the report already has.

Two are never stored, because they are entirely about the moment: a `429`, and
any `5xx`. A transport failure is not stored either — it says nothing about the
request.

`cache status` marks the remembered refusals, so you can see how much of the
cache is "this is not available here":

```
  › 409 usable at a 900s TTL, 110 of them remembered refusals, 271.7 kB on disk
```

## Flags

```bash
mlab-cloudflare dns --no-cache      # read nothing from it; still refresh it
mlab-cloudflare dns --cache-ttl 60  # entries older than a minute are stale
mlab-cloudflare dns --cache-ttl 0   # no cache at all, nothing stored
```

`--no-cache` still **writes**, so a forced-fresh run leaves the cache current
for the next command instead of leaving it to fetch everything again. When you
want neither, `--cache-ttl 0` is the switch: nothing is young enough to serve,
so nothing is stored.

The TTL is compared at read time, not at write time, so lowering it re-ages what
is already held rather than requiring a clear.

## What is cached

| Read | Cached |
| --- | --- |
| Zones, accounts, DNS records, DNSSEC, holds | yes |
| Zone settings, ruleset phases, page rules, Spectrum, routes, snippets | yes |
| Certificates, origin pulls, custom hostnames, client certificates | yes |
| Members, roles, SSO, SCIM, IAM groups, OAuth clients, tokens | yes |
| A token's own policies (`whoami`) | yes |
| **Token verification** (`ping`, `whoami`) | never — liveness |
| **`/user`** under key auth | never — liveness |
| **The audit log** (`activity`) | never — see below |
| **`api`** | only with `--cache` |

`activity` is not cached for two reasons that point the same way: it is the
command you run to see what just happened, so a stale answer is the bug rather
than the saving — and its `since` is derived from the clock, so every run would
key differently and store an entry nothing ever reads.

`api` takes `--cache` rather than caching by default. It is the bench you probe
an endpoint from, and a stale answer there is far more confusing than a slow one.
Only a plain `GET` with no body is eligible.

## The `cache` command

```bash
mlab-cloudflare cache status
mlab-cloudflare cache clear
mlab-cloudflare cache path
```

```
  /Users/you/.mlab/cache/cloudflare

  REQUEST                                        AGE    STATE   KB
  LIST /zones account.id=a1b2c3d4e5f6071829…     12s    usable  14
  LIST /zones/1a2b3c4d…/dns_records              12s    usable  31
  GET /zones/1a2b3c4d…/dnssec                    12s    usable  1

  3 entries

  › 3 usable at a 900s TTL, 46.0 kB on disk
```

`cache path` prints nothing but the path, so it composes:

```bash
du -sh "$(mlab-cloudflare cache path)"
```

## Where, and what is in it

`$HOME/.mlab/cache/cloudflare`, overridable with `MLAB_CLOUDFLARE_CACHE`.

Entries hold **whatever the API returned**, and some readable endpoints return a
live credential — a Cloudflare Tunnel's connector token, a Turnstile widget's
secret. So the directory is created 0700 and the files 0600, exactly like the
credential store, and `cache clear` empties it. See [Secrets](Secrets).

Each entry records what was asked for so `cache status` can say what is held.
Account and zone ids are not secrets; the values under them may be, which is
what the mode is for.

## When it goes wrong

Every cache failure is a miss rather than an error: a corrupt entry, an
unreadable file, a clock that moved backwards. A cache that can break a command
is worse than no cache.

If you suspect it is serving something stale that it should not be, `--no-cache`
answers the question in one run without touching what is stored.

## See also

- [Errors](Errors) — the rate ceiling this exists for
- [Secrets](Secrets) — what can end up in an entry

## The mlab results

[`enrich`](Enrich) holds its results somewhere else: `$HOME/.mlab/cache/cloudflare/mlab/`.

They are not the same kind of thing as a Cloudflare response. A Cloudflare
response can be fetched again for nothing; an mlab result costs a unit of a
daily quota. Sharing one directory would mean `cache clear` throwing away a week
of paid lookups to refresh fifteen minutes of free ones.

So they are held for seven days rather than fifteen minutes, `cache status`
counts them separately, and `cache clear` keeps them and says so:

```
  ✓ removed 61 cached responses
  › kept 12 mlab results — they cost quota to fetch again; --all removes them too
```

`cache clear --all` removes both. `--no-cache` does not apply to them at all;
`enrich --refresh` is the deliberate way to look something up again.
