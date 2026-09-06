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
| `dns` (19 zones) | 15.8 s | 0.18 s |
| `dns mail` after it | 5.8 s | 0.16 s |
| `identity` | 4.1 s | 0.7 s |

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

**Failures are never cached.** A `403` may be a permission that gets granted an
hour later. Caching it would make "not readable" sticky, and an audit would keep
reporting an area as unread after it became readable.

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
