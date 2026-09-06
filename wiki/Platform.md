# `mlab-cloudflare platform`

What developers provisioned, and what it is reachable on.

```bash
mlab-cloudflare platform
mlab-cloudflare platform workers
mlab-cloudflare platform storage
mlab-cloudflare platform pages
```

The newest surface on an account and the least reviewed: a Worker, a bucket and
a Pages project are created with a wrangler config and no change ticket. The
API reads all of it — the bindings each script holds, whether a bucket is served
anonymously, what a preview deployment is wired to.

## The finding almost nobody checks

A Worker meant to serve a zone route is **also** answering at
`<script>.<subdomain>.workers.dev` unless that is switched off per script.
Traffic arriving there never touches the zone, so every custom rule, rate limit,
bot policy and Access application configured on the domain is absent — while the
script's bindings to production data are identical.

```
  high  workers  1 script serves a zone route and is also answering on workers.dev,
                 where no rule of that zone applies and the bindings are the same
                 uploader.acme.workers.dev — FILE_QUEUE (queue), MY_BUCKET (r2_bucket)
```

The detail names the bindings on purpose: the point is not that a second
hostname exists, it is that the unprotected door reaches the same data.

Telling the two cases apart needs the zone routes, so this command reads them —
one cached call per zone, usually already warm from [`posture`](Posture):

- **On a route and on workers.dev** — two doors to the same code, one behind the
  zone's rules and one not. **High.**
- **Only on workers.dev** — nothing was routed away from; that hostname is
  simply where it lives. Still worth saying, since no zone rule protects it.
  **Medium.**
- **Not published** — not reported at all.

A script whose subdomain state could not be read stays out of the finding rather
than being counted as safe.

## What else it checks

### Workers

- Preview URLs enabled, which publishes every version on a second workers.dev
  hostname.
- Scripts with neither observability nor logpush, so nothing records what they
  did.
- The **binding list as a privilege inventory**: KV, R2, D1, queues, Durable
  Objects, Hyperdrive, secrets and service bindings. That list says what each
  piece of edge code can reach, which no review of a single repository can.

### Storage

- **R2 buckets served anonymously on `r2.dev`** — one toggle, frequently
  switched on to unblock a frontend, and it publishes the whole bucket to
  anyone with the hostname. **High.**
- Buckets on a custom domain, as context.
- **Hyperdrive configs**, which name a database outside Cloudflare — one of the
  few places this API describes infrastructure that is not Cloudflare's.
- **Stores nothing reaches.** Every binding names the store it uses, so the
  ones nobody names fall out by subtraction: an unmaintained copy of something,
  and a cost line.

  Two exclusions keep that honest. A bucket published on a domain is reached
  over HTTP rather than through a binding, so no binding is the design. And a
  queue answers the question itself — it lists its own producers and consumers,
  and a dead-letter queue is named by the consumer that spills into it rather
  than bound by anyone.

### Pages

- **A preview configuration holding the same bindings as production**, while
  every branch publishes a reachable `*.pages.dev` URL that no Access policy
  covers. **High.**
- Every project's public `pages.dev` hostname.
- Projects that build on push, so a branch becomes a published URL without
  review.

### Turnstile and AI Gateway

- An AI Gateway **without authentication** is an open proxy to the model
  credentials behind it, billed to this account. **High.**
- A gateway retaining prompts and completions.
- A Turnstile widget bound to a **wildcard or empty domain**, which can be
  embedded anywhere under it and solved against this account's key.

## Cost

This is the first plane whose cost scales with something other than zones: two
reads per Worker script and two per bucket, plus eleven account-level reads and
one route listing per zone.

Forty scripts and ten buckets is about 130 calls. They run six at a time — one
at a time was a minute of round trips — which brings a cold run to roughly 26
seconds and a warm one to under half of one. See [Cache](Cache).

## Not read here

**Worker source.** It is available, and it is greppable for hardcoded keys and
permissive CORS. It is not read because that is a code review rather than a
configuration check, it doubles the data the cache holds, and a regex over
JavaScript produces findings nobody can act on. `api GET
'/accounts/{account}/workers/scripts/NAME'` returns it when you want it.

## See also

- [Posture](Posture) — the zone rules that workers.dev goes around
- [Audit surface](Audit-Surface) — the rest of the platform plane
