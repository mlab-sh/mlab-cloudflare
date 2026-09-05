# `mlab-cloudflare api`

Raw request against any endpoint, for everything the CLI does not wrap.

```bash
mlab-cloudflare api GET /user/tokens --list
mlab-cloudflare api GET '/accounts/{account}/members' --list
mlab-cloudflare api GET '/zones/{zone}/settings'
mlab-cloudflare api GET '/accounts/{account}/logs/audit' --list --cursor --limit 50
mlab-cloudflare api GET '/accounts/{account}/cfd_tunnel' --list --redact
```

The v4 API publishes some 1,700 readable operations and this CLI will never
wrap them all, so this command is a permanent part of the surface rather than a
stopgap. It is also the lab bench: try an endpoint here, and once it earns its
place it gets a module of its own.

| Flag | Meaning |
| --- | --- |
| `-d, --data JSON` | Request body: inline, `@file`, or `-` for stdin |
| `-q, --query K=V` | Extra query parameter, repeatable |
| `--list` | Treat the response as a collection and walk every page |
| `--cursor` | With `--list`, page by cursor instead of page number |
| `--limit N` | With `--list`, one page of that size instead of everything |
| `--raw` | Print the whole envelope, not just `result` |
| `--redact` | Replace every credential in the response with its length |

## Placeholders

`{account}` and `{zone}` are replaced by the resolved ids, so you do not paste
them. Resolution is lazy — a path naming neither does not pay for a lookup,
which matters because a narrowly scoped token cannot do one.

```bash
mlab-cloudflare api GET '/zones/{zone}/dns_records' --list -z example.com
```

Both accept a name or an id. See [Configuration](Configuration) for where the
defaults come from.

## Paging

Most of the API does not paginate and returns the whole collection; the rest
uses `page`/`per_page` and reports `result_info.total_pages`; a handful of
endpoints — the audit logs, the newer log surfaces — use a cursor.

`--list` handles the first two. Add `--cursor` for the third:

```bash
mlab-cloudflare api GET '/accounts/{account}/logs/audit' --list --cursor \
  -q 'since=2026-08-01T00:00:00Z' -q 'action_result=false'
```

Without `--list` the response is printed as-is, which is what you want for the
many endpoints that return a single object:

```bash
mlab-cloudflare api GET '/zones/{zone}/settings/ssl'
```

## `--raw`

By default only the `result` field is printed. `--raw` keeps the whole
envelope, which is what you want when you care about `result_info`, or about
the `messages` array that some endpoints use to warn without failing:

```json
{
  "errors": [],
  "messages": [],
  "result": [ … ],
  "result_info": { "count": 20, "page": 1, "per_page": 20, "total_count": 47, "total_pages": 3 },
  "success": true
}
```

## `--redact`

Several readable endpoints hand back a live credential: a Cloudflare Tunnel's
connector token, a Turnstile widget's server-side secret, an Access identity
provider's OIDC client secret, a secondary DNS TSIG key. `--redact` replaces
each value with its length before anything is printed:

```
  › redacted 1 credential(s)

  id     c3d4e5f60708192a3b4c5d6e7f809a1b
  token  <redacted:180>
```

A length is not a secret and it is what a strength check needs, so the output
stays useful. This is what makes a response safe to paste into a ticket. See
[Secrets](Secrets).

## Anything but GET

The method is a positional argument and nothing stops you passing `POST`. This
tool is built for reading, its documentation promises reading, and a token made
from the **Read all resources** template will refuse a write anyway — but the
escape hatch is honest about being one.

## See also

- [Audit surface](Audit-Surface) — which of the 1,700 endpoints are worth asking
- [Errors](Errors) — what a refusal means
- [Output](Output) — `--list` renders a table, `-o json` does not
