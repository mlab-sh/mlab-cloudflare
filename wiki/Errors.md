# Errors

What a failure means, and what the tool does about it before you see one.

## The envelope

Every v4 response carries the same shape:

```json
{
  "success": true,
  "errors": [],
  "messages": [],
  "result": …,
  "result_info": { "page": 1, "per_page": 20, "total_count": 47, "total_pages": 3 }
}
```

**A refusal can arrive with HTTP 200 and `success: false`.** Checking the
status code alone would let it through as an empty collection, which reports as
"nothing configured" — the wrong finding, silently. The tool checks the
envelope too, and reports that case as a refusal rather than as `API error
200`:

```
  ✖ API refused the request [7003]: Could not route to /zones/…, perhaps your object identifier is invalid?
```

Several errors often arrive together, one per scope the credential could not
reach, and the first one is rarely the informative one. All of them are printed.

## The three meanings of 403

This is the ambiguity that shapes the whole tool:

| What happened | What you see |
| --- | --- |
| Your token lacks the permission | `403` |
| Your plan does not include the product | `403` or `404` |
| The thing genuinely is not configured | `403`, `404`, or an empty result |

They are opposite findings and they look the same. Two things resolve it:

- [`whoami`](Whoami) tells you what the credential was granted, so a refusal
  can be attributed to the token rather than to the configuration.
- `/accounts/{id}/subscriptions` and `/zones/{id}` `plan.name` tell you what
  the account is entitled to, so "Page Shield is not configured" does not get
  reported for an account that does not have Page Shield.

Anything the tool could not read will be reported as **unread**, never as
passed. A check that silently degrades into a clean bill of health is worse
than no check.

## Rate limiting

**1,200 requests per five minutes, per credential** — shared with wrangler,
Terraform, and every CI job using the same token. An audit that walks hundreds
of endpoints across every zone hits this in normal operation, so it is handled
rather than reported:

```
  › GET /zones: 429, retrying in 12s
```

A `429` or a `5xx` is retried up to three times, waiting for the `Retry-After`
header when there is one and backing off otherwise. A `401`, `403` or `404` is
not retried — a missing permission will still be missing in a second.

## Hints

Errors that have one obvious cause carry it:

```
✖ API error 401 [1000]: Invalid API Token
hint: the credential was rejected; check it with `mlab-cloudflare whoami`
```

```
✖ API error 429 […]
hint: 1200 requests per five minutes are allowed per credential, shared with every
other tool using it
```

A `1000 Invalid API Token` on a token you just pasted is very often the
[two token stores](Tokens) rather than a bad paste, and the tool asks both
before it concludes anything.

## Redirects are not followed

The credential rides in a default header, which the HTTP client would replay on
a cross-host redirect. Rather than risk that, a redirect is an error:

```
✖ GET https://api.cloudflare.com/client/v4/… redirected to https://elsewhere/;
not following it, the credential would leak to the new host
```

## Response size

Bodies over 64 MB are refused rather than buffered. An HTML error page from the
edge is reduced to one line with the markup and stylesheets stripped, so a
`503` reads as a status rather than as a screenful.
