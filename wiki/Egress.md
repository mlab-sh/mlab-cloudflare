# `mlab-cloudflare egress` and `alerts`

Where the request data goes, and whether anyone is told when something breaks.

```bash
mlab-cloudflare egress
mlab-cloudflare egress jobs
mlab-cloudflare egress retention

mlab-cloudflare alerts
mlab-cloudflare alerts coverage
mlab-cloudflare alerts policies
mlab-cloudflare alerts destinations
```

Two questions in one plane, and they fail in opposite ways. Logpush is
configured once and then invisible. Notification policies are opt-in per alert
type, so the default state is silence.

## Where the data goes

- **Jobs shipping headers, cookies or client addresses** to an external
  destination. The field list is the finding: a job carrying `RayID` and
  `EdgeResponseStatus` is telemetry, one carrying `ClientRequestCookies` is
  personal data leaving the account.
- **Disabled jobs** — the logs everyone assumes exist are not being written.
- **Failing jobs**, with the error the API reports.
- Every destination, listed. A job configured two years ago may point at a
  vendor whose contract has ended.
- **Raw log retention off**, per zone. This one is worth stating precisely: it
  decides whether a question asked next month has an answer, and switching it
  on today does not answer one asked about today.

Destinations are shown as **scheme and host only**. The rest of the string
carries an access key for some backends, and an audit report is a document
people paste into tickets.

Account-level and zone-level Logpush are separate stores. It is easy to have
logs configured at one level and to assume the other, so both are read and each
job is tagged with its scope.

## Whether anyone is told

`alerts coverage` lists every alert type the account can receive and whether
anything listens. The graded report does not print that list — 55 of 57 types
having no policy is a number nobody acts on. It prints the **question nobody
answers**:

```
  medium  alerts  nothing tells anyone when 3 of these happen
                  a certificate expires or stops renewing
                  a Logpush job is disabled for failing, and the logs quietly stop
                  an Access service token is about to expire
  low     alerts  nothing tells anyone when 3 of these happen
                  a route to these prefixes is leaked or hijacked; the site is under a layer 7 attack
                  Page Shield sees a malicious script or domain
```

Each group covers several alert types and fires only when the account can
receive at least one of them and subscribes to none. **One subscription covers
its whole group** — the question is answered whichever type answers it. A
disabled policy does not count.

The catalogue comes from `available_alerts`, which already reflects the plan, so
a type the account cannot receive is a price list rather than a missing policy.

Also checked:

- Policies that exist but are **disabled**.
- **Webhooks failing more recently than they succeeded** — every policy pointing
  at one is silent, and looks identical to a working one from the dashboard.
- **Silences**, which are created to stop noise during an incident and are
  meant to be temporary.
- No notification policy at all.

## An empty report is not a clean one

This is the plane most likely to be entirely unreadable: Logpush and log control
each need their own permission, and a token made from the *Read all resources*
template does not carry them.

So `egress` prints what it could not read, last and never omitted:

```
  Not read

  ENDPOINT                                       WHY
  /accounts/{id}/logpush/jobs                    API error 403 [10000]: Authentication error
  /zones/{id}/logpush/jobs (19 zones)            API error 403 [10000]: Authentication error
  /zones/{id}/logs/control/retention/flag (19…)  API error 401 [10000]: Unauthorized

  ! 4 reads were refused; this plane is unaudited, not clean
```

Nineteen identical refusals are one fact, not nineteen, so they are collapsed
with the count.

## See also

- [Errors](Errors) — why a `403` has three meanings
- [Identity](Identity) — which permissions the credential is missing
