# `mlab-cloudflare ping`

Check that the current profile reaches the API, and report what answered.

```bash
mlab-cloudflare ping
mlab-cloudflare -p staging ping
```

```
  ✔ answered in 118ms

  profile   prod (token)
  endpoint  https://api.cloudflare.com/client/v4
  identity  token f0e1d2c3b4a5968778695a4b3c2d1e0f (account-owned)
  status    active
  account   1a2b3c4d5e6f708192a3b4c5d6e7f809
  zone
```

It calls the one endpoint every credential of its kind can reach whatever it is
scoped to: `/user/tokens/verify` (or the account store's equivalent) for a
token, `/user` for a Global API Key. So a failure here is about the credential,
never about the scope.

This is the command to run first when something else misbehaves: it separates a
network problem from a credential problem, and it names which [token
store](Tokens) answered — which is the usual surprise.

## JSON

```bash
mlab-cloudflare ping -o json
```

```json
{
  "account": "1a2b3c4d5e6f708192a3b4c5d6e7f809",
  "auth": "token",
  "elapsed": "118ms",
  "endpoint": "https://api.cloudflare.com/client/v4",
  "identity": "f0e1d2c3b4a5968778695a4b3c2d1e0f",
  "profile": "prod",
  "status": "active",
  "tokenStore": "account",
  "zone": ""
}
```

Suitable for a health check: exit code 0 and a parsable body, or exit code 1 and
a message on stderr.

## See also

- [Whoami](Whoami) — the same question, answered in far more detail
