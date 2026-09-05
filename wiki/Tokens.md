# Tokens

Everything else in this tool rests on what you are holding, so it is worth
twenty lines.

## Three kinds of credential

Cloudflare will accept three things on the v4 API. Only two of them are worth
using, and only one is worth using for an audit.

| Credential | Header | Scopable | Expirable | Revocable alone |
| --- | --- | --- | --- | --- |
| **API token** | `Authorization: Bearer <token>` | yes | yes | yes |
| **Global API Key** | `X-Auth-Email` + `X-Auth-Key` | no | no | no |
| Origin CA key | `X-Auth-User-Service-Key` | n/a | no | — |

The Global API Key carries **every permission its user has, on every account
they can reach**. It cannot be narrowed, it cannot be given an expiry, and
rotating it breaks every other integration that shares it — which, on an
account of any age, is usually several. The tool supports it, warns about it
every time it prints a profile, and would rather you did not.

The Origin CA key is for issuing origin certificates and is not used here.

## The two token stores

This is the part that surprises people, and the reason a perfectly good token
can come back `1000 Invalid API Token`.

Cloudflare keeps tokens in **two separate namespaces that cannot see each
other**:

| Created at | Belongs to | Verified at |
| --- | --- | --- |
| My Profile → API Tokens | you | `/user/tokens/verify` |
| **Manage Account → Account API tokens** | **the account** | **`/accounts/{id}/tokens/verify`** |

Asking the store that does not hold your token answers `401` with code `1000
Invalid API Token` — the exact same response a mistyped credential gets. So a
rejection is not evidence of a bad token until both stores have been asked, and
that is what the tool does.

Two consequences worth carrying:

- **An account-owned token needs its account id to be verified at all.** Its
  store is addressed by account. `login` asks you for the id when it needs one;
  in a script, pass `--account`.
- **An account-owned token is not tied to a person.** Removing its creator from
  the account does not revoke it. That is exactly what you want for a CI
  pipeline and exactly what gets missed during an offboarding, which is why
  [`whoami`](Whoami) says so out loud.

The Account API tokens page is also where the R2 S3-compatible credentials are
handed out now, so an R2 token is an account-owned token.

`login` tries both stores, records which one answered in the profile as
`owner`, and later runs go straight to it.

## Making the right token

For an audit you want the **Read all resources** template, at
`dash.cloudflare.com/profile/api-tokens`. It is the closest fit to what this
tool does, and it grants no writes.

Two things that template does not give you, and that you may want to add:

- **An expiry.** Tokens default to none. An audit token should outlive the
  audit and not much more.
- **A source-IP condition.** `Client IP Address Filtering` restricts where the
  token may be used from. `whoami` prints it, and prints `none` when there
  isn't one.

Two things it does not cover at all: Zero Trust seat data, and billing.

## Reading a scope

Token policies name their scope as URNs, and the shape matters:

```
com.cloudflare.api.account.zone.1a2b3c4d5e6f708192a3b4c5d6e7f809   one zone
com.cloudflare.api.account.a1b2c3d4e5f60718293a4b5c6d7e8f90        one account
```

But when the value of an account URN is itself a map:

```json
{ "com.cloudflare.api.account.a1b2c3d4e5f60718293a4b5c6d7e8f90": {
    "com.cloudflare.api.account.zone.*": "*" } }
```

that is not "these zones" — it is **every zone the account will ever hold**,
including ones added after the token was made. `whoami` renders the two
differently for that reason:

```
  allow  zone 1a2b3c4d5e6f708192a3b4c5d6e7f809   Zone Read
  allow  all zone in account f037e56e…           Zone Read, DNS Read
```

## Read or write

Cloudflare names permission groups consistently: everything readable ends in
`Read`. Any granted group that does not — `DNS Write`, `Zone Settings Write`,
`Workers Scripts Write` — is write access, whatever the token is named.

`whoami` applies exactly that rule and says so:

```
  ✔ read-only: every granted permission group is a read
```

or

```
  ! this token can write: DNS Write, Workers Scripts Write
```

It can only do this when the token may read its own policies, which needs the
`API Tokens Read` permission — and a well-scoped audit token deliberately does
not have it. When that read is refused, `whoami` says so rather than reporting
a token as read-only on no evidence.

## See also

- [Whoami](Whoami) — the command that reports all of the above
- [Configuration](Configuration) — where the credential is stored
- [Secrets](Secrets) — the credentials the API hands *back*
