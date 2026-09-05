# `mlab-cloudflare accounts`

Every account this credential reaches.

```bash
mlab-cloudflare accounts
mlab-cloudflare accounts --limit 10
```

```
  Accounts

  NAME       ID                                TYPE      2FA REQUIRED  CREATED
  acme-corp  a1b2c3d4e5f60718293a4b5c6d7e8f90  standard  true          2021-03-04T18:22:09Z
  acme-labs  b2c3d4e5f60718293a4b5c6d7e8f90a1  standard  false         2024-11-19T09:41:55Z

  2 accounts

  ! two-factor authentication is not enforced on: acme-labs
```

`--limit N` takes a single page of that size instead of walking every page.

This is the one command that deliberately looks across accounts, because it is
how you decide which one to scan. Everything else works inside a single account
— see [Zones](Zones).

Once you know which one you want, save it so nothing asks again:

```bash
mlab-cloudflare login --account acme-corp
```

## The two-factor line

`settings.enforce_twofactor` is the account-wide switch that decides whether
every member must carry a second factor. It comes back on this listing, so
saying it costs no extra request.

It is only half a finding on its own — the other half is which members
currently have one, which is `/accounts/{id}/members` and belongs to the
identity audit rather than here.

## Narrowly scoped credentials

A credential scoped to one account's resources — an R2 token, most
account-owned tokens — cannot list accounts. When the profile names one, the
command reads that account directly rather than reporting nothing found:

```
  › this credential cannot list accounts; reading the configured one
```

If that read is refused too, the original listing error is what you get, since
it is the one that explains what the credential is missing.

## See also

- [Zones](Zones) — the other half of the inventory
- [Audit surface](Audit-Surface) — what else the account plane holds
