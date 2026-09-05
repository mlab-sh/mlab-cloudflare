# `mlab-cloudflare login`

Create or update a profile, prove the credential works, and save it.

```bash
mlab-cloudflare login
mlab-cloudflare login --account 1a2b3c4d5e6f708192a3b4c5d6e7f809
mlab-cloudflare login -n staging --set-default
```

| Flag | Meaning |
| --- | --- |
| `-n, --name NAME` | Profile to create or update (default: `default`) |
| `--set-default` | Make this the default profile |
| `--no-test` | Save without checking that the credential works |
| `--non-interactive` | Never prompt; fail when something is missing |

Everything else comes from the [global flags](Configuration): `--auth`,
`--token`, `--email`, `--api-key`, `--account`, `--zone`.

## What it does

1. Works out the credential kind — from `--auth`, from the environment, from the
   profile being updated, or by asking.
2. Reads the credential without echoing it.
3. Verifies it, which for a token means finding out **which token store holds
   it** (see [Tokens](Tokens)).
4. Settles the default account.
5. Writes the file 0600 in a 0700 directory, and prints the profile with the
   credential masked.

```
  auth (token|key) [token]:
  API token (dash.cloudflare.com -> My Profile -> API Tokens):
  ✔ token is active, in the user token store
  › expires on 2027-01-31T23:59:59Z
  › account a1b2c3d4e5f60718293a4b5c6d7e8f90
  ✔ saved profile "default" to /Users/you/.mlab/cloudflare.conf

  account  a1b2c3d4e5f60718293a4b5c6d7e8f90
  auth     token
  owner    user
  token    ****WXYZ
```

## Account-owned tokens

A token created under **Manage Account → Account API tokens** can only be
verified against its own account, and `login` does not have the id yet. So it
asks for it rather than failing:

```
  API token (dash.cloudflare.com -> My Profile -> API Tokens):
  ! this token is not in your user token store
  › tokens made under Manage Account -> Account API tokens belong to the account, and verify against it
  account id (32 hex, from the dashboard URL dash.cloudflare.com/<id>):
```

Pass `--account` up front and it never asks. In `--non-interactive` mode it
cannot ask, so it explains instead:

```
✖ the token is not in your user token store, and there is no account to check the other one against.
Tokens created under Manage Account -> Account API tokens belong to the account rather than to you —
that page is also where the R2 credentials now come from — and they can only be verified against
their own account.
Re-run with --account <ACCOUNT ID>: the 32-character id in the dashboard URL,
dash.cloudflare.com/<id>, or on the right of the account home page.
```

Once verified this way the account is already proved, so `login` does not go on
to list accounts — which a narrowly scoped token could not do anyway.

## Choosing an account

With one account in scope, it is taken and reported. With several, they are
listed and you pick:

```
    [1] mlab (a1b2c3d4e5f60718293a4b5c6d7e8f90)
    [2] acme-labs (b2c3d4e5f60718293a4b5c6d7e8f90a1)

  account number [1]:
```

With `--account NAME` it is matched by name or id without asking. In
`--non-interactive` mode with several accounts, it stops and tells you to pass
one.

A credential that cannot list accounts at all — which is normal and fine for a
zone-scoped or R2 token — leaves the account unset with a warning rather than
failing.

## Notes it will give you

`login` says the things about a credential that are worth knowing on day one
rather than on incident day:

```
  ! this token has no expiry date
  › account-owned tokens are not tied to a person and outlive their creator's membership
  ! a Global API Key carries every permission its user has, on every account they can
    reach, and cannot be scoped or expired; a read-only API token is the safer credential
    for an audit
```

## Updating a profile

Running `login` again with the same `-n` keeps what you do not change,
including the credential:

```
  › keeping the stored API token (****WXYZ)
```

Which makes it the way to change the default account or zone on an existing
profile without re-pasting anything.

## See also

- [Tokens](Tokens) — the two stores, and which token to make
- [Whoami](Whoami) — what the credential can actually do
- [Configuration](Configuration) — where all of this ends up
