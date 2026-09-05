# `mlab-cloudflare whoami`

What this credential is, and exactly what it may do.

```bash
mlab-cloudflare whoami
mlab-cloudflare whoami -o json
```

**Run this first.** Cloudflare answers `403` both for "this is not configured"
and for "you may not look", and those are opposite findings. Every other
command's output is conditional on the answer here.

## Output

```
  Credential

  profile    prod
  kind       API token, user-owned
  token id   f0e1d2c3b4a5968778695a4b3c2d1e0f
  name       audit-readonly
  status     active
  issued     2026-08-14T00:00:00Z
  expires    2027-02-14T00:00:00Z
  last used  2026-09-05T10:22:11Z
  ip filter  only from 203.0.113.0/24

  Grants

  EFFECT  SCOPE                                       PERMISSIONS
  allow   all zone in account f037e56e89293a05774…    Zone Read, DNS Read, Zone Settings Read
  allow   account a1b2c3d4e5f60718293a4b5c6d7e8f90    Account Settings Read, Workers Scripts Read

  2 policies

  ✔ read-only: every granted permission group is a read

  Reach

  accounts  1 (acme-corp)
  zones     14 (example.com, example.net, …, +11 more)
```

## What each part answers

**Credential.** Which [token store](Tokens) holds it, whether it is active,
whether it has an expiry, whether it has a source-IP condition, and when it was
last used. A token with no expiry gets a warning; an account-owned one gets a
note that it outlives its creator's membership.

**Grants.** One row per policy: the effect, what it covers, and which
permission groups it carries. The scope column is the one to read — see
[Tokens](Tokens) for why `all zone in account X` is a different thing from a
list of zones.

**Read or write.** Every Cloudflare permission group that grants a read ends in
`Read`. Anything else is a write, and gets called out:

```
  ! this token can write: DNS Write, Workers Scripts Write
```

**Reach.** What the credential can *actually* see, whatever it was granted on
paper. An empty reach is reported as `none, or not listable with this
credential`, because a zone-scoped token gets a `403` on `/accounts` and a bare
zero would read as "this credential reaches nothing".

## When the policies cannot be read

Reading a token's own policies needs the `API Tokens Read` permission, which a
well-scoped audit token deliberately does not have. That is a normal outcome,
not a failure, and `whoami` says so instead of reporting a token as read-only
on no evidence:

```
  › this token cannot read its own policies (no "User API Tokens Read" permission),
    so what follows is what it could reach, not what it was granted
```

The Reach section still works, because it is measured rather than declared.

## With a Global API Key

```
  Credential

  profile     legacy
  kind        Global API Key
  user        ops@example.com
  user id     9f8e7d6c5b4a39281706f5e4d3c2b1a0
  two-factor  off

  Reach

  accounts  3 (acme-corp, acme-labs, acme-sandbox)
  zones     41 (…)

  ! a Global API Key holds every permission of its user on every account it reaches;
    nothing below is out of its write scope
  ! two-factor authentication is off on the user behind this key
```

There are no policies to print, which is the point.

## JSON

`-o json` returns the same information structured, including `permissionList`
per policy and `writePermissions` as a flat array — which is what you would
gate a CI check on:

```bash
mlab-cloudflare whoami -o json | jq -e '.writePermissions == []'
```

## See also

- [Tokens](Tokens) — the concepts this command reports on
- [Errors](Errors) — why a `403` is three different findings
