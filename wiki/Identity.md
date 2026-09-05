# `mlab-cloudflare identity`

Who can change this account, and with what.

```bash
mlab-cloudflare identity
mlab-cloudflare identity members
mlab-cloudflare identity tokens
mlab-cloudflare identity access
```

With no subcommand it runs every check in the plane and prints the graded
report. The subcommands are the detail behind it: the same data, listed rather
than judged.

## The report

```
  Identity of acme-corp

  members         12
  account tokens  4
  user tokens     not readable
  sso             1
  scim users      9
  iam groups      2
  oauth clients   0

  Findings

  high    members    2 of 12 members have no second factor
          dana@example.com, eli@example.com
  high    tokens     1 active account-owned token can write, not only read
          ci-deploy (DNS Write, Workers Scripts Write)
  medium  directory  3 members are not managed by the directory, so nothing removes them automatically
          contractor@example.net, ops@example.com, sre@example.com
  medium  tokens     2 active account-owned tokens have no expiry
          ci-deploy, terraform

  4 findings

  › 2 high
  › 2 medium

  Not read

  AREA    ENDPOINT      WHY
  tokens  /user/tokens  API error 403 [9109]: Unauthorized to access requested resource

  ! 1 read was refused; those areas are unaudited, not clean
```

## Not read is not clean

Cloudflare answers `403` for "you may not look" and for "this is not
configured" alike. A check whose read was refused is listed under **Not read**
and never counted as passing — see [Errors](Errors).

That section is printed last and is never omitted, because a report that does
not say where it stopped looking reads as though it looked everywhere.

## What it checks

### Members

- **Two-factor.** The account-wide `enforce_twofactor` switch, and then the
  members who have no second factor despite it. Pending invitations are
  excluded from that count — they have no user record yet, and counting them
  would report one person twice.
- **Invitations never accepted.** An invite that has sat unaccepted for months
  is either a person who never joined or an address nobody controls.
- **Concentration of privilege.** Not the role name but what the role can do:
  who can add and remove members, who can change how the account
  authenticates, who can change billing. Permissions are the **union across a
  member's roles**, so holding two roles means holding both their edits.
- **Two permission models at once.** A member holding both a legacy role and an
  IAM policy is an account partway through a migration, where the effective
  permission is the union of the two and nobody has that union in their head.

### Tokens

Read from both [token stores](Tokens), and graded separately because the store
changes what a finding means.

- **Writes.** Cloudflare names every readable permission group `… Read`, so any
  other granted group is a write — whatever the token is called. The detail
  names the groups.
- **No expiry.** Tokens default to none.
- **Blanket scope.** A policy whose resource is nested under an account rather
  than naming zones covers every zone that account will ever hold, including
  ones created after the grant. See [Tokens](Tokens) for the JSON shape.
- **Never used.** An active credential nothing has ever presented.
- **No address condition**, raised only when *no* token has one — a single
  fenced token proves the account knows the feature exists.
- **Expired and disabled tokens**, counted. They are inert; a list full of them
  is a list nobody reviews, which is why the live ones went unnoticed.

### Directory

- A member **deactivated in the directory who still holds account access** —
  offboarding that half-completed. The one finding here that is an open door
  rather than a missing process.
- Members **the directory does not know about**, so nothing removes them
  automatically.
- **SSO configured without SCIM**: removing someone from the directory does not
  remove their account access.
- **No SSO at all** on an account with more than two members, which is a fact
  worth stating rather than a fault.

## Subcommands

`identity members` lists the members with their status, second factor and
roles, then repeats whatever the checks found underneath.

`identity tokens` lists both stores with each token's status, whether it grants
writes, its expiry and its last use.

`identity access` lists the SSO connectors, the SCIM users with their active
flag, the IAM user groups and the OAuth clients — and says plainly when each is
empty, since "no SCIM users" is the finding.

## JSON

`-o json` returns the counts, the findings and the unread list, which is what a
CI gate reads:

```bash
mlab-cloudflare identity -o json \
  | jq -e '[.findings[] | select(.severity == "high")] | length == 0'
```

## See also

- [Activity](Activity) — what was actually done, rather than who could
- [Tokens](Tokens) — the two stores, scoping, and read versus write
- [Audit surface](Audit-Surface) — the rest of the identity plane
