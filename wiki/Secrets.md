# Secrets

Two separate problems: the credential you hold, and the credentials the API
hands back.

## The credential you hold

`$HOME/.mlab/cloudflare.conf` is a credential store. It holds the token in
cleartext, at mode 0600 in a 0700 directory, and the tool warns on every run
when those permissions have drifted.

Nothing that prints a profile prints the credential: it is masked to its last
four characters everywhere, including `config show`, `profile show`, `profile
list` and the summary `login` prints after saving.

Prefer the environment to a flag. `--token` on a command line is visible to
every other user on the machine through the process list, and lands in your
shell history; `CLOUDFLARE_API_TOKEN` does neither. The tool reads it, and
`CF_API_TOKEN`, without any configuration.

**Removing a profile does not revoke anything.** `profile remove` deletes the
credential from this machine only, and says so:

```
  ✔ removed profile "old"
  › the credential itself still exists; revoke it in the dashboard if it is no longer wanted
```

## The credentials the API hands back

Several endpoints that are readable with a read permission return a live
secret. The ones that matter:

| Endpoint | What comes back |
| --- | --- |
| `/accounts/{id}/cfd_tunnel/{id}/token` | the tunnel's connector token — enough to run a connector |
| `/accounts/{id}/challenges/widgets/{sitekey}` | a Turnstile widget's server-side secret |
| `/accounts/{id}/access/identity_providers` | an IdP's OIDC `client_secret` |
| `/accounts/{id}/secondary_dns/tsigs` | the TSIG secret for zone transfer |
| `/accounts/{id}/images/v1/keys`, `/stream/keys` | signing keys |
| `/accounts/{id}/logpush/jobs` | object-store credentials inside `destination_conf` |

Which means a "read-only" audit token is not read-only in the way you would
hope: it can extract material that grants access to other systems. That is a
reason to scope the token, give it an expiry, and treat its output as sensitive
— not a reason to avoid the audit.

## Redaction

`api --redact` replaces every known credential field with its length before
anything is printed:

```
  token  <redacted:180>
```

A length is not a secret and it is what a strength check needs, so a redacted
record stays auditable — and the count of what was redacted is itself worth
knowing, being the measure of what the credential exposes.

The list is deliberately **exact field names**, not a substring rule. Every
audit log entry carries `actor_token_id` and `actor_token_name`, and a redactor
that blanks the field naming which credential made a change is a redactor
people switch off. An empty secret is left alone rather than marked, because
`<redacted:0>` would turn "this widget has no secret" into "this widget has a
secret".

Anything that writes an API response to disk goes through the same list, so a
field cannot be redacted in one place and stored in another.

## See also

- [Tokens](Tokens) — scoping and expiring the credential you hold
- [Api](Api) — the `--redact` flag
