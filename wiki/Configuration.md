# Configuration

Also covers the `profile` and `config` commands.

## The file

One JSON file, `$HOME/.mlab/cloudflare.conf`, holding any number of named
profiles plus the name of the default one.

It is written **0600 inside a 0700 directory**, because it holds credentials in
cleartext. The tool checks the mode on every run that needs the API and warns
when it has drifted:

```
  ! config /Users/you/.mlab/cloudflare.conf has mode 0644; it holds API credentials, 0600 is recommended
```

Override the location with `MLAB_CLOUDFLARE_CONFIG`, which is what the test
commands in this wiki do so they never touch your real profiles.

```json
{
  "default": "prod",
  "profiles": {
    "prod": {
      "auth": "token",
      "token": "v1_…",
      "owner": "account",
      "account": "1a2b3c4d5e6f708192a3b4c5d6e7f809"
    },
    "legacy": {
      "auth": "key",
      "email": "ops@example.com",
      "api_key": "…"
    }
  }
}
```

| Field | Meaning |
| --- | --- |
| `auth` | `token` (default) or `key`. See [Tokens](Tokens). |
| `token` | The API token, with `auth: token`. |
| `email`, `api_key` | The Global API Key pair, with `auth: key`. |
| `owner` | `user` or `account` — which [token store](Tokens) holds the token, discovered by `login`. |
| `account` | The account to scan. Required for an account-owned token, and the thing you set once so nothing asks again. |
| `zone` | Default zone id, used by `{zone}` in [`api`](Api). |
| `output` | `human` or `json`, when you always want one of them for this profile. |

## Precedence

**Flags** beat **environment** beat **file**. Nothing is merged; the first place
a value is found wins for that value alone.

The environment is read under three prefixes, in order:

```
MLAB_CLOUDFLARE_<NAME>   →   CLOUDFLARE_<NAME>   →   CF_<NAME>
```

The last two are what wrangler, the Terraform provider and every Cloudflare CI
action already export, so a machine that can deploy can audit without setting
anything new:

| Variable | Sets |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | the API token |
| `CLOUDFLARE_EMAIL`, `CLOUDFLARE_API_KEY` | the Global API Key pair |
| `CLOUDFLARE_ACCOUNT_ID` | the default account |
| `CLOUDFLARE_ZONE_ID` | the default zone |
| `CLOUDFLARE_AUTH` | `token` or `key`, when the inference is wrong |
| `CLOUDFLARE_OUTPUT` | `human` or `json` |

The auth kind is inferred rather than demanded: a bare `CLOUDFLARE_API_KEY`
with no token means key auth. Making CI set a second variable to explain the
first one is how credentials end up hardcoded.

**With a credential in the environment, no config file is needed at all.** The
profile shows as `(flags)`.

## `profile`

```bash
mlab-cloudflare profile list
mlab-cloudflare profile show [NAME]
mlab-cloudflare profile use NAME
mlab-cloudflare profile remove NAME
```

```
  · legacy  key    ops@example.com  global key
  ● prod    token  ****WXYZ  account-owned

  ● default profile
```

Credentials are masked to their last four characters everywhere they are
printed. `profile show` adds the notes that matter about the credential kind:

```
  Profile prod

  account  1a2b3c4d5e6f708192a3b4c5d6e7f809
  auth     token
  owner    account
  token    ****WXYZ

  › this is an account-owned token: it is not tied to a person, and removing its creator from the account does not revoke it
```

`profile remove` deletes the profile from this machine and says the one thing
people forget:

```
  ✔ removed profile "old"
  › the credential itself still exists; revoke it in the dashboard if it is no longer wanted
```

## `config`

```bash
mlab-cloudflare config path     # just the path, for scripting
mlab-cloudflare config show     # the whole file, credentials masked
```

`config path` prints nothing but the path, so it composes:

```bash
chmod 600 "$(mlab-cloudflare config path)"
```

## See also

- [Tokens](Tokens) — which credential to use and why
- [Login](Login) — the wizard that writes all of this
