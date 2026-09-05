//! Config storage for the `mlab-cloudflare` CLI.
//!
//! One file, `$HOME/.mlab/cloudflare.conf` (JSON), holding any number of named
//! profiles plus the name of the default one. Written 0600 inside a 0700 dir:
//! it contains API credentials.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// How a profile proves who it is.
///
/// Cloudflare offers two, and they are not equivalent. A token can be scoped
/// to specific permissions, accounts and zones, and can be expired or revoked
/// on its own; the global key carries every permission the user has, on every
/// account they can reach, and revoking it breaks every other integration that
/// shares it. This tool defaults to a token and says so wherever the other one
/// turns up.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    /// `Authorization: Bearer <token>` — a scoped API token.
    #[default]
    Token,
    /// `X-Auth-Email` + `X-Auth-Key` — the account-wide Global API Key.
    Key,
}

impl std::fmt::Display for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Auth::Token => "token",
            Auth::Key => "key",
        })
    }
}

impl std::str::FromStr for Auth {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "token" | "bearer" | "api-token" | "api_token" => Ok(Auth::Token),
            "key" | "global" | "global-key" | "api-key" | "api_key" => Ok(Auth::Key),
            other => bail!("unknown auth {other:?} (expected \"token\" or \"key\")"),
        }
    }
}

/// Which of Cloudflare's two token stores a token lives in.
///
/// They are separate namespaces and neither can see the other. A token created
/// under **My Profile -> API Tokens** belongs to the user and verifies at
/// `/user/tokens/verify`; one created under **Manage Account -> Account API
/// tokens** — which is also where the R2 credentials are now handed out —
/// belongs to the account and verifies at `/accounts/{id}/tokens/verify`.
///
/// Asking the wrong store answers `1000 Invalid API Token`, which is
/// indistinguishable from a mistyped credential. Which store answered is
/// therefore worth discovering once and remembering.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Owner {
    /// Created under My Profile; tied to one person and removed with them.
    #[default]
    User,
    /// Created under the account; outlives its creator's membership.
    Account,
}

impl std::fmt::Display for Owner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Owner::User => "user",
            Owner::Account => "account",
        })
    }
}

/// Credentials and default scope for one Cloudflare account.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    #[serde(default)]
    pub auth: Auth,
    /// Scoped API token, used with `auth: token`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token: String,
    /// Which token store `token` lives in, as discovered by `login`.
    #[serde(default)]
    pub owner: Owner,
    /// Account email, used with `auth: key`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
    /// Global API Key, used with `auth: key`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub api_key: String,
    /// Default account id for account-scoped commands.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub account: String,
    /// Default zone id for zone-scoped commands.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zone: String,
    /// `json` or `human`; `None` means the global default (`human`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Profile {
    /// Reject a profile that cannot produce a request.
    pub fn validate(&self) -> Result<()> {
        match self.auth {
            Auth::Token => {
                if self.token.is_empty() {
                    bail!("api token is missing (set --token, CLOUDFLARE_API_TOKEN, or run `mlab-cloudflare login`)");
                }
                if self.owner == Owner::Account && self.account.is_empty() {
                    bail!("an account-owned token needs its account (set --account or CLOUDFLARE_ACCOUNT_ID); it cannot be verified without one");
                }
            }
            Auth::Key => {
                if self.email.is_empty() {
                    bail!("email is missing (set --email or CLOUDFLARE_EMAIL); the Global API Key needs one");
                }
                if self.api_key.is_empty() {
                    bail!("global api key is missing (set --api-key or CLOUDFLARE_API_KEY)");
                }
            }
        }
        Ok(())
    }

    /// A copy with the credentials blanked, for printing.
    pub fn redacted(&self) -> Profile {
        let mut p = self.clone();
        p.token = redact(&self.token);
        p.api_key = redact(&self.api_key);
        p
    }
}

/// Mask a credential down to its last 4 characters.
pub fn redact(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("****{tail}")
}

/// The whole config file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigFile {
    /// Name of the profile used when `--profile` is not given.
    #[serde(rename = "default", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ConfigFile {
    /// Resolve `name` (or the default profile when `None`).
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        let wanted = match name {
            Some(n) => n.to_string(),
            None => match &self.default_profile {
                Some(d) => d.clone(),
                None if self.profiles.len() == 1 => self.profiles.keys().next().unwrap().clone(),
                _ => bail!("no profile selected and no default set; run `mlab-cloudflare login`"),
            },
        };
        match self.profiles.get(&wanted) {
            Some(p) => Ok((wanted, p.clone())),
            None => bail!(
                "profile {wanted:?} not found in {} (known: {})",
                path().display(),
                if self.profiles.is_empty() {
                    "none".to_string()
                } else {
                    self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                }
            ),
        }
    }
}

/// `$MLAB_CLOUDFLARE_CONFIG`, else `$HOME/.mlab/cloudflare.conf`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_CLOUDFLARE_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("cloudflare.conf")
}

/// Read the config file. A missing file is an empty config, not an error.
pub fn load() -> Result<ConfigFile> {
    let p = path();
    let data = match fs::read_to_string(&p) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigFile::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    if data.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    serde_json::from_str(&data).with_context(|| format!("parsing {}", p.display()))
}

/// Write the config file, 0600 in a 0700 directory.
pub fn save(cfg: &ConfigFile) -> Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let mut data = serde_json::to_string_pretty(cfg)?;
    data.push('\n');
    fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
    set_mode(&p, 0o600)?;
    Ok(())
}

/// Non-empty when the config file is readable or writable by group/others.
pub fn perms_warning() -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = path();
        let meta = fs::metadata(&p).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "config {} has mode {mode:04o}; it holds API credentials, 0600 is recommended",
                p.display()
            ));
        }
    }
    None
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// First non-empty of `MLAB_CLOUDFLARE_<name>`, `CLOUDFLARE_<name>`, `CF_<name>`.
///
/// The last two are what wrangler, the Terraform provider and every Cloudflare
/// CI action already export, so a machine that can deploy can audit without
/// setting anything new.
pub fn env(name: &str) -> Option<String> {
    for key in [
        format!("MLAB_CLOUDFLARE_{name}"),
        format!("CLOUDFLARE_{name}"),
        format!("CF_{name}"),
    ] {
        if let Ok(v) = std::env::var(&key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_asks_for_what_each_auth_actually_needs() {
        let mut p = Profile::default();
        assert!(p.validate().is_err(), "a token profile needs a token");
        p.token = "t".into();
        assert!(p.validate().is_ok());

        let mut k = Profile {
            auth: Auth::Key,
            ..Default::default()
        };
        assert!(k.validate().is_err());
        k.api_key = "k".into();
        assert!(k.validate().is_err(), "the global key is useless alone");
        k.email = "a@b.c".into();
        assert!(k.validate().is_ok());
    }

    #[test]
    fn an_account_owned_token_is_incomplete_without_its_account() {
        // It cannot even be verified: its store is addressed by account id.
        let mut p = Profile {
            token: "t".into(),
            owner: Owner::Account,
            ..Default::default()
        };
        assert!(p.validate().is_err());
        p.account = "1a2b3c4d5e6f708192a3b4c5d6e7f809".into();
        assert!(p.validate().is_ok());
    }

    #[test]
    fn redact_keeps_only_the_tail() {
        assert_eq!(redact("abcdefgh"), "****efgh");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn a_redacted_profile_carries_no_credential_of_either_kind() {
        let p = Profile {
            auth: Auth::Key,
            token: "tokenvalue".into(),
            api_key: "keyvalue".into(),
            email: "a@b.c".into(),
            ..Default::default()
        };
        let r = p.redacted();
        assert_eq!(r.token, "****alue");
        assert_eq!(r.api_key, "****alue");
        assert_eq!(
            r.email, "a@b.c",
            "the email is not a secret, and identifies"
        );
    }

    #[test]
    fn auth_parses_the_names_people_actually_type() {
        assert_eq!("TOKEN".parse::<Auth>().unwrap(), Auth::Token);
        assert_eq!("global-key".parse::<Auth>().unwrap(), Auth::Key);
        assert!("oauth".parse::<Auth>().is_err());
    }

    #[test]
    fn profile_falls_back_to_the_only_one() {
        let mut cfg = ConfigFile::default();
        cfg.profiles.insert("only".into(), Profile::default());
        assert_eq!(cfg.profile(None).unwrap().0, "only");
        assert!(cfg.profile(Some("other")).is_err());
    }
}
