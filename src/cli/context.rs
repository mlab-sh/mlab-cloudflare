//! Turning flags, environment and config file into one resolved connection.

use std::time::Duration;

use anyhow::Result;

use crate::cf::{config, Profile};
use crate::cli::Cli;
use crate::ui::render;

/// Settings a flag may override on top of a stored profile. Kept apart from
/// [`Cli`] so the login wizard can take the same shape without clap in scope.
#[derive(Debug, Default)]
pub struct Overrides {
    pub auth: Option<String>,
    pub token: Option<String>,
    pub email: Option<String>,
    pub api_key: Option<String>,
    pub account: Option<String>,
    pub zone: Option<String>,
    pub output: Option<String>,
    pub mlab_key: Option<String>,
}

impl From<&Cli> for Overrides {
    fn from(cli: &Cli) -> Self {
        Overrides {
            auth: cli.auth.clone(),
            token: cli.token.clone(),
            email: cli.email.clone(),
            api_key: cli.api_key.clone(),
            account: cli.account.clone(),
            zone: cli.zone.clone(),
            output: cli.output.clone(),
            mlab_key: cli.mlab_key.clone(),
        }
    }
}

/// The resolved connection settings for this invocation.
pub struct Ctx {
    pub name: String,
    pub profile: Profile,
    pub timeout: Duration,
}

impl Ctx {
    /// Resolve the profile for this run: file, then environment, then flags.
    pub fn build(cli: &Cli) -> Result<Ctx> {
        let cfg = config::load()?;
        let ov = Overrides::from(cli);

        let (name, mut p) = match cfg.profile(cli.profile.as_deref()) {
            Ok(found) => found,
            Err(e) => {
                // Usable with no config file at all when a credential is given,
                // which is how this runs in CI: the token is already in the
                // environment as CLOUDFLARE_API_TOKEN.
                let has_cred = ov.token.is_some()
                    || ov.api_key.is_some()
                    || config::env("API_TOKEN").is_some()
                    || config::env("API_KEY").is_some();
                if cli.profile.is_none() && has_cred {
                    ("(flags)".to_string(), Profile::default())
                } else {
                    return Err(e);
                }
            }
        };

        if let Some(v) = config::env("API_TOKEN") {
            p.token = v;
        }
        if let Some(v) = config::env("EMAIL") {
            p.email = v;
        }
        if let Some(v) = config::env("API_KEY") {
            p.api_key = v;
        }
        if let Some(v) = config::env("ACCOUNT_ID") {
            p.account = v;
        }
        if let Some(v) = config::env("ZONE_ID") {
            p.zone = v;
        }
        // Its own name, because it is a key for a different service: reading
        // CLOUDFLARE_API_TOKEN into it would be a category error.
        for key in ["MLAB_API_KEY", "MLAB_KEY"] {
            if let Ok(v) = std::env::var(key) {
                if !v.is_empty() {
                    p.mlab_key = v;
                    break;
                }
            }
        }
        // The mode is inferred rather than asked for: a bare CLOUDFLARE_API_KEY
        // in the environment is unambiguous, and making CI set a second
        // variable to explain the first one is how credentials end up hardcoded.
        if let Some(v) = config::env("AUTH") {
            p.auth = v.parse()?;
        } else if p.token.is_empty() && !p.api_key.is_empty() {
            p.auth = config::Auth::Key;
        }

        if let Some(v) = &ov.auth {
            p.auth = v.parse()?;
        }
        if let Some(v) = &ov.token {
            p.token = v.clone();
            if ov.auth.is_none() {
                p.auth = config::Auth::Token;
            }
        }
        if let Some(v) = &ov.email {
            p.email = v.clone();
        }
        if let Some(v) = &ov.api_key {
            p.api_key = v.clone();
            if ov.auth.is_none() && ov.token.is_none() {
                p.auth = config::Auth::Key;
            }
        }
        if let Some(v) = &ov.account {
            p.account = v.clone();
        }
        if let Some(v) = &ov.zone {
            p.zone = v.clone();
        }
        if let Some(v) = &ov.mlab_key {
            p.mlab_key = v.clone();
        }

        // The flag and the environment were applied at startup; a profile-level
        // preference only speaks when neither of them did.
        if ov.output.is_none() && config::env("OUTPUT").is_none() {
            render::init(p.output.as_deref());
        }

        Ok(Ctx {
            name,
            profile: p,
            timeout: Duration::from_secs(cli.timeout.max(1)),
        })
    }
}
