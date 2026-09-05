//! `login` — create or update a profile, prove it works, save it.

use std::io::IsTerminal;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::cf::{config, token, Auth, Client, Owner, Profile};
use crate::cli::Overrides;
use crate::commands::prompt::{ask, ask_secret};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Profile name to create or update
    #[arg(long, short = 'n', default_value = "default", value_name = "NAME")]
    pub name: String,

    /// Make this profile the default one
    #[arg(long)]
    pub set_default: bool,

    /// Save without checking that the credential works
    #[arg(long)]
    pub no_test: bool,

    /// Never prompt; fail when something is missing
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(ov: &Overrides, args: &LoginArgs) -> Result<()> {
    let mut cfg = config::load()?;
    let existing = cfg.profiles.get(&args.name).cloned();
    let base = existing.clone().unwrap_or_default();
    let interactive = !args.non_interactive && std::io::stdin().is_terminal();

    let auth: Auth = match ov.auth.clone().or_else(|| config::env("AUTH")) {
        Some(a) => a.parse()?,
        None if existing.is_some() => base.auth,
        None if ov.api_key.is_some() || config::env("API_KEY").is_some() => Auth::Key,
        None if interactive => ask("auth (token|key)", "token")?.parse()?,
        None => Auth::Token,
    };

    let mut p = Profile {
        auth,
        account: ov.account.clone().unwrap_or_else(|| base.account.clone()),
        zone: ov.zone.clone().unwrap_or_else(|| base.zone.clone()),
        output: ov.output.clone().or(base.output.clone()),
        ..Default::default()
    };

    match auth {
        Auth::Token => p.token = token(ov, &base, interactive)?,
        Auth::Key => {
            p.email = email(ov, &base, interactive)?;
            p.api_key = global_key(ov, &base, interactive)?;
            ui::warning(
                "a Global API Key carries every permission its user has, on every account they \
                 can reach, and cannot be scoped or expired; a read-only API token is the safer \
                 credential for an audit",
            );
        }
    }
    p.validate()?;

    if args.no_test {
        ui::warning("skipping the credential test (--no-test)");
    } else {
        verify(&mut p, interactive).await?;
    }

    let first = cfg.profiles.is_empty();
    cfg.profiles.insert(args.name.clone(), p.clone());
    if args.set_default || first || cfg.default_profile.is_none() {
        cfg.default_profile = Some(args.name.clone());
    }
    config::save(&cfg)?;

    ui::success(&format!(
        "saved profile {:?} to {}",
        args.name,
        config::path().display()
    ));
    render::one(&serde_json::to_value(p.redacted())?);
    Ok(())
}

/// A token from the flags, the environment, the stored profile, or the terminal.
fn token(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let mut key = ov
        .token
        .clone()
        .or_else(|| config::env("API_TOKEN"))
        .unwrap_or_default();

    if key.is_empty() {
        if !base.token.is_empty() {
            ui::info(&format!(
                "keeping the stored API token ({})",
                config::redact(&base.token)
            ));
            key = base.token.clone();
        } else if interactive {
            key = ask_secret("API token (dash.cloudflare.com -> My Profile -> API Tokens)")?;
        } else {
            bail!("--token or CLOUDFLARE_API_TOKEN is required");
        }
    }

    if key.trim().is_empty() {
        bail!("the API token is empty");
    }
    Ok(key.trim().to_string())
}

fn email(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let v = ov
        .email
        .clone()
        .or_else(|| config::env("EMAIL"))
        .unwrap_or_else(|| base.email.clone());
    if !v.is_empty() {
        return Ok(v);
    }
    if !interactive {
        bail!("--email or CLOUDFLARE_EMAIL is required with the Global API Key");
    }
    ask("account email", "")
}

fn global_key(ov: &Overrides, base: &Profile, interactive: bool) -> Result<String> {
    let mut key = ov
        .api_key
        .clone()
        .or_else(|| config::env("API_KEY"))
        .unwrap_or_default();

    if key.is_empty() {
        if !base.api_key.is_empty() {
            ui::info(&format!(
                "keeping the stored Global API Key ({})",
                config::redact(&base.api_key)
            ));
            key = base.api_key.clone();
        } else if interactive {
            key = ask_secret("Global API Key (dash.cloudflare.com -> My Profile -> API Tokens)")?;
        } else {
            bail!("--api-key or CLOUDFLARE_API_KEY is required");
        }
    }

    if key.trim().is_empty() {
        bail!("the Global API Key is empty");
    }
    Ok(key.trim().to_string())
}

/// Prove the credential works before it is written, and settle the account.
async fn verify(p: &mut Profile, interactive: bool) -> Result<()> {
    let c = Client::new(p, Duration::from_secs(30))?;

    match p.auth {
        Auth::Token => {
            let (owner, v) = check(&c, p, interactive).await?;
            p.owner = owner;

            let status = v.get("status").and_then(Value::as_str).unwrap_or("unknown");
            if status != "active" {
                bail!("the token verifies but its status is {status:?}");
            }
            ui::success(&format!("token is active, in the {owner} token store"));
            if owner == Owner::Account {
                // Worth saying once: this is the property that makes these
                // tokens survive an offboarding nobody thought to check.
                ui::info("account-owned tokens are not tied to a person and outlive their creator's membership");
            }
            if let Some(exp) = v.get("expires_on").and_then(Value::as_str) {
                ui::info(&format!("expires on {exp}"));
            } else {
                ui::warning("this token has no expiry date");
            }
        }
        Auth::Key => {
            let v = ui::spin(
                "Verifying the key",
                c.request(Method::GET, "/user", &[], None),
            )
            .await?;
            let who = v.get("email").and_then(Value::as_str).unwrap_or("");
            ui::success(&format!("authenticated as {who}"));
            if v.get("two_factor_authentication_enabled")
                .and_then(Value::as_bool)
                == Some(false)
            {
                ui::warning("two-factor authentication is off on this user");
            }
        }
    }

    // An account-owned token verified against an account has already proved
    // which one it belongs to; asking it to list accounts would only fail.
    if p.auth == Auth::Token && p.owner == Owner::Account {
        ui::info(&format!("account {}", p.account));
    } else {
        p.account = pick_account(&c, &p.account, interactive).await?;
    }
    Ok(())
}

/// Verify the token, and when it turns out not to be a user token, get the
/// account id its own store is addressed by.
async fn check(c: &Client, p: &mut Profile, interactive: bool) -> Result<(Owner, Value)> {
    match ui::spin("Verifying the token", token::verify(c, p.owner, &p.account)).await {
        Ok(ok) => Ok(ok),
        // Only one thing is missing here and only the operator has it, so ask
        // for it rather than failing with instructions to run the same command
        // again.
        Err(e) if interactive && p.account.is_empty() => {
            ui::warning("this token is not in your user token store");
            ui::info(
                "tokens made under Manage Account -> Account API tokens belong to the account,                  and verify against it",
            );
            let id = ask(
                "account id (32 hex, from the dashboard URL dash.cloudflare.com/<id>)",
                "",
            )?;
            if id.trim().is_empty() {
                return Err(e);
            }
            p.account = id.trim().to_string();
            ui::spin(
                "Verifying against the account",
                token::verify(c, Owner::Account, &p.account),
            )
            .await
        }
        Err(e) => Err(e),
    }
}

/// Confirm the configured account, or choose one from what the credential sees.
async fn pick_account(c: &Client, want: &str, interactive: bool) -> Result<String> {
    // A token scoped to a single zone cannot list accounts at all, which is a
    // perfectly good token; it just has no default account to remember.
    let accounts = match ui::spin("Listing accounts", c.list("/accounts", &[], None)).await {
        Ok(a) => a,
        Err(e) => {
            ui::warning(&format!(
                "cannot list accounts ({e}); leaving the account unset"
            ));
            return Ok(want.to_string());
        }
    };
    let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();

    if accounts.is_empty() {
        ui::warning("this credential reaches no account");
        return Ok(want.to_string());
    }

    if !want.is_empty() {
        for a in &accounts {
            if field(a, "id") == want || field(a, "name").eq_ignore_ascii_case(want) {
                return Ok(field(a, "id"));
            }
        }
        bail!("no account matches {want:?}");
    }

    if accounts.len() == 1 {
        let id = field(&accounts[0], "id");
        ui::info(&format!("account {} ({id})", field(&accounts[0], "name")));
        return Ok(id);
    }

    eprintln!();
    for (i, a) in accounts.iter().enumerate() {
        eprintln!("    [{}] {} ({})", i + 1, field(a, "name"), field(a, "id"));
    }
    eprintln!();
    if !interactive {
        bail!("several accounts are in scope; re-run with --account NAME");
    }

    let idx: usize = ask("account number", "1")?
        .trim()
        .parse()
        .context("that is not a number")?;
    let chosen = accounts.get(idx.saturating_sub(1)).unwrap_or(&accounts[0]);
    Ok(field(chosen, "id"))
}
