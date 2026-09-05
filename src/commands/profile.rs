//! `profile` — list, inspect, select and delete saved profiles.

use anyhow::{bail, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::Value;

use crate::cf::{config, Auth, Owner};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum ProfileCmd {
    /// List saved profiles
    #[command(alias = "ls")]
    List,
    /// Show one profile, with credentials masked
    Show {
        /// Profile name (default: the default profile)
        name: Option<String>,
    },
    /// Set the default profile
    Use { name: String },
    /// Delete a profile
    #[command(alias = "rm", alias = "delete")]
    Remove { name: String },
}

pub fn run(cmd: &ProfileCmd) -> Result<()> {
    let mut cfg = config::load()?;

    match cmd {
        ProfileCmd::List => list(&cfg),
        ProfileCmd::Show { name } => {
            let (name, p) = cfg.profile(name.as_deref())?;
            render::heading(&format!("Profile {name}"));
            render::one(&serde_json::to_value(p.redacted())?);
            match p.auth {
                Auth::Key => ui::warning(
                    "this profile holds a Global API Key, which carries every permission the user has",
                ),
                Auth::Token if p.owner == Owner::Account => ui::info(
                    "this is an account-owned token: it is not tied to a person, and removing its \
                     creator from the account does not revoke it",
                ),
                Auth::Token => {}
            }
            Ok(())
        }
        ProfileCmd::Use { name } => {
            if !cfg.profiles.contains_key(name) {
                bail!("profile {name:?} does not exist");
            }
            cfg.default_profile = Some(name.clone());
            config::save(&cfg)?;
            ui::success(&format!("default profile is now {name:?}"));
            Ok(())
        }
        ProfileCmd::Remove { name } => {
            if cfg.profiles.remove(name).is_none() {
                bail!("profile {name:?} does not exist");
            }
            if cfg.default_profile.as_deref() == Some(name.as_str()) {
                cfg.default_profile = cfg.profiles.keys().next().cloned();
            }
            config::save(&cfg)?;
            // The credential is gone from this machine, not from Cloudflare.
            ui::success(&format!("removed profile {name:?}"));
            ui::info("the credential itself still exists; revoke it in the dashboard if it is no longer wanted");
            Ok(())
        }
    }
}

fn list(cfg: &config::ConfigFile) -> Result<()> {
    if cfg.profiles.is_empty() {
        if render::is_json() {
            render::print_json(&serde_json::json!([]));
        } else {
            ui::warning("no profile yet; run `mlab-cloudflare login`");
        }
        return Ok(());
    }

    let rows: Vec<Value> = cfg
        .profiles
        .iter()
        .map(|(name, p)| {
            serde_json::json!({
                "name": name,
                "default": cfg.default_profile.as_deref() == Some(name),
                "auth": p.auth.to_string(),
                "store": match p.auth {
                    Auth::Token => p.owner.to_string(),
                    Auth::Key => String::new(),
                },
                "identity": match p.auth {
                    Auth::Token => config::redact(&p.token),
                    Auth::Key => p.email.clone(),
                },
                "account": p.account,
                "zone": p.zone,
            })
        })
        .collect();

    if render::is_json() {
        render::print_json(&Value::Array(rows));
        return Ok(());
    }

    // Pad the plain text, then colour: ANSI codes count as characters in a
    // format width, which would break the alignment.
    let width = cfg
        .profiles
        .keys()
        .map(|n| n.chars().count())
        .max()
        .unwrap_or(0);
    println!();
    for r in &rows {
        let is_default = r["default"].as_bool().unwrap_or(false);
        let marker = if is_default {
            "●".green()
        } else {
            "·".dimmed()
        };
        let padded = format!("{:<width$}", r["name"].as_str().unwrap_or_default());
        let name = if is_default {
            padded.bold()
        } else {
            padded.normal()
        };
        let auth = format!("{:<5}", r["auth"].as_str().unwrap_or_default());
        let warn = match (r["auth"].as_str(), r["store"].as_str()) {
            (Some("key"), _) => format!("  {}", "global key".yellow()),
            (_, Some("account")) => format!("  {}", "account-owned".dimmed()),
            _ => String::new(),
        };
        println!(
            "  {marker} {name}  {}  {}{warn}",
            auth.dimmed(),
            r["identity"].as_str().unwrap_or_default()
        );
    }
    println!();
    println!("  {}", "● default profile".dimmed());
    Ok(())
}
