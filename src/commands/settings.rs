//! `config` — where the config file is, and what is in it.

use anyhow::Result;
use clap::Subcommand;

use crate::cf::config;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    /// Print the path of the config file
    Path,
    /// Print the config file, with credentials masked
    Show,
}

pub fn run(cmd: &ConfigCmd) -> Result<()> {
    match cmd {
        // Always plain: this one is meant to be pasted into another command.
        ConfigCmd::Path => println!("{}", config::path().display()),
        ConfigCmd::Show => {
            let mut cfg = config::load()?;
            for p in cfg.profiles.values_mut() {
                *p = p.redacted();
            }
            render::heading(&config::path().display().to_string());
            render::one(&serde_json::to_value(&cfg)?);
            if let Some(w) = config::perms_warning() {
                ui::warning(&w);
            }
        }
    }
    Ok(())
}
