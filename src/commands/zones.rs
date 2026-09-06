//! `zones` — the zones of the account being scanned.

use anyhow::Result;
use clap::Args;
use serde_json::Value;

use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::commands::named_where;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct ZonesArgs {
    /// Every zone the credential reaches, across all accounts
    #[arg(long)]
    pub all_accounts: bool,

    /// Only zones in this state
    #[arg(long, value_name = "STATUS", value_parser = ["initializing", "pending", "active", "moved", "deleted", "deactivated"])]
    pub status: Option<String>,

    /// Return a single page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &ZonesArgs) -> Result<()> {
    let mut q = Vec::new();

    // A scan covers one account. Listing every zone the credential can reach
    // is the inventory question, not the scan question, so it is opt-in.
    let scoped = if a.all_accounts {
        None
    } else {
        let id = scope::account(c, &ctx.profile.account).await?;
        q.push(("account.id".to_string(), id.clone()));
        Some(id)
    };

    if let Some(s) = &a.status {
        q.push(("status".to_string(), s.clone()));
    }

    let rows = match ui::spin("Listing zones", c.cached_list("/zones", &q, a.limit)).await {
        Ok(rows) => rows,
        // A zone-scoped credential is refused the listing and allowed the one
        // zone it covers, the same way `accounts` handles its own refusal.
        Err(e) if !ctx.profile.zone.is_empty() => {
            ui::info("this credential cannot list zones; reading the configured one");
            let path = format!("/zones/{}", esc(&scope::zone(c, &ctx.profile.zone).await?));
            match c.cached(&path, &[]).await {
                Ok(v) => vec![v],
                Err(_) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };

    render::heading(&match &scoped {
        // Name the account rather than the id: the id is already in the config
        // and the name is what tells you whether you scanned what you meant to.
        Some(id) => format!(
            "Zones of {}",
            account_name(&rows).unwrap_or_else(|| id.clone())
        ),
        None => "Zones, every account in scope".to_string(),
    });
    render::list(
        &rows,
        match scoped {
            Some(_) => render::ZONE_COLS,
            None => render::ZONE_ACROSS_COLS,
        },
    );
    render::count(rows.len(), "zone");

    if render::is_json() {
        return Ok(());
    }

    // Two states that look configured and enforce nothing. Both come back on
    // this listing, so neither costs a request.
    let paused = named_where(&rows, |z| {
        z.get("paused").and_then(Value::as_bool) == Some(true)
    });
    let pending = named_where(&rows, |z| {
        z.get("status").and_then(Value::as_str) == Some("pending")
    });
    if !paused.is_empty() || !pending.is_empty() {
        ui::gap();
    }
    if !paused.is_empty() {
        ui::warning(&format!(
            "paused, so nothing configured on them is enforced: {}",
            paused.join(", ")
        ));
    }
    // `pending` means the nameservers were never pointed at Cloudflare: the
    // zone's whole configuration is inert while it reads as set up.
    if !pending.is_empty() {
        ui::warning(&format!(
            "never delegated, so Cloudflare serves no traffic for them: {}",
            pending.join(", ")
        ));
    }
    Ok(())
}

/// The account name carried on the zones themselves, so naming the scanned
/// account costs no extra request. `None` when the account holds no zone.
fn account_name(rows: &[Value]) -> Option<String> {
    rows.first()
        .and_then(|z| z.get("account"))
        .and_then(|a| a.get("name"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}
