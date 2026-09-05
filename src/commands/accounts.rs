//! `accounts` — every account this credential reaches.

use anyhow::Result;
use reqwest::Method;
use serde_json::Value;

use crate::cf::{esc, Client};
use crate::cli::{Ctx, ListArgs};
use crate::commands::named_where;
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx, a: &ListArgs) -> Result<()> {
    let rows = match ui::spin("Listing accounts", c.list("/accounts", &[], a.limit)).await {
        Ok(rows) => rows,
        // A credential scoped to one account's resources — an R2 token, most
        // account-owned tokens — cannot list accounts but can usually read the
        // one it belongs to. Reporting nothing found would be the wrong answer.
        Err(e) if !ctx.profile.account.is_empty() => {
            ui::info("this credential cannot list accounts; reading the configured one");
            let path = format!("/accounts/{}", esc(&ctx.profile.account));
            match c.request(Method::GET, &path, &[], None).await {
                Ok(v) => vec![v],
                // The fallback failing says nothing new; the first refusal is
                // the one that explains what the credential is missing.
                Err(_) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    };

    render::heading("Accounts");
    render::list(&rows, render::ACCOUNT_COLS);
    render::count(rows.len(), "account");

    // The account-wide switch that decides whether every member must carry a
    // second factor. It comes back on this listing, so it costs nothing to say.
    let lax = named_where(&rows, |r| {
        r.get("settings")
            .and_then(|s| s.get("enforce_twofactor"))
            .and_then(Value::as_bool)
            == Some(false)
    });
    if !lax.is_empty() && !render::is_json() {
        ui::gap();
        ui::warning(&format!(
            "two-factor authentication is not enforced on: {}",
            lax.join(", ")
        ));
    }
    Ok(())
}
