//! `ping` — can this profile reach the API, and how fast.

use anyhow::Result;
use reqwest::Method;
use serde_json::Value;

use crate::cf::{token, Auth, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let started = std::time::Instant::now();

    // Both of these are readable by any credential of their kind, whatever it
    // is scoped to, so a failure here means the credential, not the scope.
    // A token also settles which of the two token stores holds it, which is the
    // one piece of identity a bare `/user` call cannot report.
    let (store, v) = match c.auth() {
        Auth::Token => {
            let (owner, v) = ui::spin(
                "Verifying the token",
                token::verify(c, ctx.profile.owner, &ctx.profile.account),
            )
            .await?;
            (Some(owner), v)
        }
        Auth::Key => (
            None,
            ui::spin(
                "Reaching the API",
                c.request(Method::GET, "/user", &[], None),
            )
            .await?,
        ),
    };
    let took = ui::elapsed(started.elapsed());

    let identity = match c.auth() {
        Auth::Token => v
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        Auth::Key => v
            .get("email")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    };
    let status = v
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("active")
        .to_string();

    if render::is_json() {
        render::print_json(&serde_json::json!({
            "profile": ctx.name,
            "auth": c.auth().to_string(),
            "tokenStore": store.map(|o| o.to_string()),
            "endpoint": c.base(),
            "identity": identity,
            "status": status,
            "account": ctx.profile.account,
            "zone": ctx.profile.zone,
            "elapsed": took,
        }));
        return Ok(());
    }

    ui::success(&format!("answered in {took}"));
    render::pairs(&[
        ("profile", format!("{} ({})", ctx.name, c.auth())),
        ("endpoint", c.base().to_string()),
        (
            "identity",
            match store {
                Some(owner) => format!("token {identity} ({owner}-owned)"),
                None => identity,
            },
        ),
        ("status", status),
        ("account", ctx.profile.account.clone()),
        ("zone", ctx.profile.zone.clone()),
    ]);
    Ok(())
}
