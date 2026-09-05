//! `activity` — what was actually done to this account, and by whom.
//!
//! The audit log is the only record of what a setting used to be, and its
//! retention is plan-dependent — so it is also the clock on how far back any
//! incident can be reconstructed.

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::audit::{self, Finding};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct ActivityArgs {
    /// How far back to look: a number of days
    #[arg(long, default_value_t = 30, value_name = "DAYS")]
    pub days: u32,

    /// Only actions that failed
    #[arg(long)]
    pub failed: bool,

    /// Only changes made by a token or by the system, not by a person
    #[arg(long)]
    pub by_token: bool,

    /// Only deletions and revocations
    #[arg(long)]
    pub destructive: bool,

    /// Only actions by this actor's email address
    #[arg(long, value_name = "EMAIL")]
    pub actor: Option<String>,

    /// Stop after this many entries
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &ActivityArgs) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let window = format!("{} days", a.days);

    let mut q = vec![
        ("since".to_string(), since(a.days)?),
        ("direction".to_string(), "desc".to_string()),
    ];
    if let Some(actor) = &a.actor {
        q.push(("actor.email".to_string(), actor.clone()));
    }

    let path = format!("/accounts/{}/audit_logs", esc(&account));
    let entries = ui::spin(
        &format!("Reading the last {window}"),
        c.list(&path, &q, a.limit),
    )
    .await
    .context("reading the audit log")?;

    // Filters the API does not offer are applied here rather than not at all,
    // and the findings below are computed on the whole window so a filtered
    // view still reports the shape of everything in it.
    let findings = audit::activity(&entries, &window);
    let shown: Vec<&Value> = entries.iter().filter(|e| keep(e, a)).collect();

    let rows: Vec<Value> = shown.iter().map(|e| row(e)).collect();

    if render::is_json() {
        render::print_json(&json!({
            "window": window,
            "total": entries.len(),
            "shown": rows.len(),
            "entries": rows,
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    render::heading(&format!("Activity, last {window}"));
    render::list(&rows, render::ACTIVITY_COLS);
    render::count(rows.len(), "entry");
    if rows.len() != entries.len() {
        ui::info(&format!(
            "{} entries in the window, {} shown by the filters",
            entries.len(),
            rows.len()
        ));
    }

    if !findings.is_empty() {
        ui::gap();
        for f in audit::sorted(findings) {
            let line = if f.detail.is_empty() {
                f.finding.clone()
            } else {
                format!("{} — {}", f.finding, f.detail)
            };
            match f.severity {
                audit::Severity::High | audit::Severity::Medium => ui::warning(&line),
                _ => ui::info(&line),
            }
        }
    }
    Ok(())
}

/// Whether an entry survives the command-line filters. With none given,
/// everything does.
fn keep(e: &Value, a: &ActivityArgs) -> bool {
    if a.failed && result_of(e) != Some(false) {
        return false;
    }
    if a.by_token {
        let t = actor(e, "type");
        if t.is_empty() || t == "user" {
            return false;
        }
    }
    if a.destructive {
        let t = action(e);
        if !(t.contains("delete") || t.contains("revoke") || t.contains("remove")) {
            return false;
        }
    }
    true
}

fn row(e: &Value) -> Value {
    // A token has no address of its own, so it is identified by its id. The
    // system's own actor id is the literal "1", which identifies nothing — the
    // BY column already says the change was internal.
    let who = match (actor(e, "email"), actor(e, "type")) {
        (email, _) if !email.is_empty() => email,
        (_, kind) if kind == "system" => String::new(),
        _ => actor(e, "id"),
    };
    json!({
        "when": e.get("when"),
        "actor": who,
        "by": actor(e, "type"),
        "action": action(e),
        "result": match result_of(e) {
            Some(true) => "ok",
            Some(false) => "failed",
            None => "",
        },
        "resource": e.get("resource").map(|r| {
            r.get("type").and_then(Value::as_str).unwrap_or("").to_string()
        }),
        "ip": actor(e, "ip"),
    })
}

fn actor(e: &Value, k: &str) -> String {
    e.get("actor")
        .and_then(|a| a.get(k))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn action(e: &Value) -> String {
    e.get("action")
        .and_then(|a| a.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn result_of(e: &Value) -> Option<bool> {
    e.get("action")
        .and_then(|a| a.get("result"))
        .and_then(Value::as_bool)
}

/// `days` ago as an RFC 3339 timestamp, which is what `since` wants.
///
/// Computed from the wall clock without a date library: the audit log takes a
/// UTC instant and the only arithmetic needed is a subtraction of seconds.
fn since(days: u32) -> Result<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("the system clock is before 1970")?
        .as_secs() as i64;
    Ok(crate::cf::iso8601(now - i64::from(days) * 86_400))
}
