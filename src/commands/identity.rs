//! `identity` — who can change this account, and with what.
//!
//! One account, four reads: the account itself, its members, its API tokens,
//! and how membership is provisioned. Each is allowed to be refused — a token
//! scoped for a DNS audit cannot read the member list — and a refusal is
//! reported as unread rather than silently as a clean result.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Finding};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum IdentityCmd {
    /// Members, their roles, and what those roles can change
    Members,
    /// API tokens on this account and on the calling user
    Tokens,
    /// SSO, SCIM provisioning, and the scoped IAM model
    Access,
}

/// What one read produced, or why it produced nothing.
///
/// The distinction is the whole point: `403` on the member list means the
/// credential may not look, and reporting that as "no members with findings"
/// would be a clean bill of health issued on no evidence.
struct Reads {
    account: Value,
    members: Result<Vec<Value>, String>,
    account_tokens: Result<Vec<Value>, String>,
    user_tokens: Result<Vec<Value>, String>,
    sso: Result<Vec<Value>, String>,
    scim: Result<Vec<Value>, String>,
    groups: Result<Vec<Value>, String>,
    oauth: Result<Vec<Value>, String>,
}

impl Reads {
    /// Every read that was refused, as (area, path, reason).
    fn unread(&self) -> Vec<(&'static str, &'static str, String)> {
        [
            ("members", "/accounts/{id}/members", &self.members),
            ("tokens", "/accounts/{id}/tokens", &self.account_tokens),
            ("tokens", "/user/tokens", &self.user_tokens),
            ("directory", "/accounts/{id}/sso_connectors", &self.sso),
            ("directory", "/accounts/{id}/scim/v2/Users", &self.scim),
            ("directory", "/accounts/{id}/iam/user_groups", &self.groups),
            ("directory", "/accounts/{id}/oauth_clients", &self.oauth),
        ]
        .into_iter()
        .filter_map(|(area, path, r)| r.as_ref().err().map(|e| (area, path, one_line(e))))
        .collect()
    }
}

/// Collapse a multi-line API error to the sentence that names the cause.
fn one_line(e: &str) -> String {
    e.lines().next().unwrap_or(e).trim().to_string()
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<IdentityCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let reads = gather(c, &account).await?;

    match cmd {
        Some(IdentityCmd::Members) => members(&reads),
        Some(IdentityCmd::Tokens) => tokens(&reads),
        Some(IdentityCmd::Access) => access(&reads),
        None => report(&reads),
    }
    Ok(())
}

/// Every read the identity plane needs, in one pass.
///
/// The account object is required — without it there is no scope and no
/// two-factor setting — and everything else may fail.
async fn gather(c: &Client, account_id: &str) -> Result<Reads> {
    let acct = format!("/accounts/{}", esc(account_id));

    let account = ui::spin("Reading the account", c.cached(&acct, &[])).await?;

    let opt = |r: Result<Vec<Value>>| r.map_err(|e| format!("{e:#}"));

    let members = opt(ui::spin(
        "Listing members",
        c.cached_list(&format!("{acct}/members"), &[], None),
    )
    .await);

    let account_tokens = opt(ui::spin(
        "Listing account tokens",
        c.cached_list(&format!("{acct}/tokens"), &[], None),
    )
    .await);

    let user_tokens = opt(ui::spin(
        "Listing user tokens",
        c.cached_list("/user/tokens", &[], None),
    )
    .await);

    let sso = opt(ui::spin(
        "Reading SSO",
        c.cached_list(&format!("{acct}/sso_connectors"), &[], None),
    )
    .await);

    let scim = ui::spin(
        "Reading SCIM users",
        c.cached(&format!("{acct}/scim/v2/Users"), &[]),
    )
    .await
    .map(|v| scim_users(&v))
    .map_err(|e| format!("{e:#}"));

    let groups = opt(ui::spin(
        "Listing IAM groups",
        c.cached_list(&format!("{acct}/iam/user_groups"), &[], None),
    )
    .await);

    let oauth = opt(ui::spin(
        "Listing OAuth clients",
        c.cached_list(&format!("{acct}/oauth_clients"), &[], None),
    )
    .await);

    Ok(Reads {
        account,
        members,
        account_tokens,
        user_tokens,
        sso,
        scim,
        groups,
        oauth,
    })
}

/// SCIM answers with its own ListResponse envelope rather than the Cloudflare
/// one, so the users sit under `Resources` instead of being the result.
fn scim_users(v: &Value) -> Vec<Value> {
    v.get("Resources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

// ---- the graded report ------------------------------------------------------

fn report(r: &Reads) {
    let mut findings: Vec<Finding> = Vec::new();
    if let Ok(m) = &r.members {
        findings.extend(audit::members(&r.account, m));
    }
    if let Ok(t) = &r.account_tokens {
        findings.extend(audit::tokens(t, "account-owned"));
    }
    if let Ok(t) = &r.user_tokens {
        findings.extend(audit::tokens(t, "user-owned"));
    }
    if let (Ok(m), Ok(s), Ok(sc)) = (&r.members, &r.sso, &r.scim) {
        findings.extend(audit::directory(m, s, sc));
    }
    let findings = audit::sorted(findings);
    let unread = r.unread();

    if render::is_json() {
        render::print_json(&json!({
            "account": {
                "id": r.account.get("id"),
                "name": r.account.get("name"),
                "enforceTwoFactor": r.account.get("settings")
                    .and_then(|s| s.get("enforce_twofactor")),
            },
            "counts": {
                "members": r.members.as_ref().map(Vec::len).ok(),
                "accountTokens": r.account_tokens.as_ref().map(Vec::len).ok(),
                "userTokens": r.user_tokens.as_ref().map(Vec::len).ok(),
                "ssoConnectors": r.sso.as_ref().map(Vec::len).ok(),
                "scimUsers": r.scim.as_ref().map(Vec::len).ok(),
            },
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
            "unread": unread.iter()
                .map(|(area, path, why)| json!({"area": area, "path": path, "reason": why}))
                .collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading(&format!(
        "Identity of {}",
        r.account
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("this account")
    ));
    render::pairs(&[
        ("members", count_or_unread(&r.members)),
        ("account tokens", count_or_unread(&r.account_tokens)),
        ("user tokens", count_or_unread(&r.user_tokens)),
        ("sso", count_or_unread(&r.sso)),
        ("scim users", count_or_unread(&r.scim)),
        ("iam groups", count_or_unread(&r.groups)),
        ("oauth clients", count_or_unread(&r.oauth)),
    ]);

    render::heading("Findings");
    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    render::findings(&rows);
    render::count(findings.len(), "finding");

    if !findings.is_empty() {
        ui::gap();
        for (sev, n) in audit::tally(&findings) {
            ui::info(&format!("{n} {sev}"));
        }
    }

    // Printed last and never omitted: a report that does not say where it
    // stopped looking reads as though it looked everywhere.
    if !unread.is_empty() {
        render::heading("Not read");
        let rows: Vec<Value> = unread
            .iter()
            .map(|(area, path, why)| json!({"area": area, "path": path, "reason": why}))
            .collect();
        render::list(&rows, render::UNREAD_COLS);
        ui::gap();
        ui::warning(&format!(
            "{} reads were refused; those areas are unaudited, not clean",
            unread.len()
        ));
    }
}

/// `"7"`, or a word saying the number is unknown rather than zero.
fn count_or_unread<T>(r: &Result<Vec<T>, String>) -> String {
    match r {
        Ok(v) => v.len().to_string(),
        Err(_) => "not readable".to_string(),
    }
}

// ---- the detail views -------------------------------------------------------

fn members(r: &Reads) {
    let Ok(members) = &r.members else {
        refused("members", &r.members);
        return;
    };

    let rows: Vec<Value> = members
        .iter()
        .map(|m| {
            let roles: Vec<String> = m
                .get("roles")
                .and_then(Value::as_array)
                .map(|rs| {
                    rs.iter()
                        .filter_map(|x| x.get("name").and_then(Value::as_str))
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();
            json!({
                "email": m.get("user").and_then(|u| u.get("email")).or_else(|| m.get("email")),
                "status": m.get("status"),
                "twoFactor": m.get("user")
                    .and_then(|u| u.get("two_factor_authentication_enabled")),
                "roles": if roles.is_empty() {
                    // A member with no legacy role is on the IAM model; saying
                    // "none" would read as having no access at all.
                    Value::String(format!("{} IAM policies", m.get("policies")
                        .and_then(Value::as_array).map(Vec::len).unwrap_or(0)))
                } else {
                    Value::String(roles.join(", "))
                },
                "id": m.get("id"),
            })
        })
        .collect();

    render::heading("Members");
    render::list(&rows, render::MEMBER_COLS);
    render::count(members.len(), "member");
    observe(audit::members(&r.account, members));
}

fn tokens(r: &Reads) {
    for (store, read) in [
        ("Account-owned tokens", &r.account_tokens),
        ("User-owned tokens", &r.user_tokens),
    ] {
        render::heading(store);
        match read {
            Err(e) => {
                if !render::is_json() {
                    ui::warning(&format!("not readable: {}", one_line(e)));
                }
            }
            Ok(list) => {
                let rows: Vec<Value> = list.iter().map(token_row).collect();
                render::list(&rows, render::TOKEN_COLS);
                render::count(list.len(), "token");
                observe(audit::tokens(
                    list,
                    if store.starts_with("Account") {
                        "account-owned"
                    } else {
                        "user-owned"
                    },
                ));
            }
        }
    }
}

fn token_row(t: &Value) -> Value {
    let policies = t.get("policies").and_then(Value::as_array);
    let writes = policies
        .map(|ps| {
            ps.iter()
                .flat_map(|p| {
                    p.get("permission_groups")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|g| g.get("name").and_then(Value::as_str).map(str::to_string))
                .any(|n| !n.ends_with(" Read"))
        })
        .unwrap_or(false);

    json!({
        "name": t.get("name"),
        "status": t.get("status"),
        "expires": t.get("expires_on").cloned().unwrap_or(Value::String("never".into())),
        "lastUsed": t.get("last_used_on").cloned().unwrap_or(Value::String("never".into())),
        "access": if writes { "write" } else { "read" },
        "policies": policies.map(Vec::len).unwrap_or(0),
        "id": t.get("id"),
    })
}

fn access(r: &Reads) {
    render::heading("Single sign-on");
    match &r.sso {
        Err(e) => ui::warning(&format!("not readable: {}", one_line(e))),
        Ok(v) if v.is_empty() => {
            ui::info("no SSO connector; members sign in with their own credentials")
        }
        Ok(v) => render::list_auto(v),
    }

    render::heading("Directory provisioning (SCIM)");
    match &r.scim {
        Err(e) => ui::warning(&format!("not readable: {}", one_line(e))),
        Ok(v) if v.is_empty() => ui::info(
            "no SCIM users; nothing removes account access when someone leaves the directory",
        ),
        Ok(v) => {
            let rows: Vec<Value> = v
                .iter()
                .map(|u| {
                    json!({
                        "user": u.get("userName").or_else(|| u.get("displayName")),
                        "active": u.get("active"),
                        "id": u.get("id"),
                    })
                })
                .collect();
            render::list(&rows, render::SCIM_COLS);
            render::count(v.len(), "directory user");
        }
    }

    render::heading("Scoped access (IAM groups)");
    match &r.groups {
        Err(e) => ui::warning(&format!("not readable: {}", one_line(e))),
        Ok(v) if v.is_empty() => {
            ui::info("no user groups; members hold roles or policies directly")
        }
        Ok(v) => render::list_auto(v),
    }

    render::heading("OAuth clients");
    match &r.oauth {
        Err(e) => ui::warning(&format!("not readable: {}", one_line(e))),
        Ok(v) if v.is_empty() => ui::info("no third-party application holds delegated access"),
        Ok(v) => render::list_auto(v),
    }

    if let (Ok(m), Ok(s), Ok(sc)) = (&r.members, &r.sso, &r.scim) {
        observe(audit::directory(m, s, sc));
    }
}

/// Print the findings a detail view produced, under the table they belong to.
fn observe(findings: Vec<Finding>) {
    if render::is_json() || findings.is_empty() {
        return;
    }
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

fn refused<T>(what: &str, r: &Result<T, String>) {
    if let Err(e) = r {
        ui::warning(&format!("{what} is not readable: {}", one_line(e)));
    }
}

/// Read everything this plane needs, for a snapshot.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    gather(c, &account).await.map(|_| ())
}
