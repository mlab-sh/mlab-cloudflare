//! `egress` and `alerts` — where the request data goes, and whether anyone is
//! told when something breaks.
//!
//! Two questions in one plane, and they fail in opposite ways. Logpush is
//! configured once and then invisible: the destination may belong to a vendor
//! whose contract expired, and a job that stops working leaves everyone
//! believing they still have logs. Notification policies are the reverse — they
//! are opt-in and per alert type, so the default state is silence, and a
//! silenced or webhook-broken policy looks identical to a working one.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Alerting, Egress, Finding};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum EgressCmd {
    /// Every Logpush job, account-level and zone-level
    Jobs,
    /// Whether raw logs are retained, per zone
    Retention,
}

#[derive(Subcommand, Debug)]
pub enum AlertsCmd {
    /// The notification policies that exist
    Policies,
    /// Which questions nothing on this account answers
    Coverage,
    /// Where the alerts are pointed, and whether they arrive
    Destinations,
}

// ---- egress -----------------------------------------------------------------

pub async fn run_egress(c: &Client, ctx: &Ctx, cmd: Option<EgressCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let e = gather_egress(c, ctx, &account).await?;

    if !e.jobs_readable && !render::is_json() {
        // Said before anything else, because everything below is conditional
        // on it: Logpush needs its own permission, and without it this half of
        // the plane is unaudited rather than clean.
        ui::warning("Logpush is not readable with this credential; it needs the Logs permission");
    }

    match cmd {
        Some(EgressCmd::Jobs) => jobs(&e),
        Some(EgressCmd::Retention) => retention(&e),
        None => egress_report(&e),
    }
    Ok(())
}

async fn gather_egress(c: &Client, ctx: &Ctx, account: &str) -> Result<Egress> {
    let acct = format!("/accounts/{}", esc(account));

    let (account_jobs, residency) = ui::spin("Reading Logpush", async {
        let (a, b) = (
            format!("{acct}/logpush/jobs"),
            format!("{acct}/logs/control/cmb/config"),
        );
        tokio::join!(c.cached_list(&a, &[], None), c.cached(&b, &[]))
    })
    .await;

    let mut unread = Vec::new();
    let readable = account_jobs.is_ok();
    if let Err(e) = &account_jobs {
        unread.push(("/accounts/{id}/logpush/jobs".to_string(), one_line(e)));
    }
    if let Err(e) = &residency {
        unread.push((
            "/accounts/{id}/logs/control/cmb/config".to_string(),
            one_line(e),
        ));
    }
    let mut jobs: Vec<(String, Value)> = account_jobs
        .unwrap_or_default()
        .into_iter()
        .map(|j| ("account".to_string(), j))
        .collect();

    // Zone-level jobs are a separate store from account-level ones, and it is
    // easy to have logs configured at one level and assume the other.
    let zones = crate::commands::zones_in_scope(c, ctx)
        .await
        .unwrap_or_default();
    let mut retention = Vec::new();
    let (mut zone_job_errors, mut retention_errors) = (Vec::new(), Vec::new());
    for z in &zones {
        let (name, id) = (str_of(z, "name"), str_of(z, "id"));
        let (jobs_p, flag_p) = (
            format!("/zones/{}/logpush/jobs", esc(&id)),
            format!("/zones/{}/logs/control/retention/flag", esc(&id)),
        );
        let (zj, flag) = ui::spin(&format!("Reading {name}"), async {
            tokio::join!(c.cached_list(&jobs_p, &[], None), c.cached(&flag_p, &[]))
        })
        .await;

        if let Err(e) = &zj {
            zone_job_errors.push(one_line(e));
        }
        jobs.extend(
            zj.unwrap_or_default()
                .into_iter()
                .map(|j| (name.clone(), j)),
        );
        // Only zones whose flag was actually read: an unreadable one is not a
        // zone with retention off.
        match flag {
            Ok(f) => {
                if let Some(on) = f.get("flag").and_then(Value::as_bool) {
                    retention.push((name, on));
                }
            }
            Err(e) => retention_errors.push(one_line(&e)),
        }
    }

    // Nineteen identical refusals are one fact, not nineteen.
    if let Some(why) = zone_job_errors.first() {
        unread.push((
            format!(
                "/zones/{{id}}/logpush/jobs ({} zones)",
                zone_job_errors.len()
            ),
            why.clone(),
        ));
    }
    if let Some(why) = retention_errors.first() {
        unread.push((
            format!(
                "/zones/{{id}}/logs/control/retention/flag ({} zones)",
                retention_errors.len()
            ),
            why.clone(),
        ));
    }

    Ok(Egress {
        jobs,
        jobs_readable: readable,
        residency: residency.ok(),
        retention,
        unread,
    })
}

/// Collapse a multi-line API error to the sentence that names the cause.
fn one_line(e: &anyhow::Error) -> String {
    format!("{e:#}")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn egress_report(e: &Egress) {
    let findings = audit::sorted(audit::egress(e));

    if render::is_json() {
        render::print_json(&json!({
            "logpushReadable": e.jobs_readable,
            "jobs": e.jobs.len(),
            "retentionOn": e.retention.iter().filter(|(_, on)| *on).count(),
            "retentionRead": e.retention.len(),
            "dataResidency": e.residency,
            "unread": e.unread.iter()
                .map(|(what, why)| json!({"path": what, "reason": why}))
                .collect::<Vec<_>>(),
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading("Where the data goes");
    render::pairs(&[
        (
            "logpush jobs",
            if e.jobs_readable {
                e.jobs.len().to_string()
            } else {
                "not readable".to_string()
            },
        ),
        (
            "log retention",
            format!(
                "{} of {} zones read",
                e.retention.iter().filter(|(_, on)| *on).count(),
                e.retention.len()
            ),
        ),
        (
            "data residency",
            match &e.residency {
                Some(r) => str_of(r, "regions"),
                None => "not readable".to_string(),
            },
        ),
    ]);

    render::heading("Findings");
    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    render::findings(&rows);
    render::count(findings.len(), "finding");
    tally(&findings);

    // Printed last and never omitted. An empty findings list on this plane
    // usually means nothing was looked at, and a report that does not say so
    // reads as a clean bill of health issued on no evidence.
    if !e.unread.is_empty() {
        render::heading("Not read");
        let rows: Vec<Value> = e
            .unread
            .iter()
            .map(|(what, why)| json!({"path": what, "reason": why}))
            .collect();
        render::list(&rows, render::UNREAD_EGRESS_COLS);
        ui::gap();
        ui::warning(&format!(
            "{} {} refused; this plane is unaudited, not clean",
            e.unread.len(),
            if e.unread.len() == 1 {
                "read was"
            } else {
                "reads were"
            }
        ));
    }
}

fn jobs(e: &Egress) {
    let rows: Vec<Value> = e
        .jobs
        .iter()
        .map(|(scope, j)| {
            json!({
                "scope": scope,
                "name": j.get("name"),
                "dataset": j.get("dataset"),
                "destination": audit::destination_of(&str_of(j, "destination_conf")),
                "on": j.get("enabled"),
                "error": j.get("last_error"),
            })
        })
        .collect();

    render::heading("Logpush jobs");
    render::list(&rows, render::LOGPUSH_COLS);
    render::count(rows.len(), "job");
    if !render::is_json() && !e.jobs.is_empty() {
        ui::gap();
        // A destination string carries credentials in its query for some
        // backends, so only the scheme and host are ever shown.
        ui::info("destinations are shown as scheme and host only; the rest of the string can carry credentials");
    }
    observe(audit::egress(e));
}

fn retention(e: &Egress) {
    let rows: Vec<Value> = e
        .retention
        .iter()
        .map(|(z, on)| json!({"zone": z, "retention": if *on { "on" } else { "off" }}))
        .collect();
    render::heading("Raw log retention");
    render::list(&rows, render::RETENTION_COLS);
    render::count(rows.len(), "zone");
    observe(audit::egress(e));
}

// ---- alerts -----------------------------------------------------------------

pub async fn run_alerts(c: &Client, ctx: &Ctx, cmd: Option<AlertsCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let a = gather_alerts(c, &account).await?;

    match cmd {
        Some(AlertsCmd::Policies) => policies(&a),
        Some(AlertsCmd::Coverage) => coverage(&a),
        Some(AlertsCmd::Destinations) => destinations(&a),
        None => alerts_report(&a),
    }
    Ok(())
}

async fn gather_alerts(c: &Client, account: &str) -> Result<Alerting> {
    let base = format!("/accounts/{}/alerting/v3", esc(account));
    let p = |x: &str| format!("{base}/{x}");

    let (policies, available, webhooks, pagerduty, silences, history) =
        ui::spin("Reading notifications", async {
            let paths = (
                p("policies"),
                p("available_alerts"),
                p("destinations/webhooks"),
                p("destinations/pagerduty"),
                p("silences"),
                p("history"),
            );
            tokio::join!(
                c.cached_list(&paths.0, &[], None),
                c.cached(&paths.1, &[]),
                c.cached_list(&paths.2, &[], None),
                c.cached_list(&paths.3, &[], None),
                c.cached_list(&paths.4, &[], None),
                c.cached_list(&paths.5, &[], None),
            )
        })
        .await;

    Ok(Alerting {
        policies: policies.unwrap_or_default(),
        // The catalogue arrives grouped by product category, and what matters
        // is the flat set of types this account can receive.
        available: available
            .ok()
            .and_then(|v| v.as_object().cloned())
            .map(|groups| {
                groups
                    .values()
                    .filter_map(Value::as_array)
                    .flatten()
                    .map(|a| (str_of(a, "type"), str_of(a, "display_name")))
                    .filter(|(t, _)| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        webhooks: webhooks.unwrap_or_default(),
        pagerduty: pagerduty.unwrap_or_default(),
        silences: silences.unwrap_or_default(),
        history: history.unwrap_or_default(),
    })
}

fn alerts_report(a: &Alerting) {
    let findings = audit::sorted(audit::alerting(a));

    if render::is_json() {
        render::print_json(&json!({
            "policies": a.policies.len(),
            "availableTypes": a.available.len(),
            "webhooks": a.webhooks.len(),
            "silences": a.silences.len(),
            "recentlyFired": a.history.len(),
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading("Who is told");
    render::pairs(&[
        (
            "policies",
            format!("{} of {} alert types", a.policies.len(), a.available.len()),
        ),
        (
            "destinations",
            format!(
                "{} webhooks, {} PagerDuty",
                a.webhooks.len(),
                a.pagerduty.len()
            ),
        ),
        ("silenced", a.silences.len().to_string()),
        ("recently fired", a.history.len().to_string()),
    ]);

    render::heading("Findings");
    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    render::findings(&rows);
    render::count(findings.len(), "finding");
    tally(&findings);
}

fn policies(a: &Alerting) {
    let names: std::collections::BTreeMap<String, String> = a.available.iter().cloned().collect();
    let rows: Vec<Value> = a
        .policies
        .iter()
        .map(|p| {
            let t = str_of(p, "alert_type");
            json!({
                "policy": p.get("name"),
                "alert": names.get(&t).cloned().unwrap_or(t),
                "on": p.get("enabled"),
                "via": p.get("mechanisms").and_then(Value::as_object)
                    .map(|m| m.keys().cloned().collect::<Vec<_>>().join(", ")),
            })
        })
        .collect();

    render::heading("Notification policies");
    render::list(&rows, render::ALERT_POLICY_COLS);
    render::count(rows.len(), "policy");
    observe(audit::alerting(a));
}

fn coverage(a: &Alerting) {
    let subscribed: std::collections::BTreeSet<String> = a
        .policies
        .iter()
        .filter(|p| p.get("enabled").and_then(Value::as_bool) != Some(false))
        .map(|p| str_of(p, "alert_type"))
        .collect();

    let rows: Vec<Value> = a
        .available
        .iter()
        .map(|(t, name)| {
            json!({
                "alert": name,
                "type": t,
                "policy": if subscribed.contains(t) { "yes" } else { "" },
            })
        })
        .collect();

    render::heading("Every alert this account can receive");
    render::list(&rows, render::COVERAGE_COLS);
    render::count(rows.len(), "alert type");
    if !render::is_json() {
        ui::gap();
        ui::info(&format!(
            "{} of {} have a policy",
            subscribed.len(),
            a.available.len()
        ));
    }
    observe(audit::alerting(a));
}

fn destinations(a: &Alerting) {
    let rows: Vec<Value> = a
        .webhooks
        .iter()
        .map(|w| {
            json!({
                "kind": "webhook",
                "name": w.get("name"),
                "lastSuccess": w.get("last_success"),
                "lastFailure": w.get("last_failure"),
            })
        })
        .chain(a.pagerduty.iter().map(|p| {
            json!({"kind": "pagerduty", "name": p.get("name"),
                   "lastSuccess": Value::Null, "lastFailure": Value::Null})
        }))
        .collect();

    render::heading("Where the alerts are pointed");
    render::list(&rows, render::DESTINATION_COLS);
    render::count(rows.len(), "destination");
    if rows.is_empty() && !render::is_json() {
        ui::gap();
        ui::info("no webhook or PagerDuty destination; policies can still deliver by email");
    }

    if !a.silences.is_empty() {
        render::heading("Silenced");
        render::list_auto(&a.silences);
    }
    observe(audit::alerting(a));
}

// ---- shared -----------------------------------------------------------------

fn tally(findings: &[Finding]) {
    if render::is_json() || findings.is_empty() {
        return;
    }
    ui::gap();
    for (sev, n) in audit::tally(findings) {
        ui::info(&format!("{n} {sev}"));
    }
}

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

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Read everything both halves of this plane need, for a snapshot.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    gather_egress(c, ctx, &account).await?;
    gather_alerts(c, &account).await.map(|_| ())
}
