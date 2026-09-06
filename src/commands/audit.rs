//! `audit` — every plane, one graded document, one exit code.
//!
//! The commands this calls each answer a question about one part of an account.
//! This one answers the question somebody actually asks: *is anything wrong
//! here, and what.*
//!
//! Two properties matter more than the report's shape:
//!
//! - **An exit code a gate can act on.** `--fail-on` decides at which severity
//!   the process exits non-zero, and it exits `2` rather than `1` so a pipeline
//!   can tell "the audit found things" from "the tool broke".
//! - **What was not read is part of the answer.** Every refusal is collected
//!   from the same recorder a [snapshot](super::snapshot) uses, so no plane can
//!   quietly contribute an empty finding list because its reads were denied.

use std::collections::BTreeMap;

use anyhow::Result;
use clap::Args;
use serde_json::{json, Value};

use crate::audit::{self as checks, Finding, Severity};
use crate::cf::{esc, record, scope, Client};
use crate::cli::Ctx;
use crate::commands;
use crate::ui::{self, render};

/// Exit code when findings reach the `--fail-on` threshold.
///
/// Deliberately not `1`: that is what every other failure uses, and a gate that
/// cannot tell a finding from a crash will eventually be switched off.
const FOUND: i32 = 2;

#[derive(Args, Debug)]
pub struct AuditArgs {
    /// Exit with code 2 when a finding reaches this severity
    #[arg(long, default_value = "never", value_parser = ["high", "medium", "low", "info", "never"], value_name = "SEVERITY")]
    pub fail_on: String,

    /// Print every finding rather than the worst of each severity
    #[arg(long)]
    pub full: bool,

    /// Include what `enrich` already looked up from outside the account
    ///
    /// Reads only held results and never spends mlab quota; run `enrich` to
    /// fetch them.
    #[arg(long)]
    pub enrich: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &AuditArgs) -> Result<i32> {
    let account = scope::account(c, &ctx.profile.account).await?;
    // One cached call, so the report is headed by the name somebody chose
    // rather than by thirty-two hex characters.
    let account_name = c
        .cached(&format!("/accounts/{}", esc(&account)), &[])
        .await
        .ok()
        .map(|v| {
            v.get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string()
        })
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| account.clone());

    // The recorder gives one uniform account of what was refused, across every
    // plane, without each one having to keep its own list.
    let recorder = std::sync::Arc::new(record::Recorder::new());
    c.record_into(recorder.clone());

    let mut findings = Vec::new();
    let mut broken = Vec::new();
    for (plane, result) in [
        ("identity", commands::identity::findings(c, ctx).await),
        ("dns", commands::dns::findings(c, ctx).await),
        ("posture", commands::posture::findings(c, ctx).await),
        ("tls", commands::tls::findings(c, ctx).await),
        ("platform", commands::platform::findings(c, ctx).await),
        ("zerotrust", commands::zerotrust::findings(c, ctx).await),
        ("egress", commands::egress::findings(c, ctx).await),
        ("network", commands::network::findings(c, ctx).await),
    ] {
        match result {
            Ok(f) => findings.extend(f),
            // A plane that fails outright is named and does not stop the rest:
            // seven planes reported is worth more than none.
            Err(e) => broken.push(format!("{plane}: {}", one_line(&e))),
        }
    }

    // The outside view, when there is one to read. Opt-in and held-only: this
    // command spends no quota, so a target nobody has looked up yet is counted
    // as unread rather than fetched.
    let mut not_enriched = 0usize;
    if a.enrich {
        let zones = commands::zones_in_scope(c, ctx).await?;
        match commands::enrich::held_findings(c, ctx, &zones, 30).await {
            Ok((f, missing)) => {
                findings.extend(f);
                not_enriched = missing;
            }
            Err(e) => broken.push(format!("enrich: {}", one_line(&e))),
        }
    }
    let findings = checks::sorted(findings);
    let unread = unread_from(&recorder);

    let threshold = threshold(&a.fail_on);
    let tripped = threshold.is_some_and(|t| findings.iter().any(|f| f.severity >= t));

    if render::is_json() {
        render::print_json(&json!({
            "account": account,
            "zone": ctx.profile.zone,
            "takenAt": crate::cf::iso8601(now()),
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
            "counts": checks::tally(&findings).into_iter()
                .map(|(s, n)| (s.to_string(), n))
                .collect::<BTreeMap<_, _>>(),
            "unread": unread.iter()
                .map(|(what, why, n)| json!({
                    "endpoint": what,
                    "reason": why,
                    "reads": n,
                    "cause": if is_entitlement(why) { "plan" } else { "permission" },
                }))
                .collect::<Vec<_>>(),
            "planesFailed": broken,
            "notEnriched": not_enriched,
            "failOn": a.fail_on,
            "exitCode": if tripped { FOUND } else { 0 },
        }));
        return Ok(if tripped { FOUND } else { 0 });
    }

    render::heading(&format!(
        "Audit of {}",
        if ctx.profile.zone.is_empty() {
            account_name.clone()
        } else {
            ctx.profile.zone.clone()
        }
    ));

    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    let shown: Vec<Value> = if a.full { rows.clone() } else { trimmed(&rows) };
    render::findings(&shown);
    if shown.len() != rows.len() {
        ui::gap();
        ui::info(&format!(
            "showing {} of {} findings; --full prints the rest",
            shown.len(),
            rows.len()
        ));
    }

    render::heading("Summary");
    let mut pairs: Vec<(&str, String)> = checks::tally(&findings)
        .into_iter()
        .map(|(s, n)| (label(s), n.to_string()))
        .collect();
    if findings.is_empty() {
        pairs.push(("findings", "none".to_string()));
    }
    pairs.push((
        "not read",
        unread.iter().map(|(_, _, n)| n).sum::<usize>().to_string(),
    ));
    if a.enrich {
        // Same rule as "not read", for the same reason: a target the outside
        // view never covered must not read as a target it found nothing on.
        pairs.push(("not looked up outside", not_enriched.to_string()));
    }
    render::pairs(&pairs);

    if a.enrich && not_enriched > 0 {
        ui::gap();
        ui::info(&format!(
            "{not_enriched} {} no held mlab result; `enrich` looks them up",
            if not_enriched == 1 {
                "target has"
            } else {
                "targets have"
            }
        ));
    }

    // Printed last and never omitted, on every plane at once. An audit that
    // does not say where it stopped looking reads as though it looked
    // everywhere.
    if !unread.is_empty() {
        render::heading("Not read");
        let rows: Vec<Value> = unread
            .iter()
            .map(|(what, why, n)| {
                json!({
                    "endpoint": what,
                    "reads": n,
                    "cause": if is_entitlement(why) { "plan" } else { "permission" },
                    "reason": why,
                })
            })
            .collect();
        render::list(&rows, render::AUDIT_UNREAD_COLS);
        ui::gap();

        // A refusal for the credential and a refusal for the plan are different
        // facts, and only one of them is a gap somebody can close.
        let (plan, denied): (Vec<_>, Vec<_>) =
            unread.iter().partition(|(_, why, _)| is_entitlement(why));
        if !denied.is_empty() {
            ui::warning(&format!(
                "{} {} refused; those areas are unaudited, not clean",
                denied.len(),
                if denied.len() == 1 {
                    "endpoint was"
                } else {
                    "endpoints were"
                }
            ));
        }
        if !plan.is_empty() {
            ui::info(&format!(
                "{} more {} not included in this account's plan",
                plan.len(),
                if plan.len() == 1 {
                    "endpoint is"
                } else {
                    "endpoints are"
                }
            ));
        }
    }

    if !broken.is_empty() {
        ui::gap();
        ui::warning(&format!(
            "{} {} could not run at all: {}",
            broken.len(),
            if broken.len() == 1 { "plane" } else { "planes" },
            broken.join("; ")
        ));
    }

    if tripped {
        ui::gap();
        ui::warning(&format!(
            "exiting {FOUND}: a finding reached the --fail-on threshold of {}",
            a.fail_on
        ));
    }
    Ok(if tripped { FOUND } else { 0 })
}

/// The severity at which the process should fail, if any.
fn threshold(name: &str) -> Option<Severity> {
    match name {
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "info" => Some(Severity::Info),
        _ => None,
    }
}

fn label(s: Severity) -> &'static str {
    match s {
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// The worst few of each severity, so a first look fits a screen.
///
/// Info is dropped entirely from the short view: it is context for a finding
/// above it, and forty lines of context ahead of two high findings is how a
/// report stops being read.
fn trimmed(rows: &[Value]) -> Vec<Value> {
    const PER_SEVERITY: usize = 5;
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    rows.iter()
        .filter(|r| r["severity"] != "info")
        .filter(|r| {
            let n = seen
                .entry(r["severity"].as_str().unwrap_or_default().to_string())
                .or_default();
            *n += 1;
            *n <= PER_SEVERITY
        })
        .cloned()
        .collect()
}

/// Whether a refusal is the plan rather than the credential.
///
/// Only claimed where the API says so in as many words. Guessing at it from a
/// status code would turn "you cannot look" into "you do not have this", which
/// is the more comfortable of the two and the wrong one to assume.
fn is_entitlement(why: &str) -> bool {
    let m = why.to_ascii_lowercase();
    m.contains("plan level") || m.contains("feature not enabled")
}

/// The refusals, one row per endpoint shape rather than per object.
fn unread_from(recorder: &record::Recorder) -> Vec<(String, String, usize)> {
    let mut grouped: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (request, value) in recorder.take() {
        let Some(why) = value
            .get(record::UNREAD)
            .and_then(Value::as_str)
            .filter(|_| record::is_unread(&value))
        else {
            continue;
        };
        *grouped
            .entry((generalise(&request), why.to_string()))
            .or_default() += 1;
    }
    let mut rows: Vec<(String, String, usize)> = grouped
        .into_iter()
        .map(|((what, why), n)| (what, why, n))
        .collect();
    // Most-repeated first: nineteen refusals of one endpoint is the bigger gap.
    rows.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// A request with its object ids replaced by a placeholder.
///
/// Nineteen zones refusing the same read are one gap in the audit, not
/// nineteen, and a report that lists them separately buries every other gap
/// underneath.
fn generalise(request: &str) -> String {
    request
        .split('/')
        .map(|seg| {
            let (head, tail) = match seg.split_once('=') {
                Some((k, v)) => (Some(k), v),
                None => (None, seg),
            };
            let replaced = if is_id(tail) { "{id}" } else { tail };
            match head {
                Some(k) => format!("{k}={replaced}"),
                None => replaced.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Whether a path segment is an object identifier rather than a route name.
fn is_id(seg: &str) -> bool {
    // A 32-character hex id, or the dashed UUID the tunnel endpoints use.
    (seg.len() == 32 && seg.chars().all(|c| c.is_ascii_hexdigit()))
        || (seg.len() == 36
            && seg.matches('-').count() == 4
            && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn one_line(e: &anyhow::Error) -> String {
    format!("{e:#}")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_threshold_of_never_lets_everything_through() {
        assert!(threshold("never").is_none());
        assert_eq!(threshold("high"), Some(Severity::High));
        assert_eq!(threshold("info"), Some(Severity::Info));
    }

    #[test]
    fn the_threshold_is_at_or_above_rather_than_exactly() {
        // `--fail-on medium` has to trip on a high finding too, or a gate
        // catches the middle of the scale and misses the top of it.
        let high = Severity::High;
        assert!(high >= threshold("medium").unwrap());
        assert!(high >= threshold("high").unwrap());
        assert!(!(Severity::Low >= threshold("medium").unwrap()));
    }

    #[test]
    fn object_ids_are_generalised_so_one_gap_is_one_row() {
        assert_eq!(
            generalise("LIST /zones/1a2b3c4d5e6f708192a3b4c5d6e7f809/logpush/jobs"),
            "LIST /zones/{id}/logpush/jobs"
        );
        assert_eq!(
            generalise("GET /accounts/a1b2c3d4e5f60718293a4b5c6d7e8f90/cfd_tunnel/1a2b3c4d-5e6f-7081-92a3-b4c5d6e7f809/configurations"),
            "GET /accounts/{id}/cfd_tunnel/{id}/configurations"
        );
        assert_eq!(
            generalise("LIST /zones account.id=a1b2c3d4e5f60718293a4b5c6d7e8f90"),
            "LIST /zones account.id={id}"
        );
    }

    #[test]
    fn a_route_name_is_not_mistaken_for_an_identifier() {
        assert_eq!(generalise("LIST /accounts"), "LIST /accounts");
        assert_eq!(
            generalise("GET /zones/example.com/dnssec"),
            "GET /zones/example.com/dnssec"
        );
        assert!(!is_id("dns_records"));
        assert!(!is_id("1a2b3c4d5e6f708192a3b4c5d6e7f80"), "31 characters");
    }

    #[test]
    fn the_plan_and_the_credential_are_different_refusals() {
        assert!(is_entitlement(
            "API error 400 [1011]: Plan level does not allow custom certificates"
        ));
        assert!(is_entitlement("403 [1101]: forbidden: feature not enabled"));
        assert!(
            !is_entitlement("API error 403 [9109]: Unauthorized to access requested resource"),
            "a permission refusal must not be reported as a price list"
        );
        assert!(
            !is_entitlement("404 could not find entrypoint rules"),
            "and neither must a phase that is simply not configured"
        );
    }

    #[test]
    fn identical_refusals_across_objects_collapse_into_one_row() {
        let r = record::Recorder::new();
        for id in [
            "aaaa1111bbbb2222cccc3333dddd4444",
            "bbbb1111cccc2222dddd3333eeee4444",
        ] {
            r.refusal(
                &format!("LIST /zones/{id}/logpush/jobs"),
                "403 Authentication error",
            );
        }
        r.refusal(
            "LIST /accounts/{id}/logs/control/cmb/config",
            "401 Unauthorized",
        );
        r.body("LIST /zones", &json!([]));

        let rows = unread_from(&r);
        assert_eq!(rows.len(), 2, "two gaps, not three refusals and a body");
        assert_eq!(rows[0].0, "LIST /zones/{id}/logpush/jobs");
        assert_eq!(rows[0].2, 2, "and it says how many objects it covered");
    }

    #[test]
    fn the_short_view_keeps_the_worst_and_drops_the_context() {
        let rows: Vec<Value> = (0..8)
            .map(|i| json!({"severity": "high", "area": "x", "finding": format!("h{i}")}))
            .chain(
                (0..3)
                    .map(|i| json!({"severity": "info", "area": "x", "finding": format!("i{i}")})),
            )
            .collect();
        let short = trimmed(&rows);
        assert_eq!(short.len(), 5, "five of each severity");
        assert!(
            short.iter().all(|r| r["severity"] != "info"),
            "info is context for a finding above it, not a finding"
        );
    }
}
