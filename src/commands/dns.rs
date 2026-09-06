//! `dns` — what the account's zones point at, and what points nowhere.
//!
//! The densest plane on the platform, and the one that most benefits from
//! covering a whole account rather than one domain: a dangling record is
//! invisible in the zone it sits in and obvious across a portfolio.
//!
//! Cost is what shapes this module. A record listing is one call per zone and
//! answers most of the checks — including the whole of the mail posture, which
//! is MX and TXT records already in the set. DNSSEC and the zone hold are one
//! extra call each, so the views that do not need them do not pay for them.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Finding, Zone};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum DnsCmd {
    /// Every record, across the zones in scope
    Records,
    /// Records pointing at a third-party platform
    Takeover,
    /// Where the origin is published, and where private space is
    Exposure,
    /// SPF, DMARC and MX, per zone
    Mail,
    /// Domains registered at Cloudflare Registrar
    Domains,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<DnsCmd>) -> Result<()> {
    // The zone-scoped flag narrows to one zone; otherwise the unit is the
    // account, as everywhere else in the tool.
    let zones = crate::commands::zones_in_scope(c, ctx).await?;

    if matches!(cmd, Some(DnsCmd::Domains)) {
        return domains(c, ctx).await;
    }

    // Only the graded report needs the signing state and the hold.
    let deep = cmd.is_none();
    let read = gather(c, &zones, deep).await?;

    match cmd {
        Some(DnsCmd::Records) => records(&read),
        Some(DnsCmd::Takeover) => section("Takeover candidates", audit::takeover(&read), &read),
        Some(DnsCmd::Exposure) => section("Origin exposure", audit::exposure(&read), &read),
        Some(DnsCmd::Mail) => mail(&read),
        Some(DnsCmd::Domains) => unreachable!("handled above"),
        None => report(&read),
    }
    Ok(())
}

/// Fetch each zone's records, and optionally its signing state and hold.
async fn gather(c: &Client, zones: &[Value], deep: bool) -> Result<Vec<Zone>> {
    let mut out = Vec::with_capacity(zones.len());

    for (i, z) in zones.iter().enumerate() {
        let name = str_of(z, "name");
        let id = str_of(z, "id");
        let base = format!("/zones/{}", esc(&id));
        let label = format!("Reading {name} ({}/{})", i + 1, zones.len());

        // The three reads are independent, so they go out together: a zone
        // costs one round trip rather than three, which is the difference
        // between half a minute and ten seconds across a portfolio.
        //
        // DNSSEC and the hold are an entitlement on some plans and a setting on
        // others, so a refusal means "cannot say" — which is what `None`
        // carries into the checks.
        // The paths outlive the join: a `&format!(...)` inside the macro is a
        // temporary that would be dropped while the future still borrows it.
        let (recs, sec, held) = (
            format!("{base}/dns_records"),
            format!("{base}/dnssec"),
            format!("{base}/hold"),
        );
        let (records, dnssec, hold) = ui::spin(&label, async {
            if deep {
                let (r, d, h) = tokio::join!(
                    c.cached_list(&recs, &[], None),
                    c.cached(&sec, &[]),
                    c.cached(&held, &[]),
                );
                (r, d.ok(), h.ok())
            } else {
                (c.cached_list(&recs, &[], None).await, None, None)
            }
        })
        .await;
        let records = records?;

        out.push(Zone {
            name,
            id,
            records,
            dnssec,
            hold,
        });
    }
    Ok(out)
}

// ---- the graded report ------------------------------------------------------

fn report(zones: &[Zone]) {
    let findings = audit::sorted(
        [
            audit::takeover(zones),
            audit::exposure(zones),
            audit::namespace(zones),
            audit::mail(zones),
        ]
        .concat(),
    );
    let records: usize = zones.iter().map(|z| z.records.len()).sum();

    if render::is_json() {
        render::print_json(&json!({
            "zones": zones.iter().map(|z| json!({
                "name": z.name,
                "id": z.id,
                "records": z.records.len(),
                "dnssec": z.dnssec.as_ref().and_then(|d| d.get("status")),
            })).collect::<Vec<_>>(),
            "records": records,
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading(&format!(
        "DNS across {} {}",
        zones.len(),
        if zones.len() == 1 { "zone" } else { "zones" }
    ));
    render::pairs(&[
        ("zones", zones.len().to_string()),
        ("records", records.to_string()),
        (
            "signed",
            format!(
                "{} of {}",
                zones
                    .iter()
                    .filter(|z| z
                        .dnssec
                        .as_ref()
                        .map(|d| str_of(d, "status") == "active")
                        .unwrap_or(false))
                    .count(),
                zones.len()
            ),
        ),
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
}

/// One check's findings, under a heading of their own.
fn section(title: &str, findings: Vec<Finding>, zones: &[Zone]) {
    let findings = audit::sorted(findings);
    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    if render::is_json() {
        render::print_json(&Value::Array(rows));
        return;
    }
    render::heading(&format!(
        "{title}, across {} {}",
        zones.len(),
        if zones.len() == 1 { "zone" } else { "zones" }
    ));
    render::findings(&rows);
    render::count(findings.len(), "finding");
}

// ---- the listings -----------------------------------------------------------

fn records(zones: &[Zone]) {
    let rows: Vec<Value> = zones
        .iter()
        .flat_map(|z| {
            z.records.iter().map(move |r| {
                json!({
                    "name": r.get("name"),
                    "type": r.get("type"),
                    "content": r.get("content"),
                    "proxied": r.get("proxied"),
                    "ttl": r.get("ttl"),
                    "comment": r.get("comment"),
                })
            })
        })
        .collect();

    render::heading("Records");
    render::list(&rows, render::DNS_COLS);
    render::count(rows.len(), "record");

    if render::is_json() {
        return;
    }
    // Ownership metadata is the only thing in a record that says whether it can
    // be deleted, and a zone where nothing has it cannot answer that question.
    let commented = rows
        .iter()
        .filter(|r| {
            r.get("comment")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.is_empty())
        })
        .count();
    if commented == 0 && !rows.is_empty() {
        ui::gap();
        ui::info("no record carries a comment or tag, so nothing records who owns them");
    }
}

fn mail(zones: &[Zone]) {
    let rows: Vec<Value> = zones
        .iter()
        .map(|z| {
            let txt = |prefix: &str| -> Vec<String> {
                z.records
                    .iter()
                    .filter(|r| str_of(r, "type") == "TXT" && str_of(r, "name") == prefix)
                    .map(|r| str_of(r, "content"))
                    .collect()
            };
            let spf = txt(&z.name)
                .into_iter()
                .find(|c| c.to_ascii_lowercase().contains("v=spf1"));
            let dmarc = txt(&format!("_dmarc.{}", z.name)).into_iter().next();
            let mx = z
                .records
                .iter()
                .filter(|r| str_of(r, "type") == "MX")
                .count();
            json!({
                "zone": z.name,
                "mx": mx,
                "spf": spf.map(|s| policy(&s, &["-all", "~all", "?all", "+all"]))
                    .unwrap_or_else(|| "none".into()),
                "dmarc": dmarc.map(|s| policy(&s, &["p=reject", "p=quarantine", "p=none"]))
                    .unwrap_or_else(|| "none".into()),
            })
        })
        .collect();

    render::heading("Mail authentication");
    render::list(&rows, render::MAIL_COLS);
    render::count(rows.len(), "zone");
    observe(audit::mail(zones));
}

/// The strongest directive present in a policy record, for the column.
fn policy(record: &str, wanted: &[&str]) -> String {
    let lower = record.to_ascii_lowercase();
    wanted
        .iter()
        .find(|w| lower.contains(*w))
        .map(|w| w.to_string())
        .unwrap_or_else(|| "set".to_string())
}

async fn domains(c: &Client, ctx: &Ctx) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    // `/registrar/domains` is deprecated and answers an empty list rather than
    // an error, so an account with registrations reports none and the audit
    // finds nothing. `/registrar/registrations` is the canonical read, and it
    // pages by cursor.
    let path = format!("/accounts/{}/registrar/registrations", esc(&account));
    let domains = ui::spin(
        "Listing registered domains",
        c.cached_list_cursor(&path, &[], None),
    )
    .await?;

    let rows: Vec<Value> = domains
        .iter()
        .map(|d| {
            json!({
                "name": d.get("domain_name").or_else(|| d.get("name")),
                "status": d.get("status"),
                "expires": d.get("expires_at"),
                "autoRenew": d.get("auto_renew"),
                "locked": d.get("locked"),
                "privacy": d.get("privacy_mode"),
            })
        })
        .collect();

    render::heading("Registered domains");
    render::list(&rows, render::DOMAIN_COLS);
    render::count(domains.len(), "domain");

    if domains.is_empty() && !render::is_json() {
        ui::gap();
        // An empty list is not a finding: most domains are registered
        // elsewhere, and this endpoint only knows about Cloudflare Registrar.
        ui::info(
            "no domain is registered through Cloudflare Registrar; expiry and transfer lock \
             for domains held elsewhere cannot be read from this API",
        );
    }
    observe(audit::registrar(&domains, 60));
    Ok(())
}

/// Print findings under the table they belong to.
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

/// Every check in this plane, for the whole-account report.
pub(crate) async fn findings(c: &Client, ctx: &Ctx) -> Result<Vec<Finding>> {
    let zones = crate::commands::zones_in_scope(c, ctx).await?;
    let read = gather(c, &zones, true).await?;
    Ok([
        audit::takeover(&read),
        audit::exposure(&read),
        audit::namespace(&read),
        audit::mail(&read),
    ]
    .concat())
}

/// Read everything this plane needs, for a snapshot.
///
/// The findings are discarded on purpose: what a snapshot keeps is what the API
/// said, which the client records on the way past.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    findings(c, ctx).await.map(|_| ())
}
