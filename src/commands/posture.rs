//! `posture` — what the edge is configured to do, and what has been carved out
//! of it.
//!
//! The question is never "is there a WAF" — there is. It is whether the rules
//! run, in which order, and what has been exempted from them. So the source of
//! truth here is the ruleset phase entrypoints, which return what actually
//! executes in order, rather than the ruleset list or the deprecated
//! `/firewall/rules` view of the same store.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Finding, Posture};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

/// The phases worth reading. `http_request_firewall_custom` is where the skips
/// live, `..._managed` is what they skip, `http_ratelimit` is usually empty and
/// that is the finding, and `http_config_settings` can change a zone setting
/// per request — which makes the settings blob a default rather than the truth.
const PHASES: [&str; 4] = [
    "http_request_firewall_custom",
    "http_request_firewall_managed",
    "http_ratelimit",
    "http_config_settings",
];

#[derive(Subcommand, Debug)]
pub enum PostureCmd {
    /// The settings that decide how the zone speaks TLS, per zone
    Settings,
    /// Every rule that executes, in the order it executes, per phase
    Rules,
    /// Code and raw ports published at the edge
    Edge,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<PostureCmd>) -> Result<()> {
    let zones = if ctx.profile.zone.is_empty() {
        let account = scope::account(c, &ctx.profile.account).await?;
        ui::spin(
            "Listing zones",
            c.cached_list("/zones", &[("account.id".to_string(), account)], None),
        )
        .await?
    } else {
        let id = scope::zone(c, &ctx.profile.zone).await?;
        vec![c.cached(&format!("/zones/{}", esc(&id)), &[]).await?]
    };

    let read = gather(c, &zones).await?;

    match cmd {
        Some(PostureCmd::Settings) => settings(&read),
        Some(PostureCmd::Rules) => rules(&read),
        Some(PostureCmd::Edge) => edge(&read),
        None => report(&read),
    }
    Ok(())
}

async fn gather(c: &Client, zones: &[Value]) -> Result<Vec<Posture>> {
    let mut out = Vec::with_capacity(zones.len());

    for (i, z) in zones.iter().enumerate() {
        let name = str_of(z, "name");
        let plan = z.get("plan").map(|p| str_of(p, "name")).unwrap_or_default();
        let base = format!("/zones/{}", esc(&str_of(z, "id")));
        let label = format!("Reading {name} ({}/{})", i + 1, zones.len());

        // Paths outlive the joins: a `&format!(...)` inside the macro would be
        // dropped while the future still borrows it.
        let settings_p = format!("{base}/settings");
        let phase_paths: Vec<String> = PHASES
            .iter()
            .map(|p| format!("{base}/rulesets/phases/{p}/entrypoint"))
            .collect();
        let (pr, sp, wr, sn, ps) = (
            format!("{base}/pagerules"),
            format!("{base}/spectrum/apps"),
            format!("{base}/workers/routes"),
            format!("{base}/snippets"),
            format!("{base}/page_shield"),
        );

        // Nine independent reads, issued together. Everything but the settings
        // is allowed to fail: a phase with no ruleset answers 404, and Spectrum
        // and Page Shield are entitlements rather than settings.
        let (settings, phases, readable_phases, pagerules, spectrum, routes, snippets, page_shield) = ui::spin(
            &label,
            async {
                let (settings, p0, p1, p2, p3, pagerules, spectrum, routes, snippets, shield) = tokio::join!(
                    c.cached_list(&settings_p, &[], None),
                    c.cached(&phase_paths[0], &[]),
                    c.cached(&phase_paths[1], &[]),
                    c.cached(&phase_paths[2], &[]),
                    c.cached(&phase_paths[3], &[]),
                    c.cached_list(&pr, &[], None),
                    c.cached_list(&sp, &[], None),
                    c.cached_list(&wr, &[], None),
                    c.cached_list(&sn, &[], None),
                    c.cached(&ps, &[]),
                );
                let mut phases = BTreeMap::new();
                let mut readable = BTreeSet::new();
                for (name, got) in PHASES.iter().zip([p0, p1, p2, p3]) {
                    // A readable but empty phase and an unreadable one are
                    // different facts: the second means the plan has no entry
                    // point to configure, not that nobody configured it.
                    if let Ok(e) = got {
                        readable.insert((*name).to_string());
                        let rules = e
                            .get("rules")
                            .and_then(Value::as_array)
                            .cloned()
                            .unwrap_or_default();
                        phases.insert((*name).to_string(), rules);
                    } else {
                        phases.insert((*name).to_string(), Vec::new());
                    }
                }
                (
                    settings,
                    phases,
                    readable,
                    pagerules.unwrap_or_default(),
                    spectrum.unwrap_or_default(),
                    routes.unwrap_or_default(),
                    snippets.unwrap_or_default(),
                    shield.ok(),
                )
            },
        )
        .await;

        // The settings call answers a dozen checks on its own, so a failure
        // there is a failure of the command rather than a gap in the report.
        let settings = settings?
            .into_iter()
            .filter_map(|s| {
                let id = str_of(&s, "id");
                (!id.is_empty()).then(|| (id, s.get("value").cloned().unwrap_or(Value::Null)))
            })
            .collect();

        out.push(Posture {
            name,
            plan,
            settings,
            phases,
            readable_phases,
            pagerules,
            spectrum,
            routes,
            snippets,
            page_shield,
        });
    }
    Ok(out)
}

// ---- the graded report ------------------------------------------------------

fn report(zones: &[Posture]) {
    let findings = audit::sorted(
        [
            audit::transport(zones),
            audit::enforcement(zones),
            audit::edge(zones),
        ]
        .concat(),
    );

    if render::is_json() {
        render::print_json(&json!({
            "zones": zones.iter().map(|z| json!({
                "name": z.name,
                "plan": z.plan,
                "ssl": z.settings.get("ssl"),
                "minTlsVersion": z.settings.get("min_tls_version"),
            })).collect::<Vec<_>>(),
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading(&format!(
        "Edge posture across {} {}",
        zones.len(),
        if zones.len() == 1 { "zone" } else { "zones" }
    ));
    render::pairs(&[
        ("zones", zones.len().to_string()),
        (
            "paid plans",
            format!(
                "{} of {}",
                zones
                    .iter()
                    .filter(|z| !z.plan.to_ascii_lowercase().contains("free"))
                    .count(),
                zones.len()
            ),
        ),
        (
            "custom rules",
            zones
                .iter()
                .map(|z| {
                    z.phases
                        .get("http_request_firewall_custom")
                        .map_or(0, Vec::len)
                })
                .sum::<usize>()
                .to_string(),
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

// ---- the listings -----------------------------------------------------------

fn settings(zones: &[Posture]) {
    let rows: Vec<Value> = zones
        .iter()
        .map(|z| {
            let hsts = z
                .settings
                .get("security_header")
                .and_then(|v| v.get("strict_transport_security"));
            json!({
                "zone": z.name,
                "plan": z.plan,
                "ssl": z.settings.get("ssl"),
                "minTls": z.settings.get("min_tls_version"),
                "hsts": match hsts.and_then(|h| h.get("enabled")).and_then(Value::as_bool) {
                    Some(true) => hsts
                        .and_then(|h| h.get("max_age"))
                        .and_then(Value::as_u64)
                        .map(|a| format!("{}d", a / 86_400))
                        .unwrap_or_else(|| "on".into()),
                    _ => "off".into(),
                },
                "https": z.settings.get("always_use_https"),
                "security": z.settings.get("security_level"),
                "dev": z.settings.get("development_mode"),
            })
        })
        .collect();

    render::heading("Zone settings");
    render::list(&rows, render::POSTURE_COLS);
    render::count(rows.len(), "zone");
    observe(audit::transport(zones));
}

fn rules(zones: &[Posture]) {
    for z in zones {
        render::heading(&format!("Rules on {}", z.name));
        let mut any = false;
        for (phase, rules) in &z.phases {
            if rules.is_empty() {
                continue;
            }
            any = true;
            render::heading(phase);
            // Order is the point: a broad rule above the blocks makes
            // everything below it decorative, and only the entry point knows it.
            let rows: Vec<Value> = rules
                .iter()
                .enumerate()
                .map(|(i, r)| {
                    json!({
                        "n": i + 1,
                        "action": r.get("action"),
                        "on": r.get("enabled"),
                        "description": r.get("description"),
                        "expression": r.get("expression"),
                    })
                })
                .collect();
            render::list(&rows, render::RULE_COLS);
        }
        if !any && !render::is_json() {
            ui::info("no rule executes in any phase read");
        }
        if !z.pagerules.is_empty() {
            render::heading("page rules (a separate engine, evaluated first)");
            render::list_auto(&z.pagerules);
        }
    }
    observe(audit::enforcement(zones));
}

fn edge(zones: &[Posture]) {
    let rows: Vec<Value> = zones
        .iter()
        .flat_map(|z| {
            let spectrum = z.spectrum.iter().map(move |a| {
                json!({
                    "zone": z.name,
                    "kind": "spectrum",
                    "what": a.get("protocol"),
                    "target": a.get("origin_direct").or_else(|| a.get("origin_dns")),
                })
            });
            let routes = z.routes.iter().map(move |r| {
                json!({
                    "zone": z.name,
                    "kind": "worker route",
                    "what": r.get("pattern"),
                    "target": r.get("script"),
                })
            });
            let snippets = z.snippets.iter().map(move |s| {
                json!({
                    "zone": z.name,
                    "kind": "snippet",
                    "what": s.get("snippet_name"),
                    "target": Value::Null,
                })
            });
            spectrum.chain(routes).chain(snippets).collect::<Vec<_>>()
        })
        .collect();

    render::heading("Code and ports at the edge");
    render::list(&rows, render::EDGE_COLS);
    render::count(rows.len(), "entry");
    observe(audit::edge(zones));
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
