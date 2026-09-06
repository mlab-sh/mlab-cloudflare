//! `zerotrust` — who reaches internal systems, and whether fleet traffic is
//! inspected at all.
//!
//! Where an account has this, it is usually the plane with the highest blast
//! radius: Access policies are the perimeter, Gateway policies are the egress
//! control, the device profile decides which traffic ever reaches Gateway, and
//! the tunnels decide what internal surface is reachable in the first place.
//!
//! One endpoint is deliberately never called. `/cfd_tunnel/{id}/token` returns
//! a live connector credential, and an audit has no use for the value — not
//! reading it is a stronger guarantee than redacting it, because it never
//! reaches the cache.

use anyhow::Result;
use clap::Subcommand;
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};

use crate::audit::{self, Finding, Tunnel, ZeroTrust};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum ZeroTrustCmd {
    /// Applications, the policies on them, and the service tokens
    Access,
    /// Egress policies, inspection, and what is logged
    Gateway,
    /// The device profile, the split tunnel, and posture rules
    Devices,
    /// Tunnels, their ingress rules, and the routes they advertise
    Tunnels,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<ZeroTrustCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let z = gather(c, &account).await?;

    // Zero Trust is absent from most accounts, and an empty plane is a fact
    // rather than a wall of findings.
    if !render::is_json() && is_empty(&z) {
        render::heading("Zero Trust");
        ui::info("no Access application, Gateway policy, tunnel or enrolled device profile");
        ui::info("this account does not use Zero Trust, which is not a finding");
        return Ok(());
    }

    match cmd {
        Some(ZeroTrustCmd::Access) => access(&z),
        Some(ZeroTrustCmd::Gateway) => gateway(&z),
        Some(ZeroTrustCmd::Devices) => devices(&z),
        Some(ZeroTrustCmd::Tunnels) => tunnels(&z),
        None => report(&z),
    }
    Ok(())
}

fn is_empty(z: &ZeroTrust) -> bool {
    z.apps.is_empty()
        && z.gateway_rules.is_empty()
        && z.tunnels.is_empty()
        && z.device_policies.is_empty()
        && z.gateway_config.is_none()
}

async fn gather(c: &Client, account: &str) -> Result<ZeroTrust> {
    let base = format!("/accounts/{}", esc(account));
    let p = |x: &str| format!("{base}/{x}");

    // Fifteen reads, together. Every one may fail: this whole plane is an
    // entitlement, and on an account without it they all will.
    let (
        apps,
        tokens,
        idps,
        rules,
        config,
        logging,
        policies,
        exclude,
        include,
        posture,
        tuns,
        routes,
        targets,
    ) = ui::spin("Reading Zero Trust", async {
        let paths = (
            p("access/apps"),
            p("access/service_tokens"),
            p("access/identity_providers"),
            p("gateway/rules"),
            p("gateway/configuration"),
            p("gateway/logging"),
            p("devices/policies"),
            p("devices/policy/exclude"),
            p("devices/policy/include"),
            p("devices/posture"),
            p("cfd_tunnel"),
            p("teamnet/routes"),
            p("infrastructure/targets"),
        );
        tokio::join!(
            c.cached_list(&paths.0, &[], None),
            c.cached_list(&paths.1, &[], None),
            c.cached_list(&paths.2, &[], None),
            c.cached_list(&paths.3, &[], None),
            c.cached(&paths.4, &[]),
            c.cached(&paths.5, &[]),
            c.cached_list(&paths.6, &[], None),
            c.cached_list(&paths.7, &[], None),
            c.cached_list(&paths.8, &[], None),
            c.cached_list(&paths.9, &[], None),
            c.cached_list(&paths.10, &[], None),
            c.cached_list(&paths.11, &[], None),
            c.cached_list(&paths.12, &[], None),
        )
    })
    .await;

    let tunnels = read_tunnels(c, &base, tuns.unwrap_or_default()).await;

    Ok(ZeroTrust {
        apps: apps.unwrap_or_default(),
        service_tokens: tokens.unwrap_or_default(),
        idps: idps.unwrap_or_default(),
        gateway_rules: rules.unwrap_or_default(),
        gateway_config: config.ok(),
        gateway_logging: logging.ok(),
        device_policies: policies.unwrap_or_default(),
        split_exclude: exclude.unwrap_or_default(),
        split_include: include.unwrap_or_default(),
        posture_rules: posture.unwrap_or_default(),
        tunnels,
        routes: routes.unwrap_or_default(),
        targets: targets.unwrap_or_default(),
    })
}

/// Each tunnel's ingress rules — the authoritative list of what the internet
/// can reach inside the network.
async fn read_tunnels(c: &Client, base: &str, listed: Vec<Value>) -> Vec<Tunnel> {
    let wanted: Vec<(String, String, String, usize)> = listed
        .iter()
        // A deleted tunnel keeps its record and serves nothing.
        .filter(|t| t.get("deleted_at").map(Value::is_null).unwrap_or(true))
        .map(|t| {
            (
                str_of(t, "id"),
                str_of(t, "name"),
                str_of(t, "status"),
                t.get("connections")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(0),
            )
        })
        .filter(|(id, ..)| !id.is_empty())
        .collect();

    let label = format!("Reading {} tunnels", wanted.len());
    ui::spin(&label, async {
        stream::iter(wanted)
            .map(|(id, name, status, connections)| async move {
                let path = format!("{base}/cfd_tunnel/{}/configurations", esc(&id));
                let config = c.cached(&path, &[]).await.ok();
                // A tunnel run from a local config file reports `source:
                // "local"` and no ingress; that is unread, not empty.
                let readable = config
                    .as_ref()
                    .map(|v| str_of(v, "source") == "cloudflare")
                    .unwrap_or(false);
                let ingress = config
                    .and_then(|v| {
                        v.get("config")
                            .and_then(|c| c.get("ingress"))
                            .and_then(Value::as_array)
                            .cloned()
                    })
                    .unwrap_or_default();
                Tunnel {
                    name,
                    status,
                    connections,
                    ingress,
                    ingress_readable: readable,
                }
            })
            .buffered(4)
            .collect()
            .await
    })
    .await
}

// ---- the graded report ------------------------------------------------------

fn report(z: &ZeroTrust) {
    let findings = audit::sorted(
        [
            audit::access(z),
            audit::gateway(z),
            audit::devices(z),
            audit::tunnels(z),
        ]
        .concat(),
    );

    if render::is_json() {
        render::print_json(&json!({
            "counts": {
                "applications": z.apps.len(),
                "serviceTokens": z.service_tokens.len(),
                "identityProviders": z.idps.len(),
                "gatewayRules": z.gateway_rules.len(),
                "devicePolicies": z.device_policies.len(),
                "postureRules": z.posture_rules.len(),
                "tunnels": z.tunnels.len(),
                "privateRoutes": z.routes.len(),
                "infrastructureTargets": z.targets.len(),
            },
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading("Zero Trust");
    render::pairs(&[
        ("applications", z.apps.len().to_string()),
        (
            "identity providers",
            format!(
                "{} ({} service tokens)",
                z.idps.len(),
                z.service_tokens.len()
            ),
        ),
        ("gateway policies", z.gateway_rules.len().to_string()),
        (
            "split tunnel",
            format!(
                "{} excluded, {} included",
                z.split_exclude.len(),
                z.split_include.len()
            ),
        ),
        (
            "tunnels",
            format!(
                "{} ({} internal services)",
                z.tunnels.len(),
                z.tunnels
                    .iter()
                    .map(|t| t
                        .ingress
                        .iter()
                        .filter(|r| r.get("hostname").is_some())
                        .count())
                    .sum::<usize>()
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

// ---- the listings -----------------------------------------------------------

fn access(z: &ZeroTrust) {
    let rows: Vec<Value> = z
        .apps
        .iter()
        .flat_map(|a| {
            let policies = a
                .get("policies")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let name = str_of(a, "name");
            let domain = str_of(a, "domain");
            let kind = str_of(a, "type");
            let session = str_of(a, "session_duration");
            policies
                .into_iter()
                .map(move |p| {
                    json!({
                        "application": name,
                        "type": kind,
                        "domain": domain,
                        "policy": p.get("name"),
                        "decision": p.get("decision"),
                        "admits": criteria(&p, "include"),
                        "requires": criteria(&p, "require"),
                        "session": session,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    render::heading("Access applications");
    render::list(&rows, render::ACCESS_COLS);
    render::count(z.apps.len(), "application");

    render::heading("Identity providers");
    let idps: Vec<Value> = z
        .idps
        .iter()
        .map(|i| {
            json!({
                "name": i.get("name"),
                "type": i.get("type"),
                "scim": i.get("scim_config").and_then(|c| c.get("enabled")),
            })
        })
        .collect();
    render::list(&idps, render::IDP_COLS);

    if !z.service_tokens.is_empty() {
        render::heading("Service tokens");
        render::list_auto(&z.service_tokens);
    }
    observe(audit::access(z));
}

/// The kinds of rule a policy names, which is what decides who gets in.
fn criteria(p: &Value, key: &str) -> String {
    p.get(key)
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter_map(|c| c.as_object().and_then(|o| o.keys().next().cloned()))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn gateway(z: &ZeroTrust) {
    render::heading("Gateway policies");
    if z.gateway_rules.is_empty() {
        if !render::is_json() {
            ui::info("no policy: Gateway decides nothing about the traffic it sees");
        }
    } else {
        let rows: Vec<Value> = z
            .gateway_rules
            .iter()
            .enumerate()
            .map(|(i, r)| {
                json!({
                    "n": i + 1,
                    "action": r.get("action"),
                    "on": r.get("enabled"),
                    "description": r.get("name"),
                    "expression": r.get("traffic").or_else(|| r.get("identity")),
                })
            })
            .collect();
        render::list(&rows, render::RULE_COLS);
        render::count(rows.len(), "policy");
    }

    if let Some(cfg) = &z.gateway_config {
        render::heading("Inspection");
        let s = |path: &[&str]| -> Value {
            let mut cur = cfg.get("settings");
            for k in path {
                cur = cur.and_then(|c| c.get(k));
            }
            cur.cloned().unwrap_or(Value::Null)
        };
        render::pairs(&[
            ("tls decryption", show(&s(&["tls_decrypt", "enabled"]))),
            ("activity log", show(&s(&["activity_log", "enabled"]))),
            (
                "protocol detection",
                show(&s(&["protocol_detection", "enabled"])),
            ),
            (
                "antivirus (download)",
                show(&s(&["antivirus", "enabled_download_phase"])),
            ),
            ("block page", show(&s(&["block_page", "enabled"]))),
        ]);
    }
    observe(audit::gateway(z));
}

fn show(v: &Value) -> String {
    match v.as_bool() {
        Some(true) => "on".into(),
        Some(false) => "off".into(),
        None => "not readable".into(),
    }
}

fn devices(z: &ZeroTrust) {
    render::heading("Device profiles");
    let rows: Vec<Value> = z
        .device_policies
        .iter()
        .map(|p| {
            json!({
                "profile": p.get("name").cloned().filter(|v| !v.is_null())
                    .unwrap_or(Value::String("default".into())),
                "mode": p.get("service_mode_v2").map(|m| str_of(m, "mode")),
                "on": p.get("enabled"),
                "userCanDisable": p.get("allow_mode_switch"),
                "autoUpdate": p.get("allow_updates"),
                "autoConnect": p.get("auto_connect"),
            })
        })
        .collect();
    render::list(&rows, render::DEVICE_COLS);

    render::heading(&format!(
        "Split tunnel ({} excluded, {} included)",
        z.split_exclude.len(),
        z.split_include.len()
    ));
    let split: Vec<Value> = z
        .split_exclude
        .iter()
        .map(|e| json!({"mode": "exclude", "target": e.get("address").or_else(|| e.get("host")), "note": e.get("description")}))
        .chain(z.split_include.iter().map(|e| {
            json!({"mode": "include", "target": e.get("address").or_else(|| e.get("host")), "note": e.get("description")})
        }))
        .collect();
    render::list(&split, render::SPLIT_COLS);

    if !z.posture_rules.is_empty() {
        render::heading("Posture rules");
        let rows: Vec<Value> = z
            .posture_rules
            .iter()
            .map(|r| json!({"name": r.get("name"), "type": r.get("type"), "id": r.get("id")}))
            .collect();
        render::list(&rows, render::POSTURE_RULE_COLS);
    }
    observe(audit::devices(z));
}

fn tunnels(z: &ZeroTrust) {
    let rows: Vec<Value> = z
        .tunnels
        .iter()
        .flat_map(|t| {
            t.ingress.iter().map(move |r| {
                json!({
                    "tunnel": t.name,
                    "status": t.status,
                    "hostname": r.get("hostname").cloned()
                        .filter(|v| !v.as_str().unwrap_or_default().is_empty())
                        .unwrap_or(Value::String("(catch-all)".into())),
                    "service": r.get("service"),
                    "path": r.get("path"),
                })
            })
        })
        .collect();

    render::heading("What the tunnels publish inward");
    render::list(&rows, render::INGRESS_COLS);
    render::count(z.tunnels.len(), "tunnel");

    if !z.routes.is_empty() {
        render::heading("Private routes advertised to enrolled devices");
        let routes: Vec<Value> = z
            .routes
            .iter()
            .map(|r| json!({"network": r.get("network"), "note": r.get("comment"), "vnet": r.get("virtual_network_id")}))
            .collect();
        render::list(&routes, render::ROUTE_COLS);
    }
    if !z.targets.is_empty() {
        render::heading("Infrastructure targets");
        render::list_auto(&z.targets);
    }
    observe(audit::tunnels(z));
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
