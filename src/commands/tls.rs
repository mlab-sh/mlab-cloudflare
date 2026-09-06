//! `tls` — what browsers are served, and whether the origin will talk to
//! anyone who finds it.
//!
//! Two questions that get conflated. The browser-facing half is mostly
//! inventory and expiry, and Cloudflare manages most of it. The origin-facing
//! half is the argument: encrypting the origin leg protects the transport and
//! says nothing about who may open the connection. That is what Authenticated
//! Origin Pulls decides, and it is why this command also reads the DNS records
//! — an address published there is only an exposure when the origin does not
//! check who is calling.

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Finding, Tls};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum TlsCmd {
    /// Whether the origin requires Cloudflare's client certificate
    Origin,
    /// The certificate inventory, with expiries
    Certs,
    /// Customer hostnames and client certificates
    Hostnames,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<TlsCmd>) -> Result<()> {
    let zones = crate::commands::zones_in_scope(c, ctx).await?;

    let read = gather(c, &zones).await?;
    let account_certs = account_mtls(c, ctx).await;

    match cmd {
        Some(TlsCmd::Origin) => origin(&read),
        Some(TlsCmd::Certs) => certs(&read, &account_certs),
        Some(TlsCmd::Hostnames) => hostnames(&read),
        None => report(&read, &account_certs),
    }
    Ok(())
}

/// The account's mTLS certificate pool, which several products draw from.
/// Allowed to fail: it needs its own permission.
async fn account_mtls(c: &Client, ctx: &Ctx) -> Vec<Value> {
    let Ok(account) = scope::account(c, &ctx.profile.account).await else {
        return Vec::new();
    };
    let path = format!("/accounts/{}/mtls_certificates", esc(&account));
    ui::spin(
        "Reading account certificates",
        c.cached_list(&path, &[], None),
    )
    .await
    .unwrap_or_default()
}

async fn gather(c: &Client, zones: &[Value]) -> Result<Vec<Tls>> {
    let mut out = Vec::with_capacity(zones.len());

    for (i, z) in zones.iter().enumerate() {
        let name = str_of(z, "name");
        let base = format!("/zones/{}", esc(&str_of(z, "id")));
        let label = format!("Reading {name} ({}/{})", i + 1, zones.len());

        let (aop_p, hosts_p, packs_p, uni_p, custom_p, ch_p, cc_p, ct_p, dns_p, set_p) = (
            format!("{base}/origin_tls_client_auth/settings"),
            format!("{base}/origin_tls_client_auth/hostnames"),
            format!("{base}/ssl/certificate_packs"),
            format!("{base}/ssl/universal/settings"),
            format!("{base}/custom_certificates"),
            format!("{base}/custom_hostnames"),
            format!("{base}/client_certificates"),
            format!("{base}/ct/alerting"),
            format!("{base}/dns_records"),
            format!("{base}/settings"),
        );

        // Ten independent reads, issued together and all cached — the records
        // and the settings are usually already warm from `dns` and `posture`.
        //
        // Only the AOP setting has to succeed for the plane's argument to be
        // made; everything else is an entitlement on some plan. `custom_certificates`
        // in particular answers `400` rather than `403` where the plan excludes
        // it, which is why nothing here treats a status code as the signal.
        let (
            aop,
            aop_hostnames,
            packs,
            universal,
            custom_certs,
            custom_hostnames,
            client_certs,
            ct,
            records,
            settings,
        ) = ui::spin(&label, async {
            tokio::join!(
                c.cached(&aop_p, &[]),
                c.cached_list(&hosts_p, &[], None),
                c.cached_list(&packs_p, &[], None),
                c.cached(&uni_p, &[]),
                c.cached_list(&custom_p, &[], None),
                c.cached_list(&ch_p, &[], None),
                c.cached_list(&cc_p, &[], None),
                c.cached(&ct_p, &[]),
                c.cached_list(&dns_p, &[], None),
                c.cached_list(&set_p, &[], None),
            )
        })
        .await;

        let ssl_mode = settings
            .unwrap_or_default()
            .iter()
            .find(|s| str_of(s, "id") == "ssl")
            .and_then(|s| s.get("value").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_default();

        out.push(Tls {
            name,
            ssl_mode,
            aop: aop
                .ok()
                .and_then(|v| v.get("enabled").and_then(Value::as_bool)),
            aop_hostnames: aop_hostnames.unwrap_or_default(),
            packs: packs.unwrap_or_default(),
            universal: universal.ok(),
            custom_certs: custom_certs.unwrap_or_default(),
            custom_hostnames: custom_hostnames.unwrap_or_default(),
            client_certs: client_certs.unwrap_or_default(),
            ct_alerting: ct.ok(),
            exposed_origins: audit::published_origins(&records.unwrap_or_default()),
        });
    }
    Ok(out)
}

// ---- the graded report ------------------------------------------------------

fn report(zones: &[Tls], account_certs: &[Value]) {
    let findings = audit::sorted(
        [
            audit::origin_trust(zones),
            audit::certificates(zones, 30),
            audit::hostnames(zones),
            audit::account_certificates(account_certs, 30),
        ]
        .concat(),
    );

    if render::is_json() {
        render::print_json(&json!({
            "zones": zones.iter().map(|z| json!({
                "name": z.name,
                "sslMode": z.ssl_mode,
                "authenticatedOriginPulls": z.aop,
                "certificatePacks": z.packs.len(),
                "publishedOrigins": z.exposed_origins,
            })).collect::<Vec<_>>(),
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading(&format!(
        "Certificates and origin trust across {} {}",
        zones.len(),
        if zones.len() == 1 { "zone" } else { "zones" }
    ));
    render::pairs(&[
        ("zones", zones.len().to_string()),
        (
            "origin pulls on",
            format!(
                "{} of {}",
                zones.iter().filter(|z| z.aop == Some(true)).count(),
                zones.len()
            ),
        ),
        (
            "certificate packs",
            zones
                .iter()
                .map(|z| z.packs.len())
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

fn origin(zones: &[Tls]) {
    let rows: Vec<Value> = zones
        .iter()
        .map(|z| {
            json!({
                "zone": z.name,
                "ssl": z.ssl_mode,
                "originPulls": match z.aop {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => "not readable",
                },
                "published": z.exposed_origins.len(),
                "exposure": if z.aop == Some(false) && !z.exposed_origins.is_empty() {
                    "reachable"
                } else {
                    ""
                },
            })
        })
        .collect();

    render::heading("Origin trust");
    render::list(&rows, render::ORIGIN_COLS);
    render::count(rows.len(), "zone");

    if !render::is_json() {
        ui::gap();
        ui::info(
            "PUBLISHED counts the DNS records that name an address the proxy also fronts for; \
             REACHABLE means the origin does not check that a request came through Cloudflare",
        );
    }
    observe(audit::origin_trust(zones));
}

fn certs(zones: &[Tls], account_certs: &[Value]) {
    let rows: Vec<Value> = zones
        .iter()
        .flat_map(|z| {
            z.packs.iter().flat_map(move |p| {
                let pack_status = p.get("status").cloned().unwrap_or(Value::Null);
                p.get("certificates")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |cert| {
                        json!({
                            "zone": z.name,
                            "hosts": cert.get("hosts").or_else(|| p.get("hosts")),
                            "issuer": cert.get("issuer"),
                            "signature": cert.get("signature"),
                            "status": cert.get("status").cloned().unwrap_or(pack_status.clone()),
                            "expires": cert.get("expires_on"),
                        })
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();

    render::heading("Certificates");
    render::list(&rows, render::CERT_COLS);
    render::count(rows.len(), "certificate");

    if !account_certs.is_empty() {
        render::heading("Account mTLS certificates");
        let rows: Vec<Value> = account_certs
            .iter()
            .map(|c| {
                json!({
                    "name": c.get("name"),
                    "type": c.get("type"),
                    "issuer": c.get("issuer"),
                    "ca": c.get("ca"),
                    "expires": c.get("expires_on"),
                })
            })
            .collect();
        render::list(&rows, render::ACCOUNT_CERT_COLS);
    }

    observe(
        [
            audit::certificates(zones, 30),
            audit::account_certificates(account_certs, 30),
        ]
        .concat(),
    );
}

fn hostnames(zones: &[Tls]) {
    let rows: Vec<Value> = zones
        .iter()
        .flat_map(|z| {
            let customers = z.custom_hostnames.iter().map(move |h| {
                json!({
                    "zone": z.name,
                    "kind": "customer hostname",
                    "name": h.get("hostname"),
                    "status": h.get("status"),
                    "ssl": h.get("ssl").map(|s| s.get("status").cloned().unwrap_or(Value::Null)),
                    "expires": Value::Null,
                })
            });
            let clients = z.client_certs.iter().map(move |c| {
                json!({
                    "zone": z.name,
                    "kind": "client certificate",
                    "name": c.get("common_name"),
                    "status": c.get("status"),
                    "ssl": Value::Null,
                    "expires": c.get("expires_on"),
                })
            });
            customers.chain(clients).collect::<Vec<_>>()
        })
        .collect();

    render::heading("Customer hostnames and client certificates");
    render::list(&rows, render::HOSTNAME_COLS);
    render::count(rows.len(), "entry");

    if rows.is_empty() && !render::is_json() {
        ui::gap();
        // Both are SaaS and mTLS features; empty is the normal state for a zone
        // that serves its own traffic, and is not a finding.
        ui::info("no customer hostname and no client certificate on these zones");
    }
    observe(audit::hostnames(zones));
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
    let read = gather(c, &zones).await?;
    let account_certs = account_mtls(c, ctx).await;
    Ok([
        audit::origin_trust(&read),
        audit::certificates(&read, 30),
        audit::hostnames(&read),
        audit::account_certificates(&account_certs, 30),
    ]
    .concat())
}

/// Read everything this plane needs, for a snapshot.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    findings(c, ctx).await.map(|_| ())
}
