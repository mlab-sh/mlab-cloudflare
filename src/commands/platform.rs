//! `platform` — what developers provisioned, and what it is reachable on.
//!
//! The newest surface on the account and the least reviewed: a Worker, a bucket
//! and a Pages project are created with a wrangler config and no change ticket.
//! The API reads all of it — the bindings each script holds, whether a bucket is
//! served anonymously, what a preview deployment is wired to.
//!
//! This is also the first plane whose cost scales with something other than
//! zones: two reads per Worker script and two per bucket. Forty scripts is
//! eighty calls, which the cache absorbs on every run after the first.

use std::collections::BTreeSet;

use futures_util::{stream, StreamExt};

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::audit::{self, Bucket, Finding, Platform, Script};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

/// How many per-object reads are in flight at once.
///
/// The fan-out here is per Worker script rather than per zone, and forty
/// scripts read one at a time is a minute of round trips. Six is enough to hide
/// the latency and far enough below the rate ceiling that a large account still
/// gets its retries.
const CONCURRENCY: usize = 6;

#[derive(Subcommand, Debug)]
pub enum PlatformCmd {
    /// Worker scripts, what they are reachable on, and what they can reach
    Workers,
    /// R2, KV, D1, queues, Hyperdrive and the secrets store
    Storage,
    /// Pages projects and their deployment configurations
    Pages,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<PlatformCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let p = gather(c, ctx, &account).await?;

    match cmd {
        Some(PlatformCmd::Workers) => workers(&p),
        Some(PlatformCmd::Storage) => storage(&p),
        Some(PlatformCmd::Pages) => pages(&p),
        None => report(&p),
    }
    Ok(())
}

async fn gather(c: &Client, ctx: &Ctx, account: &str) -> Result<Platform> {
    let base = format!("/accounts/{}", esc(account));
    let path = |p: &str| format!("{base}/{p}");

    // Eleven account-level reads, together. All but the script list are allowed
    // to fail: most are entitlements, and an account with no Hyperdrive is not
    // an account with a problem.
    let (scripts, subdomain, pages, buckets, kv, d1, queues, hyperdrive, stores, widgets, gateways) =
        ui::spin("Reading the account", async {
            let (a, b, cc, d, e, f, g, h, i, j, k) = (
                path("workers/scripts"),
                path("workers/subdomain"),
                path("pages/projects"),
                path("r2/buckets"),
                path("storage/kv/namespaces"),
                path("d1/database"),
                path("queues"),
                path("hyperdrive/configs"),
                path("secrets_store/stores"),
                path("challenges/widgets"),
                path("ai-gateway/gateways"),
            );
            tokio::join!(
                c.cached_list(&a, &[], None),
                c.cached(&b, &[]),
                c.cached_list(&cc, &[], None),
                c.cached_list(&d, &[], None),
                c.cached_list(&e, &[], None),
                c.cached_list(&f, &[], None),
                c.cached_list(&g, &[], None),
                c.cached_list(&h, &[], None),
                c.cached_list(&i, &[], None),
                c.cached_list(&j, &[], None),
                c.cached_list(&k, &[], None),
            )
        })
        .await;

    let scripts = scripts?;
    let subdomain = subdomain
        .ok()
        .map(|v| str_of(&v, "subdomain"))
        .unwrap_or_default();

    let scripts = read_scripts(c, &base, scripts).await;
    let buckets = read_buckets(c, &base, buckets.unwrap_or_default()).await;
    let routed = routed_scripts(c, ctx).await;

    Ok(Platform {
        subdomain,
        scripts,
        routed,
        pages: pages.unwrap_or_default(),
        buckets,
        kv: kv.unwrap_or_default(),
        d1: d1.unwrap_or_default(),
        queues: queues.unwrap_or_default(),
        hyperdrive: hyperdrive.unwrap_or_default(),
        secret_stores: stores.unwrap_or_default(),
        widgets: widgets.unwrap_or_default(),
        gateways: gateways.unwrap_or_default(),
    })
}

/// Per script: whether it answers on workers.dev, and what it is bound to.
async fn read_scripts(c: &Client, base: &str, listed: Vec<Value>) -> Vec<Script> {
    let names: Vec<String> = listed
        .iter()
        .map(|s| str_of(s, "id"))
        .filter(|n| !n.is_empty())
        .collect();

    let label = format!("Reading {} worker scripts", names.len());
    ui::spin(&label, async {
        stream::iter(names)
            .map(|name| async move {
                let (sub_p, set_p) = (
                    format!("{base}/workers/scripts/{}/subdomain", esc(&name)),
                    format!("{base}/workers/scripts/{}/settings", esc(&name)),
                );
                let (sub, settings) = tokio::join!(c.cached(&sub_p, &[]), c.cached(&set_p, &[]));
                let settings = settings.unwrap_or(Value::Null);
                Script {
                    name,
                    // A refused read is not "off": a script whose subdomain
                    // state could not be read stays out of the exposure finding
                    // rather than being counted as safe.
                    on_subdomain: sub
                        .as_ref()
                        .ok()
                        .and_then(|v| v.get("enabled").and_then(Value::as_bool))
                        == Some(true),
                    previews: sub
                        .ok()
                        .and_then(|v| v.get("previews_enabled").and_then(Value::as_bool))
                        == Some(true),
                    bindings: settings
                        .get("bindings")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default(),
                    observability: settings
                        .get("observability")
                        .and_then(|o| o.get("enabled"))
                        .and_then(Value::as_bool)
                        == Some(true),
                    logpush: settings.get("logpush").and_then(Value::as_bool) == Some(true),
                }
            })
            .buffered(CONCURRENCY)
            .collect()
            .await
    })
    .await
}

/// Per bucket: whether anonymous access is on, and which domains serve it.
async fn read_buckets(c: &Client, base: &str, listed: Vec<Value>) -> Vec<Bucket> {
    let names: Vec<String> = listed
        .iter()
        .map(|b| str_of(b, "name"))
        .filter(|n| !n.is_empty())
        .collect();

    let label = format!("Reading {} R2 buckets", names.len());
    ui::spin(&label, async {
        stream::iter(names)
            .map(|name| async move {
                let (managed_p, custom_p) = (
                    format!("{base}/r2/buckets/{}/domains/managed", esc(&name)),
                    format!("{base}/r2/buckets/{}/domains/custom", esc(&name)),
                );
                let (managed, custom) = tokio::join!(
                    c.cached(&managed_p, &[]),
                    c.cached_list(&custom_p, &[], None)
                );
                Bucket {
                    name,
                    public_domain: managed.ok().and_then(|m| {
                        (m.get("enabled").and_then(Value::as_bool) == Some(true))
                            .then(|| str_of(&m, "domain"))
                    }),
                    custom_domains: custom
                        .unwrap_or_default()
                        .iter()
                        .filter(|d| d.get("enabled").and_then(Value::as_bool) != Some(false))
                        .map(|d| str_of(d, "domain"))
                        .filter(|d| !d.is_empty())
                        .collect(),
                }
            })
            .buffered(CONCURRENCY)
            .collect()
            .await
    })
    .await
}

/// The script names bound to a zone route.
///
/// One cached read per zone, usually already warm from `posture`. Without it a
/// script on workers.dev cannot be told apart from one that is *only* there —
/// and those are a bypass and a design respectively.
async fn routed_scripts(c: &Client, ctx: &Ctx) -> BTreeSet<String> {
    let zones = crate::commands::zones_in_scope(c, ctx)
        .await
        .unwrap_or_default();

    let mut out = BTreeSet::new();
    for z in &zones {
        let path = format!("/zones/{}/workers/routes", esc(&str_of(z, "id")));
        if let Ok(routes) = ui::spin("Reading worker routes", c.cached_list(&path, &[], None)).await
        {
            out.extend(
                routes
                    .iter()
                    .map(|r| str_of(r, "script"))
                    .filter(|s| !s.is_empty()),
            );
        }
    }
    out
}

// ---- the graded report ------------------------------------------------------

fn report(p: &Platform) {
    let findings = audit::sorted(
        [
            audit::workers(p),
            audit::storage(p),
            audit::pages(&p.pages),
            audit::services(p),
        ]
        .concat(),
    );

    if render::is_json() {
        render::print_json(&json!({
            "subdomain": p.subdomain,
            "counts": {
                "workers": p.scripts.len(),
                "onWorkersDev": p.scripts.iter().filter(|s| s.on_subdomain).count(),
                "pages": p.pages.len(),
                "r2Buckets": p.buckets.len(),
                "kvNamespaces": p.kv.len(),
                "d1Databases": p.d1.len(),
                "queues": p.queues.len(),
                "hyperdrive": p.hyperdrive.len(),
                "secretStores": p.secret_stores.len(),
            },
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading("Developer platform");
    render::pairs(&[
        ("workers.dev subdomain", p.subdomain.clone()),
        (
            "workers",
            format!(
                "{} ({} on workers.dev)",
                p.scripts.len(),
                p.scripts.iter().filter(|s| s.on_subdomain).count()
            ),
        ),
        ("pages projects", p.pages.len().to_string()),
        (
            "data stores",
            format!(
                "{} R2, {} KV, {} D1, {} queues",
                p.buckets.len(),
                p.kv.len(),
                p.d1.len(),
                p.queues.len()
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

fn workers(p: &Platform) {
    let rows: Vec<Value> = p
        .scripts
        .iter()
        .map(|s| {
            json!({
                "script": s.name,
                "workersDev": if s.on_subdomain { "on" } else { "off" },
                "route": if p.routed.contains(&s.name) { "yes" } else { "" },
                "bindings": s.bindings.len(),
                "reaches": s.bindings.iter()
                    .map(|b| b.get("type").and_then(Value::as_str).unwrap_or("").to_string())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
                "logs": if s.observability || s.logpush { "on" } else { "off" },
            })
        })
        .collect();

    render::heading(&format!("Workers on {}.workers.dev", p.subdomain));
    render::list(&rows, render::WORKER_COLS);
    render::count(rows.len(), "script");
    observe(audit::workers(p));
}

fn storage(p: &Platform) {
    let mut rows: Vec<Value> = p
        .buckets
        .iter()
        .map(|b| {
            json!({
                "kind": "R2 bucket",
                "name": b.name,
                "detail": match (&b.public_domain, b.custom_domains.is_empty()) {
                    (Some(d), _) => format!("public at {d}"),
                    (None, false) => b.custom_domains.join(", "),
                    (None, true) => String::new(),
                },
            })
        })
        .collect();

    for (kind, items, name_key) in [
        ("KV namespace", &p.kv, "title"),
        ("D1 database", &p.d1, "name"),
        ("queue", &p.queues, "queue_name"),
        ("secrets store", &p.secret_stores, "name"),
    ] {
        rows.extend(
            items
                .iter()
                .map(|it| json!({"kind": kind, "name": it.get(name_key), "detail": Value::Null})),
        );
    }
    rows.extend(p.hyperdrive.iter().map(|h| {
        json!({
            "kind": "Hyperdrive",
            "name": h.get("name"),
            "detail": h.get("origin").map(|o| {
                format!("{}/{}", str_of(o, "host"), str_of(o, "database"))
            }),
        })
    }));

    render::heading("Data stores");
    render::list(&rows, render::STORE_COLS);
    render::count(rows.len(), "store");
    observe(audit::storage(p));
}

fn pages(p: &Platform) {
    let rows: Vec<Value> = p
        .pages
        .iter()
        .map(|pr| {
            json!({
                "project": pr.get("name"),
                "subdomain": pr.get("subdomain"),
                "branch": pr.get("production_branch"),
                "source": pr.get("source")
                    .and_then(|s| s.get("config"))
                    .map(|c| str_of(c, "owner")),
                "autoBuild": pr.get("source")
                    .and_then(|s| s.get("config"))
                    .and_then(|c| c.get("deployments_enabled")),
            })
        })
        .collect();

    render::heading("Pages projects");
    render::list(&rows, render::PAGES_COLS);
    render::count(rows.len(), "project");
    observe(audit::pages(&p.pages));
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
    let account = scope::account(c, &ctx.profile.account).await?;
    let p = gather(c, ctx, &account).await?;
    Ok([
        audit::workers(&p),
        audit::storage(&p),
        audit::pages(&p.pages),
        audit::services(&p),
    ]
    .concat())
}

/// Read everything this plane needs, for a snapshot.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    findings(c, ctx).await.map(|_| ())
}
