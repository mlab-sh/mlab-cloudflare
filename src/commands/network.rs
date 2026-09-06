//! `network` — the routed estate, where an account has one.
//!
//! Magic Transit and Magic WAN move an organisation's actual routing into
//! Cloudflare: tunnels, static routes, site LANs and ACLs, BGP. Everything here
//! is readable, and the failures are the ordinary failures of network
//! engineering — overlapping prefixes, permissive ACLs, health checks that were
//! never turned on — with the difference that a mistake applies to every site
//! at once.
//!
//! It is also the plane most likely to be entirely absent, which is why the
//! empty case is handled first and plainly.

use anyhow::Result;
use clap::Subcommand;
use futures_util::{stream, StreamExt};
use serde_json::{json, Value};

use crate::audit::{self, Finding, Network, Site};
use crate::cf::{esc, scope, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Sites, tunnels and the routing between them
    Magic,
    /// Announced address space and DNS Firewall
    Addressing,
    /// Load balancers, pools and their monitors
    Balancing,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<NetworkCmd>) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let n = gather(c, &account).await?;

    if n.is_empty() && !render::is_json() {
        render::heading("Network");
        ui::info("no Magic tunnel, static route, announced prefix, DNS Firewall cluster or load balancer");
        ui::info("this account does not route through Cloudflare, which is not a finding");
        return Ok(());
    }

    match cmd {
        Some(NetworkCmd::Magic) => magic(&n),
        Some(NetworkCmd::Addressing) => addressing(&n),
        Some(NetworkCmd::Balancing) => balancing(&n),
        None => report(&n),
    }
    Ok(())
}

async fn gather(c: &Client, account: &str) -> Result<Network> {
    let base = format!("/accounts/{}", esc(account));
    let p = |x: &str| format!("{base}/{x}");

    // Ten reads, together. Every one is an entitlement, so every one may be
    // refused — and on an account without any of this, all of them will be.
    let (sites, ipsec, gre, routes, prefixes, maps, dnsfw, lbs, pools, monitors) =
        ui::spin("Reading the network", async {
            let paths = (
                p("magic/sites"),
                p("magic/ipsec_tunnels"),
                p("magic/gre_tunnels"),
                p("magic/routes"),
                p("addressing/prefixes"),
                p("addressing/address_maps"),
                p("dns_firewall"),
                p("load_balancers"),
                p("load_balancers/pools"),
                p("load_balancers/monitors"),
            );
            tokio::join!(
                c.cached_list(&paths.0, &[], None),
                c.cached_list(&paths.1, &[], None),
                c.cached_list(&paths.2, &[], None),
                c.cached_list(&paths.3, &[], None),
                c.cached_list(&paths.4, &[], None),
                c.cached_list(&paths.5, &[], None),
                c.cached_list(&paths.6, &[], None),
                c.cached_list(&paths.7, &[], None),
                c.cached_list(&paths.8, &[], None),
                c.cached_list(&paths.9, &[], None),
            )
        })
        .await;

    Ok(Network {
        sites: read_sites(c, &base, sites.unwrap_or_default()).await,
        ipsec: ipsec.unwrap_or_default(),
        gre: gre.unwrap_or_default(),
        routes: routes.unwrap_or_default(),
        prefixes: prefixes.unwrap_or_default(),
        address_maps: maps.unwrap_or_default(),
        dns_firewall: dnsfw.unwrap_or_default(),
        load_balancers: lbs.unwrap_or_default(),
        pools: pools.unwrap_or_default(),
        monitors: monitors.unwrap_or_default(),
    })
}

/// Per site: the ACLs and LANs, which are what segmentation actually means
/// here. Neither is visible from the site list itself.
async fn read_sites(c: &Client, base: &str, listed: Vec<Value>) -> Vec<Site> {
    let wanted: Vec<(String, String)> = listed
        .iter()
        .map(|s| (str_of(s, "id"), str_of(s, "name")))
        .filter(|(id, _)| !id.is_empty())
        .collect();
    if wanted.is_empty() {
        return Vec::new();
    }

    let label = format!("Reading {} sites", wanted.len());
    ui::spin(&label, async {
        stream::iter(wanted)
            .map(|(id, name)| async move {
                let (acl_p, lan_p) = (
                    format!("{base}/magic/sites/{}/acls", esc(&id)),
                    format!("{base}/magic/sites/{}/lans", esc(&id)),
                );
                let (acls, lans) = tokio::join!(
                    c.cached_list(&acl_p, &[], None),
                    c.cached_list(&lan_p, &[], None)
                );
                Site {
                    name,
                    acls: acls.unwrap_or_default(),
                    lans: lans.unwrap_or_default(),
                }
            })
            .buffered(4)
            .collect()
            .await
    })
    .await
}

// ---- the graded report ------------------------------------------------------

fn report(n: &Network) {
    let findings = audit::sorted(
        [
            audit::magic(n),
            audit::addressing(n),
            audit::balancing(n),
            audit::dns_firewall(n),
        ]
        .concat(),
    );

    if render::is_json() {
        render::print_json(&json!({
            "counts": {
                "sites": n.sites.len(),
                "ipsecTunnels": n.ipsec.len(),
                "greTunnels": n.gre.len(),
                "staticRoutes": n.routes.len(),
                "prefixes": n.prefixes.len(),
                "dnsFirewall": n.dns_firewall.len(),
                "loadBalancers": n.load_balancers.len(),
                "pools": n.pools.len(),
            },
            "findings": findings.iter().map(Finding::to_json).collect::<Vec<_>>(),
        }));
        return;
    }

    render::heading("Network");
    render::pairs(&[
        (
            "magic",
            format!(
                "{} sites, {} IPsec, {} GRE, {} routes",
                n.sites.len(),
                n.ipsec.len(),
                n.gre.len(),
                n.routes.len()
            ),
        ),
        ("announced prefixes", n.prefixes.len().to_string()),
        ("dns firewall", n.dns_firewall.len().to_string()),
        (
            "load balancing",
            format!(
                "{} balancers, {} pools, {} monitors",
                n.load_balancers.len(),
                n.pools.len(),
                n.monitors.len()
            ),
        ),
    ]);

    render::heading("Findings");
    let rows: Vec<Value> = findings.iter().map(Finding::to_json).collect();
    render::findings(&rows);
    render::count(findings.len(), "finding");
    if !findings.is_empty() {
        ui::gap();
        for (sev, count) in audit::tally(&findings) {
            ui::info(&format!("{count} {sev}"));
        }
    }
}

// ---- the listings -----------------------------------------------------------

fn magic(n: &Network) {
    let rows: Vec<Value> = n
        .ipsec
        .iter()
        .map(|t| tunnel_row("ipsec", t))
        .chain(n.gre.iter().map(|t| tunnel_row("gre", t)))
        .collect();
    render::heading("Tunnels");
    render::list(&rows, render::TUNNEL_COLS);
    render::count(rows.len(), "tunnel");

    if !n.routes.is_empty() {
        render::heading("Static routes");
        let routes: Vec<Value> = n
            .routes
            .iter()
            .map(|r| {
                json!({
                    "prefix": r.get("prefix"),
                    "nexthop": r.get("nexthop"),
                    "priority": r.get("priority"),
                    "weight": r.get("weight"),
                    "note": r.get("description"),
                })
            })
            .collect();
        render::list(&routes, render::STATIC_ROUTE_COLS);
    }

    for site in &n.sites {
        render::heading(&format!("{} — access between LANs", site.name));
        let acls: Vec<Value> = site
            .acls
            .iter()
            .map(|a| {
                json!({
                    "rule": a.get("name"),
                    "from": lan_side(site, a, "lan_1"),
                    "to": lan_side(site, a, "lan_2"),
                    "protocols": protocols(a),
                    "oneWay": a.get("unidirectional"),
                })
            })
            .collect();
        render::list(&acls, render::ACL_COLS);
    }
    observe(audit::magic(n));
}

fn tunnel_row(kind: &str, t: &Value) -> Value {
    json!({
        "kind": kind,
        "name": t.get("name"),
        "peer": t.get("customer_endpoint"),
        "interface": t.get("interface_address"),
        "healthCheck": t.get("health_check").and_then(|h| h.get("enabled")),
        "replayProtection": t.get("replay_protection"),
        "nullCipher": t.get("allow_null_cipher"),
    })
}

/// One side of an ACL, as what it actually restricts.
///
/// An ACL may carry only a `lan_id`, and a rule that reads "lan_9f3a → lan_c17b"
/// tells nobody what it permits. The site's LAN list is what turns those back
/// into the names somebody chose.
fn lan_side(site: &Site, acl: &Value, side: &str) -> String {
    let Some(l) = acl.get(side) else {
        return String::new();
    };
    let name = match str_of(l, "lan_name") {
        n if !n.is_empty() => n,
        _ => {
            let id = str_of(l, "lan_id");
            site.lans
                .iter()
                .find(|lan| str_of(lan, "id") == id)
                .map(|lan| str_of(lan, "name"))
                .filter(|n| !n.is_empty())
                .unwrap_or(id)
        }
    };
    let narrowed = ["subnets", "ports", "port_ranges"].iter().any(|k| {
        l.get(*k)
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
    });
    if narrowed {
        name
    } else {
        format!("{name} (all)")
    }
}

/// An empty protocol list means every protocol, not none.
fn protocols(acl: &Value) -> String {
    match acl.get("protocols").and_then(Value::as_array) {
        Some(p) if !p.is_empty() => p
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", "),
        _ => "all".to_string(),
    }
}

fn addressing(n: &Network) {
    let rows: Vec<Value> = n
        .prefixes
        .iter()
        .map(|p| {
            json!({
                "cidr": p.get("cidr"),
                "advertised": p.get("advertised"),
                "approved": p.get("approved"),
                "rpki": p.get("rpki_validation_state"),
                "note": p.get("description"),
            })
        })
        .collect();
    render::heading("Announced address space");
    render::list(&rows, render::PREFIX_COLS);
    render::count(rows.len(), "prefix");

    if !n.dns_firewall.is_empty() {
        render::heading("DNS Firewall");
        let clusters: Vec<Value> = n
            .dns_firewall
            .iter()
            .map(|c| {
                json!({
                    "cluster": c.get("name"),
                    "upstreams": c.get("upstream_ips"),
                    "ratelimit": c.get("ratelimit"),
                    "cacheTtl": c.get("maximum_cache_ttl"),
                })
            })
            .collect();
        render::list(&clusters, render::DNSFW_COLS);
    }
    observe([audit::addressing(n), audit::dns_firewall(n)].concat());
}

fn balancing(n: &Network) {
    let monitors: std::collections::BTreeMap<String, String> = n
        .monitors
        .iter()
        .map(|m| {
            (
                str_of(m, "id"),
                format!("{} {}", str_of(m, "type"), str_of(m, "path")),
            )
        })
        .collect();

    let rows: Vec<Value> = n
        .pools
        .iter()
        .map(|p| {
            let monitor = str_of(p, "monitor");
            json!({
                "pool": p.get("name"),
                "on": p.get("enabled"),
                "origins": p.get("origins").and_then(Value::as_array).map(Vec::len),
                "minimum": p.get("minimum_origins"),
                "monitor": monitors.get(&monitor).cloned()
                    .unwrap_or_else(|| if monitor.is_empty() { "none".into() } else { "missing".into() }),
            })
        })
        .collect();

    render::heading("Pools");
    render::list(&rows, render::POOL_COLS);
    render::count(rows.len(), "pool");

    if !n.load_balancers.is_empty() {
        render::heading("Load balancers");
        let lbs: Vec<Value> = n
            .load_balancers
            .iter()
            .map(|lb| {
                json!({
                    "balancer": lb.get("name"),
                    "on": lb.get("enabled"),
                    "steering": lb.get("steering_policy"),
                    "pools": lb.get("default_pools").and_then(Value::as_array).map(Vec::len),
                    "fallback": lb.get("fallback_pool"),
                })
            })
            .collect();
        render::list(&lbs, render::LB_COLS);
    }
    observe(audit::balancing(n));
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

/// Read everything this plane needs, for a snapshot.
pub(crate) async fn collect(c: &Client, ctx: &Ctx) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    gather(c, &account).await.map(|_| ())
}
