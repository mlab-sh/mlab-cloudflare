//! `enrich` — the same account, seen from outside it.
//!
//! Every other command in this tool reads Cloudflare's record of the account.
//! That record is authoritative about intent and silent about effect: it says
//! which names the account publishes, not which names answer; which address an
//! origin is, not what kind of address that is. This command asks mlab.sh those
//! second questions and puts the two answers side by side, and every finding it
//! produces is of one shape — **the inside and the outside disagree**.
//!
//! It is the only command that talks to a service other than Cloudflare, the
//! only one that spends a quota, and therefore the only one that will not run
//! without being told how much it may spend. Three rules follow from that:
//!
//! 1. **Nothing is scanned twice.** Results are held for a week, which is how
//!    long mlab keeps its own; a second run inside that week costs nothing.
//! 2. **The budget is a ceiling, not a target.** Targets past it are reported
//!    as unread — never as clean, which is the same rule the refused-read
//!    handling follows everywhere else.
//! 3. **`--no-cache` does not apply here.** Bypassing a cache that stands
//!    between the user and a daily limit is not a debugging convenience;
//!    `--refresh` exists for when it is genuinely wanted.

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use crate::audit::{self, Address, Finding, Outside};
use crate::cf::{cache::Cache, esc, Client};
use crate::cli::Ctx;
use crate::mlab::{Mlab, Scan};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum EnrichCmd {
    /// What the origin addresses actually are: hosting, network, reputation
    Origins,
    /// What the world resolves for these zones, against what Cloudflare holds
    #[command(alias = "namespace")]
    Zones,
    /// What a full run would look up, and what it would cost
    Plan,
}

#[derive(Args, Debug)]
pub struct EnrichArgs {
    #[command(subcommand)]
    pub cmd: Option<EnrichCmd>,

    /// Most lookups this run may spend, per quota
    #[arg(long, global = true, default_value_t = 20, value_name = "N")]
    pub budget: usize,

    /// Say what would be looked up, and look nothing up
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Look up targets again even when a held result would do
    #[arg(long, global = true)]
    pub refresh: bool,

    /// Warn about public certificates expiring within this many days
    #[arg(long, global = true, default_value_t = 30, value_name = "DAYS")]
    pub expiring_within: i64,
}

pub async fn run(c: &Client, ctx: &Ctx, a: &EnrichArgs) -> Result<()> {
    let cache = Cache::named(crate::mlab::CACHE_DIR, crate::mlab::TTL, !a.refresh);
    let m = Mlab::new(&ctx.profile.mlab_key, ctx.timeout, Some(cache))?;

    let zones = crate::commands::zones_in_scope(c, ctx).await?;
    let inside = gather(c, &zones).await?;

    match a.cmd {
        Some(EnrichCmd::Plan) => {
            plan(&m, &inside);
            Ok(())
        }
        Some(EnrichCmd::Origins) => {
            let (found, unread) = origins(&m, &inside, a).await?;
            report("Origins, as the internet sees them", found, &unread);
            Ok(())
        }
        Some(EnrichCmd::Zones) => {
            let (found, unread) = namespace(&m, &inside, a).await?;
            report("Namespace, as the internet sees it", found, &unread);
            Ok(())
        }
        None => {
            // Both planes share one budget, and the namespace goes first: a
            // shadow hostname is the finding this command exists for, and a
            // truncated run should truncate the cheaper half.
            let (mut found, mut unread) = namespace(&m, &inside, a).await?;
            let (o, u) = origins(&m, &inside, a).await?;
            found.extend(o);
            unread.extend(u);
            report("The outside view", found, &unread);
            Ok(())
        }
    }
}

/// One zone as Cloudflare holds it: the names, and whether it publishes a mail
/// policy. Everything the outside view has to be compared against.
struct Inside {
    name: String,
    known: BTreeSet<String>,
    cf_spf: bool,
    cf_dmarc: bool,
    records: Vec<Value>,
}

async fn gather(c: &Client, zones: &[Value]) -> Result<Vec<Inside>> {
    let mut out = Vec::with_capacity(zones.len());

    for (i, z) in zones.iter().enumerate() {
        let name = str_of(z, "name");
        let path = format!("/zones/{}/dns_records", esc(&str_of(z, "id")));
        let records = ui::spin(
            &format!("Reading {name} ({}/{})", i + 1, zones.len()),
            c.cached_list(&path, &[], None),
        )
        .await?;

        // Every name the zone holds any record for. A hostname is "known to
        // Cloudflare" if a record of any type mentions it — a name with only an
        // MX record is still a name this account publishes.
        let known: BTreeSet<String> = records
            .iter()
            .map(|r| str_of(r, "name").trim_end_matches('.').to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();

        let apex = name.to_ascii_lowercase();
        let txt = |pred: &dyn Fn(&str, &str) -> bool| {
            records.iter().any(|r| {
                str_of(r, "type") == "TXT"
                    && pred(
                        &str_of(r, "name").trim_end_matches('.').to_ascii_lowercase(),
                        str_of(r, "content").trim_matches('"'),
                    )
            })
        };
        let cf_spf = txt(&|n, v| n == apex && v.starts_with("v=spf1"));
        let cf_dmarc = txt(&|n, v| n == format!("_dmarc.{apex}") && v.starts_with("v=DMARC1"));

        out.push(Inside {
            name,
            known,
            cf_spf,
            cf_dmarc,
            records,
        });
    }
    Ok(out)
}

// ---- the two planes ---------------------------------------------------------

/// What the world resolves for each zone.
async fn namespace(
    m: &Mlab,
    inside: &[Inside],
    a: &EnrichArgs,
) -> Result<(Vec<Finding>, Vec<(String, String)>)> {
    let targets: Vec<Scan> = inside
        .iter()
        .map(|z| Scan::Domain(z.name.clone()))
        .collect();
    let (scans, unread) = fetch(m, &targets, a).await;

    let outside: Vec<Outside> = inside
        .iter()
        .filter_map(|z| {
            scans.get(&z.name).map(|scan| Outside {
                zone: z.name.clone(),
                known: z.known.clone(),
                cf_spf: z.cf_spf,
                cf_dmarc: z.cf_dmarc,
                scan: scan.clone(),
            })
        })
        .collect();

    let found = [
        audit::shadow(&outside),
        audit::drift(&outside),
        audit::live_mail(&outside),
        audit::public_certs(&outside, a.expiring_within),
    ]
    .concat();
    Ok((found, unread))
}

/// What each published address actually is.
async fn origins(
    m: &Mlab,
    inside: &[Inside],
    a: &EnrichArgs,
) -> Result<(Vec<Finding>, Vec<(String, String)>)> {
    // One address serving four names is one lookup, not four. Merged across
    // zones, because an account that reuses an origin across zones would
    // otherwise pay for it once per zone.
    let mut merged: BTreeMap<String, (Vec<String>, bool)> = BTreeMap::new();
    for z in inside {
        for (addr, names, exposed) in audit::public_addresses(&z.records) {
            let e = merged.entry(addr).or_default();
            e.0.extend(names);
            e.1 |= exposed;
        }
    }

    // Exposed first. A budget that runs out should run out on the addresses
    // the proxy already hides, not on the ones anyone can reach.
    let mut order: Vec<(&String, bool)> = merged.iter().map(|(k, v)| (k, v.1)).collect();
    order.sort_by_key(|(addr, exposed)| (!exposed, (*addr).clone()));
    let targets: Vec<Scan> = order
        .into_iter()
        .map(|(addr, _)| Scan::Ip(addr.clone()))
        .collect();
    let (scans, unread) = fetch(m, &targets, a).await;

    let addrs: Vec<Address> = merged
        .into_iter()
        .filter_map(|(addr, (mut names, exposed))| {
            names.sort();
            names.dedup();
            scans.get(&addr).map(|scan| Address {
                names,
                addr: addr.clone(),
                exposed,
                scan: scan.clone(),
            })
        })
        .collect();

    Ok((audit::origins(&addrs), unread))
}

// ---- spending ---------------------------------------------------------------

/// Look up what is held for free and as much of the rest as the budget allows.
///
/// Returns the results by target, and the targets left unlooked-up with the
/// reason — which the report prints, because a target nobody looked at is not
/// a target with nothing wrong.
async fn fetch(
    m: &Mlab,
    targets: &[Scan],
    a: &EnrichArgs,
) -> (BTreeMap<String, Value>, Vec<(String, String)>) {
    let mut out = BTreeMap::new();
    let mut unread = Vec::new();
    let mut spent = 0usize;

    for (i, t) in targets.iter().enumerate() {
        if let Some(held) = m.held(t) {
            out.insert(t.target().to_string(), held);
            continue;
        }
        if a.dry_run {
            unread.push((t.target().to_string(), "not looked up: --dry-run".into()));
            continue;
        }
        if spent >= a.budget {
            unread.push((
                t.target().to_string(),
                format!("not looked up: --budget {} reached", a.budget),
            ));
            continue;
        }

        let label = format!(
            "Looking up {} ({}/{}, {} spent)",
            t.target(),
            i + 1,
            targets.len(),
            spent + 1
        );
        match ui::spin(&label, m.fetch(t)).await {
            Ok(v) => {
                spent += 1;
                out.insert(t.target().to_string(), v);
            }
            // One refusal must not abandon the rest: a quota that ran out
            // partway through still leaves everything before it worth
            // reporting, and everything after it honestly unread.
            Err(e) => {
                spent += 1;
                unread.push((t.target().to_string(), first_line(&e)));
            }
        }
    }
    (out, unread)
}

/// What a run would look up, without looking anything up.
fn plan(m: &Mlab, inside: &[Inside]) {
    let mut rows = Vec::new();
    let mut to_spend = BTreeMap::new();

    let mut addrs: BTreeMap<String, bool> = BTreeMap::new();
    for z in inside {
        for (addr, _, exposed) in audit::public_addresses(&z.records) {
            *addrs.entry(addr).or_default() |= exposed;
        }
    }

    let targets: Vec<Scan> = inside
        .iter()
        .map(|z| Scan::Domain(z.name.clone()))
        .chain(addrs.keys().cloned().map(Scan::Ip))
        .collect();

    for t in &targets {
        let held = m.held(t).is_some();
        if !held {
            *to_spend.entry(t.kind()).or_insert(0usize) += 1;
        }
        rows.push(json!({
            "target": t.target(),
            "quota": t.kind(),
            "state": if held { "held" } else { "would be looked up" },
        }));
    }

    render::heading("What a full run would look up");
    render::list(&rows, render::ENRICH_PLAN_COLS);
    render::count(rows.len(), "target");

    if render::is_json() {
        return;
    }
    ui::gap();
    if to_spend.is_empty() {
        ui::success("everything is held; a full run would spend nothing");
        return;
    }
    for (quota, n) in &to_spend {
        ui::info(&format!("{n} {quota} {} to spend", plural(*n, "lookup")));
    }
    ui::info("results are held for 7 days, which is how long mlab keeps its own");
}

// ---- the report -------------------------------------------------------------

fn report(title: &str, found: Vec<Finding>, unread: &[(String, String)]) {
    let found = audit::sorted(found);
    let rows: Vec<Value> = found.iter().map(Finding::to_json).collect();
    let missed: Vec<Value> = unread
        .iter()
        .map(|(t, why)| json!({ "target": t, "reason": why }))
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "findings": rows,
            "unread": missed,
        }));
        return;
    }

    render::heading(title);
    render::findings(&rows);
    render::count(found.len(), "finding");

    if !found.is_empty() {
        ui::gap();
        for (sev, n) in audit::tally(&found) {
            ui::info(&format!("{n} {sev}"));
        }
    }
    if !missed.is_empty() {
        render::heading("Not looked up");
        render::list(&missed, render::ENRICH_UNREAD_COLS);
        ui::gap();
        // The one thing this report must never let the reader assume.
        ui::warning("these targets were not checked; nothing above covers them");
    }
}

/// The findings a held-results-only run produces, for `audit --enrich`.
///
/// `audit` never spends quota: it reports what `enrich` already fetched and
/// says so. A command that silently drew down a daily limit as a side effect of
/// running the ordinary report would be a bad surprise exactly once, and it
/// would be the run that mattered.
pub(crate) async fn held_findings(
    c: &Client,
    ctx: &Ctx,
    zones: &[Value],
    expiring_within: i64,
) -> Result<(Vec<Finding>, usize)> {
    let a = EnrichArgs {
        cmd: None,
        budget: 0,
        dry_run: true,
        refresh: false,
        expiring_within,
    };
    let cache = Cache::named(crate::mlab::CACHE_DIR, crate::mlab::TTL, true);
    // The key is only a cache key here; nothing is sent, so a profile with no
    // mlab key still reads whatever an earlier `enrich` left behind.
    let m = Mlab::new(
        match ctx.profile.mlab_key.as_str() {
            "" => "unset",
            k => k,
        },
        ctx.timeout,
        Some(cache),
    )?;

    let inside = gather(c, zones).await?;
    let (mut found, unread) = namespace(&m, &inside, &a).await?;
    let (o, u) = origins(&m, &inside, &a).await?;
    found.extend(o);
    Ok((found, unread.len() + u.len()))
}

fn first_line(e: &anyhow::Error) -> String {
    e.to_string().lines().next().unwrap_or_default().to_string()
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plurals_agree_with_their_count() {
        assert_eq!(plural(1, "lookup"), "lookup");
        assert_eq!(plural(2, "lookup"), "lookups");
    }

    #[test]
    fn an_error_is_reported_as_one_line() {
        let e = anyhow::anyhow!("mlab quota exhausted\nhint: limits are per day");
        assert_eq!(first_line(&e), "mlab quota exhausted");
    }
}
