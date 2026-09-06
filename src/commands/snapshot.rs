//! `snapshot` and `diff` — one dated record of what the account looks like, and
//! what changed between two of them.
//!
//! Configuration drift is the finding no single read can produce, and the audit
//! log's retention horizon is the argument for recording before the answer is
//! needed rather than after.
//!
//! A snapshot keeps the **responses**, not this tool's reading of them, so a
//! check written next month can be run against a record taken today. Everything
//! goes through the redaction list on the way to disk: several readable
//! endpoints return a live credential, and a file people copy between machines
//! is the last place for one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::{json, Value};

use crate::cf::{record, scope, secrets, Client};
use crate::cli::Ctx;
use crate::commands;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    /// Where to write it (default: mlab-cloudflare-<account>-<date>.json)
    ///
    /// No short form: `-o` is the global --output.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct DiffArgs {
    /// The earlier snapshot
    pub before: PathBuf,
    /// The later snapshot
    pub after: PathBuf,
    /// Show every changed value rather than a summary per read
    #[arg(long)]
    pub full: bool,
}

/// The version of the file format, so a later reader can tell what it has.
const FORMAT: u64 = 1;

// ---- snapshot ---------------------------------------------------------------

pub async fn run(c: &Client, ctx: &Ctx, a: &SnapshotArgs) -> Result<()> {
    let account = scope::account(c, &ctx.profile.account).await?;
    let recorder = std::sync::Arc::new(record::Recorder::new());
    c.record_into(recorder.clone());

    // Every plane, in the order a report reads them. A plane that fails
    // outright is noted and does not stop the rest: a snapshot of eight planes
    // is worth more than none.
    let mut failed = Vec::new();
    for (name, result) in [
        ("identity", commands::identity::collect(c, ctx).await),
        ("dns", commands::dns::collect(c, ctx).await),
        ("posture", commands::posture::collect(c, ctx).await),
        ("tls", commands::tls::collect(c, ctx).await),
        ("platform", commands::platform::collect(c, ctx).await),
        ("zerotrust", commands::zerotrust::collect(c, ctx).await),
        ("egress", commands::egress::collect(c, ctx).await),
        ("network", commands::network::collect(c, ctx).await),
    ] {
        if let Err(e) = result {
            failed.push(format!("{name}: {}", one_line(&e)));
        }
    }

    let mut reads: BTreeMap<String, Value> = recorder.take();
    // The same list every other persisting path uses, so a field cannot be
    // masked in one place and stored in another.
    let redacted: usize = reads.values_mut().map(secrets::redact).sum();

    let doc = json!({
        "format": FORMAT,
        "tool": concat!("mlab-cloudflare ", env!("CARGO_PKG_VERSION")),
        "takenAt": crate::cf::iso8601(now()),
        "account": account,
        "zone": ctx.profile.zone,
        "reads": reads.len(),
        "redacted": redacted,
        "incomplete": failed,
        "data": reads,
    });

    let path = a
        .out
        .clone()
        .unwrap_or_else(|| default_name(&account, ctx.profile.zone.as_str()));
    let mut text = serde_json::to_string_pretty(&doc)?;
    text.push('\n');
    std::fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;

    if render::is_json() {
        render::print_json(&json!({
            "path": path.display().to_string(),
            "reads": doc["reads"],
            "redacted": redacted,
            "bytes": text.len(),
            "incomplete": doc["incomplete"],
        }));
        return Ok(());
    }

    ui::success(&format!("wrote {}", path.display()));
    render::pairs(&[
        ("reads", doc["reads"].to_string()),
        ("size", format!("{} kB", text.len() / 1024)),
        ("credentials redacted", redacted.to_string()),
    ]);
    if redacted > 0 {
        ui::info("each redacted value was replaced by its length, so the record stays auditable");
    }
    if !failed.is_empty() {
        ui::gap();
        ui::warning(&format!(
            "{} {} could not be read in full: {}",
            failed.len(),
            if failed.len() == 1 { "plane" } else { "planes" },
            failed.join("; ")
        ));
    }
    Ok(())
}

/// `mlab-cloudflare-<account>-<date>.json`, in the working directory.
fn default_name(account: &str, zone: &str) -> PathBuf {
    let day = &crate::cf::iso8601(now())[..10];
    let scope = if zone.is_empty() {
        account.chars().take(8).collect::<String>()
    } else {
        zone.replace('.', "-")
    };
    PathBuf::from(format!("mlab-cloudflare-{scope}-{day}.json"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- diff -------------------------------------------------------------------

pub fn diff(a: &DiffArgs) -> Result<()> {
    let (before, after) = (read_snapshot(&a.before)?, read_snapshot(&a.after)?);
    let (bd, ad) = (data_of(&before), data_of(&after));

    let keys: BTreeSet<&String> = bd.keys().chain(ad.keys()).collect();
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    let mut changed_reads = 0usize;

    for key in keys {
        let label = commands::abbreviate(key);
        let lines: Vec<String> = match (bd.get(key), ad.get(key)) {
            (None, Some(_)) => vec!["read added".to_string()],
            (Some(_), None) => vec!["no longer read".to_string()],
            // A read that became readable, or stopped being readable, is a
            // change in permission rather than in configuration — and it is the
            // more interesting of the two.
            (Some(b), Some(a2)) => match (record::is_unread(b), record::is_unread(a2)) {
                (true, false) => vec!["became readable".to_string()],
                (false, true) => vec!["no longer readable".to_string()],
                (true, true) => vec![],
                (false, false) => compare(b, a2, "").iter().map(Change::describe).collect(),
            },
            (None, None) => vec![],
        };
        if lines.is_empty() {
            continue;
        }
        changed_reads += 1;
        let shown = if a.full || lines.len() <= 8 {
            lines
        } else {
            // A read whose whole body was replaced would otherwise print a
            // hundred lines and bury the eight that were read before it.
            let rest = lines.len() - 8;
            let mut head: Vec<String> = lines.into_iter().take(8).collect();
            head.push(format!("… and {rest} more (--full to see them)"));
            head
        };
        groups.push((label, shown));
    }

    if render::is_json() {
        render::print_json(&json!(groups
            .iter()
            .map(|(read, changes)| json!({"read": read, "changes": changes}))
            .collect::<Vec<_>>()));
        return Ok(());
    }

    render::heading(&format!(
        "{} → {}",
        str_of(&before, "takenAt"),
        str_of(&after, "takenAt")
    ));
    render::grouped(&groups);
    render::count(changed_reads, "changed read");
    if groups.is_empty() {
        ui::gap();
        ui::info("nothing changed between these two snapshots");
    }
    Ok(())
}

fn read_snapshot(p: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    let v: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", p.display()))?;
    match v.get("format").and_then(Value::as_u64) {
        Some(FORMAT) => Ok(v),
        Some(other) => anyhow::bail!(
            "{} is a version {other} snapshot; this build reads version {FORMAT}",
            p.display()
        ),
        None => anyhow::bail!("{} is not a snapshot", p.display()),
    }
}

fn data_of(v: &Value) -> BTreeMap<String, Value> {
    v.get("data")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

// ---- the comparison ---------------------------------------------------------

/// One difference between two documents.
pub struct Change {
    pub path: String,
    pub kind: &'static str,
    pub from: String,
    pub to: String,
}

impl Change {
    fn describe(&self) -> String {
        // An identity-matched element already carries its name in the path, so
        // repeating it as the value would read as `[www.example.com]:
        // www.example.com`.
        let named = |v: &str| self.path.ends_with(&format!("[{v}]"));
        match self.kind {
            "added" if named(&self.to) => format!("{} added", self.path),
            "removed" if named(&self.from) => format!("{} removed", self.path),
            "added" => format!("{}: {}", self.path, self.to),
            "removed" => format!("{}: {}", self.path, self.from),
            _ => format!("{}: {} → {}", self.path, self.from, self.to),
        }
    }
}

/// Compare two JSON documents, reporting the leaves that differ.
///
/// Arrays of objects are matched **by identity rather than by position**. A
/// zone added at the front of a list would otherwise shift every element after
/// it and report the whole list as changed, which buries the one thing that
/// actually happened.
pub fn compare(before: &Value, after: &Value, path: &str) -> Vec<Change> {
    let at = |k: &str| {
        if path.is_empty() {
            k.to_string()
        } else {
            format!("{path}.{k}")
        }
    };

    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            let keys: BTreeSet<&String> = b.keys().chain(a.keys()).collect();
            keys.into_iter()
                .flat_map(|k| match (b.get(k), a.get(k)) {
                    (Some(x), Some(y)) => compare(x, y, &at(k)),
                    (None, Some(y)) => vec![Change {
                        path: at(k),
                        kind: "added",
                        from: String::new(),
                        to: brief(y),
                    }],
                    (Some(x), None) => vec![Change {
                        path: at(k),
                        kind: "removed",
                        from: brief(x),
                        to: String::new(),
                    }],
                    (None, None) => vec![],
                })
                .collect()
        }
        (Value::Array(b), Value::Array(a)) => match identity_key(b, a) {
            Some(key) => compare_by_identity(b, a, &key, path),
            None => compare_by_position(b, a, path),
        },
        (x, y) if x == y => Vec::new(),
        (x, y) => vec![Change {
            path: path.to_string(),
            kind: "changed",
            from: brief(x),
            to: brief(y),
        }],
    }
}

/// The field that identifies an element of these arrays, if there is one.
///
/// Required on every element of both sides: a key present on some of them would
/// match part of the list by name and the rest by position, which is worse than
/// either.
fn identity_key(b: &[Value], a: &[Value]) -> Option<String> {
    const CANDIDATES: [&str; 8] = [
        "id",
        "uuid",
        "name",
        "hostname",
        "queue_name",
        "domain_name",
        "cidr",
        "prefix",
    ];
    let all = || b.iter().chain(a.iter());
    if all().count() == 0 || !all().all(Value::is_object) {
        return None;
    }
    CANDIDATES
        .iter()
        .find(|k| {
            all().all(|v| {
                v.get(**k)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            })
        })
        .map(|k| (*k).to_string())
}

fn compare_by_identity(b: &[Value], a: &[Value], key: &str, path: &str) -> Vec<Change> {
    let index = |xs: &[Value]| -> BTreeMap<String, Value> {
        xs.iter()
            .map(|v| {
                (
                    v.get(key)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                    v.clone(),
                )
            })
            .collect()
    };
    // Matched on the stable key, shown by the one somebody chose: a rename
    // should read as a change rather than as an addition and a removal, and a
    // path of `[4e0fe953…]` tells nobody which zone it is.
    let shown = |v: Option<&Value>, id: &str| -> String {
        v.and_then(|v| {
            ["name", "hostname", "queue_name", "title"]
                .iter()
                .find_map(|k| v.get(*k).and_then(Value::as_str))
        })
        .filter(|s| !s.is_empty() && *s != id)
        .map(str::to_string)
        .unwrap_or_else(|| id.to_string())
    };
    let (bi, ai) = (index(b), index(a));
    let ids: BTreeSet<&String> = bi.keys().chain(ai.keys()).collect();

    ids.into_iter()
        .flat_map(|id| {
            let where_ = format!("{path}[{}]", shown(bi.get(id).or_else(|| ai.get(id)), id));
            match (bi.get(id), ai.get(id)) {
                (Some(x), Some(y)) => compare(x, y, &where_),
                (None, Some(v)) => vec![Change {
                    path: where_,
                    kind: "added",
                    from: String::new(),
                    to: shown(Some(v), id),
                }],
                (Some(v), None) => vec![Change {
                    path: where_,
                    kind: "removed",
                    from: shown(Some(v), id),
                    to: String::new(),
                }],
                (None, None) => vec![],
            }
        })
        .collect()
}

fn compare_by_position(b: &[Value], a: &[Value], path: &str) -> Vec<Change> {
    let mut out = Vec::new();
    for i in 0..b.len().max(a.len()) {
        let where_ = format!("{path}[{i}]");
        match (b.get(i), a.get(i)) {
            (Some(x), Some(y)) => out.extend(compare(x, y, &where_)),
            (None, Some(y)) => out.push(Change {
                path: where_,
                kind: "added",
                from: String::new(),
                to: brief(y),
            }),
            (Some(x), None) => out.push(Change {
                path: where_,
                kind: "removed",
                from: brief(x),
                to: String::new(),
            }),
            (None, None) => {}
        }
    }
    out
}

/// A value as one short line, so a diff row stays readable.
fn brief(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    };
    if s.chars().count() <= 60 {
        return s;
    }
    format!("{}…", s.chars().take(59).collect::<String>())
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

    fn paths(cs: &[Change]) -> Vec<String> {
        cs.iter().map(Change::describe).collect()
    }

    #[test]
    fn an_identical_document_has_no_changes() {
        let v = json!({"a": 1, "b": [{"id": "x", "on": true}]});
        assert!(compare(&v, &v, "").is_empty());
    }

    #[test]
    fn a_changed_leaf_is_reported_with_both_values() {
        let cs = compare(
            &json!({"settings": {"ssl": "flexible"}}),
            &json!({"settings": {"ssl": "strict"}}),
            "",
        );
        assert_eq!(paths(&cs), vec!["settings.ssl: flexible → strict"]);
    }

    #[test]
    fn an_element_added_to_a_list_does_not_report_the_whole_list_as_changed() {
        // Matched by identity: inserting at the front would otherwise shift
        // every element after it and bury the one thing that happened.
        let before = json!([{"id": "a", "on": true}, {"id": "b", "on": true}]);
        let after =
            json!([{"id": "z", "on": true}, {"id": "a", "on": true}, {"id": "b", "on": false}]);
        let cs = compare(&before, &after, "zones");
        assert_eq!(
            paths(&cs),
            vec!["zones[b].on: true → false", "zones[z] added"],
            "one addition and one change, not three shifted rows"
        );
    }

    #[test]
    fn a_removed_element_is_named_by_its_identity_and_not_twice() {
        let cs = compare(
            &json!([{"name": "old"}, {"name": "kept"}]),
            &json!([{"name": "kept"}]),
            "rules",
        );
        assert_eq!(paths(&cs), vec!["rules[old] removed"]);
        assert_eq!(cs[0].kind, "removed");
    }

    #[test]
    fn an_element_matched_by_id_is_shown_by_the_name_somebody_chose() {
        // Matching on the id keeps a rename a change rather than an add and a
        // remove; showing the name is what makes the line mean something.
        let cs = compare(
            &json!([{"id": "4e0fe953", "name": "example.com", "paused": false}]),
            &json!([{"id": "4e0fe953", "name": "example.com", "paused": true}]),
            "zones",
        );
        assert_eq!(paths(&cs), vec!["zones[example.com].paused: false → true"]);
    }

    #[test]
    fn a_list_without_a_shared_identity_falls_back_to_position() {
        // Half-matching by name and half by index would be worse than either.
        let cs = compare(&json!([1, 2, 3]), &json!([1, 9, 3]), "ports");
        assert_eq!(paths(&cs), vec!["ports[1]: 2 → 9"]);

        let mixed = compare(
            &json!([{"id": "a"}, {"noid": 1}]),
            &json!([{"id": "a"}, {"noid": 2}]),
            "xs",
        );
        assert_eq!(paths(&mixed), vec!["xs[1].noid: 1 → 2"]);
    }

    #[test]
    fn a_long_value_is_shortened_rather_than_wrapped_across_the_row() {
        let long = "x".repeat(200);
        let cs = compare(&json!({"k": "short"}), &json!({"k": long}), "");
        assert!(cs[0].to.ends_with('…'));
        assert_eq!(cs[0].to.chars().count(), 60);
    }

    #[test]
    fn an_added_key_is_distinguished_from_a_changed_one() {
        let cs = compare(&json!({"a": 1}), &json!({"a": 1, "b": 2}), "");
        assert_eq!(cs[0].kind, "added");
        assert_eq!(paths(&cs), vec!["b: 2"]);
    }

    #[test]
    fn every_recorded_body_goes_through_the_redaction_list() {
        // The file is meant to be moved between machines, which makes it the
        // last place for a live credential. This asserts the wiring, not the
        // list — `cf::secrets` owns and tests that.
        let mut reads: BTreeMap<String, Value> = BTreeMap::new();
        reads.insert(
            "GET /accounts/x/cfd_tunnel/t/token".into(),
            json!({"token": "eyJhIjoi-a-real-connector-credential"}),
        );
        reads.insert(
            "LIST /accounts/x/challenges/widgets".into(),
            json!([{"name": "signup", "secret": "0x4AAAAAAABkMY"}]),
        );
        reads.insert("LIST /zones".into(), json!([{"name": "example.com"}]));

        let redacted: usize = reads.values_mut().map(crate::cf::secrets::redact).sum();
        assert_eq!(redacted, 2);
        assert_eq!(
            reads["GET /accounts/x/cfd_tunnel/t/token"]["token"],
            json!("<redacted:36>"),
            "replaced by its length, so the record stays auditable"
        );
        assert_eq!(
            reads["LIST /accounts/x/challenges/widgets"][0]["secret"],
            json!("<redacted:14>")
        );
        assert_eq!(
            reads["LIST /zones"][0]["name"],
            json!("example.com"),
            "and everything else survives"
        );
    }

    #[test]
    fn an_unread_marker_survives_redaction_as_itself() {
        // A refusal is part of the record, and must not be mistaken for data.
        let mut v = json!({record::UNREAD: "API error 403"});
        assert_eq!(crate::cf::secrets::redact(&mut v), 0);
        assert!(record::is_unread(&v));
    }

    #[test]
    fn a_snapshot_of_a_zone_is_named_after_the_zone_rather_than_the_account() {
        let p = default_name("a1b2c3d4e5f60718293a4b5c6d7e8f90", "example.com");
        assert!(p.to_string_lossy().contains("example-com"));
        let acct = default_name("a1b2c3d4e5f60718293a4b5c6d7e8f90", "");
        assert!(acct.to_string_lossy().contains("a1b2c3d4"));
    }
}
