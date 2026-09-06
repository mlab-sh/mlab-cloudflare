//! Rendering.
//!
//! The default is a plain, quiet terminal render: two-space indent, dimmed
//! labels, one blank line around each block. `-o json` switches every command
//! to raw JSON on stdout, untouched and parsable — nothing is humanized there,
//! so a pipeline always sees exactly what the API returned.

use std::sync::atomic::{AtomicU8, Ordering};

use colored::Colorize;
use serde_json::Value;

/// Longest cell a table will print before truncating; a Cloudflare id (32)
/// and most hostnames still fit.
const MAX_CELL: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);

/// Resolve the format once at startup. Anything unknown means human.
pub fn init(format: Option<&str>) {
    let v = match format
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => 1,
        _ => 0,
    };
    FORMAT.store(v, Ordering::SeqCst);
}

pub fn format() -> Format {
    match FORMAT.load(Ordering::SeqCst) {
        1 => Format::Json,
        _ => Format::Human,
    }
}

pub fn is_json() -> bool {
    format() == Format::Json
}

/// A table column: a header plus the JSON paths to try, in order.
pub struct Col(pub &'static str, pub &'static [&'static str]);

pub const ACCOUNT_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("ID", &["id"]),
    Col("TYPE", &["type"]),
    Col("2FA REQUIRED", &["settings.enforce_twofactor"]),
    Col("CREATED", &["created_on"]),
];

/// Zones of one account. The owning account is in the heading, so repeating it
/// on every row would be a column of one value.
pub const ZONE_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("STATUS", &["status"]),
    Col("PLAN", &["plan.name"]),
    Col("TYPE", &["type"]),
    Col("PAUSED", &["paused"]),
    Col("ID", &["id"]),
];

/// Zones across several accounts, where the owner is the point.
pub const ZONE_ACROSS_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("STATUS", &["status"]),
    Col("PLAN", &["plan.name"]),
    Col("PAUSED", &["paused"]),
    Col("ACCOUNT", &["account.name"]),
    Col("ID", &["id"]),
];

/// One row per permission a token policy grants, so a wildcard scope is
/// visible rather than buried in a nested object.
pub const POLICY_COLS: &[Col] = &[
    Col("EFFECT", &["effect"]),
    Col("SCOPE", &["scope"]),
    Col("PERMISSIONS", &["permissions"]),
];

/// DNS records, read as the map of what a zone points at.
pub const DNS_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("TYPE", &["type"]),
    Col("CONTENT", &["content"]),
    Col("PROXIED", &["proxied"]),
    Col("TTL", &["ttl"]),
    Col("COMMENT", &["comment"]),
];

/// One row per zone: can it be sent mail as, and what does it say about it.
pub const MAIL_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("MX", &["mx"]),
    Col("SPF", &["spf"]),
    Col("DMARC", &["dmarc"]),
];

pub const DOMAIN_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("STATUS", &["status"]),
    Col("EXPIRES", &["expires"]),
    Col("AUTO-RENEW", &["autoRenew"]),
    Col("LOCKED", &["locked"]),
    Col("WHOIS", &["privacy"]),
];

pub const CACHE_COLS: &[Col] = &[
    Col("REQUEST", &["request"]),
    Col("AGE", &["age"]),
    Col("STATE", &["state"]),
    Col("KB", &["kb"]),
];

/// One row per zone: how it speaks TLS, and whether the edge is enforcing.
pub const POSTURE_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("PLAN", &["plan"]),
    Col("SSL", &["ssl"]),
    Col("MIN TLS", &["minTls"]),
    Col("HSTS", &["hsts"]),
    Col("HTTPS", &["https"]),
    Col("SECURITY", &["security"]),
    Col("DEV MODE", &["dev"]),
];

/// Rules in the order they execute, which is the only order that matters.
pub const RULE_COLS: &[Col] = &[
    Col("#", &["n"]),
    Col("ACTION", &["action"]),
    Col("ON", &["on"]),
    Col("DESCRIPTION", &["description"]),
    Col("EXPRESSION", &["expression"]),
];

pub const EDGE_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("KIND", &["kind"]),
    Col("WHAT", &["what"]),
    Col("TARGET", &["target"]),
];

/// Whether the origin will talk to anyone who finds its address.
pub const ORIGIN_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("SSL", &["ssl"]),
    Col("ORIGIN PULLS", &["originPulls"]),
    Col("PUBLISHED", &["published"]),
    Col("ORIGIN", &["exposure"]),
];

pub const CERT_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("HOSTS", &["hosts"]),
    Col("ISSUER", &["issuer"]),
    Col("SIGNATURE", &["signature"]),
    Col("STATUS", &["status"]),
    Col("EXPIRES", &["expires"]),
];

pub const ACCOUNT_CERT_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("TYPE", &["type"]),
    Col("ISSUER", &["issuer"]),
    Col("CA", &["ca"]),
    Col("EXPIRES", &["expires"]),
];

pub const HOSTNAME_COLS: &[Col] = &[
    Col("ZONE", &["zone"]),
    Col("KIND", &["kind"]),
    Col("NAME", &["name"]),
    Col("STATUS", &["status"]),
    Col("SSL", &["ssl"]),
    Col("EXPIRES", &["expires"]),
];

/// What an audit could not look at, so a report never implies it did.
pub const UNREAD_COLS: &[Col] = &[
    Col("AREA", &["area"]),
    Col("ENDPOINT", &["path"]),
    Col("WHY", &["reason"]),
];

pub const MEMBER_COLS: &[Col] = &[
    Col("EMAIL", &["email"]),
    Col("STATUS", &["status"]),
    Col("2FA", &["twoFactor"]),
    Col("ROLES", &["roles"]),
    Col("ID", &["id"]),
];

/// API tokens, read as credentials: what is missing — an expiry, a last-used
/// date — matters as much as what is set.
pub const TOKEN_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("STATUS", &["status"]),
    Col("ACCESS", &["access"]),
    Col("EXPIRES", &["expires"]),
    Col("LAST USED", &["lastUsed"]),
    Col("POLICIES", &["policies"]),
    Col("ID", &["id"]),
];

pub const SCIM_COLS: &[Col] = &[
    Col("USER", &["user"]),
    Col("ACTIVE", &["active"]),
    Col("ID", &["id"]),
];

pub const ACTIVITY_COLS: &[Col] = &[
    Col("WHEN", &["when"]),
    Col("ACTOR", &["actor"]),
    Col("BY", &["by"]),
    Col("ACTION", &["action"]),
    Col("RESULT", &["result"]),
    Col("RESOURCE", &["resource"]),
    Col("IP", &["ip"]),
];

// ---- blocks -----------------------------------------------------------------

/// Graded findings, worst first.
///
/// Not a table: the detail of a finding is the list of names somebody has to
/// act on, and a column would clip it at the width of the terminal. So each
/// finding is a severity tag, a sentence, and its names wrapped underneath.
pub fn findings(rows: &[Value]) {
    if is_json() {
        print_json(&Value::Array(rows.to_vec()));
        return;
    }
    if rows.is_empty() {
        println!();
        println!("  {}", "nothing to report".dimmed());
        return;
    }

    // Both leading columns are padded to their widest value so the sentences
    // start on one line down the block; an unpadded area column makes the
    // findings read as ragged rather than as a list.
    let width_of = |key: &str| {
        rows.iter()
            .map(|f| str_at(f, key).chars().count())
            .max()
            .unwrap_or(0)
    };
    let (sev_w, area_w) = (width_of("severity"), width_of("area"));
    let indent = sev_w + area_w + 4;

    println!();
    for f in rows {
        let sev = str_at(f, "severity");
        println!(
            "  {}  {}  {}",
            format!("{sev:<sev_w$}").bold().color(severity_color(&sev)),
            format!("{:<area_w$}", str_at(f, "area")).dimmed(),
            str_at(f, "finding")
        );
        let detail = str_at(f, "detail");
        if !detail.is_empty() {
            // Indented under the sentence it belongs to, and wrapped rather
            // than clipped, because these are the names to act on.
            for line in wrap(&detail, 88) {
                println!("  {}{}", " ".repeat(indent), line.dimmed());
            }
        }
    }
}

fn severity_color(sev: &str) -> colored::Color {
    match sev {
        "high" => colored::Color::Red,
        "medium" => colored::Color::Yellow,
        "low" => colored::Color::Cyan,
        _ => colored::Color::White,
    }
}

fn str_at(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Break a detail into lines of at most `width` characters, on separator
/// boundaries so no item is split in half.
///
/// Findings use two separators: a comma between plain names, and a semicolon
/// between items that contain commas of their own. Breaking on the comma when
/// the semicolon is the real separator splits sentences mid-clause, so the
/// outer separator wins when it is present.
fn wrap(s: &str, width: usize) -> Vec<String> {
    let sep = if s.contains("; ") { "; " } else { ", " };
    let mut lines = Vec::new();
    let mut cur = String::new();
    for part in s.split(sep) {
        if !cur.is_empty() && cur.chars().count() + sep.len() + part.chars().count() > width {
            lines.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push_str(sep);
        }
        cur.push_str(part);
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

/// A section title, printed above a block.
pub fn heading(text: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", text.bold());
}

/// The count line closing a list.
pub fn count(n: usize, noun: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", format!("{n} {}", plural(noun, n)).dimmed());
}

/// English plural, enough for the nouns this CLI counts.
fn plural(noun: &str, n: usize) -> String {
    if n == 1 {
        return noun.to_string();
    }
    match noun.chars().last() {
        // "policy" -> "policies", but "day" -> "days": only a consonant before
        // the y takes the -ies form.
        Some('y') if !noun.ends_with(['a', 'e', 'i', 'o', 'u', 'y']) => noun.to_string(),
        Some('y') => format!("{}ies", &noun[..noun.len() - 1]),
        Some('s') | Some('x') | Some('z') => format!("{noun}es"),
        _ => format!("{noun}s"),
    }
}

/// An aligned key/value block, for status output the CLI composes itself
/// rather than reading from the API.
pub fn pairs(rows: &[(&str, String)]) {
    if is_json() {
        return;
    }
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    println!();
    for (k, v) in rows {
        println!("  {:<width$}  {}", k.dimmed(), tint(v));
    }
    println!();
}

/// Render one value: an object as a key/value block, anything else inline.
pub fn one(v: &Value) {
    if is_json() {
        print_json(v);
        return;
    }
    println!();
    block(v, 2);
    println!();
}

/// Render a list with known columns.
pub fn list(rows: &[Value], cols: &[Col]) {
    let spec: Vec<(String, Vec<String>)> = cols
        .iter()
        .map(|c| (c.0.to_string(), c.1.iter().map(|p| p.to_string()).collect()))
        .collect();
    render(rows, &spec);
}

/// Render a list whose shape is only known at runtime, i.e. `api ... --list`:
/// columns are the scalar fields of the first row.
pub fn list_auto(rows: &[Value]) {
    render(rows, &auto_spec(rows));
}

fn auto_spec(rows: &[Value]) -> Vec<(String, Vec<String>)> {
    const MAX_COLS: usize = 8;
    let Some(map) = rows.first().and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = map
        .iter()
        .filter(|(_, v)| !matches!(v, Value::Object(_) | Value::Array(_)))
        .map(|(k, _)| k)
        .collect();
    keys.sort_by_key(|k| (rank(k), k.to_string()));
    keys.into_iter()
        .take(MAX_COLS)
        .map(|k| (k.to_uppercase(), vec![k.clone()]))
        .collect()
}

fn render(rows: &[Value], spec: &[(String, Vec<String>)]) {
    if is_json() {
        print_json(&Value::Array(rows.to_vec()));
        return;
    }
    if rows.is_empty() || spec.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    // Keep only the columns that actually carry data on this account.
    let used: Vec<&(String, Vec<String>)> = spec
        .iter()
        .filter(|c| {
            let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
            rows.iter().any(|r| !first(r, &paths).is_empty())
        })
        .collect();
    if used.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            used.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&first(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = used.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    println!();
    let head: Vec<String> = used.iter().map(|c| c.0.clone()).collect();
    println!("  {}", pad_join(&head, &widths, |s| s.dimmed().to_string()));
    for row in &cells {
        println!("  {}", pad_join(row, &widths, |s| tint(s).to_string()));
    }
}

/// Pad every cell but the last to its column width, then colour it.
fn pad_join(cells: &[String], widths: &[usize], paint: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for (i, c) in cells.iter().enumerate() {
        out.push_str(&paint(c));
        if i + 1 != cells.len() {
            out.push_str(&" ".repeat(widths[i].saturating_sub(c.chars().count()) + 2));
        }
    }
    out.trim_end().to_string()
}

/// A key/value block, recursing into nested objects and tables of objects.
fn block(v: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    let Some(map) = v.as_object() else {
        println!("{pad}{}", tint(&scalar(v)));
        return;
    };

    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| (rank(k), k.to_string()));

    let width = keys
        .iter()
        .filter(|k| !matches!(map[**k], Value::Object(_) | Value::Array(_)))
        .map(|k| k.chars().count())
        .max()
        .unwrap_or(0);

    // Scalars first, so the identity of the thing is at the top of the block.
    for k in &keys {
        match &map[*k] {
            Value::Object(_) | Value::Array(_) => {}
            val => println!("{pad}{:<width$}  {}", k.dimmed(), tint(&humanize(k, val))),
        }
    }

    for k in &keys {
        // A branch that would print nothing but its own title is noise.
        if !has_content(&map[*k]) {
            continue;
        }
        match &map[*k] {
            Value::Array(items) if items.iter().all(|i| i.is_object()) => {
                println!();
                println!("{pad}{}", k.bold());
                let spec = auto_spec(items);
                for line in table_lines(items, &spec) {
                    println!("{pad}  {line}");
                }
            }
            Value::Array(items) => {
                let joined = items.iter().map(scalar).collect::<Vec<_>>().join(", ");
                println!("{pad}{:<width$}  {}", k.dimmed(), tint(&clip(&joined)));
            }
            Value::Object(_) => {
                println!();
                println!("{pad}{}", k.bold());
                block(&map[*k], indent + 2);
            }
            _ => {}
        }
    }
}

/// The lines of a sub-table, so a nested block can indent them.
fn table_lines(rows: &[Value], spec: &[(String, Vec<String>)]) -> Vec<String> {
    if spec.is_empty() {
        return Vec::new();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            spec.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&first(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = spec.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    let mut out = vec![pad_join(
        &spec.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        &widths,
        |s| s.dimmed().to_string(),
    )];
    out.extend(
        cells
            .iter()
            .map(|r| pad_join(r, &widths, |s| tint(s).to_string())),
    );
    out
}

/// Print raw JSON on stdout. The only thing `-o json` ever emits.
pub fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

// ---- helpers ----------------------------------------------------------------

/// Whether a value carries anything printable, however deeply nested.
fn has_content(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.values().any(has_content),
        Value::Array(a) => a.iter().any(has_content),
        Value::Null => false,
        _ => true,
    }
}

/// Identity fields float to the top of a block and to the left of a table.
fn rank(key: &str) -> u8 {
    match key {
        "name" => 0,
        "id" => 1,
        "status" => 2,
        "type" => 3,
        "content" => 4,
        "enabled" | "paused" => 5,
        "created_on" => 6,
        "modified_on" => 7,
        _ => 50,
    }
}

/// Colour a cell by what it says: statuses read faster than they scan.
fn tint(s: &str) -> colored::ColoredString {
    match s {
        "active" | "ok" | "healthy" | "on" | "verified" | "true" | "usable" => s.green(),
        // `false` is an absence, not a fault — a list of unproxied records must
        // not read as a wall of errors.
        "false" => s.dimmed(),
        "pending" | "initializing" | "moved" | "expiring" | "degraded" | "registration_pending" => {
            s.yellow()
        }
        "deactivated" | "deleted" | "expired" | "revoked" | "off" | "unhealthy" | "suspended"
        | "redemption_period" | "pending_delete" => s.red(),
        "redaction" => s.green(),
        "appeared" => s.yellow(),
        "disappeared" => s.dimmed(),
        "changed" => s.cyan(),
        "critical" => s.red().bold(),
        "high" => s.red(),
        "medium" | "weak" => s.yellow(),
        "low" | "info" | "unknown" | "none" | "stale" => s.dimmed(),
        "allow" | "read" | "-all" | "p=reject" => s.green(),
        "deny" | "block" | "failed" | "write" | "+all" | "?all" | "flexible"
        | "essentially_off" => s.red(),
        "skip" | "log" | "full" | "1.0" | "1.1" | "pending_validation" => s.yellow(),
        "reachable" => s.red().bold(),
        "not readable" => s.dimmed(),
        "strict" | "managed_challenge" | "challenge" | "1.2" | "1.3" => s.green(),
        "~all" | "p=quarantine" | "p=none" | "set" => s.yellow(),
        "" => s.normal(),
        _ => s.normal(),
    }
}

/// Units the API leaves raw. Only applied to unambiguously named keys, and only
/// in human mode — `-o json` keeps the original numbers.
fn humanize(key: &str, v: &Value) -> String {
    let raw = scalar(v);
    let Some(n) = v.as_f64() else { return raw };

    // A DNS TTL of 1 means "automatic", which is not a duration at all, and
    // printing "(0m)" next to it says the opposite of what it means.
    if key == "ttl" {
        return match n {
            1.0 => "1  (auto)".to_string(),
            s if s >= 60.0 => format!("{raw}  {}", format!("({})", duration(s as u64)).dimmed()),
            _ => raw,
        };
    }
    if key.ends_with("_bytes") || key == "size" {
        return format!("{raw}  {}", format!("({})", bytes(n)).dimmed());
    }
    if key.ends_with("_seconds") && n >= 60.0 {
        return format!("{raw}  {}", format!("({})", duration(n as u64)).dimmed());
    }
    raw
}

fn bytes(b: f64) -> String {
    match b {
        n if n >= 1e12 => format!("{:.1} TB", n / 1e12),
        n if n >= 1e9 => format!("{:.1} GB", n / 1e9),
        n if n >= 1e6 => format!("{:.1} MB", n / 1e6),
        n if n >= 1e3 => format!("{:.1} kB", n / 1e3),
        n => format!("{n:.0} B"),
    }
}

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    match (d, h) {
        (0, 0) => format!("{m}m"),
        (0, _) => format!("{h}h{m:02}m"),
        _ => format!("{d}d {h}h"),
    }
}

/// First non-empty value among `paths`, as a display string.
fn first(v: &Value, paths: &[&str]) -> String {
    for p in paths {
        if let Some(found) = dig(v, p) {
            let s = scalar(found);
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

/// Follow a dotted path into a JSON object.
fn dig<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// One-line rendering of a value; nested ones fall back to compact JSON.
fn scalar(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        // An empty list is an absence, not the two characters "[]", and a list
        // of scalars reads better as a list than as JSON.
        Value::Array(a) if a.is_empty() => String::new(),
        Value::Array(a) if a.iter().all(|i| !i.is_object() && !i.is_array()) => {
            a.iter().map(scalar).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// Truncate an over-long cell so one field cannot wreck the alignment.
fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_CELL {
        return s.to_string();
    }
    let kept: String = s.chars().take(MAX_CELL - 1).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_unknown_or_missing_format_falls_back_to_human() {
        init(None);
        assert_eq!(format(), Format::Human);
        init(Some("banana"));
        assert_eq!(format(), Format::Human);
        init(Some("JSON"));
        assert!(is_json(), "the format is matched case-insensitively");
        init(None);
    }

    #[test]
    fn auto_columns_are_scalars_only_with_identity_first() {
        let rows = vec![json!({"zzz": 1, "name": "example.com", "meta": {"cdn": true}, "id": "x"})];
        let cols: Vec<String> = auto_spec(&rows).into_iter().map(|c| c.0).collect();
        assert_eq!(
            cols,
            vec!["NAME", "ID", "ZZZ"],
            "nested fields stay out of the table"
        );
    }

    #[test]
    fn a_path_can_be_dotted_with_fallbacks() {
        let v = json!({"plan": {"name": "Enterprise"}});
        assert_eq!(first(&v, &["name", "plan.name"]), "Enterprise");
        assert_eq!(first(&v, &["nope"]), "");
    }

    #[test]
    fn units_are_only_added_to_unambiguous_keys() {
        assert!(humanize("ttl", &json!(3600)).contains("1h00m"));
        assert!(humanize("size", &json!(1_500_000_000.0)).contains("1.5 GB"));
        assert!(humanize("retention_seconds", &json!(561466)).contains("6d 11h"));
        assert_eq!(
            humanize("priority", &json!(4)),
            "4",
            "a plain number is left alone"
        );
        assert_eq!(
            humanize("name", &json!("ttl")),
            "ttl",
            "strings are never rewritten"
        );
    }

    #[test]
    fn an_automatic_ttl_is_not_reported_as_a_duration() {
        // TTL 1 is Cloudflare's "automatic"; rendering it as "(0m)" would say
        // the record expires immediately.
        assert_eq!(humanize("ttl", &json!(1)), "1  (auto)");
        assert_eq!(humanize("ttl", &json!(30)), "30", "under a minute, as-is");
    }

    #[test]
    fn a_branch_with_nothing_in_it_is_not_printable() {
        assert!(!has_content(&json!({"plan": {"features": []}})));
        assert!(!has_content(&json!({})));
        assert!(has_content(&json!({"plan": {"features": [{"id": 1}]}})));
        assert!(
            has_content(&json!(false)),
            "false is a value, not an absence"
        );
    }

    #[test]
    fn nouns_are_pluralized_rather_than_suffixed() {
        assert_eq!(plural("zone", 2), "zones");
        assert_eq!(plural("policy", 2), "policies", "not \"policys\"");
        assert_eq!(plural("token", 1), "token");
        assert_eq!(plural("account", 0), "accounts", "none is still plural");
    }

    #[test]
    fn lists_read_as_lists_and_an_empty_one_reads_as_nothing() {
        assert_eq!(scalar(&json!([])), "", "an empty list is an absence");
        assert_eq!(scalar(&json!(["#waf", "#dns"])), "#waf, #dns");
        assert_eq!(
            scalar(&json!([{"a": 1}])),
            "[{\"a\":1}]",
            "objects still fall back to JSON"
        );
    }

    #[test]
    fn the_outer_separator_wins_when_items_contain_commas_of_their_own() {
        // Breaking on the comma here would split "skips a, b" mid-clause.
        let detail = "zone1: rule skips a, b; zone2: rule skips c, d; zone3: rule skips e";
        let lines = wrap(detail, 40);
        assert!(
            lines.iter().all(|l| !l.starts_with(char::is_whitespace)),
            "{lines:?}"
        );
        assert!(lines[0].ends_with("skips a, b"), "{lines:?}");
    }

    #[test]
    fn a_detail_wraps_on_separators_rather_than_mid_name() {
        let names = "alice@example.com, bob@example.com, carol@example.com";
        let lines = wrap(names, 40);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("bob@example.com"), "{lines:?}");
        assert!(
            lines.iter().all(|l| !l.starts_with(',')),
            "no line starts on a separator: {lines:?}"
        );
    }

    #[test]
    fn a_single_item_longer_than_the_width_still_gets_its_own_line() {
        // Better one over-long line than a truncated address.
        let one = "a-very-long-address@some-extremely-long-domain.example.com";
        assert_eq!(wrap(one, 20), vec![one.to_string()]);
    }

    #[test]
    fn long_cells_are_clipped_to_keep_columns_aligned() {
        let long = "x".repeat(80);
        assert_eq!(clip(&long).chars().count(), MAX_CELL);
        assert!(clip(&long).ends_with('…'));
        assert_eq!(clip("short"), "short");
    }
}
