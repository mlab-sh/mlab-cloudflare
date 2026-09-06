//! The graded checks, as pure functions over data someone else fetched.
//!
//! Nothing here performs a request. A check takes what an endpoint returned and
//! returns [`Finding`]s, which makes every one of them testable against a
//! recorded response and keeps the question "what does this mean" separate from
//! "how do I get it".
//!
//! Three rules the checks follow, because an audit that breaks them stops being
//! believed:
//!
//! 1. **A finding names what is true, not what is missing.** "No SSO connector"
//!    is a fact about an account with three members and a finding about one with
//!    forty; the check says which.
//! 2. **Absence of data is never a pass.** A read that was refused is reported
//!    as unread by the caller, never silently as "nothing found".
//! 3. **The detail carries the names.** A count tells you there is work; the
//!    list tells you where, and is what gets pasted into the ticket.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

/// How much a finding should worry the reader.
///
/// Ordered so `sort` puts the worst last and `rev` puts it first; the variants
/// are declared low-to-high for that reason. The scale holds exactly the levels
/// some check can currently emit — a level nothing produces is a promise the
/// report does not keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Worth knowing, not worth doing anything about on its own.
    Info,
    /// Hygiene: real, but it needs something else to go wrong first.
    Low,
    /// A control that is weaker than it looks.
    Medium,
    /// A credential or a permission that would matter on a bad day.
    High,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        })
    }
}

/// One graded observation.
#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    /// The area of the account this is about, e.g. `members` or `tokens`.
    pub area: &'static str,
    /// One line, in the present tense, saying what is the case.
    pub finding: String,
    /// The names behind the count. Empty when the finding is about the account
    /// as a whole rather than about a list of things.
    pub detail: String,
}

impl Finding {
    fn new(severity: Severity, area: &'static str, finding: impl Into<String>) -> Self {
        Finding {
            severity,
            area,
            finding: finding.into(),
            detail: String::new(),
        }
    }

    fn with(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    pub fn to_json(&self) -> Value {
        json!({
            "severity": self.severity.to_string(),
            "area": self.area,
            "finding": self.finding,
            "detail": self.detail,
        })
    }
}

/// Worst first, then by area, so a report reads top-down in priority order.
pub fn sorted(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.area.cmp(b.area))
            .then_with(|| a.finding.cmp(&b.finding))
    });
    findings
}

/// How many findings there are at each severity, worst first.
pub fn tally(findings: &[Finding]) -> Vec<(Severity, usize)> {
    let mut counts: BTreeMap<Severity, usize> = BTreeMap::new();
    for f in findings {
        *counts.entry(f.severity).or_default() += 1;
    }
    counts.into_iter().rev().collect()
}

/// English agreement for a count-led sentence.
///
/// A finding that says "1 members hold" is a finding people stop reading, and
/// every check here leads with a count.
fn agree(n: usize, one: &'static str, many: &'static str) -> &'static str {
    if n == 1 {
        one
    } else {
        many
    }
}

// ---- members ----------------------------------------------------------------

/// Checks over the account object and its member list.
pub fn members(account: &Value, members: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    let total = members.len();

    let enforced = account
        .get("settings")
        .and_then(|s| s.get("enforce_twofactor"))
        .and_then(Value::as_bool);
    if enforced == Some(false) {
        out.push(Finding::new(
            Severity::High,
            "members",
            "two-factor authentication is not enforced on the account",
        ));
    }

    // Accepted members only: an invitation nobody took up has no second factor
    // yet by definition, and counting it here would double-report the next one.
    let joined: Vec<&Value> = members.iter().filter(|m| accepted(m)).collect();
    let no_2fa: Vec<String> = joined
        .iter()
        .filter(|m| {
            m.get("user")
                .and_then(|u| u.get("two_factor_authentication_enabled"))
                .and_then(Value::as_bool)
                == Some(false)
        })
        .map(|m| email(m))
        .collect();
    if !no_2fa.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "members",
                format!(
                    "{} of {total} {} no second factor",
                    no_2fa.len(),
                    agree(no_2fa.len(), "members has", "members have")
                ),
            )
            .with(no_2fa.join(", ")),
        );
    }

    let pending: Vec<String> = members.iter().filter(|m| !accepted(m)).map(email).collect();
    if !pending.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "members",
                format!(
                    "{} {} never accepted",
                    pending.len(),
                    agree(pending.len(), "invitation was", "invitations were")
                ),
            )
            .with(pending.join(", ")),
        );
    }

    // The privileges that decide who can grant privileges. Membership and SSO
    // are the two that turn any account access into all account access;
    // billing is the one that turns it into money.
    for (product, what, severity) in [
        ("member", "add and remove members", Severity::Medium),
        (
            "dash_sso",
            "change how the account authenticates",
            Severity::Medium,
        ),
        ("billing", "change billing", Severity::Info),
    ] {
        let who: Vec<String> = joined
            .iter()
            .filter(|m| can_edit(m, product))
            .map(|m| email(m))
            .collect();
        if who.len() > 1 {
            out.push(
                Finding::new(
                    severity,
                    "members",
                    format!("{} of {total} members can {what}", who.len()),
                )
                .with(who.join(", ")),
            );
        }
    }

    // A member carrying both a legacy role and an IAM policy is an account
    // partway through a migration, where the effective permission is the union
    // and nobody has that union in their head.
    let both: Vec<String> = joined
        .iter()
        .filter(|m| !list(m, "roles").is_empty() && !list(m, "policies").is_empty())
        .map(|m| email(m))
        .collect();
    if !both.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "members",
                format!(
                    "{} {} both a legacy role and an IAM policy; the effective permission \
                     is the union of the two",
                    both.len(),
                    agree(both.len(), "member holds", "members hold")
                ),
            )
            .with(both.join(", ")),
        );
    }

    out
}

// ---- tokens -----------------------------------------------------------------

/// Checks over a list of API tokens, from either store.
///
/// `store` names which one, because it changes what a finding means: an
/// account-owned token surviving its creator is the feature, and a user-owned
/// one doing so is impossible.
pub fn tokens(tokens: &[Value], store: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let area = "tokens";
    let live: Vec<&Value> = tokens
        .iter()
        .filter(|t| str_of(t, "status") == "active")
        .collect();

    let named = |ts: &[&Value]| -> String {
        ts.iter()
            .map(|t| {
                let n = str_of(t, "name");
                if n.is_empty() {
                    str_of(t, "id")
                } else {
                    n
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    let writers: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|t| !write_groups(t).is_empty())
        .collect();
    if !writers.is_empty() {
        let detail = writers
            .iter()
            .map(|t| format!("{} ({})", str_of(t, "name"), write_groups(t).join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        out.push(
            Finding::new(
                Severity::High,
                area,
                format!(
                    "{} active {store} {} write, not only read",
                    writers.len(),
                    agree(writers.len(), "token can", "tokens can")
                ),
            )
            .with(detail),
        );
    }

    let forever: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|t| str_of(t, "expires_on").is_empty())
        .collect();
    if !forever.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                area,
                format!(
                    "{} active {store} {} no expiry",
                    forever.len(),
                    agree(forever.len(), "token has", "tokens have")
                ),
            )
            .with(named(&forever)),
        );
    }

    // A token granted on the account rather than on named zones covers every
    // zone the account will ever hold, including ones created after the grant.
    let blanket: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|t| has_blanket_scope(t))
        .collect();
    if !blanket.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                area,
                format!(
                    "{} active {store} {} scoped to every zone of an account, including \
                     zones added later",
                    blanket.len(),
                    agree(blanket.len(), "token is", "tokens are")
                ),
            )
            .with(named(&blanket)),
        );
    }

    let unused: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|t| str_of(t, "last_used_on").is_empty())
        .collect();
    if !unused.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                area,
                format!(
                    "{} active {store} {} never been used",
                    unused.len(),
                    agree(unused.len(), "token has", "tokens have")
                ),
            )
            .with(named(&unused)),
        );
    }

    let open: Vec<&Value> = live
        .iter()
        .copied()
        .filter(|t| !has_ip_condition(t))
        .collect();
    if !open.is_empty() && open.len() == live.len() {
        out.push(Finding::new(
            Severity::Low,
            area,
            format!("no {store} token restricts the addresses it may be used from"),
        ));
    }

    // Revoked and expired tokens are inert, but a list full of them is a list
    // nobody reviews, which is why the live ones went unnoticed.
    let dead = tokens.len() - live.len();
    if dead > 0 {
        out.push(Finding::new(
            Severity::Info,
            area,
            format!(
                "{dead} of {} {store} tokens are expired or disabled",
                tokens.len()
            ),
        ));
    }

    out
}

// ---- directory --------------------------------------------------------------

/// Checks over how membership is managed: SSO, and SCIM deprovisioning.
///
/// `scim` is the flattened SCIM user list, not the ListResponse envelope.
pub fn directory(members: &[Value], sso: &[Value], scim: &[Value]) -> Vec<Finding> {
    let mut out = Vec::new();
    let area = "directory";
    let joined: Vec<&Value> = members.iter().filter(|m| accepted(m)).collect();

    if sso.is_empty() && joined.len() > 2 {
        out.push(Finding::new(
            Severity::Low,
            area,
            format!(
                "{} members sign in without SSO, so each account is governed by its own \
                 password and second factor",
                joined.len()
            ),
        ));
    }

    if !sso.is_empty() && scim.is_empty() {
        out.push(Finding::new(
            Severity::Medium,
            area,
            "SSO is configured but SCIM provisioning is not, so removing someone from the \
             directory does not remove their account access",
        ));
    }

    if scim.is_empty() {
        return out;
    }

    // Deactivated in the directory and still a member: the offboarding half
    // completed. This is the one finding in this area that is an open door
    // rather than a missing process.
    let member_emails: BTreeSet<String> = joined
        .iter()
        .map(|m| email(m).to_ascii_lowercase())
        .collect();
    let stale: Vec<String> = scim
        .iter()
        .filter(|u| u.get("active").and_then(Value::as_bool) == Some(false))
        .map(scim_email)
        .filter(|e| member_emails.contains(&e.to_ascii_lowercase()))
        .collect();
    if !stale.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                area,
                format!(
                    "{} {} deactivated in the directory but still {} account access",
                    stale.len(),
                    agree(stale.len(), "member is", "members are"),
                    agree(stale.len(), "holds", "hold")
                ),
            )
            .with(stale.join(", ")),
        );
    }

    let scim_emails: BTreeSet<String> = scim
        .iter()
        .map(|u| scim_email(u).to_ascii_lowercase())
        .collect();
    let orphans: Vec<String> = joined
        .iter()
        .map(|m| email(m))
        .filter(|e| !scim_emails.contains(&e.to_ascii_lowercase()))
        .collect();
    if !orphans.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                area,
                format!(
                    "{} {} not managed by the directory, so nothing removes them \
                     automatically",
                    orphans.len(),
                    agree(orphans.len(), "member is", "members are")
                ),
            )
            .with(orphans.join(", ")),
        );
    }

    out
}

// ---- activity ---------------------------------------------------------------

/// Checks over a window of audit-log entries.
pub fn activity(entries: &[Value], window: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let area = "activity";
    if entries.is_empty() {
        return out;
    }

    let failed = entries
        .iter()
        .filter(|e| {
            e.get("action")
                .and_then(|a| a.get("result"))
                .and_then(Value::as_bool)
                == Some(false)
        })
        .count();
    if failed > 0 {
        out.push(Finding::new(
            Severity::Medium,
            area,
            format!(
                "{failed} {} in the last {window}; a run of failures is what a credential \
                 being tried looks like",
                agree(failed, "action failed", "actions failed")
            ),
        ));
    }

    // Who acted, by kind. A configuration change made by a token is normal in a
    // pipeline and worth seeing in an account that has no pipeline.
    let by_token = entries
        .iter()
        .filter(|e| {
            let t = e
                .get("actor")
                .map(|a| str_of(a, "type"))
                .unwrap_or_default();
            !t.is_empty() && t != "user"
        })
        .count();
    if by_token > 0 {
        out.push(Finding::new(
            Severity::Info,
            area,
            format!("{by_token} of {} changes in the last {window} were made by a token or by the system rather than by a person", entries.len()),
        ));
    }

    let destructive: Vec<String> = entries
        .iter()
        .filter(|e| {
            let t = e
                .get("action")
                .map(|a| str_of(a, "type"))
                .unwrap_or_default();
            t.contains("delete") || t.contains("revoke") || t.contains("remove")
        })
        .map(|e| {
            e.get("action")
                .map(|a| str_of(a, "type"))
                .unwrap_or_default()
        })
        .collect();
    if !destructive.is_empty() {
        let kinds: BTreeSet<&String> = destructive.iter().collect();
        out.push(
            Finding::new(
                Severity::Info,
                area,
                format!(
                    "{} {} in the last {window}",
                    destructive.len(),
                    agree(
                        destructive.len(),
                        "deletion or revocation",
                        "deletions or revocations"
                    )
                ),
            )
            .with(kinds.into_iter().cloned().collect::<Vec<_>>().join(", ")),
        );
    }

    // Distinct source addresses, which is the cheapest form of "did this come
    // from where it usually comes from" without a baseline to compare against.
    let ips: BTreeSet<String> = entries
        .iter()
        .filter_map(|e| e.get("actor").map(|a| str_of(a, "ip")))
        .filter(|s| !s.is_empty())
        .collect();
    if ips.len() > 1 {
        out.push(
            Finding::new(
                Severity::Info,
                area,
                format!("changes came from {} distinct addresses", ips.len()),
            )
            .with(ips.into_iter().collect::<Vec<_>>().join(", ")),
        );
    }

    out
}

// ---- dns -------------------------------------------------------------------

/// One zone's DNS, as read. `dnssec` and `hold` are optional because the
/// listing views do not pay for them.
pub struct Zone {
    pub name: String,
    pub id: String,
    pub records: Vec<Value>,
    pub dnssec: Option<Value>,
    pub hold: Option<Value>,
}

impl Zone {
    fn of_type<'a>(&'a self, kinds: &'a [&str]) -> impl Iterator<Item = &'a Value> {
        self.records
            .iter()
            .filter(move |r| kinds.contains(&str_of(r, "type").as_str()))
    }
}

/// The addresses Cloudflare proxies for, which is to say the origins.
///
/// A proxied record still reports its real target in `content`; the proxy hides
/// it from a resolver, not from the API.
fn proxied_origins(records: &[Value]) -> BTreeSet<String> {
    records
        .iter()
        .filter(|r| {
            matches!(str_of(r, "type").as_str(), "A" | "AAAA")
                && r.get("proxied").and_then(Value::as_bool) == Some(true)
        })
        .map(|r| str_of(r, "content"))
        .filter(|c| !is_placeholder(c))
        .collect()
}

/// The records that publish an address Cloudflare also fronts for, as
/// `name → address`.
///
/// Public because the certificate plane asks the same question of the same
/// records — an origin published in DNS is only an exposure when the origin
/// also accepts connections that did not come through Cloudflare — and two
/// implementations of one question would eventually disagree.
pub fn published_origins(records: &[Value]) -> Vec<String> {
    let origins = proxied_origins(records);
    records
        .iter()
        .filter(|r| {
            matches!(str_of(r, "type").as_str(), "A" | "AAAA")
                && r.get("proxied").and_then(Value::as_bool) != Some(true)
                && r.get("proxiable").and_then(Value::as_bool) != Some(false)
                && origins.contains(&str_of(r, "content"))
        })
        .map(|r| format!("{} → {}", str_of(r, "name"), str_of(r, "content")))
        .collect()
}

/// Every public address the zone publishes, with the records that publish it
/// and whether Cloudflare also proxies for it.
///
/// [`published_origins`] answers the narrower question the DNS plane asks — an
/// origin published *around* the proxy — and formats its answer for a report.
/// This returns the addresses themselves, because the enrichment plane has to
/// look each one up and can only afford to do that once per address.
pub fn public_addresses(records: &[Value]) -> Vec<(String, Vec<String>, bool)> {
    let proxied = proxied_origins(records);
    let mut by_addr: BTreeMap<String, (Vec<String>, bool)> = BTreeMap::new();

    for r in records {
        if !matches!(str_of(r, "type").as_str(), "A" | "AAAA") {
            continue;
        }
        let addr = str_of(r, "content");
        // A placeholder is deliberate filler and a private address is
        // unreachable; neither is worth a lookup, and looking one up would
        // spend somebody's quota to learn nothing.
        if addr.is_empty() || is_placeholder(&addr) || is_private(&addr) {
            continue;
        }
        let unproxied = r.get("proxied").and_then(Value::as_bool) != Some(true);
        let entry = by_addr.entry(addr.clone()).or_default();
        entry.0.push(str_of(r, "name"));
        // Exposed means: reachable without going through the proxy, while the
        // proxy is fronting for it. One such record is enough.
        entry.1 |= unproxied && proxied.contains(&addr);
    }

    by_addr
        .into_iter()
        .map(|(addr, (mut names, exposed))| {
            names.sort();
            names.dedup();
            (addr, names, exposed)
        })
        .collect()
}

/// A record that resolves to nothing on purpose.
///
/// `100::` is the IPv6 discard prefix and `192.0.2.0/24` is documentation
/// space; both are the conventional filler for a name that should only ever be
/// reached through the proxy. Reporting them as exposed origins would bury the
/// records that are.
fn is_placeholder(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            // TEST-NET-1, TEST-NET-2, TEST-NET-3.
            matches!(
                (o[0], o[1], o[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            )
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            // 100::/64, the discard-only prefix.
            let seg = v6.segments();
            seg[0] == 0x0100 && seg[1..4] == [0, 0, 0]
        }
        Err(_) => false,
    }
}

/// An address that should not appear in public DNS at all.
fn is_private(addr: &str) -> bool {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                // 100.64.0.0/10, carrier-grade NAT.
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// Records pointing at a third-party platform, where the resource behind the
/// name may no longer exist.
pub fn takeover(zones: &[Zone]) -> Vec<Finding> {
    let mut open = Vec::new();
    let mut verified = Vec::new();
    let mut own = Vec::new();

    for z in zones {
        for r in z.of_type(&["CNAME"]) {
            let target = str_of(r, "content");
            let Some(p) = crate::providers::lookup(&target) else {
                continue;
            };
            let line = format!("{} → {} ({})", str_of(r, "name"), target, p.name);
            match p.claim {
                crate::providers::Claim::Open => open.push(line),
                crate::providers::Claim::Verified => verified.push(line),
                crate::providers::Claim::Own => own.push(line),
            }
        }
    }

    let mut out = Vec::new();
    if !open.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "takeover",
                format!(
                    "{} {} at a platform that hands out names first-come; if the resource \
                     was deprovisioned the name is claimable by anyone",
                    open.len(),
                    agree(open.len(), "record points", "records point")
                ),
            )
            .with(open.join("; ")),
        );
    }
    if !verified.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "takeover",
                format!(
                    "{} {} at a platform that verifies domain ownership; a dangling one is \
                     a dead reference rather than an open door",
                    verified.len(),
                    agree(verified.len(), "record points", "records point")
                ),
            )
            .with(verified.join("; ")),
        );
    }
    if !own.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                "takeover",
                format!(
                    "{} {} at this account's own Cloudflare resources",
                    own.len(),
                    agree(own.len(), "record points", "records point")
                ),
            )
            .with(own.join("; ")),
        );
    }
    // Said once, not per record — and only where it is the question: a record
    // pointing at this account's own resources needs no outside resolution to
    // settle, since nobody else could claim it.
    if !open.is_empty() || !verified.is_empty() {
        out.push(Finding::new(
            Severity::Info,
            "takeover",
            "whether the resource behind each of these still exists cannot be read from \
             the API; confirming it needs a resolution against the outside world",
        ));
    }
    out
}

/// Where the origin is published, and where private space is.
pub fn exposure(zones: &[Zone]) -> Vec<Finding> {
    let mut leaks = Vec::new();
    let mut plain = Vec::new();
    let mut private = Vec::new();
    let mut wildcards = Vec::new();

    for z in zones {
        leaks.extend(published_origins(&z.records));
        for r in z.of_type(&["A", "AAAA"]) {
            let name = str_of(r, "name");
            let content = str_of(r, "content");

            if is_private(&content) {
                private.push(format!("{name} → {content}"));
                continue;
            }
            if r.get("proxied").and_then(Value::as_bool) == Some(true)
                || is_placeholder(&content)
                || r.get("proxiable").and_then(Value::as_bool) == Some(false)
            {
                continue;
            }
            if !proxied_origins(&z.records).contains(&content) {
                plain.push(format!("{name} → {content}"));
            }
        }
        for r in &z.records {
            if str_of(r, "name").starts_with("*.") || str_of(r, "name") == format!("*.{}", z.name) {
                wildcards.push(format!("{} ({})", str_of(r, "name"), str_of(r, "type")));
            }
        }
    }

    let mut out = Vec::new();
    if !leaks.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "exposure",
                format!(
                    "{} unproxied {} an address that also sits behind the proxy, so the \
                     origin can be reached by name and every rule on the zone is bypassed",
                    leaks.len(),
                    agree(leaks.len(), "record publishes", "records publish")
                ),
            )
            .with(leaks.join(", ")),
        );
    }
    if !plain.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "exposure",
                format!(
                    "{} proxiable {} unproxied, publishing an address directly",
                    plain.len(),
                    agree(plain.len(), "record is", "records are")
                ),
            )
            .with(plain.join(", ")),
        );
    }
    if !private.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "exposure",
                format!(
                    "{} public {} an address in private or reserved space, which describes \
                     the internal network to anyone who asks",
                    private.len(),
                    agree(private.len(), "record holds", "records hold")
                ),
            )
            .with(private.join(", ")),
        );
    }
    if !wildcards.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "exposure",
                format!(
                    "{} wildcard {} resolves",
                    wildcards.len(),
                    agree(
                        wildcards.len(),
                        "record, so every unregistered name under it",
                        "records, so every unregistered name under them"
                    )
                ),
            )
            .with(wildcards.join(", ")),
        );
    }
    out
}

/// Signing, and whether the zone can be claimed elsewhere.
pub fn namespace(zones: &[Zone]) -> Vec<Finding> {
    let mut pending = Vec::new();
    let mut off = Vec::new();
    let mut unheld = Vec::new();

    for z in zones {
        if let Some(d) = &z.dnssec {
            match str_of(d, "status").as_str() {
                "pending" | "pending-disabled" => pending.push(z.name.clone()),
                "active" => {}
                _ => off.push(z.name.clone()),
            }
        }
        if let Some(h) = &z.hold {
            if h.get("hold").and_then(Value::as_bool) == Some(false) {
                unheld.push(z.name.clone());
            }
        }
    }

    let mut out = Vec::new();
    if !pending.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "namespace",
                format!(
                    "DNSSEC is signed but incomplete on {} {}: the DS record was never added \
                     at the registrar, so nothing is validated",
                    pending.len(),
                    agree(pending.len(), "zone", "zones")
                ),
            )
            .with(pending.join(", ")),
        );
    }
    if !off.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "namespace",
                format!(
                    "DNSSEC is off on {} {}",
                    off.len(),
                    agree(off.len(), "zone", "zones")
                ),
            )
            .with(off.join(", ")),
        );
    }
    if !unheld.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "namespace",
                format!(
                    "{} {} no zone hold, so the domain can be added to another Cloudflare \
                     account by whoever controls its DNS next",
                    unheld.len(),
                    agree(unheld.len(), "zone has", "zones have")
                ),
            )
            .with(unheld.join(", ")),
        );
    }
    out
}

/// Whether a zone can be sent mail as, read from its own records.
///
/// No extra request: MX, SPF and DMARC are all TXT and MX records in the set
/// already fetched.
pub fn mail(zones: &[Zone]) -> Vec<Finding> {
    let mut parked = Vec::new();
    let mut sending = Vec::new();
    let mut permissive = Vec::new();
    let mut duplicated = Vec::new();
    let mut no_dmarc = Vec::new();
    let mut monitoring = Vec::new();

    for z in zones {
        let spf: Vec<String> = z
            .of_type(&["TXT"])
            .filter(|r| str_of(r, "name") == z.name)
            .map(|r| unquote(&str_of(r, "content")))
            .filter(|c| c.to_ascii_lowercase().starts_with("v=spf1"))
            .collect();
        let dmarc: Vec<String> = z
            .of_type(&["TXT"])
            .filter(|r| str_of(r, "name") == format!("_dmarc.{}", z.name))
            .map(|r| unquote(&str_of(r, "content")))
            .collect();
        let has_mx = z.of_type(&["MX"]).next().is_some();

        if spf.len() > 1 {
            duplicated.push(z.name.clone());
        }
        // More than one SPF record is not a stricter policy, it is no policy:
        // a resolver seeing two treats the result as permerror.
        if spf.iter().any(|s| {
            let l = s.to_ascii_lowercase();
            l.contains("+all") || l.contains("?all")
        }) {
            permissive.push(z.name.clone());
        }
        // No SPF is one fault with two different remedies. A zone that carries
        // MX is in use for mail and needs a real policy; a zone with none is
        // parked and wants a null MX with `v=spf1 -all`. Reporting them
        // together would give half the readers the wrong instruction.
        if spf.is_empty() {
            if has_mx {
                sending.push(z.name.clone());
            } else {
                parked.push(z.name.clone());
            }
        }
        match dmarc.first() {
            None => no_dmarc.push(z.name.clone()),
            Some(d) if d.to_ascii_lowercase().contains("p=none") => monitoring.push(z.name.clone()),
            _ => {}
        }
    }

    let mut out = Vec::new();
    if !permissive.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "mail",
                format!(
                    "{} {} an SPF record ending in +all or ?all, which authorises every \
                     sender on the internet",
                    permissive.len(),
                    agree(permissive.len(), "zone has", "zones have")
                ),
            )
            .with(permissive.join(", ")),
        );
    }
    if !duplicated.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "mail",
                format!(
                    "{} {} more than one SPF record, which resolvers treat as no SPF at all",
                    duplicated.len(),
                    agree(duplicated.len(), "zone has", "zones have")
                ),
            )
            .with(duplicated.join(", ")),
        );
    }
    if !sending.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "mail",
                format!(
                    "{} {} mail but {} no SPF record, so nothing says which servers may \
                     send as them",
                    sending.len(),
                    agree(sending.len(), "zone receives", "zones receive"),
                    agree(sending.len(), "publishes", "publish")
                ),
            )
            .with(sending.join(", ")),
        );
    }
    if !parked.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "mail",
                format!(
                    "{} parked {} neither MX nor SPF, so anyone can send mail as them; a \
                     domain that sends no mail should say so with a null MX and v=spf1 -all",
                    parked.len(),
                    agree(parked.len(), "zone has", "zones have")
                ),
            )
            .with(parked.join(", ")),
        );
    }
    if !no_dmarc.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "mail",
                format!(
                    "{} {} no DMARC record, so a receiver has no instruction for mail that \
                     fails authentication",
                    no_dmarc.len(),
                    agree(no_dmarc.len(), "zone has", "zones have")
                ),
            )
            .with(no_dmarc.join(", ")),
        );
    }
    if !monitoring.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "mail",
                format!(
                    "{} {} DMARC at p=none, which reports failures and rejects nothing",
                    monitoring.len(),
                    agree(monitoring.len(), "zone has", "zones have")
                ),
            )
            .with(monitoring.join(", ")),
        );
    }
    out
}

/// A TXT record's content, with the quoting a resolver would strip.
///
/// Long values arrive as several quoted strings that a resolver concatenates,
/// and an SPF record split across two of them would otherwise fail to match on
/// its own mechanisms. A value with no quotes at all is returned as it came.
fn unquote(s: &str) -> String {
    let joined: String = s.split('"').skip(1).step_by(2).collect();
    if joined.is_empty() {
        s.trim().to_string()
    } else {
        joined
    }
}

/// Registrations held at Cloudflare Registrar.
///
/// Read from `/registrar/registrations`, whose field for the name is
/// `domain_name`. The older `/registrar/domains` is deprecated and answers with
/// an empty list rather than an error, which makes it the worst possible thing
/// to build on: an account with six registered domains reports none, in a
/// success response, and the audit quietly finds nothing.
pub fn registrar(domains: &[Value], within_days: i64) -> Vec<Finding> {
    let mut expiring = Vec::new();
    let mut no_renew = Vec::new();
    let mut unlocked = Vec::new();
    let mut lapsed = Vec::new();
    let mut public_whois = Vec::new();

    for d in domains {
        // `name` is the deprecated resource's spelling, kept as a fallback so a
        // recorded response from either shape reads the same.
        let name = match str_of(d, "domain_name") {
            n if n.is_empty() => str_of(d, "name"),
            n => n,
        };

        match str_of(d, "status").as_str() {
            // Past the expiry and heading for release. `redemption_period` is
            // still recoverable, for a fee; `pending_delete` is not.
            st @ ("expired" | "redemption_period" | "pending_delete" | "suspended") => {
                lapsed.push(format!("{name} ({st})"));
            }
            _ => {
                if let Some(days) = days_until(&str_of(d, "expires_at")) {
                    if days <= within_days {
                        expiring.push(format!("{name} in {days}d"));
                    }
                }
            }
        }

        if d.get("auto_renew").and_then(Value::as_bool) == Some(false) {
            no_renew.push(name.clone());
        }
        if d.get("locked").and_then(Value::as_bool) == Some(false) {
            unlocked.push(name.clone());
        }
        if str_of(d, "privacy_mode") == "off" {
            public_whois.push(name);
        }
    }

    let mut out = Vec::new();
    if !lapsed.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "registrar",
                format!(
                    "{} {} past its registration: the name is on its way back to the pool, \
                     and whoever registers it next inherits the domain",
                    lapsed.len(),
                    agree(lapsed.len(), "domain is", "domains are")
                ),
            )
            .with(lapsed.join(", ")),
        );
    }
    if !expiring.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "registrar",
                format!(
                    "{} {} within {within_days} days; an expiry is a full outage followed \
                     by a hostile registration, and no edge setting mitigates it",
                    expiring.len(),
                    agree(expiring.len(), "domain expires", "domains expire")
                ),
            )
            .with(expiring.join(", ")),
        );
    }
    if !no_renew.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "registrar",
                format!(
                    "{} {} auto-renew off",
                    no_renew.len(),
                    agree(no_renew.len(), "domain has", "domains have")
                ),
            )
            .with(no_renew.join(", ")),
        );
    }
    if !unlocked.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "registrar",
                format!(
                    "{} {} not transfer-locked",
                    unlocked.len(),
                    agree(unlocked.len(), "domain is", "domains are")
                ),
            )
            .with(unlocked.join(", ")),
        );
    }
    if !public_whois.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "registrar",
                format!(
                    "{} {} WHOIS privacy off, so the registrant contact details are public",
                    public_whois.len(),
                    agree(public_whois.len(), "domain has", "domains have")
                ),
            )
            .with(public_whois.join(", ")),
        );
    }
    out
}

/// Whole days from now to an RFC 3339 instant, or `None` when it cannot be read.
///
/// Only the date part is parsed: a domain expiry is a date, and the hours would
/// not change the answer to "is this soon".
fn days_until(rfc3339: &str) -> Option<i64> {
    let date = rfc3339.get(..10)?;
    let mut it = date.split('-');
    let (y, m, d): (i64, i64, i64) = (
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
        it.next()?.parse().ok()?,
    );
    // days_from_civil, the inverse of the shift used to print these.
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let target = era * 146_097 + doe - 719_468;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64
        / 86_400;
    Some(target - now)
}

// ---- zone posture ----------------------------------------------------------

/// One zone's edge configuration, as read.
///
/// `phases` holds the ordered rules of each ruleset phase entrypoint, which is
/// the only view that says what actually executes and in what order. The
/// deprecated `/firewall/rules` surface is a second view of the *same* store on
/// a current account, not a second engine, so it is deliberately not collected:
/// reading both would report every custom rule twice.
pub struct Posture {
    pub name: String,
    pub plan: String,
    /// Setting id to value, from the one call that returns them all.
    pub settings: BTreeMap<String, Value>,
    /// Phase name to its ordered rules.
    pub phases: BTreeMap<String, Vec<Value>>,
    /// The phases whose entry point could be read at all.
    ///
    /// A phase that answers `404 could not find entrypoint rules` has no entry
    /// point, and on a free plan that means the feature is not configurable
    /// rather than not configured: the free managed ruleset runs regardless,
    /// and rate limiting rules cannot be created. Losing this distinction turns
    /// a price list into eighteen findings.
    pub readable_phases: BTreeSet<String>,
    pub pagerules: Vec<Value>,
    pub spectrum: Vec<Value>,
    pub routes: Vec<Value>,
    pub snippets: Vec<Value>,
    pub page_shield: Option<Value>,
}

impl Posture {
    fn setting(&self, id: &str) -> Option<&Value> {
        self.settings.get(id)
    }

    fn text(&self, id: &str) -> String {
        self.setting(id)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn rules(&self, phase: &str) -> &[Value] {
        self.phases.get(phase).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether a paid-plan feature could be configured here at all.
    ///
    /// Reporting "Page Shield is off" on a zone whose plan does not include it
    /// is not a finding, it is a price list. The check has to know the
    /// difference or the report fills with work nobody can do.
    fn paid(&self) -> bool {
        !self.plan.to_ascii_lowercase().contains("free")
    }

    /// Whether a phase is configurable here, as opposed to absent from the plan.
    fn configurable(&self, phase: &str) -> bool {
        self.paid() || self.readable_phases.contains(phase)
    }
}

/// How the zone speaks TLS, and what it tells a browser about it.
pub fn transport(zones: &[Posture]) -> Vec<Finding> {
    let mut plaintext = Vec::new();
    let mut unvalidated = Vec::new();
    let mut old_tls = Vec::new();
    let mut no_hsts = Vec::new();
    let mut short_hsts = Vec::new();
    let mut apex_only = Vec::new();
    let mut no_redirect = Vec::new();
    let mut early_data = Vec::new();

    for z in zones {
        match z.text("ssl").as_str() {
            // The browser sees a padlock and the origin leg is cleartext.
            "off" | "flexible" => plaintext.push(format!("{} ({})", z.name, z.text("ssl"))),
            // Encrypted to the origin, and no certificate is checked, so
            // anyone who can intercept that leg can present anything.
            "full" => unvalidated.push(z.name.clone()),
            _ => {}
        }
        if matches!(z.text("min_tls_version").as_str(), "1.0" | "1.1") {
            old_tls.push(format!("{} ({})", z.name, z.text("min_tls_version")));
        }
        if z.text("always_use_https") == "off" {
            no_redirect.push(z.name.clone());
        }
        if z.text("0rtt") == "on" {
            early_data.push(z.name.clone());
        }

        let hsts = z
            .setting("security_header")
            .and_then(|v| v.get("strict_transport_security"));
        match hsts {
            Some(h) if h.get("enabled").and_then(Value::as_bool) == Some(true) => {
                let age = h.get("max_age").and_then(Value::as_u64).unwrap_or(0);
                // Six months is the floor the preload list asks for; below it
                // the header protects a window rather than a browser.
                if age < 15_768_000 {
                    short_hsts.push(format!("{} ({age}s)", z.name));
                }
                if h.get("include_subdomains").and_then(Value::as_bool) != Some(true) {
                    apex_only.push(z.name.clone());
                }
            }
            Some(_) => no_hsts.push(z.name.clone()),
            None => {}
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "transport", text).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} cleartext to the origin while the browser sees a padlock",
            plaintext.len(),
            agree(plaintext.len(), "zone sends", "zones send")
        ),
        plaintext.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} to the origin without validating its certificate; only \"full (strict)\" \
             checks one",
            unvalidated.len(),
            agree(unvalidated.len(), "zone encrypts", "zones encrypt")
        ),
        unvalidated.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} TLS 1.0 or 1.1",
            old_tls.len(),
            agree(old_tls.len(), "zone still accepts", "zones still accept")
        ),
        old_tls.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} HSTS off, so a browser will try plaintext first every time",
            no_hsts.len(),
            agree(no_hsts.len(), "zone has", "zones have")
        ),
        no_hsts.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} redirect to HTTPS",
            no_redirect.len(),
            agree(no_redirect.len(), "zone does not", "zones do not")
        ),
        no_redirect.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} an HSTS max-age under six months",
            short_hsts.len(),
            agree(short_hsts.len(), "zone has", "zones have")
        ),
        short_hsts.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} HSTS on the apex only, leaving every subdomain unprotected",
            apex_only.len(),
            agree(apex_only.len(), "zone sets", "zones set")
        ),
        apex_only.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} 0-RTT enabled, which permits replay of early data on any endpoint that \
             is not idempotent",
            early_data.len(),
            agree(early_data.len(), "zone has", "zones have")
        ),
        early_data.clone(),
    );
    out
}

/// What the rule engine will actually do, and what has been carved out of it.
pub fn enforcement(zones: &[Posture]) -> Vec<Finding> {
    let mut dev_mode = Vec::new();
    let mut wide_open = Vec::new();
    let mut skips = Vec::new();
    let mut weakened = Vec::new();
    let mut unmanaged = Vec::new();
    let mut log_only = Vec::new();
    let mut disabled = Vec::new();
    let mut no_limit = Vec::new();
    let mut page_rules = Vec::new();
    let mut shield_off = Vec::new();
    let mut free = Vec::new();

    for z in zones {
        // Bypasses caching and relaxes the edge. It expires on its own after
        // three hours — unless something keeps switching it back on.
        if z.text("development_mode") == "on" {
            dev_mode.push(z.name.clone());
        }
        if z.text("security_level") == "essentially_off" {
            wide_open.push(z.name.clone());
        }

        let custom = z.rules("http_request_firewall_custom");
        for r in custom {
            if r.get("enabled").and_then(Value::as_bool) == Some(false) {
                disabled.push(format!("{}: {}", z.name, description(r)));
                continue;
            }
            match str_of(r, "action").as_str() {
                "skip" => skips.push(format!(
                    "{}: {} skips {}",
                    z.name,
                    description(r),
                    skipped(r)
                )),
                "log" => log_only.push(format!("{}: {}", z.name, description(r))),
                _ => {}
            }
        }

        let managed = z.rules("http_request_firewall_managed");
        if managed.is_empty() && z.configurable("http_request_firewall_managed") {
            unmanaged.push(z.name.clone());
        }
        for r in managed {
            for what in weakenings(r) {
                weakened.push(format!("{}: {what}", z.name));
            }
        }

        if z.rules("http_ratelimit").is_empty() && z.configurable("http_ratelimit") {
            no_limit.push(z.name.clone());
        }
        if !z.pagerules.is_empty() {
            page_rules.push(format!("{} ({})", z.name, z.pagerules.len()));
        }
        if !z.paid() {
            free.push(z.name.clone());
        }
        // Only where the plan includes it.
        if z.paid()
            && z.page_shield
                .as_ref()
                .and_then(|p| p.get("enabled"))
                .and_then(Value::as_bool)
                == Some(false)
        {
            shield_off.push(z.name.clone());
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "enforcement", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} in development mode, which bypasses the cache and relaxes the edge",
            dev_mode.len(),
            agree(dev_mode.len(), "zone is", "zones are")
        ),
        dev_mode.clone(),
    );
    push(
        Severity::High,
        format!(
            "{} {} security level set to essentially off",
            wide_open.len(),
            agree(wide_open.len(), "zone has", "zones have")
        ),
        wide_open.clone(),
    );
    push(
        Severity::High,
        format!(
            "{} {} carve a path out of the rule engine; each one names the phases and \
             products it turns off for the requests it matches",
            skips.len(),
            agree(skips.len(), "rule", "rules")
        ),
        skips.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} managed ruleset {} weakened by an override",
            weakened.len(),
            agree(weakened.len(), "deployment is", "deployments are")
        ),
        weakened.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} no managed ruleset deployed at all",
            unmanaged.len(),
            agree(unmanaged.len(), "zone has", "zones have")
        ),
        unmanaged.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} no rate limit rule anywhere, so nothing bounds requests to a login or \
             an API path",
            no_limit.len(),
            agree(no_limit.len(), "zone has", "zones have")
        ),
        no_limit.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "Page Shield is off on {} paid {}, so nothing reports the scripts the browser \
             actually loads",
            shield_off.len(),
            agree(shield_off.len(), "zone", "zones")
        ),
        shield_off.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} custom {} at log, so it records and blocks nothing",
            log_only.len(),
            agree(log_only.len(), "rule is", "rules are")
        ),
        log_only.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} custom {} disabled",
            disabled.len(),
            agree(disabled.len(), "rule is", "rules are")
        ),
        disabled.clone(),
    );
    // Named rather than left silent, so the reader knows why those zones are
    // absent from the two checks above rather than assuming they passed.
    push(
        Severity::Info,
        format!(
            "{} {} on a free plan, where the managed ruleset applies automatically and \
             cannot be tuned, and rate limiting rules are not available",
            free.len(),
            agree(free.len(), "zone is", "zones are")
        ),
        free.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} {} page rules, which are a separate engine evaluated before the rulesets",
            page_rules.len(),
            agree(page_rules.len(), "zone still uses", "zones still use")
        ),
        page_rules.clone(),
    );
    out
}

/// Code and raw ports published at the edge.
pub fn edge(zones: &[Posture]) -> Vec<Finding> {
    let mut admin_ports = Vec::new();
    let mut other_ports = Vec::new();
    let mut routes = Vec::new();
    let mut snippets = Vec::new();

    for z in zones {
        for app in &z.spectrum {
            let proto = str_of(app, "protocol");
            let host = app
                .get("dns")
                .map(|d| str_of(d, "name"))
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| z.name.clone());
            let line = format!("{host} ({proto})");
            match port_of(&proto) {
                // Remote administration and databases, published globally with
                // none of the HTTP security stack in front of them.
                Some(22 | 23 | 3389 | 3306 | 5432 | 6379 | 27017 | 1433 | 5900) => {
                    admin_ports.push(line)
                }
                _ => other_ports.push(line),
            }
        }
        for r in &z.routes {
            let pattern = str_of(r, "pattern");
            let script = str_of(r, "script");
            routes.push(if script.is_empty() {
                format!("{pattern} (no script)")
            } else {
                format!("{pattern} → {script}")
            });
        }
        for sn in &z.snippets {
            snippets.push(format!("{}: {}", z.name, str_of(sn, "snippet_name")));
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "edge", text).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} Spectrum {} a remote administration or database port to the internet, with \
             none of the HTTP security stack in front of it",
            admin_ports.len(),
            agree(
                admin_ports.len(),
                "application publishes",
                "applications publish"
            )
        ),
        admin_ports.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} Spectrum {} raw TCP or UDP, which no review of web traffic will show",
            other_ports.len(),
            agree(
                other_ports.len(),
                "application proxies",
                "applications proxy"
            )
        ),
        other_ports.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} worker {} request handling on a path",
            routes.len(),
            agree(routes.len(), "route changes", "routes change")
        ),
        routes.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} {} at the edge, outside the rule engine",
            snippets.len(),
            agree(snippets.len(), "snippet runs", "snippets run")
        ),
        snippets.clone(),
    );
    out
}

/// A rule's own description, or its id when it has none.
fn description(r: &Value) -> String {
    match str_of(r, "description") {
        d if d.is_empty() => format!("rule {}", str_of(r, "id")),
        d => format!("{d:?}"),
    }
}

/// What a `skip` rule turns off, from its action parameters.
fn skipped(r: &Value) -> String {
    let Some(ap) = r.get("action_parameters") else {
        return "the rest of this ruleset".to_string();
    };
    let mut parts = Vec::new();
    // Each group is named, because "a, b and c, d" reads as one list of four
    // rather than as two lists of two.
    for key in ["phases", "products"] {
        let names: Vec<String> = ap
            .get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !names.is_empty() {
            parts.push(format!("{key} {}", names.join("+")));
        }
    }
    if ap.get("ruleset").and_then(Value::as_str) == Some("current") {
        parts.push("the rest of this ruleset".to_string());
    }
    if ap.get("rules").is_some() {
        parts.push("named managed rules".to_string());
    }
    if parts.is_empty() {
        "nothing it names".to_string()
    } else {
        parts.join(", ")
    }
}

/// The ways one managed-ruleset deployment has been turned down.
///
/// OWASP paranoia levels are excluded: choosing not to run levels 2 to 4 is how
/// that ruleset is meant to be tuned, and reporting it would bury the overrides
/// that really do switch protection off.
fn weakenings(r: &Value) -> Vec<String> {
    let name = description(r);
    let Some(ov) = r.get("action_parameters").and_then(|a| a.get("overrides")) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    if ov.get("enabled").and_then(Value::as_bool) == Some(false) {
        out.push(format!("{name} is deployed but disabled"));
    }
    if ov.get("action").and_then(Value::as_str) == Some("log") {
        out.push(format!("{name} is set to log rather than block"));
    }

    let off_categories: Vec<String> = ov
        .get("categories")
        .and_then(Value::as_array)
        .map(|cs| {
            cs.iter()
                .filter(|c| c.get("enabled").and_then(Value::as_bool) == Some(false))
                .map(|c| str_of(c, "category"))
                .filter(|c| !c.starts_with("paranoia-level-"))
                .collect()
        })
        .unwrap_or_default();
    if !off_categories.is_empty() {
        out.push(format!(
            "{name} has {} {} disabled ({})",
            off_categories.len(),
            agree(off_categories.len(), "category", "categories"),
            off_categories.join(", ")
        ));
    }

    let off_rules = ov
        .get("rules")
        .and_then(Value::as_array)
        .map(|rs| {
            rs.iter()
                .filter(|x| {
                    x.get("enabled").and_then(Value::as_bool) == Some(false)
                        || x.get("action").and_then(Value::as_str) == Some("log")
                })
                .count()
        })
        .unwrap_or(0);
    if off_rules > 0 {
        out.push(format!(
            "{name} has {off_rules} individual {} turned down",
            agree(off_rules, "rule", "rules")
        ));
    }
    out
}

/// The port from a Spectrum protocol string such as `tcp/22`.
fn port_of(protocol: &str) -> Option<u16> {
    protocol.rsplit('/').next()?.split('-').next()?.parse().ok()
}

// ---- certificates and origin trust -----------------------------------------

/// One zone's certificate posture and what its origin will accept.
pub struct Tls {
    pub name: String,
    /// From the settings blob, so the two planes agree on what mode is set.
    pub ssl_mode: String,
    /// `None` when the setting could not be read, which is not the same as off.
    pub aop: Option<bool>,
    pub aop_hostnames: Vec<Value>,
    pub universal: Option<Value>,
    pub packs: Vec<Value>,
    pub custom_certs: Vec<Value>,
    pub custom_hostnames: Vec<Value>,
    pub client_certs: Vec<Value>,
    pub ct_alerting: Option<Value>,
    /// `name → address` for every record that publishes an address the proxy
    /// also fronts for, from [`published_origins`].
    pub exposed_origins: Vec<String>,
}

impl Tls {
    fn aop_off(&self) -> bool {
        self.aop == Some(false)
    }
}

/// Whether the origin will talk to anyone who finds its address.
///
/// This is the plane's whole argument. Encrypting the origin leg protects the
/// transport; it does nothing about who may open the connection. Authenticated
/// Origin Pulls is the control that makes the origin refuse a request that did
/// not come through Cloudflare, and without it every address the DNS plane
/// found published is a way in rather than an information disclosure.
pub fn origin_trust(zones: &[Tls]) -> Vec<Finding> {
    let mut chained = Vec::new();
    let mut unguarded = Vec::new();
    let mut partial = Vec::new();
    let mut no_universal = Vec::new();

    for z in zones {
        if z.aop_off() {
            if z.exposed_origins.is_empty() {
                unguarded.push(z.name.clone());
            } else {
                // The complete chain: the address is published, and the origin
                // does not check who is calling.
                chained.push(format!(
                    "{} ({} published, ssl {})",
                    z.name,
                    z.exposed_origins.len(),
                    if z.ssl_mode.is_empty() {
                        "unknown"
                    } else {
                        &z.ssl_mode
                    }
                ));
            }
        }

        // Enabled zone-wide, and off for particular hostnames: the gap is the
        // finding, because the zone reads as covered.
        if z.aop == Some(true) {
            let gaps: Vec<String> = z
                .aop_hostnames
                .iter()
                .filter(|h| h.get("enabled").and_then(Value::as_bool) == Some(false))
                .map(|h| str_of(h, "hostname"))
                .collect();
            if !gaps.is_empty() {
                partial.push(format!("{}: {}", z.name, gaps.join(", ")));
            }
        }

        // Universal SSL off with nothing uploaded means the hostnames covered
        // by neither are served no certificate at all.
        if z.universal
            .as_ref()
            .and_then(|u| u.get("enabled"))
            .and_then(Value::as_bool)
            == Some(false)
            && z.custom_certs.is_empty()
        {
            no_universal.push(z.name.clone());
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "origin", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} an origin address in DNS and {} require Cloudflare's client certificate \
             at the origin, so that address is a way in rather than an information \
             disclosure",
            chained.len(),
            agree(chained.len(), "zone publishes", "zones publish"),
            agree(chained.len(), "does not", "do not")
        ),
        chained.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} Authenticated Origin Pulls off, so nothing at the origin distinguishes \
             Cloudflare from anyone else who learns the address",
            unguarded.len(),
            agree(unguarded.len(), "zone has", "zones have")
        ),
        unguarded.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} Authenticated Origin Pulls on with hostnames excluded from it",
            partial.len(),
            agree(partial.len(), "zone has", "zones have")
        ),
        partial.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} Universal SSL off and no certificate uploaded",
            no_universal.len(),
            agree(no_universal.len(), "zone has", "zones have")
        ),
        no_universal.clone(),
    );
    out
}

/// The certificate inventory: what expires, and what never finished issuing.
pub fn certificates(zones: &[Tls], soon_days: i64) -> Vec<Finding> {
    let mut imminent = Vec::new();
    let mut expiring = Vec::new();
    let mut stalled = Vec::new();
    let mut client_forever = Vec::new();
    let mut no_ct = Vec::new();

    for z in zones {
        // A pack holds one certificate per signature algorithm, and each
        // carries its own expiry.
        for pack in &z.packs {
            let status = str_of(pack, "status");
            if !status.is_empty() && status != "active" {
                stalled.push(format!(
                    "{}: {} ({status})",
                    z.name,
                    hosts_of(pack).unwrap_or_else(|| str_of(pack, "id"))
                ));
            }
            for cert in pack
                .get("certificates")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                note_expiry(&z.name, cert, soon_days, &mut imminent, &mut expiring);
            }
        }
        for cert in &z.custom_certs {
            note_expiry(&z.name, cert, soon_days, &mut imminent, &mut expiring);
        }

        for c in &z.client_certs {
            let name = str_of(c, "common_name");
            match days_until(&str_of(c, "expires_on")) {
                None => client_forever.push(format!("{}: {name}", z.name)),
                Some(d) if d <= soon_days => {
                    expiring.push(format!("{}: client certificate {name} in {d}d", z.name))
                }
                Some(_) => {}
            }
        }

        // Nobody watching means a certificate issued for the domain by anyone
        // else goes unnoticed.
        if z.ct_alerting
            .as_ref()
            .and_then(|c| c.get("enabled"))
            .and_then(Value::as_bool)
            == Some(false)
        {
            no_ct.push(z.name.clone());
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "certificates", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} within two weeks",
            imminent.len(),
            agree(imminent.len(), "certificate expires", "certificates expire")
        ),
        imminent.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} within {soon_days} days",
            expiring.len(),
            agree(expiring.len(), "certificate expires", "certificates expire")
        ),
        expiring.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} certificate {} never reached active, so the hostnames it covers are not \
             served by it",
            stalled.len(),
            agree(stalled.len(), "pack", "packs")
        ),
        stalled.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} client {} no expiry, which makes it an unrotatable credential outside the \
             token system",
            client_forever.len(),
            agree(client_forever.len(), "certificate has", "certificates have")
        ),
        client_forever.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} nobody subscribed to certificate transparency alerts, so a certificate \
             issued for the domain by anyone else goes unnoticed",
            no_ct.len(),
            agree(no_ct.len(), "zone has", "zones have")
        ),
        no_ct.clone(),
    );
    out
}

/// Customer hostnames on a SaaS zone, which is a tenant list.
pub fn hostnames(zones: &[Tls]) -> Vec<Finding> {
    let mut unverified = Vec::new();
    let mut custom_origin = Vec::new();

    for z in zones {
        for h in &z.custom_hostnames {
            let name = str_of(h, "hostname");
            let status = str_of(h, "status");
            let ssl = h
                .get("ssl")
                .map(|s| str_of(s, "status"))
                .unwrap_or_default();
            if (!status.is_empty() && status != "active") || (!ssl.is_empty() && ssl != "active") {
                unverified.push(format!("{}: {name} ({status}, ssl {ssl})", z.name));
            }
            if let Some(origin) = h.get("custom_origin_server").and_then(Value::as_str) {
                if !origin.is_empty() {
                    custom_origin.push(format!("{name} → {origin}"));
                }
            }
        }
    }

    let mut out = Vec::new();
    if !unverified.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "hostnames",
                format!(
                    "{} customer {} never finished verification, which is the same dangling \
                     shape as a stale DNS record with the zone owner serving it",
                    unverified.len(),
                    agree(unverified.len(), "hostname", "hostnames")
                ),
            )
            .with(unverified.join("; ")),
        );
    }
    if !custom_origin.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                "hostnames",
                format!(
                    "{} customer {} at an origin of its own",
                    custom_origin.len(),
                    agree(custom_origin.len(), "hostname points", "hostnames point")
                ),
            )
            .with(custom_origin.join(", ")),
        );
    }
    out
}

/// Account-level mTLS certificates, which several products draw from.
pub fn account_certificates(certs: &[Value], soon_days: i64) -> Vec<Finding> {
    let mut expiring = Vec::new();
    let mut fleet = Vec::new();

    for c in certs {
        let name = str_of(c, "name");
        let Some(days) = days_until(&str_of(c, "expires_on")) else {
            continue;
        };
        // The Gateway CA is installed on every managed device; its expiry is a
        // fleet-wide outage with a date on it, and it wants a year of warning
        // rather than a month.
        if str_of(c, "type") == "gateway_managed" {
            if days <= 365 {
                fleet.push(format!("{name} in {days}d"));
            }
        } else if days <= soon_days {
            expiring.push(format!("{name} in {days}d"));
        }
    }

    let mut out = Vec::new();
    if !fleet.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "certificates",
                format!(
                    "{} Gateway {} within a year; it is trusted by every managed device, so \
                     its expiry is a fleet-wide outage with a date on it",
                    fleet.len(),
                    agree(fleet.len(), "CA expires", "CAs expire")
                ),
            )
            .with(fleet.join(", ")),
        );
    }
    if !expiring.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "certificates",
                format!(
                    "{} account mTLS {} within {soon_days} days",
                    expiring.len(),
                    agree(expiring.len(), "certificate expires", "certificates expire")
                ),
            )
            .with(expiring.join(", ")),
        );
    }
    out
}

/// Sort one certificate into the right expiry bucket.
///
/// Two weeks is the line: inside it there is no time for a renewal that needs a
/// DNS change or a purchase, and the finding has to outrank the rest of the
/// report.
fn note_expiry(
    zone: &str,
    cert: &Value,
    soon_days: i64,
    imminent: &mut Vec<String>,
    expiring: &mut Vec<String>,
) {
    let Some(days) = days_until(&str_of(cert, "expires_on")) else {
        return;
    };
    let hosts = hosts_of(cert).unwrap_or_else(|| str_of(cert, "id"));
    let line = format!("{zone}: {hosts} in {days}d");
    if days <= 14 {
        imminent.push(line);
    } else if days <= soon_days {
        expiring.push(line);
    }
}

/// The hostnames a certificate covers, shortened to the first few.
fn hosts_of(v: &Value) -> Option<String> {
    let hosts = v.get("hosts")?.as_array()?;
    let names: Vec<&str> = hosts.iter().filter_map(Value::as_str).collect();
    if names.is_empty() {
        return None;
    }
    Some(match names.len() {
        1..=2 => names.join(", "),
        n => format!("{}, +{} more", names[..2].join(", "), n - 2),
    })
}

// ---- the developer platform ------------------------------------------------

/// One Worker script, with the two facts that decide what it is.
pub struct Script {
    pub name: String,
    /// Reachable at `<name>.<subdomain>.workers.dev`.
    pub on_subdomain: bool,
    pub previews: bool,
    pub bindings: Vec<Value>,
    pub observability: bool,
    pub logpush: bool,
}

/// One R2 bucket and how it is published.
pub struct Bucket {
    pub name: String,
    /// The `pub-<hash>.r2.dev` hostname, when anonymous access is switched on.
    pub public_domain: Option<String>,
    pub custom_domains: Vec<String>,
}

/// Everything the developer platform holds on one account.
pub struct Platform {
    pub subdomain: String,
    pub scripts: Vec<Script>,
    /// Script names bound to at least one zone route.
    pub routed: BTreeSet<String>,
    pub pages: Vec<Value>,
    pub buckets: Vec<Bucket>,
    pub kv: Vec<Value>,
    pub d1: Vec<Value>,
    pub queues: Vec<Value>,
    pub hyperdrive: Vec<Value>,
    pub secret_stores: Vec<Value>,
    pub widgets: Vec<Value>,
    pub gateways: Vec<Value>,
}

impl Script {
    /// The bindings that reach stored data, named by kind.
    fn data_bindings(&self) -> Vec<String> {
        self.bindings
            .iter()
            .filter(|b| {
                matches!(
                    str_of(b, "type").as_str(),
                    "kv_namespace"
                        | "d1"
                        | "r2_bucket"
                        | "queue"
                        | "hyperdrive"
                        | "durable_object_namespace"
                        | "secret_text"
                        | "secrets_store_secret"
                        | "vectorize"
                )
            })
            .map(|b| format!("{} ({})", str_of(b, "name"), str_of(b, "type")))
            .collect()
    }
}

/// What each Worker is reachable on, and with what.
///
/// The finding almost nobody checks: a Worker meant to serve a zone route is
/// *also* answering at `<name>.<subdomain>.workers.dev` unless that is switched
/// off per script. Traffic arriving there never touches the zone, so every
/// custom rule, rate limit, bot policy and Access application configured on the
/// domain is absent — while the script's bindings to production data are
/// identical.
pub fn workers(p: &Platform) -> Vec<Finding> {
    let mut bypass = Vec::new();
    let mut only = Vec::new();
    let mut previews = Vec::new();
    let mut blind = Vec::new();

    let at = |s: &Script| {
        if p.subdomain.is_empty() {
            s.name.clone()
        } else {
            format!("{}.{}.workers.dev", s.name, p.subdomain)
        }
    };

    for s in &p.scripts {
        if s.on_subdomain {
            let data = s.data_bindings();
            let line = if data.is_empty() {
                at(s)
            } else {
                format!("{} — {}", at(s), data.join(", "))
            };
            // A script that also serves a zone route has a protected path and
            // an unprotected one for the same code. A script with no route is
            // reachable only here, which is a design rather than a bypass.
            if p.routed.contains(&s.name) {
                bypass.push(line);
            } else {
                only.push(line);
            }
        }
        if s.previews {
            previews.push(s.name.clone());
        }
        if !s.observability && !s.logpush {
            blind.push(s.name.clone());
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "workers", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} a zone route and {} also answering on workers.dev, where no rule of \
             that zone applies and the bindings are the same",
            bypass.len(),
            agree(bypass.len(), "script serves", "scripts serve"),
            agree(bypass.len(), "is", "are")
        ),
        bypass.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} only on workers.dev, so nothing configured on any zone protects {}",
            only.len(),
            agree(only.len(), "script answers", "scripts answer"),
            agree(only.len(), "it", "them")
        ),
        only.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} preview URLs enabled, which publishes every version on a second \
             workers.dev hostname",
            previews.len(),
            agree(previews.len(), "script has", "scripts have")
        ),
        previews.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} neither observability nor logpush, so nothing records what {} did",
            blind.len(),
            agree(blind.len(), "script has", "scripts have"),
            agree(blind.len(), "it", "they")
        ),
        blind.clone(),
    );
    out
}

/// Where the data is, who reaches it, and what nothing reaches.
pub fn storage(p: &Platform) -> Vec<Finding> {
    let mut public = Vec::new();
    let mut custom = Vec::new();
    let mut databases = Vec::new();

    for b in &p.buckets {
        if let Some(domain) = &b.public_domain {
            public.push(format!("{} → {domain}", b.name));
        }
        for d in &b.custom_domains {
            custom.push(format!("{} → {d}", b.name));
        }
    }
    for h in &p.hyperdrive {
        let origin = h.get("origin");
        databases.push(format!(
            "{} → {}",
            str_of(h, "name"),
            origin
                .map(|o| format!(
                    "{}:{}/{}",
                    str_of(o, "host"),
                    o.get("port").map(|v| v.to_string()).unwrap_or_default(),
                    str_of(o, "database")
                ))
                .unwrap_or_else(|| "(origin not readable)".into())
        ));
    }

    // What nothing is bound to. Every binding across every script names the
    // store it reaches, so the stores nobody names fall out by subtraction.
    let bound: BTreeSet<String> = p
        .scripts
        .iter()
        .flat_map(|s| s.bindings.iter())
        .flat_map(|b| {
            [
                "namespace_id",
                "id",
                "bucket_name",
                "queue_name",
                "store_id",
            ]
            .iter()
            .filter_map(|k| b.get(*k).and_then(Value::as_str).map(str::to_string))
            .collect::<Vec<_>>()
        })
        .collect();
    let mut orphans = Vec::new();
    // Each kind is matched on the identifier a binding actually carries, which
    // is not always the one the listing calls primary: a queue binding names
    // the queue, not its id.
    for (kind, items, keys) in [
        ("KV namespace", &p.kv, ["id", "title"]),
        ("D1 database", &p.d1, ["uuid", "name"]),
    ] {
        for it in items {
            let id = str_of(it, keys[0]);
            if !id.is_empty() && !bound.contains(&id) {
                orphans.push(format!("{kind} {}", str_of(it, keys[1])));
            }
        }
    }

    // A queue answers the question itself, and better than a binding scan can:
    // it lists its own producers and consumers, and a dead-letter queue is
    // named by the consumer that spills into it rather than bound by anyone.
    let dead_letter: BTreeSet<String> = p
        .queues
        .iter()
        .flat_map(|q| {
            q.get("consumers")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .map(|cons| str_of(&cons, "dead_letter_queue"))
        .filter(|d| !d.is_empty())
        .collect();
    for q in &p.queues {
        let name = str_of(q, "queue_name");
        let attached = |k: &str| {
            q.get(k)
                .and_then(Value::as_array)
                .is_some_and(|a| !a.is_empty())
        };
        if !attached("producers") && !attached("consumers") && !dead_letter.contains(&name) {
            orphans.push(format!("queue {name}"));
        }
    }
    for b in &p.buckets {
        // A bucket published on a domain is reached over HTTP rather than
        // through a binding, so no binding is the design and not neglect.
        let served = b.public_domain.is_some() || !b.custom_domains.is_empty();
        if !served && !bound.contains(&b.name) {
            orphans.push(format!("R2 bucket {}", b.name));
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "storage", text).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} R2 {} served anonymously on r2.dev, which publishes the whole bucket to \
             anyone with the hostname",
            public.len(),
            agree(public.len(), "bucket is", "buckets are")
        ),
        public.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} R2 {} served on a custom domain",
            custom.len(),
            agree(custom.len(), "bucket is", "buckets are")
        ),
        custom.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} Hyperdrive {} to a database outside Cloudflare",
            databases.len(),
            agree(databases.len(), "config points", "configs point")
        ),
        databases.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} data {} bound to no Worker: an unmaintained copy of something, and a cost \
             line",
            orphans.len(),
            agree(orphans.len(), "store is", "stores are")
        ),
        orphans.clone(),
    );
    out
}

/// Pages projects, where the preview is the surface people forget.
pub fn pages(projects: &[Value]) -> Vec<Finding> {
    let mut shared = Vec::new();
    let mut public = Vec::new();
    let mut auto_build = Vec::new();

    for p in projects {
        let name = str_of(p, "name");
        let cfg = |env: &str| p.get("deployment_configs").and_then(|c| c.get(env));

        // The mistake this check exists for: a preview configuration carrying
        // the same bindings as production, while every pull request publishes a
        // reachable *.pages.dev URL that no Access policy covers.
        let (prod, prev) = (cfg("production"), cfg("preview"));
        let shared_names = shared_bindings(prod, prev);
        if !shared_names.is_empty() {
            shared.push(format!("{name}: {}", shared_names.join(", ")));
        }

        let subdomain = str_of(p, "subdomain");
        if !subdomain.is_empty() {
            public.push(format!("{name} → {subdomain}"));
        }
        if p.get("source")
            .and_then(|s| s.get("config"))
            .and_then(|c| c.get("deployments_enabled"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            auto_build.push(name);
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "pages", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} Pages {} the same bindings in preview as in production, while every branch \
             publishes a reachable pages.dev URL",
            shared.len(),
            agree(shared.len(), "project holds", "projects hold")
        ),
        shared.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} Pages {} a public pages.dev hostname",
            public.len(),
            agree(public.len(), "project has", "projects have")
        ),
        public.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} Pages {} on push, so a branch becomes a published URL without review",
            auto_build.len(),
            agree(auto_build.len(), "project builds", "projects build")
        ),
        auto_build.clone(),
    );
    out
}

/// The binding names a preview configuration shares with production.
fn shared_bindings(production: Option<&Value>, preview: Option<&Value>) -> Vec<String> {
    let names = |cfg: Option<&Value>| -> BTreeSet<String> {
        let Some(Value::Object(map)) = cfg else {
            return BTreeSet::new();
        };
        // Bindings sit under one key per kind, each an object of name to
        // target: d1_databases, kv_namespaces, r2_buckets, queue_producers…
        map.iter()
            .filter(|(k, _)| k.ends_with('s') && !k.starts_with("env_vars"))
            .filter_map(|(k, v)| v.as_object().map(|o| (k, o)))
            .flat_map(|(kind, o)| {
                o.iter()
                    .filter_map(move |(name, target)| {
                        target_id(target).map(|id| format!("{kind}.{name}={id}"))
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    };
    names(production)
        .intersection(&names(preview))
        .cloned()
        .collect()
}

/// The identifier a Pages binding points at, whatever it is called.
fn target_id(target: &Value) -> Option<String> {
    for key in ["id", "namespace_id", "name", "queue_name", "database_id"] {
        if let Some(v) = target.get(key).and_then(Value::as_str) {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The smaller services that sit beside the platform.
pub fn services(p: &Platform) -> Vec<Finding> {
    let mut wildcard = Vec::new();
    let mut open_gateway = Vec::new();
    let mut logging = Vec::new();

    for w in &p.widgets {
        let domains: Vec<String> = w
            .get("domains")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        // A widget bound to a wildcard can be embedded on any host under it and
        // solved against your site key.
        if domains.iter().any(|d| d.starts_with('*') || d.is_empty()) {
            wildcard.push(format!("{} ({})", str_of(w, "name"), domains.join(", ")));
        }
    }

    for g in &p.gateways {
        let id = str_of(g, "id");
        if g.get("authentication").and_then(Value::as_bool) == Some(false) {
            open_gateway.push(id.clone());
        }
        if g.get("collect_logs").and_then(Value::as_bool) == Some(true) {
            logging.push(id);
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "services", text).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} AI {} without authentication, which is an open proxy to the model \
             credentials behind it, billed to this account",
            open_gateway.len(),
            agree(open_gateway.len(), "gateway answers", "gateways answer")
        ),
        open_gateway.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} Turnstile {} a wildcard or empty domain, so it can be embedded anywhere \
             under it and solved against this account's key",
            wildcard.len(),
            agree(wildcard.len(), "widget allows", "widgets allow")
        ),
        wildcard.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} AI {} prompts and completions",
            logging.len(),
            agree(logging.len(), "gateway retains", "gateways retain")
        ),
        logging.clone(),
    );
    out
}

// ---- zero trust ------------------------------------------------------------

/// One Cloudflare Tunnel and what it publishes inward.
pub struct Tunnel {
    pub name: String,
    pub status: String,
    pub connections: usize,
    /// The ingress rules, in order. The last is the catch-all.
    pub ingress: Vec<Value>,
    /// False when the tunnel is configured from a file on the connector rather
    /// than from Cloudflare, in which case the API cannot see its ingress at
    /// all — and "publishes nothing" would be the wrong thing to report.
    pub ingress_readable: bool,
}

/// The Zero Trust configuration of one account.
///
/// `/cfd_tunnel/{id}/token` is deliberately absent: it returns a live connector
/// credential, and an audit has no use for the value. Not reading it is a
/// stronger guarantee than redacting it, because it never enters the cache.
pub struct ZeroTrust {
    pub apps: Vec<Value>,
    pub service_tokens: Vec<Value>,
    pub idps: Vec<Value>,
    pub gateway_rules: Vec<Value>,
    pub gateway_config: Option<Value>,
    pub gateway_logging: Option<Value>,
    pub device_policies: Vec<Value>,
    pub split_exclude: Vec<Value>,
    pub split_include: Vec<Value>,
    pub posture_rules: Vec<Value>,
    pub tunnels: Vec<Tunnel>,
    pub routes: Vec<Value>,
    pub targets: Vec<Value>,
}

/// Who reaches the applications behind Access.
pub fn access(z: &ZeroTrust) -> Vec<Finding> {
    let mut public = Vec::new();
    let mut bypassed = Vec::new();
    let mut identity_only = Vec::new();
    let mut weak_idp = Vec::new();
    let mut forever = Vec::new();
    let mut no_scim = Vec::new();

    // Providers whose only factor is possession of an inbox.
    let otp: BTreeSet<String> = z
        .idps
        .iter()
        .filter(|i| str_of(i, "type") == "onetimepin")
        .map(|i| str_of(i, "id"))
        .collect();

    for app in &z.apps {
        let name = str_of(app, "name");
        let where_ = str_of(app, "domain");
        let label = if where_.is_empty() {
            name.clone()
        } else {
            format!("{name} ({where_})")
        };

        for p in list(app, "policies") {
            let decision = str_of(p, "decision");
            let includes: Vec<String> = list(p, "include")
                .iter()
                .filter_map(|c| c.as_object().and_then(|o| o.keys().next().cloned()))
                .collect();
            let requires = list(p, "require").len();

            if decision == "bypass" {
                // The app still appears in the list, and Access is off for it.
                bypassed.push(format!("{label}: {:?}", str_of(p, "name")));
            } else if decision == "allow" && includes.iter().any(|i| i == "everyone") {
                public.push(format!("{label}: {:?}", str_of(p, "name")));
            } else if decision == "allow"
                && requires == 0
                && includes
                    .iter()
                    .all(|i| matches!(i.as_str(), "email" | "email_domain" | "login_method"))
            {
                identity_only.push(label.clone());
            }
        }

        // An application that will accept an emailed code has one factor, and
        // it is the inbox.
        let allowed = list(app, "allowed_idps");
        if !otp.is_empty()
            && allowed
                .iter()
                .filter_map(Value::as_str)
                .any(|i| otp.contains(i))
        {
            weak_idp.push(label.clone());
        }

        match str_of(app, "session_duration").as_str() {
            // `0` means the session never expires.
            "" => {}
            "0" => forever.push(format!("{label} (never expires)")),
            d if long_session(d) => forever.push(format!("{label} ({d})")),
            _ => {}
        }
    }

    for i in &z.idps {
        if i.get("scim_config")
            .and_then(|c| c.get("enabled"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            no_scim.push(format!("{} ({})", str_of(i, "name"), str_of(i, "type")));
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "access", text).with(names.join("; ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} Access {} everyone in",
            public.len(),
            agree(public.len(), "policy lets", "policies let")
        ),
        public.clone(),
    );
    push(
        Severity::High,
        format!(
            "{} Access {} the decision to bypass, so Access is off for that path while the \
             application still reads as protected",
            bypassed.len(),
            agree(bypassed.len(), "policy sets", "policies set")
        ),
        bypassed.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} on an address alone, with no device, posture or second-factor \
             requirement",
            identity_only.len(),
            agree(
                identity_only.len(),
                "application admits",
                "applications admit"
            )
        ),
        identity_only.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} a one-time-PIN provider, where an email inbox is the only factor",
            weak_idp.len(),
            agree(weak_idp.len(), "application accepts", "applications accept")
        ),
        weak_idp.clone(),
    );
    push(
        Severity::Low,
        format!(
            "{} {} a session of a day or more",
            forever.len(),
            agree(forever.len(), "application holds", "applications hold")
        ),
        forever.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} identity {} SCIM provisioning, so removing someone from the directory does \
             not remove their Access",
            no_scim.len(),
            agree(no_scim.len(), "provider has no", "providers have no")
        ),
        no_scim.clone(),
    );

    out.extend(service_tokens(&z.service_tokens));
    out
}

/// Whether a session duration is a day or longer.
///
/// The value is a Go duration string, where the units stop at hours and **`m`
/// is minutes, not months** — so a week is `168h` and `30m` is half an hour.
/// Reading `m` as a month would report the shortest session available as the
/// longest.
fn long_session(d: &str) -> bool {
    let split = d.find(|c: char| !c.is_ascii_digit()).unwrap_or(d.len());
    let (num, unit) = d.split_at(split);
    matches!(unit, "h") && num.parse::<u64>().unwrap_or(0) >= 24
}

/// Access service tokens, which bypass interactive authentication entirely.
fn service_tokens(tokens: &[Value]) -> Vec<Finding> {
    let mut forever = Vec::new();
    let mut idle = Vec::new();

    for t in tokens {
        let name = str_of(t, "name");
        match days_until(&str_of(t, "expires_at")) {
            None => forever.push(name.clone()),
            Some(d) if d > 365 => forever.push(format!("{name} (in {d}d)")),
            _ => {}
        }
        if str_of(t, "last_seen_at").is_empty() {
            idle.push(name);
        }
    }

    let mut out = Vec::new();
    if !forever.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "access",
                format!(
                    "{} service {} interactive authentication and {} no expiry within the \
                     year",
                    forever.len(),
                    agree(forever.len(), "token bypasses", "tokens bypass"),
                    agree(forever.len(), "has", "have")
                ),
            )
            .with(forever.join(", ")),
        );
    }
    if !idle.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "access",
                format!(
                    "{} service {} never been used",
                    idle.len(),
                    agree(idle.len(), "token has", "tokens have")
                ),
            )
            .with(idle.join(", ")),
        );
    }
    out
}

/// Whether the egress control enforces anything, and whether it records it.
pub fn gateway(z: &ZeroTrust) -> Vec<Finding> {
    let mut out = Vec::new();

    // Deployed and enforcing nothing is the state to name first: the product
    // reads as present in the dashboard and decides nothing.
    if z.gateway_config.is_some() && z.gateway_rules.is_empty() {
        out.push(Finding::new(
            Severity::High,
            "gateway",
            "Gateway is configured and has no policy at all, so it inspects traffic and \
             decides nothing about it",
        ));
    }

    // Order is the whole of it: a broad allow near the top makes everything
    // below it decorative.
    let mut above_first_block = Vec::new();
    for r in &z.gateway_rules {
        if r.get("enabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        match str_of(r, "action").as_str() {
            "block" | "isolate" | "quarantine" => break,
            "allow" | "off" if str_of(r, "traffic").trim().is_empty() => {
                above_first_block.push(str_of(r, "name"))
            }
            "allow" | "off" => above_first_block.push(str_of(r, "name")),
            _ => {}
        }
    }
    if !above_first_block.is_empty() && !z.gateway_rules.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "gateway",
                format!(
                    "{} {} above the first block, so everything they match is decided before \
                     any block is reached",
                    above_first_block.len(),
                    agree(
                        above_first_block.len(),
                        "allow rule sits",
                        "allow rules sit"
                    )
                ),
            )
            .with(above_first_block.join(", ")),
        );
    }

    let setting = |path: &[&str]| -> Option<bool> {
        let mut cur = z.gateway_config.as_ref()?.get("settings")?;
        for k in path {
            cur = cur.get(k)?;
        }
        cur.as_bool()
    };

    if setting(&["tls_decrypt", "enabled"]) == Some(false) {
        out.push(Finding::new(
            Severity::Medium,
            "gateway",
            "TLS inspection is off, so an HTTP policy sees hostnames and nothing else",
        ));
    }
    if setting(&["activity_log", "enabled"]) == Some(false) {
        out.push(Finding::new(
            Severity::Medium,
            "gateway",
            "the activity log is off, so no decision Gateway makes can be reviewed later",
        ));
    }

    // Logging is configured per rule type and per outcome. With blocks alone,
    // what was allowed leaves no record, and no later investigation is possible.
    let block_only: Vec<String> = z
        .gateway_logging
        .as_ref()
        .and_then(|l| l.get("settings_by_rule_type"))
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter(|(_, v)| v.get("log_all").and_then(Value::as_bool) != Some(true))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    if !block_only.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "gateway",
                format!(
                    "{} rule {} only what was blocked, so allowed traffic leaves no record",
                    block_only.len(),
                    agree(block_only.len(), "type logs", "types log")
                ),
            )
            .with(block_only.join(", ")),
        );
    }
    out
}

/// What the fleet sends through Gateway, and what it does not.
pub fn devices(z: &ZeroTrust) -> Vec<Finding> {
    let mut out = Vec::new();

    // In exclude mode everything on the list leaves the device without passing
    // through Gateway. Private and multicast ranges are the expected defaults;
    // a routable one is a documented hole in the egress control.
    let public_excludes: Vec<String> = z
        .split_exclude
        .iter()
        .filter_map(|e| {
            let addr = str_of(e, "address");
            let host = str_of(e, "host");
            if !host.is_empty() {
                return Some(format!("{host} (domain)"));
            }
            (!addr.is_empty() && is_routable(&addr)).then_some(addr)
        })
        .collect();
    if !public_excludes.is_empty() {
        out.push(
            Finding::new(
                Severity::High,
                "devices",
                format!(
                    "{} split-tunnel {} routable traffic around Gateway entirely",
                    public_excludes.len(),
                    agree(public_excludes.len(), "exclusion sends", "exclusions send")
                ),
            )
            .with(public_excludes.join(", ")),
        );
    }

    for p in &z.device_policies {
        let name = match str_of(p, "name") {
            n if n.is_empty() => "the default profile".to_string(),
            n => n,
        };
        if p.get("allow_mode_switch").and_then(Value::as_bool) == Some(true)
            && p.get("switch_locked").and_then(Value::as_bool) != Some(true)
        {
            out.push(Finding::new(
                Severity::Medium,
                "devices",
                format!("{name} lets a user switch WARP off, which turns the fleet's egress control into an opt-in"),
            ));
        }
        if p.get("allow_updates").and_then(Value::as_bool) == Some(false) {
            out.push(Finding::new(
                Severity::Low,
                "devices",
                format!("{name} does not auto-update the client, so the fleet stays on whatever build it has"),
            ));
        }
    }

    // Posture rules are only controls if a policy consumes them. A populated
    // list nothing references is the most polished form of theatre here.
    if !z.posture_rules.is_empty() {
        let referenced: BTreeSet<String> = z
            .apps
            .iter()
            .flat_map(|a| list(a, "policies").to_vec())
            .flat_map(|p| [list(&p, "require").to_vec(), list(&p, "include").to_vec()].concat())
            .filter_map(|c| {
                c.get("device_posture")
                    .map(|d| str_of(d, "integration_uid"))
            })
            .filter(|s| !s.is_empty())
            .collect();
        let unused: Vec<String> = z
            .posture_rules
            .iter()
            .filter(|r| !referenced.contains(&str_of(r, "id")))
            .map(|r| str_of(r, "name"))
            .collect();
        if !unused.is_empty() {
            out.push(
                Finding::new(
                    Severity::Medium,
                    "devices",
                    format!(
                        "{} posture {} referenced by no Access policy, so {} nothing",
                        unused.len(),
                        agree(unused.len(), "rule is", "rules are"),
                        agree(unused.len(), "it gates", "they gate")
                    ),
                )
                .with(unused.join(", ")),
            );
        }
    }
    out
}

/// What the tunnels publish inward, and how wide the routes are.
pub fn tunnels(z: &ZeroTrust) -> Vec<Finding> {
    let mut inactive = Vec::new();
    let mut unverified = Vec::new();
    let mut open_catch_all = Vec::new();
    let mut exposed = Vec::new();
    let mut wide_routes = Vec::new();
    let mut unreadable = Vec::new();

    for t in &z.tunnels {
        if !t.ingress_readable {
            unreadable.push(t.name.clone());
            continue;
        }
        if !matches!(t.status.as_str(), "healthy" | "") || t.connections == 0 {
            inactive.push(format!("{} ({})", t.name, t.status));
        }
        for (i, rule) in t.ingress.iter().enumerate() {
            let hostname = str_of(rule, "hostname");
            let service = str_of(rule, "service");
            let last = i + 1 == t.ingress.len();

            if hostname.is_empty() {
                // The catch-all. Anything but a refusal means a request for an
                // unlisted hostname still reaches something inside.
                if last && !service.starts_with("http_status:4") && !service.is_empty() {
                    open_catch_all.push(format!("{}: {service}", t.name));
                }
                continue;
            }
            exposed.push(format!("{hostname} → {service}"));
            if rule
                .get("originRequest")
                .and_then(|o| o.get("noTLSVerify"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                unverified.push(format!("{hostname} → {service}"));
            }
        }
    }

    for r in &z.routes {
        let net = str_of(r, "network");
        if prefix_len(&net).is_some_and(|len| len <= 16) {
            wide_routes.push(format!("{net} ({})", str_of(r, "comment")));
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "tunnels", text).with(names.join(", ")));
        }
    };

    push(
        Severity::Medium,
        format!(
            "{} tunnel {} no healthy connector, so the paths {} configured are waiting \
             rather than serving",
            inactive.len(),
            agree(inactive.len(), "has", "have"),
            agree(inactive.len(), "it has", "they have")
        ),
        inactive.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} ingress {} the origin's certificate",
            unverified.len(),
            agree(
                unverified.len(),
                "rule does not verify",
                "rules do not verify"
            )
        ),
        unverified.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} tunnel {} a catch-all that reaches something rather than refusing, so an \
             unlisted hostname still lands inside",
            open_catch_all.len(),
            agree(open_catch_all.len(), "has", "have")
        ),
        open_catch_all.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} private {} advertised to every enrolled device at a /16 or wider",
            wide_routes.len(),
            agree(wide_routes.len(), "range is", "ranges are")
        ),
        wide_routes.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} configured on the connector rather than in Cloudflare, so what {} \
             publishes inward cannot be read from the API",
            unreadable.len(),
            agree(unreadable.len(), "tunnel is", "tunnels are"),
            agree(unreadable.len(), "it", "they")
        ),
        unreadable.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} internal {} published through a tunnel: this is the list of what the \
             internet can reach inside",
            exposed.len(),
            agree(exposed.len(), "service is", "services are")
        ),
        exposed.clone(),
    );
    out
}

/// Whether an address or prefix is globally routable unicast — space a real
/// internet service could live on.
///
/// The default split-tunnel list is almost entirely special-purpose space:
/// private, loopback, link-local, multicast, and a dozen ranges from the IANA
/// special-purpose registry. Excluding those from the fleet's tunnel is the
/// intended configuration, so flagging them turns a correct default into eight
/// findings. Only an exclusion a service could actually be reached on is worth
/// naming.
fn is_routable(cidr: &str) -> bool {
    let addr = cidr.split('/').next().unwrap_or(cidr);
    let Ok(ip) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    !is_private(addr) && !is_special_purpose(ip)
}

/// The IANA special-purpose ranges a split tunnel is expected to carry, beyond
/// the private space [`is_private`] already covers.
fn is_special_purpose(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 0.0.0.0/8 this network; 240.0.0.0/4 reserved.
                || o[0] == 0
                || o[0] >= 240
                // 192.0.0.0/24 IETF assignments; 192.88.99.0/24 deprecated 6to4.
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                // 198.18.0.0/15 benchmarking.
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        }
        std::net::IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_multicast()
                // 100::/64 discard; 64:ff9b::/96 NAT64.
                || (seg[0] == 0x0100 && seg[1..4] == [0, 0, 0])
                || (seg[0] == 0x0064 && seg[1] == 0xff9b)
                // 2001::/32 Teredo, 2001:db8::/32 documentation, 2002::/16 6to4.
                || (seg[0] == 0x2001 && (seg[1] == 0 || seg[1] == 0x0db8))
                || seg[0] == 0x2002
        }
    }
}

/// The prefix length of a CIDR, when it has one.
fn prefix_len(cidr: &str) -> Option<u8> {
    cidr.split_once('/')?.1.parse().ok()
}

// ---- egress, logging and alerting ------------------------------------------

/// Where request data goes, and whether any of it is kept.
pub struct Egress {
    /// Account-level and zone-level Logpush jobs, each tagged with its scope.
    pub jobs: Vec<(String, Value)>,
    /// `None` when the read was refused, which is the common case: Logpush
    /// needs its own permission.
    pub jobs_readable: bool,
    pub residency: Option<Value>,
    /// Zone name to whether raw log retention is on. Absent zones were unread.
    pub retention: Vec<(String, bool)>,
    /// Reads that were refused, as (what, why).
    ///
    /// This plane is the one most likely to be entirely unreadable — Logpush
    /// and log control each need their own permission — so an empty findings
    /// list here means "nothing was looked at" far more often than it means
    /// "nothing is wrong". Carrying the refusals is what stops the report
    /// saying the second when it means the first.
    pub unread: Vec<(String, String)>,
}

/// Whether anyone is told when something breaks.
pub struct Alerting {
    pub policies: Vec<Value>,
    /// Alert type to display name, for every type this account can receive.
    pub available: Vec<(String, String)>,
    pub webhooks: Vec<Value>,
    pub pagerduty: Vec<Value>,
    pub silences: Vec<Value>,
    pub history: Vec<Value>,
}

/// The field names that carry something about a person rather than a request.
const SENSITIVE_FIELDS: [&str; 8] = [
    "ClientRequestCookies",
    "ClientRequestHeaders",
    "ClientRequestUserAgent",
    "ClientIP",
    "ClientDeviceType",
    "RequestHeaders",
    "ResponseHeaders",
    "Cookies",
];

/// Checks over where the request data goes.
pub fn egress(e: &Egress) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut disabled = Vec::new();
    let mut failing = Vec::new();
    let mut sensitive = Vec::new();
    let mut destinations = Vec::new();

    for (scope, j) in &e.jobs {
        let name = match str_of(j, "name") {
            n if n.is_empty() => str_of(j, "dataset"),
            n => n,
        };
        let label = format!("{scope}/{name}");
        let dest = destination_of(&str_of(j, "destination_conf"));

        if j.get("enabled").and_then(Value::as_bool) == Some(false) {
            disabled.push(label.clone());
        }
        if !str_of(j, "last_error").is_empty() {
            failing.push(format!("{label}: {}", str_of(j, "last_error")));
        }
        destinations.push(format!("{label} → {dest} ({})", str_of(j, "dataset")));

        let fields: Vec<String> = j
            .get("output_options")
            .and_then(|o| o.get("field_names"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .filter(|f| SENSITIVE_FIELDS.contains(f))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        if !fields.is_empty() {
            sensitive.push(format!("{label} → {dest}: {}", fields.join(", ")));
        }
    }

    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "egress", text).with(names.join("; ")));
        }
    };

    push(
        Severity::Medium,
        format!(
            "{} Logpush {} headers, cookies or client addresses to an external \
             destination",
            sensitive.len(),
            agree(sensitive.len(), "job ships", "jobs ship")
        ),
        sensitive.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} Logpush {} disabled, so the logs everyone assumes exist are not being \
             written",
            disabled.len(),
            agree(disabled.len(), "job is", "jobs are")
        ),
        disabled.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} Logpush {} failing",
            failing.len(),
            agree(failing.len(), "job is", "jobs are")
        ),
        failing.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} Logpush {} data off this account",
            destinations.len(),
            agree(destinations.len(), "job sends", "jobs send")
        ),
        destinations.clone(),
    );

    // Retention decides whether a question asked next month has an answer, and
    // turning it on today does not answer it retroactively.
    let off: Vec<String> = e
        .retention
        .iter()
        .filter(|(_, on)| !on)
        .map(|(z, _)| z.clone())
        .collect();
    if !off.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "egress",
                format!(
                    "{} {} raw log retention off, so there is no record to answer a question \
                     asked later — and switching it on does not answer one asked about today",
                    off.len(),
                    agree(off.len(), "zone has", "zones have")
                ),
            )
            .with(off.join(", ")),
        );
    }

    if e.jobs_readable && e.jobs.is_empty() {
        out.push(Finding::new(
            Severity::Info,
            "egress",
            "no Logpush job: request data leaves this account through nothing configured here",
        ));
    }
    out
}

/// The service a Logpush destination points at, without its credentials.
///
/// A destination string carries the bucket and, for some backends, an access
/// key in its query. Only the scheme and host are ever shown.
pub fn destination_of(conf: &str) -> String {
    let scheme = conf.split("://").next().unwrap_or("");
    let rest = conf.split("://").nth(1).unwrap_or("");
    let host = rest.split(['?', '/']).next().unwrap_or("");
    match (scheme, host) {
        ("", _) => "(unreadable)".to_string(),
        (s, "") => s.to_string(),
        (s, h) => format!("{s}://{h}"),
    }
}

/// Alert types worth having, grouped by the question each one answers.
///
/// Grouped rather than listed because "55 of 57 alert types have no policy" is
/// a number nobody acts on, while "nothing tells you a certificate stopped
/// renewing" is a sentence with a next step. Each group fires only when the
/// account can receive at least one of its types and subscribes to none.
const WATCHED: &[(&str, &[&str], Severity)] = &[
    (
        "a certificate expires or stops renewing",
        &[
            "universal_ssl_event_type",
            "dedicated_ssl_certificate_event_type",
            "custom_ssl_certificate_event_type",
            "access_custom_certificate_expiration_type",
            "mtls_certificate_store_certificate_expiration_type",
            "zone_aop_custom_certificate_expiration_type",
            "hostname_aop_custom_certificate_expiration_type",
        ],
        Severity::Medium,
    ),
    (
        "a Logpush job is disabled for failing, and the logs quietly stop",
        &["failing_logpush_job_disabled_alert"],
        Severity::Medium,
    ),
    (
        "an Access service token is about to expire",
        &["expiring_service_token_alert"],
        Severity::Medium,
    ),
    (
        "a route to these prefixes is leaked or hijacked",
        &["bgp_hijack_notification"],
        Severity::Low,
    ),
    (
        "the site is under a layer 7 attack",
        &["dos_attack_l7"],
        Severity::Low,
    ),
    (
        "the origin stops answering",
        &[
            "real_origin_monitoring",
            "health_check_status_notification",
            "load_balancing_health_alert",
            "tunnel_health_event",
        ],
        Severity::Low,
    ),
    (
        "usage runs away and the bill with it",
        &["billing_usage_alert", "billing_budget_alert"],
        Severity::Low,
    ),
    (
        "Page Shield sees a malicious script or domain",
        &[
            "scriptmonitor_alert_new_malicious_scripts",
            "scriptmonitor_alert_new_malicious_hosts",
            "scriptmonitor_alert_new_malicious_url",
        ],
        Severity::Low,
    ),
];

/// Checks over whether anyone is told.
pub fn alerting(a: &Alerting) -> Vec<Finding> {
    let mut out = Vec::new();

    let subscribed: BTreeSet<String> = a
        .policies
        .iter()
        .filter(|p| p.get("enabled").and_then(Value::as_bool) != Some(false))
        .map(|p| str_of(p, "alert_type"))
        .collect();
    let available: BTreeSet<String> = a.available.iter().map(|(t, _)| t.clone()).collect();

    // Only groups this account could actually receive, so a plan gap is never
    // reported as a gap in configuration.
    let mut uncovered: Vec<(&str, Severity)> = Vec::new();
    for (question, types, sev) in WATCHED {
        let offered = types.iter().any(|t| available.contains(*t));
        let taken = types.iter().any(|t| subscribed.contains(*t));
        if offered && !taken {
            uncovered.push((question, *sev));
        }
    }
    for sev in [Severity::Medium, Severity::Low] {
        let questions: Vec<String> = uncovered
            .iter()
            .filter(|(_, s)| *s == sev)
            .map(|(q, _)| (*q).to_string())
            .collect();
        if !questions.is_empty() {
            out.push(
                Finding::new(
                    sev,
                    "alerts",
                    format!(
                        "nothing tells anyone when {} {}",
                        questions.len(),
                        agree(questions.len(), "of these happens", "of these happen")
                    ),
                )
                .with(questions.join("; ")),
            );
        }
    }

    let off: Vec<String> = a
        .policies
        .iter()
        .filter(|p| p.get("enabled").and_then(Value::as_bool) == Some(false))
        .map(|p| str_of(p, "name"))
        .collect();
    if !off.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "alerts",
                format!(
                    "{} notification {} disabled",
                    off.len(),
                    agree(off.len(), "policy is", "policies are")
                ),
            )
            .with(off.join(", ")),
        );
    }

    // A webhook whose last failure is newer than its last success has been
    // delivering nothing, and every policy pointing at it is silent.
    let broken: Vec<String> = a
        .webhooks
        .iter()
        .filter(|w| {
            let (ok, bad) = (str_of(w, "last_success"), str_of(w, "last_failure"));
            !bad.is_empty() && (ok.is_empty() || bad > ok)
        })
        .map(|w| {
            format!(
                "{} (last failure {})",
                str_of(w, "name"),
                str_of(w, "last_failure")
            )
        })
        .collect();
    if !broken.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "alerts",
                format!(
                    "{} webhook {} failing more recently than {} succeeded, so every policy \
                     pointing at {} is silent",
                    broken.len(),
                    agree(broken.len(), "destination is", "destinations are"),
                    agree(broken.len(), "it", "they"),
                    agree(broken.len(), "it", "them")
                ),
            )
            .with(broken.join(", ")),
        );
    }

    // A silence is created to stop noise during an incident and is meant to be
    // temporary.
    if !a.silences.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "alerts",
                format!(
                    "{} alert {} silenced",
                    a.silences.len(),
                    agree(a.silences.len(), "is", "are")
                ),
            )
            .with(
                a.silences
                    .iter()
                    .map(|s| str_of(s, "description"))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        );
    }

    if a.policies.is_empty() && !a.available.is_empty() {
        out.push(Finding::new(
            Severity::Medium,
            "alerts",
            "no notification policy at all: nothing on this account tells anyone anything",
        ));
    }
    out
}

// ---- the routed network ----------------------------------------------------

/// One Magic WAN site and the segmentation configured on it.
pub struct Site {
    pub name: String,
    pub acls: Vec<Value>,
    pub lans: Vec<Value>,
}

/// The routed estate, where an account has one.
///
/// Every field here is empty on an account that did not buy Magic Transit,
/// BYOIP or load balancing — which is most of them. An empty plane is a fact,
/// and the command that reads this says so rather than grading nothing.
pub struct Network {
    pub sites: Vec<Site>,
    pub ipsec: Vec<Value>,
    pub gre: Vec<Value>,
    pub routes: Vec<Value>,
    pub prefixes: Vec<Value>,
    pub address_maps: Vec<Value>,
    pub dns_firewall: Vec<Value>,
    pub load_balancers: Vec<Value>,
    pub pools: Vec<Value>,
    pub monitors: Vec<Value>,
}

impl Network {
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
            && self.ipsec.is_empty()
            && self.gre.is_empty()
            && self.routes.is_empty()
            && self.prefixes.is_empty()
            && self.dns_firewall.is_empty()
            && self.load_balancers.is_empty()
            && self.pools.is_empty()
    }
}

/// The tunnels and the routing between sites.
pub fn magic(n: &Network) -> Vec<Finding> {
    let mut unencrypted = Vec::new();
    let mut unchecked = Vec::new();
    let mut replayable = Vec::new();
    let mut flat = Vec::new();

    for t in n.ipsec.iter().chain(n.gre.iter()) {
        let name = str_of(t, "name");
        // An IPsec tunnel with a null cipher authenticates and does not
        // encrypt, which is the one thing everyone assumes it does.
        if t.get("allow_null_cipher").and_then(Value::as_bool) == Some(true) {
            unencrypted.push(name.clone());
        }
        if t.get("health_check")
            .and_then(|h| h.get("enabled"))
            .and_then(Value::as_bool)
            == Some(false)
        {
            unchecked.push(name.clone());
        }
        // Only IPsec carries this; a GRE tunnel has no such setting and its
        // absence must not be read as "off".
        if t.get("replay_protection").and_then(Value::as_bool) == Some(false) {
            replayable.push(name);
        }
    }

    // A rule pairing two whole LANs with every protocol is a flat network
    // wearing a segmentation diagram, and it is invisible from either site's
    // own configuration.
    for site in &n.sites {
        for acl in &site.acls {
            let unrestricted = |side: &str| {
                acl.get(side).is_some_and(|l| {
                    empty_list(l, "ports")
                        && empty_list(l, "port_ranges")
                        && empty_list(l, "subnets")
                })
            };
            let all_protocols = empty_list(acl, "protocols");
            if all_protocols && unrestricted("lan_1") && unrestricted("lan_2") {
                flat.push(format!("{}: {}", site.name, str_of(acl, "name")));
            }
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "magic", text).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} {} a null cipher, so it authenticates the peer and sends the traffic in \
             clear",
            unencrypted.len(),
            agree(unencrypted.len(), "tunnel permits", "tunnels permit")
        ),
        unencrypted.clone(),
    );
    push(
        Severity::High,
        format!(
            "{} site {} two whole LANs on every protocol, which is a flat network wearing \
             a segmentation diagram",
            flat.len(),
            agree(flat.len(), "rule pairs", "rules pair")
        ),
        flat.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} {} health checks off, so failover has nothing to act on",
            unchecked.len(),
            agree(unchecked.len(), "tunnel has", "tunnels have")
        ),
        unchecked.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} IPsec {} replay protection off",
            replayable.len(),
            agree(replayable.len(), "tunnel has", "tunnels have")
        ),
        replayable.clone(),
    );

    out.extend(overlapping_routes(&n.routes));
    out
}

/// Static routes that cover the same address space at the same priority.
///
/// Two routes for one destination at equal priority is a decision made per
/// packet rather than by the design, and neither route's own definition shows
/// it — only the pair does.
fn overlapping_routes(routes: &[Value]) -> Vec<Finding> {
    let mut clashes = Vec::new();
    for (i, a) in routes.iter().enumerate() {
        for b in routes.iter().skip(i + 1) {
            let (pa, pb) = (str_of(a, "prefix"), str_of(b, "prefix"));
            if str_of(a, "nexthop") == str_of(b, "nexthop") {
                continue;
            }
            let (ra, rb) = (
                a.get("priority").and_then(Value::as_i64),
                b.get("priority").and_then(Value::as_i64),
            );
            if ra != rb {
                continue;
            }
            if covers(&pa, &pb) || covers(&pb, &pa) {
                clashes.push(format!(
                    "{pa} → {} and {pb} → {}",
                    str_of(a, "nexthop"),
                    str_of(b, "nexthop")
                ));
            }
        }
    }
    if clashes.is_empty() {
        return Vec::new();
    }
    vec![Finding::new(
        Severity::Medium,
        "magic",
        format!(
            "{} static {} the same space at the same priority, so which one wins is \
             decided per packet",
            clashes.len(),
            agree(clashes.len(), "route pair covers", "route pairs cover")
        ),
    )
    .with(clashes.join("; "))]
}

/// Whether `outer` contains `inner`, for IPv4 prefixes.
///
/// IPv6 is left alone rather than guessed at: a wrong answer about routing is
/// worse than no answer, and the overlaps that bite in practice are v4.
fn covers(outer: &str, inner: &str) -> bool {
    let parse = |cidr: &str| -> Option<(u32, u8)> {
        let (addr, len) = cidr.split_once('/')?;
        let ip: std::net::Ipv4Addr = addr.parse().ok()?;
        Some((u32::from(ip), len.parse().ok()?))
    };
    let (Some((a, la)), Some((b, lb))) = (parse(outer), parse(inner)) else {
        return false;
    };
    if la > lb || la > 32 {
        return false;
    }
    let mask = if la == 0 { 0 } else { u32::MAX << (32 - la) };
    a & mask == b & mask
}

/// Address space announced on this account's behalf.
pub fn addressing(n: &Network) -> Vec<Finding> {
    let mut idle = Vec::new();
    let mut unvalidated = Vec::new();

    // Every prefix an address map binds is in use; the rest are announced for
    // nothing.
    let bound: BTreeSet<String> = n
        .address_maps
        .iter()
        .flat_map(|m| list(m, "ips").to_vec())
        .map(|ip| str_of(&ip, "ip"))
        .collect();

    for p in &n.prefixes {
        let cidr = str_of(p, "cidr");
        if p.get("advertised").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        if !bound.iter().any(|ip| covers(&cidr, &format!("{ip}/32"))) {
            idle.push(cidr.clone());
        }
        if !matches!(str_of(p, "rpki_validation_state").as_str(), "valid" | "") {
            unvalidated.push(format!("{cidr} ({})", str_of(p, "rpki_validation_state")));
        }
    }

    let mut out = Vec::new();
    if !idle.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "addressing",
                format!(
                    "{} {} advertised from Cloudflare with nothing bound to {}",
                    idle.len(),
                    agree(idle.len(), "prefix is", "prefixes are"),
                    agree(idle.len(), "it", "them")
                ),
            )
            .with(idle.join(", ")),
        );
    }
    if !unvalidated.is_empty() {
        out.push(
            Finding::new(
                Severity::Medium,
                "addressing",
                format!(
                    "{} advertised {} an RPKI state other than valid, so the announcement \
                     can be dropped by validating networks",
                    unvalidated.len(),
                    agree(unvalidated.len(), "prefix has", "prefixes have")
                ),
            )
            .with(unvalidated.join(", ")),
        );
    }
    out
}

/// Load balancing, and whether failover has anything to act on.
pub fn balancing(n: &Network) -> Vec<Finding> {
    let mut unmonitored = Vec::new();
    let mut no_fallback = Vec::new();
    let mut disabled_origins = Vec::new();

    let monitors: BTreeSet<String> = n.monitors.iter().map(|m| str_of(m, "id")).collect();

    for p in &n.pools {
        let name = str_of(p, "name");
        let monitor = str_of(p, "monitor");
        // A pool with no monitor, or one pointing at a monitor that no longer
        // exists, never marks an origin unhealthy — so it never fails over.
        if monitor.is_empty() || !monitors.contains(&monitor) {
            unmonitored.push(name.clone());
        }
        let off: Vec<String> = list(p, "origins")
            .iter()
            .filter(|o| o.get("enabled").and_then(Value::as_bool) == Some(false))
            .map(|o| format!("{}/{}", name, str_of(o, "name")))
            .collect();
        disabled_origins.extend(off);
    }

    for lb in &n.load_balancers {
        if str_of(lb, "fallback_pool").is_empty() {
            no_fallback.push(str_of(lb, "name"));
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, text: String, names: Vec<String>| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "balancing", text).with(names.join(", ")));
        }
    };

    push(
        Severity::Medium,
        format!(
            "{} {} no working monitor, so {} never marks an origin unhealthy and never \
             fails over",
            unmonitored.len(),
            agree(unmonitored.len(), "pool has", "pools have"),
            agree(unmonitored.len(), "it", "they")
        ),
        unmonitored.clone(),
    );
    push(
        Severity::Medium,
        format!(
            "{} load {} no fallback pool, so traffic is dropped rather than shed when every \
             pool is unhealthy",
            no_fallback.len(),
            agree(no_fallback.len(), "balancer has", "balancers have")
        ),
        no_fallback.clone(),
    );
    push(
        Severity::Info,
        format!(
            "{} disabled {} still listed in a pool, which is a record of infrastructure \
             that may still be listening",
            disabled_origins.len(),
            agree(disabled_origins.len(), "origin is", "origins are")
        ),
        disabled_origins.clone(),
    );
    out
}

/// DNS Firewall clusters, and where they forward.
pub fn dns_firewall(n: &Network) -> Vec<Finding> {
    let mut upstreams = Vec::new();
    let mut unlimited = Vec::new();

    for c in &n.dns_firewall {
        let name = str_of(c, "name");
        let ips: Vec<String> = list(c, "upstream_ips")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        if !ips.is_empty() {
            upstreams.push(format!("{name} → {}", ips.join(", ")));
        }
        if c.get("ratelimit").and_then(Value::as_f64).unwrap_or(0.0) == 0.0 {
            unlimited.push(name);
        }
    }

    let mut out = Vec::new();
    if !unlimited.is_empty() {
        out.push(
            Finding::new(
                Severity::Low,
                "dns firewall",
                format!(
                    "{} {} no rate limit, so a flood is forwarded to the upstream resolvers",
                    unlimited.len(),
                    agree(unlimited.len(), "cluster has", "clusters have")
                ),
            )
            .with(unlimited.join(", ")),
        );
    }
    if !upstreams.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                "dns firewall",
                format!(
                    "{} {} to resolvers outside Cloudflare",
                    upstreams.len(),
                    agree(upstreams.len(), "cluster forwards", "clusters forward")
                ),
            )
            .with(upstreams.join("; ")),
        );
    }
    out
}

/// Whether a list-valued field is absent or empty, which on an ACL side means
/// "everything" rather than "nothing".
fn empty_list(v: &Value, key: &str) -> bool {
    v.get(key)
        .map(|x| x.as_array().is_none_or(|a| a.is_empty()))
        .unwrap_or(true)
}

// ---- the outside view ------------------------------------------------------

/// One zone, as Cloudflare holds it and as mlab.sh observed it.
///
/// Every other plane in this tool reads the account's own record of itself.
/// This one is the only place where a second, independent observer is put
/// beside that record, and the findings below are all of one kind: **the two
/// disagree**. A name Cloudflare does not know but the world resolves is not a
/// misconfiguration in the Cloudflare account — it is proof that the Cloudflare
/// account is not the whole story.
pub struct Outside {
    pub zone: String,
    /// Every hostname the zone holds a record for, lowercased, trailing dot
    /// removed. Built from the records rather than from the scan, so a name
    /// missing here really is missing from Cloudflare.
    pub known: BTreeSet<String>,
    /// Whether the Cloudflare zone itself publishes SPF, and DMARC.
    pub cf_spf: bool,
    pub cf_dmarc: bool,
    /// `results` from a completed domain scan.
    pub scan: Value,
}

/// One published address, as Cloudflare configures it and as mlab.sh sees it.
pub struct Address {
    /// The record names pointing here, for the detail line.
    pub names: Vec<String>,
    pub addr: String,
    /// Whether Cloudflare also proxies for this address. A proxied-for address
    /// published in a second, unproxied record is the classic bypass; an
    /// address that is only ever an origin behind the proxy is not exposed by
    /// being an origin.
    pub exposed: bool,
    /// The `scan_ip` body.
    pub scan: Value,
}

impl Address {
    fn label(&self) -> String {
        if self.names.is_empty() {
            self.addr.clone()
        } else {
            format!("{} → {}", self.names.join(", "), self.addr)
        }
    }
}

/// Names the world resolves that the Cloudflare zone has no record for.
///
/// The highest-value check in the tool, and the one no amount of reading the
/// Cloudflare API can produce: a subdomain that answers but is not in the zone
/// is served by nameservers, a delegation, or a wildcard that this account does
/// not control, and nothing in the account will ever mention it.
pub fn shadow(zones: &[Outside]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut answering = Vec::new();
    let mut observed = Vec::new();
    let mut in_ct = Vec::new();
    let mut flagged = Vec::new();

    for z in zones {
        let results = scan_results(&z.scan);
        // Names the scan got an answer for. This is a positive result and is
        // used only as one: `dns.resolve` does not cover every discovered name
        // — two names that plainly answer were missing from it on a real scan
        // — so absence from it means "not shown to resolve", never "does not
        // resolve", and nothing here concludes the latter.
        let resolved = resolving(scan_dns(&z.scan));

        for host in list(results, "subdomains").iter().filter_map(Value::as_str) {
            let host = normalise(host);
            if z.known.contains(&host) {
                continue;
            }
            if resolved.contains(&host) {
                answering.push(host);
            } else {
                observed.push(host);
            }
        }

        // Certificate transparency: somebody proved control of the name to a
        // CA. A wildcard covers a label, so it is judged as the name it wraps.
        for cert in list(results, "ssl") {
            let cn = str_of(cert, "common_name");
            let host = normalise(cn.strip_prefix("*.").unwrap_or(&cn));
            // Cloudflare issues universal certificates under a hashed name of
            // its own; those belong to Cloudflare, not to the zone.
            if host.is_empty() || host.ends_with(".sni.cloudflaressl.com") {
                continue;
            }
            if in_zone(&host, &z.zone) && !z.known.contains(&host) {
                in_ct.push(host);
            }
        }

        for s in list(results, "subdomains_suspicious") {
            flagged.push(format!(
                "{} (\"{}\")",
                str_of(s, "subdomain"),
                str_of(s, "keyword")
            ));
        }
    }

    for v in [&mut answering, &mut observed, &mut in_ct, &mut flagged] {
        v.sort();
        v.dedup();
    }
    // Each name is reported once, under the strongest evidence there is for it.
    observed.retain(|h| !answering.contains(h));
    in_ct.retain(|h| !answering.contains(h) && !observed.contains(h));

    if !answering.is_empty() {
        let n = answering.len();
        out.push(
            Finding::new(
                Severity::High,
                "shadow",
                format!(
                    "{n} {} and the Cloudflare zone holds no record for {}",
                    agree(n, "hostname resolves", "hostnames resolve"),
                    agree(n, "it", "them")
                ),
            )
            .with(answering.join(", ")),
        );
    }
    if !observed.is_empty() {
        let n = observed.len();
        out.push(
            Finding::new(
                Severity::Medium,
                "shadow",
                format!(
                    "{n} {} publicly and {} in the Cloudflare zone",
                    agree(n, "hostname is known", "hostnames are known"),
                    agree(n, "has no record", "have no record")
                ),
            )
            .with(observed.join(", ")),
        );
    }
    if !in_ct.is_empty() {
        let n = in_ct.len();
        out.push(
            Finding::new(
                Severity::Medium,
                "shadow",
                format!(
                    "{n} {} a public certificate and no record in the zone",
                    agree(n, "hostname has", "hostnames have")
                ),
            )
            .with(in_ct.join(", ")),
        );
    }
    if !flagged.is_empty() {
        let n = flagged.len();
        out.push(
            Finding::new(
                Severity::Low,
                "shadow",
                format!(
                    "{n} public {} name an internal environment",
                    agree(n, "hostname", "hostnames")
                ),
            )
            .with(flagged.join(", ")),
        );
    }
    out
}

/// The hostnames a scan actually got an answer for.
///
/// `dns.resolve` holds the apex plus every discovered name that answered; a
/// discovered name missing from it did not answer. Nothing else in the scan
/// carries that distinction, and the whole of [`shadow`] turns on it.
fn resolving(dns: &Value) -> BTreeSet<String> {
    list(dns, "resolve")
        .iter()
        .filter(|r| {
            !list(r, "a").is_empty()
                || !list(r, "aaaa").is_empty()
                || !str_of(r, "cname").is_empty()
        })
        .map(|r| normalise(&str_of(r, "domain")))
        .collect()
}

/// What the world resolves, against what Cloudflare is configured to serve.
pub fn drift(zones: &[Outside]) -> Vec<Finding> {
    let mut unproxied = Vec::new();

    for z in zones {
        for r in list(scan_dns(&z.scan), "resolve") {
            let host = normalise(&str_of(r, "domain"));
            let a: Vec<String> = list(r, "a")
                .iter()
                .chain(list(r, "aaaa"))
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();

            // Cloudflare's own space is what a proxied name answers with.
            // Anything else is the origin answering directly, to anyone who
            // asks, which is the exposure the proxy exists to prevent.
            if !a.is_empty() && !a.iter().any(|ip| is_cloudflare(ip)) {
                unproxied.push(format!("{host} → {}", a.join(", ")));
            }
        }
    }
    unproxied.sort();
    unproxied.dedup();

    if unproxied.is_empty() {
        return Vec::new();
    }
    let n = unproxied.len();
    vec![Finding::new(
        Severity::Medium,
        "drift",
        format!(
            "{n} public {} an address outside Cloudflare, so the proxy is not in the path",
            agree(n, "hostname resolves to", "hostnames resolve to")
        ),
    )
    .with(unproxied.join(", "))]
}

/// The live mail policy, against the one the Cloudflare zone publishes.
///
/// The DNS plane already reports a zone with no SPF or no DMARC. This check
/// answers a question that plane cannot: whether what is *in the zone* is what
/// the world actually gets. A record present in Cloudflare and absent live means
/// the zone is not authoritative; a record absent in Cloudflare and present live
/// means the same thing from the other direction, and is the more alarming of
/// the two.
pub fn live_mail(zones: &[Outside]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut served_elsewhere = Vec::new();
    let mut not_live = Vec::new();
    let mut monitor_only = Vec::new();
    let mut permissive = Vec::new();

    for z in zones {
        let txt = scan_dns(&z.scan).get("txt").cloned().unwrap_or(json!({}));
        let spf = str_of(&txt, "spf");
        let dmarc = str_of(&txt, "dmarc");

        for (what, in_cf, live) in [
            ("SPF", z.cf_spf, !spf.is_empty()),
            ("DMARC", z.cf_dmarc, !dmarc.is_empty()),
        ] {
            match (in_cf, live) {
                (false, true) => served_elsewhere.push(format!("{} ({what})", z.zone)),
                (true, false) => not_live.push(format!("{} ({what})", z.zone)),
                _ => {}
            }
        }

        // `p=none` collects reports and rejects nothing, which is a deployment
        // step rather than a policy.
        if policy_of(&dmarc).as_deref() == Some("none") {
            monitor_only.push(z.zone.clone());
        }
        // `+all` authorises every host on the internet; `?all` asserts nothing.
        if spf.contains("+all") || spf.contains("?all") {
            permissive.push(format!("{}: {spf}", z.zone));
        }
    }

    if !served_elsewhere.is_empty() {
        let n = served_elsewhere.len();
        out.push(
            Finding::new(
                Severity::High,
                "live mail",
                format!(
                    "{n} mail {} live and absent from the Cloudflare zone, so something else answers for the {}",
                    agree(n, "policy is", "policies are"),
                    agree(n, "name", "names")
                ),
            )
            .with(served_elsewhere.join(", ")),
        );
    }
    if !not_live.is_empty() {
        let n = not_live.len();
        out.push(
            Finding::new(
                Severity::High,
                "live mail",
                format!(
                    "{n} mail {} in the Cloudflare zone and {} resolve, so {} nothing",
                    agree(n, "policy is", "policies are"),
                    agree(n, "does not", "do not"),
                    agree(n, "it enforces", "they enforce")
                ),
            )
            .with(not_live.join(", ")),
        );
    }
    if !monitor_only.is_empty() {
        let n = monitor_only.len();
        out.push(
            Finding::new(
                Severity::Medium,
                "live mail",
                format!(
                    "{n} live DMARC {} p=none, which reports and rejects nothing",
                    agree(n, "policy is", "policies are")
                ),
            )
            .with(monitor_only.join(", ")),
        );
    }
    if !permissive.is_empty() {
        let n = permissive.len();
        out.push(
            Finding::new(
                Severity::High,
                "live mail",
                format!(
                    "{n} live SPF {} every sender",
                    agree(n, "record authorises", "records authorise")
                ),
            )
            .with(permissive.join(", ")),
        );
    }
    out
}

/// Certificates in the public logs for these zones.
///
/// The certificate plane reads what Cloudflare issued. This reads what any CA
/// issued, which is the only way to see a certificate somebody obtained for
/// this name outside the account.
pub fn public_certs(zones: &[Outside], soon_days: i64) -> Vec<Finding> {
    let mut issuers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // The newest certificate for each name, by expiry. A transparency log holds
    // every certificate ever issued, so most entries for a live name are
    // already superseded; reporting those as expiring produced six findings on
    // a zone that had none.
    let mut newest: BTreeMap<String, (i64, String)> = BTreeMap::new();

    for z in zones {
        for cert in list(scan_results(&z.scan), "ssl") {
            let cn = str_of(cert, "common_name");
            if cn.is_empty() || cn.ends_with(".sni.cloudflaressl.com") {
                continue;
            }
            let issuer = issuer_name(&str_of(cert, "issuer"));
            issuers
                .entry(issuer.clone())
                .or_default()
                .insert(cn.clone());

            if let Some(days) = days_until(&str_of(cert, "not_after")) {
                let e = newest.entry(cn).or_insert((days, issuer.clone()));
                if days > e.0 {
                    *e = (days, issuer);
                }
            }
        }
    }

    let mut expiring: Vec<String> = newest
        .into_iter()
        // Below zero the name has no live certificate at all, which is a fact
        // about a name that is probably gone rather than about a renewal
        // somebody has to do this week.
        .filter(|(_, (days, _))| (0..=soon_days).contains(days))
        .map(|(cn, (days, issuer))| format!("{cn} in {days}d ({issuer})"))
        .collect();
    expiring.sort();

    let mut out = Vec::new();
    if !issuers.is_empty() {
        let names: Vec<String> = issuers
            .iter()
            .map(|(issuer, hosts)| {
                format!(
                    "{issuer}: {}",
                    hosts.iter().cloned().collect::<Vec<_>>().join(", ")
                )
            })
            .collect();
        let n = issuers.len();
        // Deliberately not phrased as "authorities other than Cloudflare":
        // Cloudflare's own universal certificates are issued by Google Trust
        // Services and Let's Encrypt, so an issuer string cannot tell a
        // Cloudflare certificate from one somebody obtained independently. The
        // list is the finding; an authority nobody recognises is the signal.
        out.push(
            Finding::new(
                Severity::Info,
                "public certificates",
                format!(
                    "{n} certificate {} {} for these names",
                    agree(n, "authority", "authorities"),
                    agree(n, "has issued", "have issued")
                ),
            )
            .with(names.join("; ")),
        );
    }
    if !expiring.is_empty() {
        let n = expiring.len();
        out.push(
            Finding::new(
                Severity::Medium,
                "public certificates",
                format!(
                    "{n} {} has no certificate valid beyond {soon_days} days",
                    agree(n, "name", "names"),
                ),
            )
            .with(expiring.join(", ")),
        );
    }
    out
}

/// What the origin addresses actually are.
///
/// Cloudflare will tell you an origin is `203.0.113.10`. It will not tell you
/// that the address is a residential line, a mobile network, a Tor exit or a
/// block with no abuse contact — and each of those changes what an exposed
/// origin costs.
pub fn origins(addrs: &[Address]) -> Vec<Finding> {
    let mut consumer = Vec::new();
    let mut mobile = Vec::new();
    let mut behind_proxy = Vec::new();
    let mut tor = Vec::new();
    let mut torrents = Vec::new();
    let mut no_abuse = Vec::new();
    let mut no_rdns = Vec::new();
    let mut unconfirmed = Vec::new();
    let mut reserved = Vec::new();
    let mut jurisdictions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for a in addrs {
        let s = &a.scan;
        let label = a.label();
        let flag = |k: &str| s.get(k).and_then(Value::as_bool) == Some(true);
        let isp = match str_of(s, "isp") {
            i if i.is_empty() => str_of(s, "org"),
            i => i,
        };

        if flag("reserved") {
            reserved.push(label.clone());
        }
        // Only an address the world can reach is worth characterising, and only
        // an exposed one is a bypass. An origin that is never published outside
        // the proxy is judged by the network plane, not by this one.
        if a.exposed {
            // `hosting` is the load-bearing field: an origin that is not in a
            // datacenter is somebody's connection, and the address is also the
            // household's.
            if !flag("hosting") && !flag("mobile") && !flag("proxy") && !flag("reserved") {
                consumer.push(format!("{label} ({isp})"));
            }
            if flag("mobile") {
                mobile.push(format!("{label} ({isp})"));
            }
            if flag("proxy") {
                behind_proxy.push(format!("{label} ({isp})"));
            }
        }
        if s.get("tor")
            .and_then(|t| t.get("is_tor"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            tor.push(label.clone());
        }

        let ikwyd = s.get("ikwyd").cloned().unwrap_or(json!({}));
        let seen = ikwyd
            .get("observations")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if ikwyd.get("exists").and_then(Value::as_bool) == Some(true) && seen > 0 {
            torrents.push(format!(
                "{label} ({seen} {})",
                agree(seen as usize, "observation", "observations")
            ));
        }

        let rdap = s.get("rdap").cloned().unwrap_or(json!({}));
        if rdap.get("found").and_then(Value::as_bool) == Some(true)
            && str_of(&rdap, "abuse_email").is_empty()
        {
            no_abuse.push(format!("{label} ({})", str_of(&rdap, "cidr")));
        }

        let rdns = s.get("rdns").cloned().unwrap_or(json!({}));
        match (
            rdns.get("found").and_then(Value::as_bool),
            rdns.get("forward_confirmed").and_then(Value::as_bool),
        ) {
            (Some(true), Some(false)) => {
                unconfirmed.push(format!("{label} ({})", str_of(&rdns, "name")));
            }
            (Some(false), _) => no_rdns.push(label.clone()),
            _ => {}
        }

        let country = str_of(s, "country");
        if !country.is_empty() {
            jurisdictions.entry(country).or_default().insert(label);
        }
    }

    let mut out = Vec::new();
    let mut push = |sev, finding: String, names: &[String]| {
        if !names.is_empty() {
            out.push(Finding::new(sev, "origins", finding).with(names.join(", ")));
        }
    };

    push(
        Severity::High,
        format!(
            "{} exposed {} on a consumer connection rather than in a datacenter",
            consumer.len(),
            agree(consumer.len(), "origin sits", "origins sit")
        ),
        &consumer,
    );
    push(
        Severity::High,
        format!(
            "{} exposed {} on a mobile network",
            mobile.len(),
            agree(mobile.len(), "origin is", "origins are")
        ),
        &mobile,
    );
    push(
        Severity::High,
        format!(
            "{} {} a Tor exit node",
            tor.len(),
            agree(tor.len(), "address is", "addresses are")
        ),
        &tor,
    );
    push(
        Severity::Medium,
        format!(
            "{} exposed {} behind a VPN or proxy service",
            behind_proxy.len(),
            agree(behind_proxy.len(), "origin is", "origins are")
        ),
        &behind_proxy,
    );
    push(
        Severity::Medium,
        format!(
            "{} published {} into reserved address space",
            reserved.len(),
            agree(reserved.len(), "record points", "records point")
        ),
        &reserved,
    );
    push(
        Severity::Low,
        format!(
            "{} origin {} peer-to-peer activity attributed to {}",
            torrents.len(),
            agree(torrents.len(), "address has", "addresses have"),
            agree(torrents.len(), "it", "them")
        ),
        &torrents,
    );
    push(
        Severity::Low,
        format!(
            "{} origin {} a reverse name that does not resolve back",
            unconfirmed.len(),
            agree(unconfirmed.len(), "address has", "addresses have")
        ),
        &unconfirmed,
    );
    push(
        Severity::Info,
        format!(
            "{} origin {} no reverse name",
            no_rdns.len(),
            agree(no_rdns.len(), "address has", "addresses have")
        ),
        &no_rdns,
    );
    push(
        Severity::Info,
        format!(
            "{} origin {} in a block with no abuse contact",
            no_abuse.len(),
            agree(no_abuse.len(), "address sits", "addresses sit")
        ),
        &no_abuse,
    );

    // Not a defect, but the one question a data-residency review always asks,
    // and the answer is sitting in data already fetched.
    if jurisdictions.len() > 1 {
        let detail: Vec<String> = jurisdictions
            .iter()
            .map(|(c, a)| format!("{c}: {}", a.iter().cloned().collect::<Vec<_>>().join(", ")))
            .collect();
        out.push(
            Finding::new(
                Severity::Info,
                "origins",
                format!("origins sit in {} countries", jurisdictions.len()),
            )
            .with(detail.join("; ")),
        );
    }
    out
}

/// The `results` object of a domain scan, whether or not the caller unwrapped
/// the scan envelope first.
fn scan_results(scan: &Value) -> &Value {
    scan.get("results").unwrap_or(scan)
}

/// The `dns` object inside those results.
///
/// `subdomains` and `ssl` sit directly under `results`; `resolve` and `txt` sit
/// one level further down, under `results.dns`. Reading them at the wrong depth
/// is silent — every accessor here returns an empty default — and it produced
/// a report claiming that names which plainly resolve resolve to nothing.
fn scan_dns(scan: &Value) -> &Value {
    const EMPTY: &Value = &Value::Null;
    scan_results(scan).get("dns").unwrap_or(EMPTY)
}

/// A hostname in the form both sides can be compared in.
fn normalise(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether `host` is the zone or sits under it.
///
/// Compared on label boundaries: `notmlab.sh` is not in `mlab.sh`, and a check
/// that used `ends_with` alone would report it as one.
fn in_zone(host: &str, zone: &str) -> bool {
    let zone = normalise(zone);
    let host = normalise(host);
    host == zone || host.ends_with(&format!(".{zone}"))
}

/// Whether an address is announced by Cloudflare.
///
/// The published ranges, which change rarely and are checked against
/// `cloudflare.com/ips` rather than guessed. A proxied name answers from these
/// and from nowhere else, so an answer outside them is the origin speaking.
fn is_cloudflare(ip: &str) -> bool {
    const V4: &[(u8, u8, u8, u8, u8)] = &[
        (173, 245, 48, 0, 20),
        (103, 21, 244, 0, 22),
        (103, 22, 200, 0, 22),
        (103, 31, 4, 0, 22),
        (141, 101, 64, 0, 18),
        (108, 162, 192, 0, 18),
        (190, 93, 240, 0, 20),
        (188, 114, 96, 0, 20),
        (197, 234, 240, 0, 22),
        (198, 41, 128, 0, 17),
        (162, 158, 0, 0, 15),
        (104, 16, 0, 0, 13),
        (104, 24, 0, 0, 14),
        (172, 64, 0, 0, 13),
        (131, 0, 72, 0, 22),
    ];
    // 2400:cb00::/32 and the rest all sit under these /32s.
    const V6: &[[u16; 2]] = &[
        [0x2400, 0xcb00],
        [0x2606, 0x4700],
        [0x2803, 0xf800],
        [0x2405, 0xb500],
        [0x2405, 0x8100],
        [0x2a06, 0x98c0],
        [0x2c0f, 0xf248],
    ];

    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let addr = u32::from(v4);
            V4.iter().any(|&(a, b, c, d, bits)| {
                let net = u32::from(std::net::Ipv4Addr::new(a, b, c, d));
                let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
                addr & mask == net & mask
            })
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            V6.iter().any(|p| s[0] == p[0] && s[1] == p[1])
        }
        Err(_) => false,
    }
}

/// The organisation out of an X.509 issuer string, for a readable detail line.
///
/// The value may be quoted precisely because it contains the separator —
/// `O="CLOUDFLARE, INC."` — so a plain split on ", " truncates it to
/// `CLOUDFLARE`, which is what the first live run printed.
fn issuer_name(issuer: &str) -> String {
    let Some(rest) = issuer.find("O=").map(|i| &issuer[i + 2..]) else {
        return issuer.to_string();
    };
    match rest.strip_prefix('"') {
        Some(quoted) => quoted
            .find('"')
            .map(|end| quoted[..end].to_string())
            .unwrap_or_else(|| quoted.to_string()),
        None => rest.split(", ").next().unwrap_or(rest).to_string(),
    }
}

/// The `p=` policy of a DMARC record.
fn policy_of(dmarc: &str) -> Option<String> {
    dmarc
        .split(';')
        .map(str::trim)
        .find_map(|t| t.strip_prefix("p="))
        .map(|p| p.trim().to_ascii_lowercase())
}

// ---- accessors --------------------------------------------------------------

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn list<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn accepted(m: &Value) -> bool {
    str_of(m, "status") == "accepted"
}

/// A member's address, from either of the two places it appears.
fn email(m: &Value) -> String {
    let nested = m
        .get("user")
        .map(|u| str_of(u, "email"))
        .unwrap_or_default();
    if nested.is_empty() {
        str_of(m, "email")
    } else {
        nested
    }
}

fn scim_email(u: &Value) -> String {
    u.get("emails")
        .and_then(Value::as_array)
        .and_then(|es| es.first())
        .map(|e| str_of(e, "value"))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| str_of(u, "userName"))
}

/// Whether any of a member's roles grants edit on `product`.
///
/// Permissions are a union across roles: holding two roles means holding both
/// their edits, and checking only the first would under-report.
fn can_edit(m: &Value, product: &str) -> bool {
    list(m, "roles").iter().any(|r| {
        r.get("permissions")
            .and_then(|p| p.get(product))
            .and_then(|p| p.get("edit"))
            .and_then(Value::as_bool)
            == Some(true)
    })
}

/// The granted permission groups that are not reads.
///
/// Cloudflare names every readable group `… Read`, so anything else is a write
/// whatever the token is called.
fn write_groups(t: &Value) -> Vec<String> {
    let mut out = BTreeSet::new();
    for p in list(t, "policies") {
        if str_of(p, "effect") != "allow" {
            continue;
        }
        for g in list(p, "permission_groups") {
            let name = str_of(g, "name");
            if !name.is_empty() && !name.ends_with(" Read") {
                out.insert(name);
            }
        }
    }
    out.into_iter().collect()
}

/// Whether any policy is scoped to a whole account's children rather than to
/// named objects — the `{"…account.<id>": {"…zone.*": "*"}}` shape.
fn has_blanket_scope(t: &Value) -> bool {
    list(t, "policies").iter().any(|p| {
        p.get("resources")
            .and_then(Value::as_object)
            .map(|m| m.values().any(Value::is_object))
            .unwrap_or(false)
    })
}

fn has_ip_condition(t: &Value) -> bool {
    t.get("condition")
        .and_then(|c| c.get("request.ip"))
        .and_then(Value::as_object)
        .map(|ip| {
            ["in", "not_in"].iter().any(|k| {
                ip.get(*k)
                    .and_then(Value::as_array)
                    .is_some_and(|a| !a.is_empty())
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A member as the API returns one: status, the nested user, legacy roles
    /// carrying a permissions matrix, and the newer policies list.
    fn member(email: &str, two_factor: bool, roles: Value, policies: Value) -> Value {
        json!({
            "id": "m-1",
            "status": "accepted",
            "user": {"email": email, "two_factor_authentication_enabled": two_factor},
            "roles": roles,
            "policies": policies,
        })
    }

    fn role(perms: Value) -> Value {
        json!([{"name": "Some Role", "permissions": perms}])
    }

    fn account(enforce: bool) -> Value {
        json!({"id": "a-1", "settings": {"enforce_twofactor": enforce}})
    }

    fn has(findings: &[Finding], needle: &str) -> bool {
        findings.iter().any(|f| f.finding.contains(needle))
    }

    fn at(findings: &[Finding], needle: &str) -> Severity {
        findings
            .iter()
            .find(|f| f.finding.contains(needle))
            .unwrap_or_else(|| panic!("no finding matching {needle:?}"))
            .severity
    }

    // ---- members ------------------------------------------------------------

    #[test]
    fn an_account_that_does_not_require_a_second_factor_is_a_finding_on_its_own() {
        let f = members(&account(false), &[]);
        assert_eq!(at(&f, "not enforced on the account"), Severity::High);
        assert!(members(&account(true), &[]).is_empty());
    }

    #[test]
    fn members_without_a_second_factor_are_named_not_only_counted() {
        let ms = vec![
            member("a@x.test", false, json!([]), json!([])),
            member("b@x.test", true, json!([]), json!([])),
        ];
        let f = members(&account(true), &ms);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("second factor"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert_eq!(hit.detail, "a@x.test", "the ticket needs the address");
        assert!(
            hit.finding.starts_with("1 of 2 members has"),
            "{}",
            hit.finding
        );
    }

    #[test]
    fn an_invitation_nobody_accepted_is_not_counted_as_a_member_without_2fa() {
        // A pending invite has no user record yet; reporting it under both
        // findings would double-count one person.
        let mut pending = member("new@x.test", false, json!([]), json!([]));
        pending["status"] = json!("pending");
        pending["user"] = json!({"email": "new@x.test"});
        let f = members(&account(true), &[pending]);
        assert!(!has(&f, "second factor"));
        assert_eq!(at(&f, "never accepted"), Severity::Medium);
        assert!(has(&f, "1 invitation was"), "singular: {f:?}");
    }

    #[test]
    fn a_permission_is_the_union_across_a_members_roles() {
        // Holding two roles means holding both their edits; checking only the
        // first role would under-report who can change membership.
        let two_roles = json!([
            {"name": "Reader", "permissions": {"member": {"edit": false, "read": true}}},
            {"name": "Ops", "permissions": {"member": {"edit": true, "read": true}}},
        ]);
        let ms = vec![
            member("a@x.test", true, two_roles, json!([])),
            member(
                "b@x.test",
                true,
                role(json!({"member": {"edit": true}})),
                json!([]),
            ),
        ];
        let f = members(&account(true), &ms);
        assert!(has(&f, "can add and remove members"), "{f:?}");
    }

    #[test]
    fn a_single_administrator_is_not_reported_as_a_concentration_of_privilege() {
        // One person who can do everything is how a small account works; the
        // finding is about several, which is when nobody knows who they are.
        let ms = vec![member(
            "solo@x.test",
            true,
            role(json!({"member": {"edit": true}, "billing": {"edit": true}})),
            json!([]),
        )];
        assert!(!has(&members(&account(true), &ms), "can add and remove"));
    }

    #[test]
    fn holding_both_permission_models_is_reported_as_the_ambiguity_it_is() {
        let ms = vec![member(
            "a@x.test",
            true,
            role(json!({"zone": {"read": true}})),
            json!([{"id": "p1"}]),
        )];
        let f = members(&account(true), &ms);
        assert_eq!(at(&f, "legacy role and an IAM policy"), Severity::Low);
    }

    // ---- tokens -------------------------------------------------------------

    fn token(name: &str, extra: Value) -> Value {
        let mut t = json!({"id": "t-1", "name": name, "status": "active", "policies": []});
        if let (Some(o), Some(e)) = (t.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        t
    }

    #[test]
    fn a_permission_group_that_is_not_a_read_is_a_write() {
        let t = token(
            "ci",
            json!({"policies": [{
                "effect": "allow",
                "permission_groups": [{"name": "Zone Read"}, {"name": "DNS Write"}]
            }]}),
        );
        let f = tokens(&[t], "user-owned");
        assert_eq!(at(&f, "write, not only read"), Severity::High);
        let detail = &f
            .iter()
            .find(|f| f.finding.contains("write, not only read"))
            .unwrap()
            .detail;
        assert!(
            detail.contains("DNS Write"),
            "the group that grants the write is the detail: {detail}"
        );
        assert!(
            !detail.contains("Zone Read"),
            "and only that group: listing the reads too would bury it in {detail}"
        );
    }

    #[test]
    fn a_token_granted_only_reads_is_not_reported_as_a_writer() {
        // The whole point of the audit token. Without this the check could
        // flag everything and still pass its other tests.
        let t = token(
            "audit",
            json!({"policies": [{
                "effect": "allow",
                "permission_groups": [{"name": "Zone Read"}, {"name": "DNS Read"}]
            }]}),
        );
        assert!(!has(&tokens(&[t], "user-owned"), "write, not only read"));
    }

    #[test]
    fn a_deny_policy_does_not_make_a_token_a_writer() {
        let t = token(
            "ci",
            json!({"policies": [{
                "effect": "deny",
                "permission_groups": [{"name": "DNS Write"}]
            }]}),
        );
        assert!(!has(&tokens(&[t], "user-owned"), "write, not only read"));
    }

    #[test]
    fn a_scope_nested_under_an_account_covers_zones_that_do_not_exist_yet() {
        let blanket = token(
            "wide",
            json!({"policies": [{
                "effect": "allow",
                "resources": {"com.cloudflare.api.account.abc": {"com.cloudflare.api.account.zone.*": "*"}},
                "permission_groups": [{"name": "Zone Read"}]
            }]}),
        );
        let named = token(
            "narrow",
            json!({"policies": [{
                "effect": "allow",
                "resources": {"com.cloudflare.api.account.zone.abc": "*"},
                "permission_groups": [{"name": "Zone Read"}]
            }]}),
        );
        assert!(has(
            &tokens(&[blanket], "user-owned"),
            "every zone of an account"
        ));
        assert!(!has(
            &tokens(&[named], "user-owned"),
            "every zone of an account"
        ));
    }

    #[test]
    fn only_live_tokens_are_judged_and_the_dead_ones_are_counted() {
        let mut revoked = token("old", json!({}));
        revoked["status"] = json!("disabled");
        let f = tokens(&[revoked], "user-owned");
        assert!(
            !has(&f, "no expiry"),
            "a disabled token has no expiry to want"
        );
        assert_eq!(at(&f, "expired or disabled"), Severity::Info);
    }

    #[test]
    fn an_expiry_and_a_last_use_are_each_their_own_finding() {
        let bare = token("bare", json!({}));
        let f = tokens(&[bare], "account-owned");
        assert_eq!(at(&f, "no expiry"), Severity::Medium);
        assert_eq!(at(&f, "never been used"), Severity::Medium);
        assert!(
            f.iter().any(|f| f.finding.contains("account-owned")),
            "the store is part of the sentence, since it changes what the finding means"
        );

        let complete = token(
            "complete",
            json!({"expires_on": "2027-01-01T00:00:00Z", "last_used_on": "2026-09-01T00:00:00Z"}),
        );
        let f = tokens(&[complete], "account-owned");
        assert!(!has(&f, "no expiry"));
        assert!(!has(&f, "never been used"));
    }

    #[test]
    fn the_address_condition_is_only_raised_when_no_token_has_one() {
        // One token with a condition proves the account knows the feature
        // exists, which makes "nobody uses it" the wrong sentence.
        let open = token("open", json!({}));
        let fenced = token(
            "fenced",
            json!({"condition": {"request.ip": {"in": ["203.0.113.0/24"]}}}),
        );
        assert!(has(
            &tokens(std::slice::from_ref(&open), "user-owned"),
            "addresses it may be used from"
        ));
        assert!(!has(
            &tokens(&[open, fenced], "user-owned"),
            "addresses it may be used from"
        ));
    }

    // ---- directory ----------------------------------------------------------

    fn scim(email: &str, active: bool) -> Value {
        json!({"id": "s-1", "active": active, "emails": [{"value": email, "primary": true}]})
    }

    #[test]
    fn someone_deactivated_in_the_directory_who_still_has_access_is_the_open_door() {
        let ms = vec![member("gone@x.test", true, json!([]), json!([]))];
        let f = directory(&ms, &[json!({"id": "sso"})], &[scim("gone@x.test", false)]);
        assert_eq!(at(&f, "deactivated in the directory"), Severity::High);
        assert!(has(&f, "1 member is"), "singular: {f:?}");
    }

    #[test]
    fn a_deactivated_directory_user_who_is_not_a_member_is_not_a_finding() {
        // That is offboarding having worked.
        let ms = vec![member("here@x.test", true, json!([]), json!([]))];
        let f = directory(
            &ms,
            &[json!({"id": "sso"})],
            &[scim("gone@x.test", false), scim("here@x.test", true)],
        );
        assert!(!has(&f, "deactivated in the directory"));
    }

    #[test]
    fn members_the_directory_does_not_know_about_are_reported_as_unmanaged() {
        let ms = vec![
            member("known@x.test", true, json!([]), json!([])),
            member("local@x.test", true, json!([]), json!([])),
        ];
        let f = directory(&ms, &[json!({"id": "sso"})], &[scim("KNOWN@x.test", true)]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("not managed"))
            .unwrap();
        assert_eq!(hit.detail, "local@x.test", "matching is case-insensitive");
    }

    #[test]
    fn sso_without_scim_is_the_finding_and_scim_without_members_is_not() {
        let ms = vec![member("a@x.test", true, json!([]), json!([]))];
        let f = directory(&ms, &[json!({"id": "sso"})], &[]);
        assert_eq!(at(&f, "SCIM provisioning is not"), Severity::Medium);

        // No SSO on a two-person account is a fact, not a finding.
        assert!(!has(&directory(&ms, &[], &[]), "without SSO"));
    }

    // ---- activity -----------------------------------------------------------

    fn entry(kind: &str, action: &str, ok: bool, ip: &str) -> Value {
        json!({
            "action": {"type": action, "result": ok},
            "actor": {"type": kind, "email": "a@x.test", "ip": ip},
            "when": "2026-09-01T00:00:00Z",
        })
    }

    #[test]
    fn failures_are_raised_and_a_quiet_window_reports_nothing() {
        let es = vec![
            entry("user", "zone_setting_update", false, "203.0.113.1"),
            entry("user", "zone_setting_update", true, "203.0.113.1"),
        ];
        let f = activity(&es, "30 days");
        assert_eq!(at(&f, "action failed"), Severity::Medium);
        assert!(activity(&[], "30 days").is_empty());
    }

    #[test]
    fn changes_made_by_something_other_than_a_person_are_counted() {
        let es = vec![
            entry("account_token", "dns_record_create", true, "203.0.113.1"),
            entry("system", "delete", true, ""),
            entry("user", "login", true, "203.0.113.1"),
        ];
        let f = activity(&es, "30 days");
        assert!(has(&f, "2 of 3 changes"), "{f:?}");
        assert_eq!(at(&f, "deletion or revocation"), Severity::Info);
    }

    #[test]
    fn distinct_source_addresses_are_only_worth_saying_when_there_are_several() {
        let one = vec![entry("user", "login", true, "203.0.113.1")];
        assert!(!has(&activity(&one, "30 days"), "distinct addresses"));
        let two = vec![
            entry("user", "login", true, "203.0.113.1"),
            entry("user", "login", true, "198.51.100.7"),
        ];
        assert!(has(&activity(&two, "30 days"), "2 distinct addresses"));
    }

    // ---- dns ----------------------------------------------------------------

    fn rec(name: &str, kind: &str, content: &str, proxied: Option<bool>) -> Value {
        json!({
            "name": name, "type": kind, "content": content,
            "proxied": proxied, "proxiable": proxied.is_some(), "ttl": 1,
        })
    }

    fn zone(name: &str, records: Vec<Value>) -> Zone {
        Zone {
            name: name.to_string(),
            id: "z-1".into(),
            records,
            dnssec: None,
            hold: None,
        }
    }

    #[test]
    fn an_unproxied_record_sharing_an_address_with_a_proxied_one_is_the_sharp_finding() {
        // The proxy hides the origin from a resolver, not from a second record
        // that names the same address.
        let z = zone(
            "example.com",
            vec![
                rec("www.example.com", "A", "198.18.0.9", Some(true)),
                rec("direct.example.com", "A", "198.18.0.9", Some(false)),
                rec("other.example.com", "A", "198.18.0.10", Some(false)),
            ],
        );
        let f = exposure(&[z]);
        let leak = f
            .iter()
            .find(|f| f.finding.contains("also sits behind"))
            .unwrap();
        assert_eq!(leak.severity, Severity::High);
        assert_eq!(leak.detail, "direct.example.com → 198.18.0.9");

        let plain = f
            .iter()
            .find(|f| f.finding.contains("publishing an address"))
            .unwrap();
        assert_eq!(plain.severity, Severity::Medium);
        assert_eq!(plain.detail, "other.example.com → 198.18.0.10");
    }

    #[test]
    fn the_conventional_filler_for_a_proxy_only_name_is_not_an_exposed_origin() {
        // 100:: and the documentation ranges are what people put on a record
        // that should only ever be reached through the proxy. Reporting them
        // would bury the records that really do publish an address.
        let z = zone(
            "example.com",
            vec![
                rec("a.example.com", "AAAA", "100::", Some(true)),
                rec("b.example.com", "A", "192.0.2.1", Some(false)),
            ],
        );
        assert!(exposure(&[z])
            .iter()
            .all(|f| !f.finding.contains("publish")));
    }

    #[test]
    fn private_space_in_public_dns_is_reported_wherever_it_sits() {
        // Proxied or not: the address is published either way.
        let z = zone(
            "example.com",
            vec![
                rec("nas.example.com", "A", "10.0.0.5", Some(false)),
                rec("vpn.example.com", "A", "192.168.1.1", Some(true)),
            ],
        );
        let f = exposure(&[z]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("private or reserved"))
            .unwrap();
        assert!(hit.detail.contains("10.0.0.5") && hit.detail.contains("192.168.1.1"));
    }

    #[test]
    fn a_record_cloudflare_could_not_proxy_is_not_a_choice_anybody_made() {
        let mut r = rec("mail.example.com", "A", "198.18.0.9", Some(false));
        r["proxiable"] = json!(false);
        assert!(exposure(&[zone("example.com", vec![r])]).is_empty());
    }

    #[test]
    fn a_takeover_candidate_is_graded_by_how_claimable_the_platform_is() {
        let z = zone(
            "example.com",
            vec![
                rec(
                    "blog.example.com",
                    "CNAME",
                    "old.herokuapp.com",
                    Some(false),
                ),
                rec("shop.example.com", "CNAME", "x.myshopify.com", Some(false)),
                rec("cdn.example.com", "CNAME", "pub-1.r2.dev", Some(false)),
                rec(
                    "app.example.com",
                    "CNAME",
                    "origin.example.net",
                    Some(false),
                ),
            ],
        );
        let f = takeover(&[z]);
        assert_eq!(at(&f, "first-come"), Severity::High);
        assert_eq!(at(&f, "verifies domain ownership"), Severity::Medium);
        assert_eq!(at(&f, "own Cloudflare resources"), Severity::Info);
        assert!(
            f.iter().all(|f| !f.detail.contains("origin.example.net")),
            "a target on nobody's platform is not a candidate"
        );
    }

    #[test]
    fn the_caveat_is_only_added_where_resolution_is_the_open_question() {
        // Nobody else can claim this account's own resources, so there is
        // nothing outside to go and check.
        let own = zone(
            "example.com",
            vec![rec("cdn.example.com", "CNAME", "pub-1.r2.dev", Some(false))],
        );
        assert!(!has(
            &takeover(&[own]),
            "resolution against the outside world"
        ));

        let external = zone(
            "example.com",
            vec![rec("blog.example.com", "CNAME", "x.github.io", Some(false))],
        );
        assert!(has(
            &takeover(&[external]),
            "resolution against the outside world"
        ));
    }

    #[test]
    fn dnssec_signed_without_a_ds_record_is_worse_than_dnssec_off() {
        // `pending` reads as enabled in the dashboard and validates nothing.
        let mut pending = zone("a.test", vec![]);
        pending.dnssec = Some(json!({"status": "pending"}));
        let mut off = zone("b.test", vec![]);
        off.dnssec = Some(json!({"status": "disabled"}));

        let f = namespace(&[pending, off]);
        assert_eq!(at(&f, "signed but incomplete"), Severity::Medium);
        assert_eq!(at(&f, "DNSSEC is off"), Severity::Low);
    }

    #[test]
    fn a_zone_whose_signing_state_could_not_be_read_is_not_reported_either_way() {
        // `None` means the read was refused, which is not evidence of anything.
        assert!(namespace(&[zone("a.test", vec![])]).is_empty());
    }

    #[test]
    fn no_spf_is_one_fault_with_two_different_remedies() {
        let sends = zone(
            "sends.test",
            vec![rec("sends.test", "MX", "10 mx.example.net", None)],
        );
        let idle = zone("idle.test", vec![]);
        let f = mail(&[sends, idle]);

        let a = f
            .iter()
            .find(|f| f.finding.contains("receives mail"))
            .unwrap();
        assert_eq!(a.detail, "sends.test");
        let b = f.iter().find(|f| f.finding.contains("parked")).unwrap();
        assert_eq!(b.detail, "idle.test");
        assert!(
            b.finding.contains("null MX"),
            "the remedy differs, so it is stated"
        );
    }

    #[test]
    fn an_spf_record_that_authorises_everyone_outranks_having_none() {
        let z = zone(
            "example.com",
            vec![rec(
                "example.com",
                "TXT",
                "\"v=spf1 include:_spf.example.net +all\"",
                None,
            )],
        );
        assert_eq!(at(&mail(&[z]), "+all or ?all"), Severity::High);
    }

    #[test]
    fn two_spf_records_are_no_spf_at_all() {
        let z = zone(
            "example.com",
            vec![
                rec("example.com", "TXT", "\"v=spf1 include:a -all\"", None),
                rec("example.com", "TXT", "\"v=spf1 include:b -all\"", None),
            ],
        );
        assert_eq!(at(&mail(&[z]), "more than one SPF"), Severity::Medium);
    }

    #[test]
    fn a_long_txt_record_split_across_quoted_strings_is_read_as_one_value() {
        // A resolver concatenates them; matching each fragment separately would
        // miss the mechanism at the end.
        let z = zone(
            "example.com",
            vec![rec(
                "example.com",
                "TXT",
                "\"v=spf1 include:_spf.example.net \" \"?all\"",
                None,
            )],
        );
        assert!(has(&mail(&[z]), "+all or ?all"));
    }

    #[test]
    fn dmarc_is_read_from_its_own_name_and_graded_by_policy() {
        let reject = zone(
            "a.test",
            vec![
                rec("a.test", "TXT", "\"v=spf1 -all\"", None),
                rec("_dmarc.a.test", "TXT", "\"v=DMARC1; p=reject\"", None),
            ],
        );
        assert!(!has(&mail(&[reject]), "DMARC"));

        let watching = zone(
            "b.test",
            vec![
                rec("b.test", "TXT", "\"v=spf1 -all\"", None),
                rec("_dmarc.b.test", "TXT", "\"v=DMARC1; p=none\"", None),
            ],
        );
        assert_eq!(at(&mail(&[watching]), "p=none"), Severity::Low);
    }

    #[test]
    fn a_domain_expiring_soon_outranks_one_that_is_merely_unlocked() {
        let soon = crate::cf::iso8601(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 10 * 86_400,
        );
        let ds = vec![json!({
            "name": "example.com", "expires_at": soon,
            "auto_renew": false, "locked": false
        })];
        let f = registrar(&ds, 60);
        assert_eq!(at(&f, "expires within"), Severity::High);
        assert_eq!(at(&f, "auto-renew off"), Severity::High);
        assert_eq!(at(&f, "not transfer-locked"), Severity::Medium);
        assert!(
            f.iter().any(|f| f.detail.contains("example.com in 10d")),
            "the number of days is what makes it actionable: {f:?}"
        );
    }

    #[test]
    fn a_domain_with_a_distant_expiry_is_left_alone() {
        let far = crate::cf::iso8601(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 300 * 86_400,
        );
        let ds = vec![json!({
            "name": "example.com", "expires_at": far,
            "auto_renew": true, "locked": true
        })];
        assert!(registrar(&ds, 60).is_empty());
    }

    #[test]
    fn an_unreadable_expiry_is_skipped_rather_than_treated_as_imminent() {
        let ds = vec![
            json!({"name": "example.com", "expires_at": "", "auto_renew": true, "locked": true}),
        ];
        assert!(registrar(&ds, 60).is_empty());
        assert_eq!(days_until("not-a-date"), None);
    }

    // ---- zone posture -------------------------------------------------------

    fn posture(name: &str, plan: &str, settings: Vec<(&str, Value)>) -> Posture {
        Posture {
            name: name.to_string(),
            plan: plan.to_string(),
            settings: settings
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            phases: BTreeMap::new(),
            readable_phases: BTreeSet::new(),
            pagerules: vec![],
            spectrum: vec![],
            routes: vec![],
            snippets: vec![],
            page_shield: None,
        }
    }

    #[test]
    fn the_ssl_mode_is_graded_by_which_leg_it_leaves_open() {
        let flexible = posture("a.test", "Pro", vec![("ssl", json!("flexible"))]);
        let full = posture("b.test", "Pro", vec![("ssl", json!("full"))]);
        let strict = posture("c.test", "Pro", vec![("ssl", json!("strict"))]);

        assert_eq!(
            at(&transport(&[flexible]), "cleartext to the origin"),
            Severity::High
        );
        assert_eq!(
            at(&transport(&[full]), "without validating its certificate"),
            Severity::Medium
        );
        assert!(
            transport(&[strict]).is_empty(),
            "strict is the one nobody has to fix"
        );
    }

    #[test]
    fn hsts_is_read_for_its_shape_not_only_its_switch() {
        let off = posture(
            "a.test",
            "Pro",
            vec![(
                "security_header",
                json!({"strict_transport_security": {"enabled": false}}),
            )],
        );
        assert_eq!(at(&transport(&[off]), "HSTS off"), Severity::Medium);

        // On, but for a month and only on the apex.
        let weak = posture(
            "b.test",
            "Pro",
            vec![(
                "security_header",
                json!({"strict_transport_security": {
                    "enabled": true, "max_age": 2_592_000, "include_subdomains": false
                }}),
            )],
        );
        let f = transport(&[weak]);
        assert!(!has(&f, "HSTS off"), "it is on: {f:?}");
        assert_eq!(at(&f, "max-age under six months"), Severity::Low);
        assert_eq!(at(&f, "apex only"), Severity::Low);

        let good = posture(
            "c.test",
            "Pro",
            vec![(
                "security_header",
                json!({"strict_transport_security": {
                    "enabled": true, "max_age": 31_536_000, "include_subdomains": true
                }}),
            )],
        );
        assert!(transport(&[good]).is_empty());
    }

    #[test]
    fn a_setting_that_was_not_returned_is_not_reported_as_off() {
        // The settings blob differs by plan; an absent key is unknown.
        assert!(transport(&[posture("a.test", "Pro", vec![])]).is_empty());
    }

    /// A rule as the ruleset entry point returns one.
    fn rule(action: &str, description: &str, params: Value) -> Value {
        json!({
            "action": action, "description": description, "enabled": true,
            "expression": "true", "id": "r-1", "action_parameters": params,
        })
    }

    fn with_phase(mut p: Posture, phase: &str, rules: Vec<Value>) -> Posture {
        p.readable_phases.insert(phase.to_string());
        p.phases.insert(phase.to_string(), rules);
        p
    }

    #[test]
    fn a_skip_rule_names_exactly_what_it_turns_off() {
        let z = with_phase(
            posture("a.test", "Pro", vec![]),
            "http_request_firewall_custom",
            vec![rule(
                "skip",
                "webhook bypass",
                json!({
                    "phases": ["http_ratelimit", "http_request_firewall_managed"],
                    "products": ["waf"],
                    "ruleset": "current"
                }),
            )],
        );
        let f = enforcement(&[z]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("carve a path"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(hit
            .detail
            .contains("phases http_ratelimit+http_request_firewall_managed"));
        assert!(hit.detail.contains("products waf"));
        assert!(hit.detail.contains("the rest of this ruleset"));
    }

    #[test]
    fn owasp_paranoia_levels_are_tuning_rather_than_a_bypass() {
        // Choosing not to run levels 2 to 4 is how that ruleset is meant to be
        // used; reporting it would bury the overrides that switch protection off.
        let tuned = with_phase(
            posture("a.test", "Pro", vec![]),
            "http_request_firewall_managed",
            vec![rule(
                "execute",
                "OWASP",
                json!({"id": "owasp", "overrides": {"categories": [
                    {"category": "paranoia-level-3", "enabled": false},
                    {"category": "paranoia-level-4", "enabled": false}
                ]}}),
            )],
        );
        assert!(!has(&enforcement(&[tuned]), "weakened by an override"));

        let gutted = with_phase(
            posture("b.test", "Pro", vec![]),
            "http_request_firewall_managed",
            vec![rule(
                "execute",
                "Managed",
                json!({"id": "managed", "overrides": {"categories": [
                    {"category": "sql-injection", "enabled": false}
                ]}}),
            )],
        );
        let f = enforcement(&[gutted]);
        assert_eq!(at(&f, "weakened by an override"), Severity::Medium);
        assert!(f.iter().any(|f| f.detail.contains("sql-injection")));
    }

    #[test]
    fn a_ruleset_set_to_log_is_a_monitoring_tool_not_a_firewall() {
        let z = with_phase(
            posture("a.test", "Pro", vec![]),
            "http_request_firewall_managed",
            vec![rule(
                "execute",
                "Managed",
                json!({"id": "managed", "overrides": {"action": "log"}}),
            )],
        );
        assert!(has(&enforcement(&[z]), "weakened by an override"));
    }

    #[test]
    fn a_plan_gap_is_not_reported_as_a_gap_in_configuration() {
        // A free zone answers 404 on these phases: the managed ruleset runs
        // automatically and rate limiting rules cannot be created. Reporting
        // those as unconfigured turns a price list into findings.
        let free = posture("free.test", "Free Website", vec![]);
        let f = enforcement(&[free]);
        assert!(!has(&f, "no managed ruleset"));
        assert!(!has(&f, "no rate limit rule"));
        assert_eq!(
            at(&f, "on a free plan"),
            Severity::Info,
            "and the reader is told why it is absent rather than left to assume it passed"
        );

        // The same emptiness on a paid zone is a real finding.
        let paid = posture("paid.test", "Pro Website", vec![]);
        let f = enforcement(&[paid]);
        assert_eq!(at(&f, "no managed ruleset"), Severity::Medium);
        assert_eq!(at(&f, "no rate limit rule"), Severity::Medium);
    }

    #[test]
    fn page_shield_is_only_expected_where_the_plan_includes_it() {
        let mut free = posture("free.test", "Free Website", vec![]);
        free.page_shield = Some(json!({"enabled": false}));
        assert!(!has(&enforcement(&[free]), "Page Shield"));

        let mut paid = posture("paid.test", "Pro Website", vec![]);
        paid.page_shield = Some(json!({"enabled": false}));
        assert!(has(&enforcement(&[paid]), "Page Shield"));
    }

    #[test]
    fn development_mode_outranks_everything_else_in_the_phase() {
        let z = posture("a.test", "Pro", vec![("development_mode", json!("on"))]);
        assert_eq!(at(&enforcement(&[z]), "development mode"), Severity::High);
    }

    #[test]
    fn a_spectrum_application_is_graded_by_the_port_it_publishes() {
        let mut ssh = posture("a.test", "Ent", vec![]);
        ssh.spectrum = vec![json!({"protocol": "tcp/22", "dns": {"name": "ssh.a.test"}})];
        let f = edge(&[ssh]);
        assert_eq!(
            at(&f, "remote administration or database port"),
            Severity::High
        );
        assert!(f.iter().any(|f| f.detail.contains("ssh.a.test")));

        let mut game = posture("b.test", "Ent", vec![]);
        game.spectrum = vec![json!({"protocol": "tcp/8443", "dns": {"name": "app.b.test"}})];
        assert_eq!(at(&edge(&[game]), "raw TCP or UDP"), Severity::Medium);
    }

    #[test]
    fn a_route_with_no_script_is_named_as_such() {
        let mut z = posture("a.test", "Pro", vec![]);
        z.routes = vec![
            json!({"pattern": "a.test/api/*", "script": "api-worker"}),
            json!({"pattern": "a.test/old/*"}),
        ];
        let f = edge(&[z]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("worker route"))
            .unwrap();
        assert!(hit.detail.contains("a.test/api/* → api-worker"));
        assert!(hit.detail.contains("a.test/old/* (no script)"));
    }

    #[test]
    fn a_port_is_read_from_the_protocol_string_however_it_is_written() {
        assert_eq!(port_of("tcp/22"), Some(22));
        assert_eq!(port_of("udp/53"), Some(53));
        assert_eq!(
            port_of("tcp/8000-9000"),
            Some(8000),
            "a range is judged by its start"
        );
        assert_eq!(port_of("nonsense"), None);
    }

    // ---- certificates and origin trust --------------------------------------

    fn tls(name: &str, aop: Option<bool>) -> Tls {
        Tls {
            name: name.to_string(),
            ssl_mode: "strict".into(),
            aop,
            aop_hostnames: vec![],
            universal: None,
            packs: vec![],
            custom_certs: vec![],
            custom_hostnames: vec![],
            client_certs: vec![],
            ct_alerting: None,
            exposed_origins: vec![],
        }
    }

    /// Days from now as the API would print the instant.
    fn in_days(d: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        crate::cf::iso8601(now + d * 86_400)
    }

    #[test]
    fn a_published_origin_becomes_an_exposure_only_when_the_origin_does_not_check() {
        // The whole argument of the plane, in one test.
        let mut exposed = tls("open.test", Some(false));
        exposed.exposed_origins = vec!["direct.open.test → 198.18.0.9".into()];
        let f = origin_trust(&[exposed]);
        assert_eq!(
            at(&f, "way in rather than an information disclosure"),
            Severity::High
        );

        // Same records, origin pulls on: the address is disclosed and not usable.
        let mut guarded = tls("closed.test", Some(true));
        guarded.exposed_origins = vec!["direct.closed.test → 198.18.0.9".into()];
        assert!(origin_trust(&[guarded]).is_empty());

        // Origin pulls off and nothing published: worth saying, one grade down.
        assert_eq!(
            at(
                &origin_trust(&[tls("quiet.test", Some(false))]),
                "distinguishes Cloudflare"
            ),
            Severity::Medium
        );
    }

    #[test]
    fn a_setting_that_could_not_be_read_is_not_reported_as_off() {
        // `None` is a refused read, which is not evidence that the control is
        // missing — and this is the plane's headline finding, so guessing here
        // would be the worst place to guess.
        assert!(origin_trust(&[tls("unknown.test", None)]).is_empty());
    }

    #[test]
    fn origin_pulls_on_with_hostnames_excluded_is_its_own_finding() {
        // The zone reads as covered, and the gap is what matters.
        let mut z = tls("a.test", Some(true));
        z.aop_hostnames = vec![
            json!({"hostname": "api.a.test", "enabled": false}),
            json!({"hostname": "www.a.test", "enabled": true}),
        ];
        let f = origin_trust(&[z]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("hostnames excluded"))
            .unwrap();
        assert!(hit.detail.contains("api.a.test"));
        assert!(!hit.detail.contains("www.a.test"));
    }

    #[test]
    fn a_certificate_inside_two_weeks_outranks_one_inside_a_month() {
        // Inside two weeks there is no time for a renewal that needs a DNS
        // change or a purchase.
        let mut z = tls("a.test", Some(true));
        z.packs = vec![json!({
            "status": "active",
            "hosts": ["a.test"],
            "certificates": [
                {"id": "c1", "hosts": ["a.test"], "expires_on": in_days(9)},
                {"id": "c2", "hosts": ["www.a.test"], "expires_on": in_days(25)},
                {"id": "c3", "hosts": ["far.a.test"], "expires_on": in_days(200)},
            ]
        })];
        let f = certificates(&[z], 30);
        assert_eq!(at(&f, "within two weeks"), Severity::High);
        assert_eq!(at(&f, "within 30 days"), Severity::Medium);
        assert!(
            f.iter().all(|f| !f.detail.contains("far.a.test")),
            "a distant expiry is not a finding"
        );
    }

    #[test]
    fn a_pack_that_never_reached_active_is_reported_with_its_state() {
        let mut z = tls("a.test", Some(true));
        z.packs = vec![json!({
            "id": "p1", "status": "pending_validation", "hosts": ["a.test", "www.a.test"],
            "certificates": []
        })];
        let f = certificates(&[z], 30);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("never reached active"))
            .unwrap();
        assert!(hit.detail.contains("pending_validation"), "{}", hit.detail);
        assert!(hit.detail.contains("a.test"));
    }

    #[test]
    fn a_client_certificate_with_no_end_date_is_an_unrotatable_credential() {
        let mut z = tls("a.test", Some(true));
        z.client_certs = vec![json!({"common_name": "partner", "expires_on": ""})];
        assert_eq!(
            at(&certificates(&[z], 30), "unrotatable credential"),
            Severity::Medium
        );
    }

    #[test]
    fn the_gateway_ca_gets_a_year_of_warning_rather_than_a_month() {
        // It is trusted by every managed device, so replacing it is a fleet
        // rollout rather than a certificate renewal.
        let ca = vec![json!({
            "name": "Gateway CA", "type": "gateway_managed", "expires_on": in_days(200)
        })];
        assert_eq!(
            at(&account_certificates(&ca, 30), "fleet-wide outage"),
            Severity::High
        );

        // An ordinary account certificate at the same distance is not due yet.
        let other =
            vec![json!({"name": "partner mTLS", "type": "custom", "expires_on": in_days(200)})];
        assert!(account_certificates(&other, 30).is_empty());
    }

    #[test]
    fn a_customer_hostname_that_never_verified_is_the_dangling_shape() {
        let mut z = tls("saas.test", Some(true));
        z.custom_hostnames = vec![
            json!({"hostname": "gone.customer.test", "status": "pending",
                   "ssl": {"status": "pending_validation"}}),
            json!({"hostname": "live.customer.test", "status": "active",
                   "ssl": {"status": "active"}}),
        ];
        let f = hostnames(&[z]);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("never finished verification"))
            .unwrap();
        assert!(hit.detail.contains("gone.customer.test"));
        assert!(!hit.detail.contains("live.customer.test"));
    }

    #[test]
    fn certificate_transparency_is_only_reported_where_the_answer_was_read() {
        let mut off = tls("a.test", Some(true));
        off.ct_alerting = Some(json!({"enabled": false}));
        assert_eq!(
            at(&certificates(&[off], 30), "certificate transparency"),
            Severity::Low
        );

        let mut on = tls("b.test", Some(true));
        on.ct_alerting = Some(json!({"enabled": true, "emails": ["a@b.test"]}));
        assert!(!has(&certificates(&[on], 30), "certificate transparency"));

        // Unreadable: no claim either way.
        assert!(!has(
            &certificates(&[tls("c.test", Some(true))], 30),
            "certificate transparency"
        ));
    }

    #[test]
    fn covered_hostnames_are_summarized_rather_than_listed_in_full() {
        // A pack can cover dozens; the finding has to stay one line.
        assert_eq!(hosts_of(&json!({"hosts": ["a.test"]})).unwrap(), "a.test");
        assert_eq!(
            hosts_of(&json!({"hosts": ["a.test", "b.test", "c.test", "d.test"]})).unwrap(),
            "a.test, b.test, +2 more"
        );
        assert!(hosts_of(&json!({"hosts": []})).is_none());
    }

    #[test]
    fn the_two_planes_agree_on_which_records_publish_an_origin() {
        // `exposure` and the certificate plane ask the same question, so they
        // share the answer rather than each computing one.
        let records = vec![
            rec("www.a.test", "A", "198.18.0.9", Some(true)),
            rec("direct.a.test", "A", "198.18.0.9", Some(false)),
            rec("other.a.test", "A", "198.18.0.10", Some(false)),
        ];
        assert_eq!(
            published_origins(&records),
            vec!["direct.a.test → 198.18.0.9"]
        );
    }

    // ---- the developer platform ----------------------------------------------

    fn script(name: &str, on_subdomain: bool, bindings: Value) -> Script {
        Script {
            name: name.to_string(),
            on_subdomain,
            previews: false,
            bindings: bindings.as_array().cloned().unwrap_or_default(),
            observability: true,
            logpush: false,
        }
    }

    fn platform(scripts: Vec<Script>, routed: &[&str]) -> Platform {
        Platform {
            subdomain: "acme".into(),
            scripts,
            routed: routed.iter().map(|s| s.to_string()).collect(),
            pages: vec![],
            buckets: vec![],
            kv: vec![],
            d1: vec![],
            queues: vec![],
            hyperdrive: vec![],
            secret_stores: vec![],
            widgets: vec![],
            gateways: vec![],
        }
    }

    #[test]
    fn a_worker_on_a_route_and_on_workers_dev_is_the_bypass() {
        // Two doors to the same code: one behind the zone's rules, one not.
        let p = platform(
            vec![script(
                "api",
                true,
                json!([{"name": "DB", "type": "d1", "id": "d-1"}]),
            )],
            &["api"],
        );
        let f = workers(&p);
        let hit = f.iter().find(|f| f.finding.contains("zone route")).unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(
            hit.detail.contains("api.acme.workers.dev"),
            "{}",
            hit.detail
        );
        assert!(
            hit.detail.contains("DB (d1)"),
            "the bindings are the point: the unprotected door reaches the same data"
        );
    }

    #[test]
    fn a_worker_only_on_workers_dev_is_a_design_rather_than_a_bypass() {
        // Nothing was routed away from; workers.dev is simply where it lives.
        let p = platform(vec![script("tool", true, json!([]))], &[]);
        let f = workers(&p);
        assert!(!has(&f, "zone route"));
        assert_eq!(at(&f, "only on workers.dev"), Severity::Medium);
    }

    #[test]
    fn a_worker_that_is_not_published_is_not_reported_at_all() {
        let p = platform(vec![script("private", false, json!([]))], &["private"]);
        let f = workers(&p);
        assert!(!has(&f, "workers.dev"));
    }

    #[test]
    fn a_bucket_reached_over_http_is_not_an_orphan() {
        // No binding names it because nothing binds it: it is served on a
        // domain. Calling that neglect would be wrong.
        let mut p = platform(vec![], &[]);
        p.buckets = vec![
            Bucket {
                name: "served".into(),
                public_domain: None,
                custom_domains: vec!["cdn.example.com".into()],
            },
            Bucket {
                name: "forgotten".into(),
                public_domain: None,
                custom_domains: vec![],
            },
        ];
        let f = storage(&p);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("bound to no Worker"))
            .unwrap();
        assert!(hit.detail.contains("forgotten"));
        assert!(!hit.detail.contains("served"));
    }

    #[test]
    fn a_public_bucket_outranks_everything_else_in_the_plane() {
        let mut p = platform(vec![], &[]);
        p.buckets = vec![Bucket {
            name: "open".into(),
            public_domain: Some("pub-abc.r2.dev".into()),
            custom_domains: vec![],
        }];
        let f = storage(&p);
        assert_eq!(at(&f, "served anonymously on r2.dev"), Severity::High);
        assert!(f.iter().any(|f| f.detail.contains("pub-abc.r2.dev")));
    }

    #[test]
    fn a_queue_answers_for_itself_rather_than_through_a_binding() {
        // Producers and consumers are on the queue, and a dead-letter queue is
        // named by the consumer that spills into it — no binding mentions it.
        let mut p = platform(vec![], &[]);
        p.queues = vec![
            json!({
                "queue_name": "work",
                "producers": [{"script": "a"}],
                "consumers": [{"script": "b", "dead_letter_queue": "work-dlq"}]
            }),
            json!({"queue_name": "work-dlq", "producers": [], "consumers": []}),
            json!({"queue_name": "abandoned", "producers": [], "consumers": []}),
        ];
        let f = storage(&p);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("bound to no Worker"))
            .unwrap();
        assert!(hit.detail.contains("queue abandoned"));
        assert!(
            !hit.detail.contains("work-dlq"),
            "a dead-letter queue is in use"
        );
        assert!(!hit.detail.contains("queue work"), "{}", hit.detail);
    }

    #[test]
    fn a_store_a_worker_binds_is_not_an_orphan() {
        let p = Platform {
            kv: vec![json!({"id": "kv-1", "title": "cache"})],
            d1: vec![json!({"uuid": "db-1", "name": "main"})],
            ..platform(
                vec![script(
                    "api",
                    false,
                    json!([
                        {"name": "CACHE", "type": "kv_namespace", "namespace_id": "kv-1"},
                        {"name": "DB", "type": "d1", "id": "db-1"}
                    ]),
                )],
                &[],
            )
        };
        assert!(!has(&storage(&p), "bound to no Worker"));
    }

    #[test]
    fn a_preview_sharing_production_bindings_is_the_pages_finding() {
        // Every branch publishes a reachable URL; the bindings decide what that
        // URL can reach.
        let shared = json!([{
            "name": "app",
            "subdomain": "app.pages.dev",
            "deployment_configs": {
                "production": {"d1_databases": {"DB": {"id": "prod-db"}}},
                "preview": {"d1_databases": {"DB": {"id": "prod-db"}}}
            }
        }]);
        let f = pages(shared.as_array().unwrap());
        assert_eq!(at(&f, "same bindings in preview"), Severity::High);

        let separate = json!([{
            "name": "app",
            "subdomain": "app.pages.dev",
            "deployment_configs": {
                "production": {"d1_databases": {"DB": {"id": "prod-db"}}},
                "preview": {"d1_databases": {"DB": {"id": "staging-db"}}}
            }
        }]);
        assert!(!has(
            &pages(separate.as_array().unwrap()),
            "same bindings in preview"
        ));
    }

    #[test]
    fn an_ai_gateway_without_authentication_is_an_open_proxy() {
        let mut p = platform(vec![], &[]);
        p.gateways = vec![
            json!({"id": "open", "authentication": false, "collect_logs": true}),
            json!({"id": "closed", "authentication": true, "collect_logs": false}),
        ];
        let f = services(&p);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("without authentication"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert_eq!(hit.detail, "open");
        assert_eq!(at(&f, "retains prompts"), Severity::Medium);
    }

    #[test]
    fn a_turnstile_widget_bound_to_a_wildcard_can_be_embedded_anywhere_under_it() {
        let mut p = platform(vec![], &[]);
        p.widgets = vec![
            json!({"name": "wide", "domains": ["*.example.com"]}),
            json!({"name": "narrow", "domains": ["app.example.com"]}),
        ];
        let f = services(&p);
        let hit = f.iter().find(|f| f.finding.contains("wildcard")).unwrap();
        assert!(hit.detail.contains("wide"));
        assert!(!hit.detail.contains("narrow"));
    }

    // ---- zero trust ----------------------------------------------------------

    fn zt() -> ZeroTrust {
        ZeroTrust {
            apps: vec![],
            service_tokens: vec![],
            idps: vec![],
            gateway_rules: vec![],
            gateway_config: None,
            gateway_logging: None,
            device_policies: vec![],
            split_exclude: vec![],
            split_include: vec![],
            posture_rules: vec![],
            tunnels: vec![],
            routes: vec![],
            targets: vec![],
        }
    }

    fn app(name: &str, policies: Value) -> Value {
        json!({
            "name": name, "domain": format!("{name}.example.com"),
            "type": "self_hosted", "session_duration": "1h",
            "allowed_idps": [], "policies": policies,
        })
    }

    #[test]
    fn a_policy_that_admits_everyone_is_the_application_being_public() {
        let mut z = zt();
        z.apps = vec![app(
            "wiki",
            json!([{"name": "open", "decision": "allow", "include": [{"everyone": {}}]}]),
        )];
        let f = access(&z);
        assert_eq!(at(&f, "lets everyone in"), Severity::High);
    }

    #[test]
    fn a_bypass_decision_turns_access_off_while_the_app_still_reads_as_protected() {
        let mut z = zt();
        z.apps = vec![app(
            "api",
            json!([{"name": "skip", "decision": "bypass", "include": [{"ip": {"ip": "0.0.0.0/0"}}]}]),
        )];
        let f = access(&z);
        assert_eq!(at(&f, "decision to bypass"), Severity::High);
    }

    #[test]
    fn an_address_alone_is_reported_and_a_second_factor_clears_it() {
        let mut z = zt();
        z.apps = vec![
            app(
                "thin",
                json!([{"name": "p", "decision": "allow",
                 "include": [{"email_domain": {"domain": "example.com"}}], "require": []}]),
            ),
            app(
                "thick",
                json!([{"name": "p", "decision": "allow",
                 "include": [{"email_domain": {"domain": "example.com"}}],
                 "require": [{"device_posture": {"integration_uid": "r-1"}}]}]),
            ),
        ];
        let f = access(&z);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("address alone"))
            .unwrap();
        assert!(hit.detail.contains("thin"));
        assert!(
            !hit.detail.contains("thick"),
            "a require clause is the difference"
        );
    }

    #[test]
    fn an_application_that_accepts_an_emailed_code_has_one_factor() {
        let mut z = zt();
        z.idps = vec![json!({"id": "otp-1", "name": "PIN", "type": "onetimepin",
                             "scim_config": {"enabled": true}})];
        let mut a = app("admin", json!([]));
        a["allowed_idps"] = json!(["otp-1"]);
        z.apps = vec![a];
        assert_eq!(at(&access(&z), "one-time-PIN"), Severity::Medium);
    }

    #[test]
    fn a_session_is_judged_by_its_unit_not_its_number() {
        assert!(long_session("24h"));
        assert!(long_session("168h"), "a week is expressed in hours");
        assert!(!long_session("8h"));
        assert!(
            !long_session("30m"),
            "m is minutes in a Go duration, and reading it as months would report \
             the shortest session available as the longest"
        );
        assert!(!long_session(""));
    }

    #[test]
    fn gateway_configured_with_no_policy_is_the_first_thing_to_say() {
        let mut z = zt();
        z.gateway_config = Some(json!({"settings": {"tls_decrypt": {"enabled": true}}}));
        assert_eq!(at(&gateway(&z), "no policy at all"), Severity::High);

        // An account without Gateway at all gets no finding, not a false one.
        assert!(!has(&gateway(&zt()), "no policy at all"));
    }

    #[test]
    fn inspection_and_logging_are_read_from_the_settings_that_exist() {
        let mut z = zt();
        z.gateway_config = Some(json!({"settings": {
            "tls_decrypt": {"enabled": false}, "activity_log": {"enabled": false}
        }}));
        z.gateway_rules = vec![json!({"action": "block", "enabled": true, "name": "malware"})];
        z.gateway_logging = Some(json!({"settings_by_rule_type": {
            "dns": {"log_all": true}, "http": {"log_all": false}
        }}));
        let f = gateway(&z);
        assert_eq!(at(&f, "TLS inspection is off"), Severity::Medium);
        assert_eq!(at(&f, "activity log is off"), Severity::Medium);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("only what was blocked"))
            .unwrap();
        assert_eq!(hit.detail, "http");
    }

    #[test]
    fn the_default_split_tunnel_list_is_not_a_finding() {
        // Almost all of it is special-purpose space, and excluding that from
        // the fleet's tunnel is the intended configuration.
        let mut z = zt();
        z.split_exclude = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "240.0.0.0/4",
            "192.0.0.0/24",
            "192.88.99.0/24",
            "198.18.0.0/15",
            "100.64.0.0/10",
            "fe80::/10",
            "ff01::/16",
            "100::/64",
        ]
        .iter()
        .map(|a| json!({"address": a}))
        .collect();
        assert!(!has(&devices(&z), "around Gateway"));
    }

    #[test]
    fn an_exclusion_a_service_could_live_on_is_the_finding() {
        let mut z = zt();
        z.split_exclude = vec![
            json!({"address": "10.0.0.0/8"}),
            json!({"address": "8.8.8.0/24"}),
            json!({"host": "updates.example.com"}),
        ];
        let f = devices(&z);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("around Gateway"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(hit.detail.contains("8.8.8.0/24"));
        assert!(hit.detail.contains("updates.example.com"));
        assert!(!hit.detail.contains("10.0.0.0/8"));
    }

    #[test]
    fn a_posture_rule_no_policy_references_gates_nothing() {
        let mut z = zt();
        z.posture_rules = vec![
            json!({"id": "r-1", "name": "disk encryption"}),
            json!({"id": "r-2", "name": "firewall"}),
        ];
        z.apps = vec![app(
            "admin",
            json!([{"name": "p", "decision": "allow", "include": [],
                    "require": [{"device_posture": {"integration_uid": "r-1"}}]}]),
        )];
        let f = devices(&z);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("referenced by no Access policy"))
            .unwrap();
        assert_eq!(hit.detail, "firewall");
    }

    fn tunnel(name: &str, ingress: Value, readable: bool) -> Tunnel {
        Tunnel {
            name: name.to_string(),
            status: "healthy".into(),
            connections: 2,
            ingress: ingress.as_array().cloned().unwrap_or_default(),
            ingress_readable: readable,
        }
    }

    #[test]
    fn the_ingress_rules_are_the_internal_exposure_map() {
        let mut z = zt();
        z.tunnels = vec![tunnel(
            "hq",
            json!([
                {"hostname": "git.example.com", "service": "http://10.0.0.5:3000"},
                {"service": "http_status:404"}
            ]),
            true,
        )];
        let f = tunnels(&z);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("published through a tunnel"))
            .unwrap();
        assert!(hit
            .detail
            .contains("git.example.com → http://10.0.0.5:3000"));
        assert!(
            !has(&f, "catch-all that reaches"),
            "a 404 catch-all refuses"
        );
    }

    #[test]
    fn a_catch_all_that_reaches_something_still_lands_inside() {
        let mut z = zt();
        z.tunnels = vec![tunnel(
            "hq",
            json!([{"service": "http://10.0.0.5:8080"}]),
            true,
        )];
        assert_eq!(at(&tunnels(&z), "catch-all that reaches"), Severity::Medium);
    }

    #[test]
    fn a_locally_configured_tunnel_is_unread_rather_than_empty() {
        // Its ingress lives in a file on the connector, so reporting that it
        // publishes nothing would be a claim the API cannot support.
        let mut z = zt();
        z.tunnels = vec![tunnel("local", json!([]), false)];
        let f = tunnels(&z);
        assert_eq!(at(&f, "configured on the connector"), Severity::Medium);
        assert!(!has(&f, "published through a tunnel"));
    }

    #[test]
    fn a_wide_private_route_reaches_the_whole_estate() {
        let mut z = zt();
        z.routes = vec![
            json!({"network": "10.0.0.0/8", "comment": "everything"}),
            json!({"network": "10.4.2.0/24", "comment": "one subnet"}),
        ];
        let f = tunnels(&z);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("/16 or wider"))
            .unwrap();
        assert!(hit.detail.contains("10.0.0.0/8"));
        assert!(!hit.detail.contains("10.4.2.0/24"));
    }

    // ---- egress, logging and alerting -----------------------------------------

    fn egress_of(jobs: Vec<(&str, Value)>) -> Egress {
        Egress {
            jobs: jobs.into_iter().map(|(s, j)| (s.to_string(), j)).collect(),
            jobs_readable: true,
            residency: None,
            retention: vec![],
            unread: vec![],
        }
    }

    #[test]
    fn a_destination_is_shown_without_whatever_follows_it() {
        // The rest of the string carries an access key for some backends.
        assert_eq!(
            destination_of(
                "s3://logs-bucket/cf?region=eu-west-1&access-key-id=AKIA&secret-access-key=x"
            ),
            "s3://logs-bucket"
        );
        assert_eq!(
            destination_of("datadog://http-intake.logs.datadoghq.com?header_DD-API-KEY=k"),
            "datadog://http-intake.logs.datadoghq.com"
        );
        assert_eq!(destination_of(""), "(unreadable)");
    }

    #[test]
    fn a_job_shipping_headers_or_cookies_is_named_with_the_fields() {
        let e = egress_of(vec![(
            "example.com",
            json!({
                "name": "http", "dataset": "http_requests", "enabled": true,
                "destination_conf": "s3://vendor-bucket/cf?region=us",
                "output_options": {"field_names": ["RayID", "ClientRequestCookies", "ClientIP"]}
            }),
        )]);
        let f = egress(&e);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("headers, cookies"))
            .unwrap();
        assert_eq!(hit.severity, Severity::Medium);
        assert!(hit.detail.contains("ClientRequestCookies"));
        assert!(hit.detail.contains("s3://vendor-bucket"));
        assert!(
            !hit.detail.contains("RayID"),
            "an ordinary field is not the point"
        );
        assert!(
            !hit.detail.contains("region=us"),
            "and the query never appears"
        );
    }

    #[test]
    fn a_disabled_job_is_the_logs_everyone_assumes_exist() {
        let e = egress_of(vec![(
            "account",
            json!({"name": "audit", "dataset": "audit_logs", "enabled": false,
                   "destination_conf": "r2://logs"}),
        )]);
        assert_eq!(at(&egress(&e), "disabled, so the logs"), Severity::Medium);
    }

    #[test]
    fn retention_is_only_judged_for_zones_whose_flag_was_read() {
        let mut e = egress_of(vec![]);
        e.retention = vec![("on.test".into(), true), ("off.test".into(), false)];
        let f = egress(&e);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("retention off"))
            .unwrap();
        assert_eq!(hit.detail, "off.test");

        // No flags read at all: no claim either way.
        let mut none = egress_of(vec![]);
        none.jobs_readable = false;
        assert!(!has(&egress(&none), "retention off"));
    }

    fn alerting_of(policies: Value, available: &[&str]) -> Alerting {
        Alerting {
            policies: policies.as_array().cloned().unwrap_or_default(),
            available: available
                .iter()
                .map(|t| ((*t).to_string(), (*t).to_string()))
                .collect(),
            webhooks: vec![],
            pagerduty: vec![],
            silences: vec![],
            history: vec![],
        }
    }

    #[test]
    fn coverage_is_reported_as_the_question_nobody_answers() {
        // Not "55 of 57 types have no policy", which is a number nobody acts
        // on, but the sentence that has a next step.
        let a = alerting_of(json!([]), &["universal_ssl_event_type", "dos_attack_l7"]);
        let f = alerting(&a);
        let hit = f
            .iter()
            .find(|f| f.detail.contains("a certificate expires"))
            .unwrap();
        assert_eq!(hit.severity, Severity::Medium);
        assert!(f.iter().any(|f| f.detail.contains("layer 7 attack")));
    }

    #[test]
    fn a_group_the_account_cannot_receive_is_not_a_gap_in_configuration() {
        // `available_alerts` already reflects the plan, so a type that is not
        // offered is a price list rather than a missing policy.
        let a = alerting_of(json!([]), &["dos_attack_l7"]);
        let f = alerting(&a);
        assert!(
            !f.iter().any(|f| f.detail.contains("a certificate expires")),
            "no certificate alert type is offered here"
        );
    }

    #[test]
    fn one_subscription_covers_its_whole_group() {
        // The question is answered, whichever of its alert types answers it.
        let a = alerting_of(
            json!([{"name": "ssl", "alert_type": "universal_ssl_event_type", "enabled": true}]),
            &[
                "universal_ssl_event_type",
                "dedicated_ssl_certificate_event_type",
            ],
        );
        assert!(!alerting(&a)
            .iter()
            .any(|f| f.detail.contains("a certificate expires")));
    }

    #[test]
    fn a_disabled_policy_does_not_count_as_coverage() {
        let a = alerting_of(
            json!([{"name": "ssl", "alert_type": "universal_ssl_event_type", "enabled": false}]),
            &["universal_ssl_event_type"],
        );
        let f = alerting(&a);
        assert!(f.iter().any(|f| f.detail.contains("a certificate expires")));
        assert_eq!(at(&f, "notification policy is disabled"), Severity::Medium);
    }

    #[test]
    fn a_webhook_failing_more_recently_than_it_succeeded_is_silent() {
        let mut a = alerting_of(json!([]), &[]);
        a.webhooks = vec![
            json!({"name": "slack", "last_success": "2026-01-01T00:00:00Z",
                   "last_failure": "2026-09-01T00:00:00Z"}),
            json!({"name": "ops", "last_success": "2026-09-02T00:00:00Z",
                   "last_failure": "2026-01-01T00:00:00Z"}),
            json!({"name": "fresh"}),
        ];
        let f = alerting(&a);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("failing more recently"))
            .unwrap();
        assert!(hit.detail.contains("slack"));
        assert!(!hit.detail.contains("ops"), "it recovered");
        assert!(!hit.detail.contains("fresh"), "it has never failed");
    }

    #[test]
    fn no_policy_at_all_is_said_plainly() {
        let a = alerting_of(json!([]), &["dos_attack_l7"]);
        assert_eq!(
            at(&alerting(&a), "no notification policy at all"),
            Severity::Medium
        );

        // An account that cannot receive anything gets no finding.
        assert!(alerting(&alerting_of(json!([]), &[])).is_empty());
    }

    // ---- the routed network ---------------------------------------------------

    fn network() -> Network {
        Network {
            sites: vec![],
            ipsec: vec![],
            gre: vec![],
            routes: vec![],
            prefixes: vec![],
            address_maps: vec![],
            dns_firewall: vec![],
            load_balancers: vec![],
            pools: vec![],
            monitors: vec![],
        }
    }

    #[test]
    fn an_empty_plane_is_empty_and_produces_nothing() {
        // Most accounts do not route through Cloudflare at all.
        let n = network();
        assert!(n.is_empty());
        assert!(magic(&n).is_empty());
        assert!(addressing(&n).is_empty());
        assert!(balancing(&n).is_empty());
    }

    #[test]
    fn a_tunnel_that_permits_a_null_cipher_does_not_encrypt() {
        let mut n = network();
        n.ipsec = vec![
            json!({"name": "clear", "allow_null_cipher": true, "replay_protection": true}),
            json!({"name": "proper", "allow_null_cipher": false, "replay_protection": true}),
        ];
        let f = magic(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("null cipher"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert_eq!(hit.detail, "clear");
    }

    #[test]
    fn replay_protection_is_only_judged_where_the_setting_exists() {
        // A GRE tunnel has no such setting, and its absence is not "off".
        let mut n = network();
        n.gre = vec![json!({"name": "gre-1"})];
        n.ipsec = vec![json!({"name": "ipsec-1", "replay_protection": false})];
        let f = magic(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("replay protection"))
            .unwrap();
        assert_eq!(hit.detail, "ipsec-1");
    }

    #[test]
    fn a_tunnel_with_health_checks_off_fails_over_on_nothing() {
        let mut n = network();
        n.gre = vec![
            json!({"name": "blind", "health_check": {"enabled": false}}),
            json!({"name": "watched", "health_check": {"enabled": true}}),
        ];
        let f = magic(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("health checks off"))
            .unwrap();
        assert_eq!(hit.detail, "blind");
    }

    #[test]
    fn an_acl_pairing_two_whole_lans_on_every_protocol_is_a_flat_network() {
        let mut n = network();
        n.sites = vec![Site {
            name: "hq".into(),
            lans: vec![],
            acls: vec![
                json!({"name": "everything", "protocols": [],
                       "lan_1": {"lan_name": "office"}, "lan_2": {"lan_name": "servers"}}),
                json!({"name": "narrow", "protocols": ["tcp"],
                       "lan_1": {"lan_name": "office", "ports": [443]},
                       "lan_2": {"lan_name": "servers", "subnets": ["10.1.0.0/24"]}}),
            ],
        }];
        let f = magic(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("two whole LANs"))
            .unwrap();
        assert_eq!(hit.severity, Severity::High);
        assert!(hit.detail.contains("everything"));
        assert!(!hit.detail.contains("narrow"));
    }

    #[test]
    fn routes_covering_the_same_space_at_one_priority_are_decided_per_packet() {
        let mut n = network();
        n.routes = vec![
            json!({"prefix": "10.0.0.0/8", "nexthop": "10.1.1.1", "priority": 100}),
            json!({"prefix": "10.4.0.0/16", "nexthop": "10.2.2.2", "priority": 100}),
            // Different priority: the design has decided.
            json!({"prefix": "10.5.0.0/16", "nexthop": "10.3.3.3", "priority": 200}),
        ];
        let f = magic(&n);
        let hit = f.iter().find(|f| f.finding.contains("same space")).unwrap();
        assert!(hit.detail.contains("10.0.0.0/8"));
        assert!(
            !hit.detail.contains("10.5.0.0/16"),
            "priority separates them"
        );
    }

    #[test]
    fn prefix_containment_is_computed_rather_than_string_matched() {
        assert!(covers("10.0.0.0/8", "10.4.0.0/16"));
        assert!(
            covers("0.0.0.0/0", "192.0.2.0/24"),
            "a default route covers everything"
        );
        assert!(
            !covers("10.4.0.0/16", "10.0.0.0/8"),
            "containment has a direction"
        );
        assert!(!covers("10.0.0.0/8", "172.16.0.0/12"));
        assert!(
            !covers("2001:db8::/32", "2001:db8:1::/48"),
            "v6 is left alone rather than guessed at"
        );
        assert!(!covers("nonsense", "10.0.0.0/8"));
    }

    #[test]
    fn a_prefix_advertised_with_nothing_bound_to_it_is_announced_for_nothing() {
        let mut n = network();
        n.prefixes = vec![
            json!({"cidr": "192.0.2.0/24", "advertised": true, "rpki_validation_state": "valid"}),
            json!({"cidr": "198.51.100.0/24", "advertised": true, "rpki_validation_state": "valid"}),
            // Not advertised: nothing is being announced, so nothing is idle.
            json!({"cidr": "203.0.113.0/24", "advertised": false}),
        ];
        n.address_maps = vec![json!({"ips": [{"ip": "192.0.2.10"}]})];
        let f = addressing(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("nothing bound"))
            .unwrap();
        assert!(hit.detail.contains("198.51.100.0/24"));
        assert!(
            !hit.detail.contains("192.0.2.0/24"),
            "an address map binds it"
        );
        assert!(!hit.detail.contains("203.0.113.0/24"));
    }

    #[test]
    fn an_rpki_state_other_than_valid_can_be_dropped_by_validating_networks() {
        let mut n = network();
        n.prefixes = vec![json!({
            "cidr": "192.0.2.0/24", "advertised": true, "rpki_validation_state": "invalid"
        })];
        let f = addressing(&n);
        assert_eq!(at(&f, "RPKI state other than valid"), Severity::Medium);
    }

    #[test]
    fn a_pool_whose_monitor_is_missing_never_fails_over() {
        let mut n = network();
        n.monitors = vec![json!({"id": "m-1", "type": "https"})];
        n.pools = vec![
            json!({"name": "eu", "monitor": "m-1", "origins": []}),
            json!({"name": "us", "monitor": "m-gone", "origins": []}),
            json!({"name": "ap", "origins": []}),
        ];
        let f = balancing(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("no working monitor"))
            .unwrap();
        assert!(
            hit.detail.contains("us"),
            "a dangling reference is as bad as none"
        );
        assert!(hit.detail.contains("ap"));
        assert!(!hit.detail.contains("eu"));
    }

    #[test]
    fn a_balancer_with_no_fallback_pool_drops_rather_than_sheds() {
        let mut n = network();
        n.load_balancers = vec![
            json!({"name": "www", "fallback_pool": ""}),
            json!({"name": "api", "fallback_pool": "p-1"}),
        ];
        let f = balancing(&n);
        let hit = f
            .iter()
            .find(|f| f.finding.contains("no fallback pool"))
            .unwrap();
        assert_eq!(hit.detail, "www");
    }

    #[test]
    fn a_dns_firewall_cluster_names_where_it_forwards() {
        let mut n = network();
        n.dns_firewall = vec![json!({
            "name": "corp", "upstream_ips": ["198.51.100.1", "198.51.100.2"], "ratelimit": 0
        })];
        let f = dns_firewall(&n);
        assert!(f.iter().any(|f| f.detail.contains("198.51.100.1")));
        assert_eq!(at(&f, "no rate limit"), Severity::Low);
    }

    // ---- ordering -----------------------------------------------------------

    #[test]
    fn findings_come_back_worst_first() {
        let f = sorted(vec![
            Finding::new(Severity::Low, "b", "low thing"),
            Finding::new(Severity::High, "z", "high thing"),
            Finding::new(Severity::Info, "a", "info thing"),
            Finding::new(Severity::Medium, "a", "medium thing"),
        ]);
        let order: Vec<String> = f.iter().map(|f| f.severity.to_string()).collect();
        assert_eq!(order, vec!["high", "medium", "low", "info"]);
    }

    #[test]
    fn the_tally_is_worst_first_too_and_skips_empty_levels() {
        let t = tally(&[
            Finding::new(Severity::Low, "a", "x"),
            Finding::new(Severity::High, "a", "y"),
            Finding::new(Severity::Low, "a", "z"),
        ]);
        assert_eq!(t, vec![(Severity::High, 1), (Severity::Low, 2)]);
    }

    #[test]
    fn a_count_of_one_reads_as_one() {
        assert_eq!(agree(1, "token has", "tokens have"), "token has");
        assert_eq!(agree(0, "token has", "tokens have"), "tokens have");
        assert_eq!(agree(2, "token has", "tokens have"), "tokens have");
    }
    // ---- the outside view --------------------------------------------------

    /// A domain scan in the shape the service actually returns, trimmed from a
    /// recorded response.
    ///
    /// The nesting is the point: `subdomains` and `ssl` sit under `results`,
    /// while `resolve` and `txt` sit under `results.dns`. Reading either at the
    /// wrong depth is silent — every accessor defaults to empty — and it once
    /// produced a report claiming that names which plainly resolve resolve to
    /// nothing. A fixture with the real nesting is what catches that.
    fn scan(subdomains: Value, resolve: Value, ssl: Value, txt: Value) -> Value {
        json!({
            "domain": "example.test",
            "status": "completed",
            "results": {
                "dns": { "resolve": resolve, "txt": txt },
                "files": { "robots_txt": "not found", "security_txt": "not found" },
                "ssl": ssl,
                "subdomains": subdomains,
                "subdomains_suspicious": [],
            }
        })
    }

    fn outside(known: &[&str], scan: Value) -> Outside {
        Outside {
            zone: "example.test".into(),
            known: known.iter().map(|s| s.to_string()).collect(),
            cf_spf: false,
            cf_dmarc: false,
            scan,
        }
    }

    #[test]
    fn a_name_the_world_resolves_and_the_zone_does_not_hold_is_the_headline() {
        let z = outside(
            &["example.test"],
            scan(
                json!(["ghost.example.test"]),
                json!([{"domain": "ghost.example.test", "a": ["203.0.113.9"], "aaaa": [], "cname": null}]),
                json!([]),
                json!({}),
            ),
        );
        let f = shadow(&[z]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].finding.contains("resolves"));
        assert_eq!(f[0].detail, "ghost.example.test");
    }

    /// The bug this guards: `dns.resolve` does not list every discovered name.
    /// Two hostnames that answer perfectly well were missing from it on a real
    /// scan, so absence from it cannot mean "does not resolve" — and no finding
    /// here may say that it does.
    #[test]
    fn a_name_missing_from_resolve_is_never_called_dead() {
        let z = outside(
            &["example.test", "known.example.test"],
            scan(
                json!(["known.example.test", "other.example.test"]),
                // Neither discovered name appears here.
                json!([{"domain": "example.test", "a": ["104.26.2.236"], "aaaa": [], "cname": null}]),
                json!([]),
                json!({}),
            ),
        );
        let f = shadow(&[z]);
        for finding in &f {
            let text = format!("{} {}", finding.finding, finding.detail);
            assert!(
                !text.contains("resolve to nothing") && !text.contains("resolves to nothing"),
                "claimed non-resolution from an absence: {text}"
            );
            // A name the zone does hold is not a shadow name at all.
            assert!(!finding.detail.contains("known.example.test"));
        }
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Medium && x.detail == "other.example.test"));
    }

    #[test]
    fn a_name_is_reported_once_under_its_strongest_evidence() {
        let z = outside(
            &["example.test"],
            scan(
                json!(["ghost.example.test"]),
                json!([{"domain": "ghost.example.test", "a": ["203.0.113.9"], "aaaa": [], "cname": null}]),
                json!([{"common_name": "ghost.example.test", "issuer": "C=US, O=Let's Encrypt, CN=R13",
                        "not_after": "2099-01-01T00:00:00", "not_before": "2020-01-01T00:00:00", "serial": "01"}]),
                json!({}),
            ),
        );
        let f = shadow(&[z]);
        let mentions = f
            .iter()
            .filter(|x| x.detail.contains("ghost.example.test"))
            .count();
        assert_eq!(mentions, 1, "one name, one finding");
        assert_eq!(f[0].severity, Severity::High);
    }

    #[test]
    fn cloudflares_own_universal_certificates_are_not_shadow_names() {
        let z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([]),
                json!([{"common_name": "fc4eb8e7.sni.cloudflaressl.com",
                        "issuer": "C=US, O=Google Trust Services, CN=WR1",
                        "not_after": "2099-01-01T00:00:00", "not_before": "2020-01-01T00:00:00", "serial": "01"}]),
                json!({}),
            ),
        );
        assert!(shadow(&[z]).is_empty());
    }

    #[test]
    fn a_wildcard_certificate_is_judged_as_the_name_it_wraps() {
        let z = outside(
            &["example.test", "staging.example.test"],
            scan(
                json!([]),
                json!([]),
                json!([
                    {"common_name": "*.staging.example.test", "issuer": "C=US, O=Let's Encrypt, CN=R13",
                     "not_after": "2099-01-01T00:00:00", "not_before": "2020-01-01T00:00:00", "serial": "01"},
                    {"common_name": "*.gone.example.test", "issuer": "C=US, O=Let's Encrypt, CN=R13",
                     "not_after": "2099-01-01T00:00:00", "not_before": "2020-01-01T00:00:00", "serial": "02"}
                ]),
                json!({}),
            ),
        );
        let f = shadow(&[z]);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].detail, "gone.example.test");
    }

    #[test]
    fn a_name_outside_the_zone_is_not_a_name_in_it() {
        assert!(in_zone("a.example.test", "example.test"));
        assert!(in_zone("example.test", "example.test"));
        assert!(in_zone("EXAMPLE.TEST.", "example.test"));
        // The label boundary: without it, a domain somebody else owns is
        // reported as a shadow name in this zone.
        assert!(!in_zone("notexample.test", "example.test"));
        assert!(!in_zone("example.test.evil.com", "example.test"));
    }

    #[test]
    fn cloudflares_ranges_are_recognised_and_nothing_else_is() {
        for ip in [
            "104.26.2.236",
            "172.67.73.61",
            "104.21.19.25",
            "2606:4700:20::681a:3ec",
            "2803:f800::1",
        ] {
            assert!(is_cloudflare(ip), "{ip} is Cloudflare space");
        }
        // 104.15.255.255 and 2600:4700::1 sit just outside the ranges above,
        // which is where an off-by-one in the mask arithmetic would show.
        for ip in [
            "93.184.216.34",
            "8.8.8.8",
            "104.15.255.255",
            "2600:4700::1",
            "nonsense",
        ] {
            assert!(!is_cloudflare(ip), "{ip} is not Cloudflare space");
        }
    }

    #[test]
    fn a_name_answering_outside_cloudflare_means_the_proxy_is_not_in_the_path() {
        let z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([
                    {"domain": "proxied.example.test", "a": ["104.26.2.236"], "aaaa": [], "cname": null},
                    {"domain": "direct.example.test", "a": ["203.0.113.9"], "aaaa": [], "cname": null}
                ]),
                json!([]),
                json!({}),
            ),
        );
        let f = drift(&[z]);
        assert_eq!(f.len(), 1);
        assert!(f[0].detail.starts_with("direct.example.test"));
        assert!(!f[0].detail.contains("proxied"));
    }

    #[test]
    fn the_inside_and_outside_mail_policies_are_compared_both_ways() {
        let case = |cf_spf, cf_dmarc, txt: Value| {
            let mut z = outside(
                &["example.test"],
                scan(json!([]), json!([]), json!([]), txt),
            );
            z.cf_spf = cf_spf;
            z.cf_dmarc = cf_dmarc;
            live_mail(&[z])
        };

        // In the zone, absent live: whatever Cloudflare holds is not what the
        // world gets, so the record enforces nothing.
        let f = case(true, true, json!({}));
        assert!(f.iter().any(
            |x| x.finding.contains("does not resolve") || x.finding.contains("do not resolve")
        ));

        // Live, absent from the zone: something other than this account is
        // answering for the name.
        let f = case(
            false,
            false,
            json!({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject;"}),
        );
        assert!(f
            .iter()
            .any(|x| x.finding.contains("something else answers")));

        // Agreeing on both sides is not a finding about authority.
        let f = case(
            true,
            true,
            json!({"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject;"}),
        );
        assert!(f.is_empty(), "{f:?}");
    }

    #[test]
    fn a_monitoring_dmarc_and_an_open_spf_are_graded_on_what_they_do() {
        let mut z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([]),
                json!([]),
                json!({"spf": "v=spf1 +all", "dmarc": "v=DMARC1; p=none; rua=mailto:a@b.c"}),
            ),
        );
        z.cf_spf = true;
        z.cf_dmarc = true;
        let f = live_mail(&[z]);
        assert!(f.iter().any(|x| x.finding.contains("p=none")));
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::High && x.finding.contains("every sender")));
    }

    #[test]
    fn a_dmarc_policy_is_read_from_the_tag_and_not_from_the_string() {
        assert_eq!(
            policy_of("v=DMARC1; p=none; rua=x").as_deref(),
            Some("none")
        );
        assert_eq!(policy_of("v=DMARC1;p=reject").as_deref(), Some("reject"));
        // `sp=` is the subdomain policy and is not `p=`.
        assert_eq!(
            policy_of("v=DMARC1; sp=none; p=quarantine").as_deref(),
            Some("quarantine")
        );
        assert_eq!(policy_of("v=DMARC1"), None);
    }

    /// The bug this guards: a transparency log holds every certificate ever
    /// issued for a name, so counting all of them reported six imminent
    /// expiries on a zone whose live certificates were all months away.
    #[test]
    fn only_the_newest_certificate_for_a_name_can_be_about_to_expire() {
        let cert = |cn: &str, not_after: &str, serial: &str| {
            json!({"common_name": cn, "issuer": "C=US, O=Let's Encrypt, CN=R13",
                   "not_after": not_after, "not_before": "2020-01-01T00:00:00", "serial": serial})
        };
        let z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([]),
                json!([
                    cert("example.test", "2020-01-05T00:00:00", "01"),
                    cert("example.test", "2099-01-01T00:00:00", "02"),
                ]),
                json!({}),
            ),
        );
        let f = public_certs(&[z], 30);
        assert!(
            !f.iter().any(|x| x.severity == Severity::Medium),
            "a superseded certificate is history, not an expiry: {f:?}"
        );
        // The issuers are still reported, because an unexpected one is the
        // signal this check exists for.
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert!(f[0].detail.contains("Let's Encrypt"));

        // The same shape with both certificates live and one inside the
        // window: the renewal already happened, so there is nothing to do.
        let z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([]),
                json!([
                    cert("example.test", &in_days(10), "01"),
                    cert("example.test", &in_days(400), "02"),
                ]),
                json!({}),
            ),
        );
        assert!(
            !public_certs(&[z], 30)
                .iter()
                .any(|x| x.severity == Severity::Medium),
            "the newest certificate is the one in service"
        );

        // And when the newest really is inside the window, it is reported.
        let z = outside(
            &["example.test"],
            scan(
                json!([]),
                json!([]),
                json!([
                    cert("example.test", &in_days(-100), "01"),
                    cert("example.test", &in_days(9), "02"),
                ]),
                json!({}),
            ),
        );
        let f = public_certs(&[z], 30);
        assert!(f
            .iter()
            .any(|x| x.severity == Severity::Medium && x.detail.contains("in 9d")));
    }

    #[test]
    fn an_issuer_is_named_by_its_organisation() {
        assert_eq!(
            issuer_name("C=US, O=Let's Encrypt, CN=R13"),
            "Let's Encrypt"
        );
        assert_eq!(
            issuer_name("C=US, O=\"CLOUDFLARE, INC.\", CN=Cloudflare TLS Issuing ECC CA 1"),
            "CLOUDFLARE, INC."
        );
        assert_eq!(issuer_name("no fields here"), "no fields here");
    }

    // ---- origins -----------------------------------------------------------

    fn addr(exposed: bool, scan: Value) -> Address {
        Address {
            names: vec!["www.example.test".into()],
            addr: "203.0.113.9".into(),
            exposed,
            scan,
        }
    }

    #[test]
    fn an_exposed_origin_on_a_consumer_line_is_the_worst_kind_of_origin() {
        let a = addr(
            true,
            json!({"hosting": false, "mobile": false, "proxy": false,
                                  "reserved": false, "isp": "Some ISP", "country": "France"}),
        );
        let f = origins(&[a]);
        assert_eq!(f[0].severity, Severity::High);
        assert!(f[0].finding.contains("consumer connection"));
        assert!(f[0].detail.contains("www.example.test → 203.0.113.9"));
        assert!(f[0].detail.contains("Some ISP"));
    }

    /// An origin the proxy actually hides is not exposed by being an origin,
    /// so the network it sits on is not a finding about this account.
    #[test]
    fn an_origin_behind_the_proxy_is_not_reported_for_its_network() {
        let a = addr(
            false,
            json!({"hosting": false, "mobile": true, "proxy": true,
                                   "reserved": false, "isp": "Some ISP"}),
        );
        assert!(origins(&[a]).is_empty());
    }

    #[test]
    fn a_datacentre_origin_is_not_a_consumer_line() {
        let a = addr(
            true,
            json!({"hosting": true, "mobile": false, "proxy": false,
                                  "reserved": false, "isp": "A Host"}),
        );
        assert!(origins(&[a]).is_empty());
    }

    #[test]
    fn tor_reserved_and_reputation_are_judged_on_any_published_address() {
        let a = Address {
            names: vec!["a.example.test".into()],
            addr: "203.0.113.9".into(),
            // Not exposed: these three are facts about the address itself.
            exposed: false,
            scan: json!({
                "hosting": true, "reserved": true,
                "tor": {"is_tor": true, "available": true},
                "ikwyd": {"exists": true, "observations": 4},
                "rdap": {"found": true, "abuse_email": "", "cidr": "203.0.113.0/24"},
                "rdns": {"found": false},
            }),
        };
        let f = origins(&[a]);
        let says = |t: &str| f.iter().any(|x| x.finding.contains(t));
        assert!(says("Tor exit node"));
        assert!(says("reserved address space"));
        assert!(says("peer-to-peer activity"));
        assert!(says("no abuse contact"));
        assert!(says("no reverse name"));
    }

    #[test]
    fn a_reverse_name_that_does_not_resolve_back_is_distinct_from_having_none() {
        let a = addr(
            true,
            json!({"hosting": true, "rdns": {"found": true,
                                  "forward_confirmed": false, "name": "host.isp.test"}}),
        );
        let f = origins(&[a]);
        assert!(f
            .iter()
            .any(|x| x.finding.contains("does not resolve back")));
        assert!(!f.iter().any(|x| x.finding.contains("no reverse name")));
    }

    #[test]
    fn origins_in_more_than_one_country_are_worth_saying_out_loud() {
        let one = |c: &str, ip: &str| Address {
            names: vec![format!("{c}.example.test")],
            addr: ip.into(),
            exposed: true,
            scan: json!({"hosting": true, "country": c}),
        };
        assert!(origins(&[one("France", "203.0.113.1")]).is_empty());
        let f = origins(&[one("France", "203.0.113.1"), one("Canada", "203.0.113.2")]);
        assert!(f.iter().any(|x| x.finding.contains("2 countries")));
    }

    // ---- what gets looked up -----------------------------------------------

    #[test]
    fn one_address_is_one_lookup_however_many_names_publish_it() {
        let recs = json!([
            {"type": "A", "name": "a.example.test", "content": "93.184.216.34", "proxied": true},
            {"type": "A", "name": "b.example.test", "content": "93.184.216.34", "proxied": true},
        ]);
        let got = public_addresses(recs.as_array().unwrap());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "93.184.216.34");
        assert_eq!(got[0].1, vec!["a.example.test", "b.example.test"]);
        assert!(!got[0].2, "every record is proxied, so nothing is exposed");
    }

    #[test]
    fn an_address_is_exposed_when_one_record_publishes_it_around_the_proxy() {
        let recs = json!([
            {"type": "A", "name": "www.example.test", "content": "93.184.216.34", "proxied": true},
            {"type": "A", "name": "direct.example.test", "content": "93.184.216.34", "proxied": false},
        ]);
        let got = public_addresses(recs.as_array().unwrap());
        assert_eq!(got.len(), 1);
        assert!(
            got[0].2,
            "one unproxied record is enough to expose the origin"
        );
    }

    /// Exposure is Cloudflare fronting for an address *and* publishing a route
    /// around itself. An address Cloudflare never proxies is just an address —
    /// a mail server, a stray host — and calling it an exposed origin would
    /// report every unproxied record in the account.
    #[test]
    fn an_address_the_proxy_never_fronts_for_is_not_an_exposed_origin() {
        let recs = json!([
            {"type": "A", "name": "mail.example.test", "content": "93.184.216.34", "proxied": false},
            {"type": "A", "name": "smtp.example.test", "content": "93.184.216.34", "proxied": false},
        ]);
        let got = public_addresses(recs.as_array().unwrap());
        assert_eq!(got.len(), 1);
        assert!(
            !got[0].2,
            "nothing is bypassed when nothing was in front of it"
        );
    }

    #[test]
    fn filler_and_private_addresses_are_never_looked_up() {
        // Each would spend a unit of somebody's daily quota to learn nothing.
        let recs = json!([
            {"type": "A", "name": "a.example.test", "content": "192.0.2.1", "proxied": true},
            {"type": "A", "name": "f.example.test", "content": "203.0.113.9", "proxied": false},
            {"type": "A", "name": "b.example.test", "content": "10.0.0.1", "proxied": false},
            {"type": "AAAA", "name": "c.example.test", "content": "100::1", "proxied": true},
            {"type": "CNAME", "name": "d.example.test", "content": "x.test", "proxied": true},
            {"type": "A", "name": "e.example.test", "content": "93.184.216.34", "proxied": true},
        ]);
        let got = public_addresses(recs.as_array().unwrap());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, "93.184.216.34");
    }
}
