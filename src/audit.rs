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

    /// The addresses Cloudflare proxies for, which is to say the origins.
    ///
    /// A proxied record still reports its real target in `content`; the proxy
    /// hides it from a resolver, not from the API.
    fn proxied_origins(&self) -> BTreeSet<String> {
        self.of_type(&["A", "AAAA"])
            .filter(|r| r.get("proxied").and_then(Value::as_bool) == Some(true))
            .map(|r| str_of(r, "content"))
            .filter(|c| !is_placeholder(c))
            .collect()
    }
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
        let origins = z.proxied_origins();
        for r in z.of_type(&["A", "AAAA"]) {
            let name = str_of(r, "name");
            let content = str_of(r, "content");
            let proxied = r.get("proxied").and_then(Value::as_bool) == Some(true);

            if is_private(&content) {
                private.push(format!("{name} → {content}"));
                continue;
            }
            if proxied || is_placeholder(&content) {
                continue;
            }
            // Only records Cloudflare could proxy: an unproxiable one is not a
            // choice anybody made.
            if r.get("proxiable").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            if origins.contains(&content) {
                leaks.push(format!("{name} → {content}"));
            } else {
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
}
