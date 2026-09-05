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
