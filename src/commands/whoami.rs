//! `whoami` — what this credential is, and exactly what it may do.
//!
//! The first question of any Cloudflare audit is what the auditor is holding,
//! because it bounds every answer that follows: a 403 further on means "not
//! permitted" rather than "not configured", and the two are opposite findings.
//! This command answers it before anything else runs.

use anyhow::Result;
use reqwest::Method;
use serde_json::{json, Value};

use crate::cf::{token, Auth, Client, Owner};
use crate::cli::Ctx;
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    match c.auth() {
        Auth::Token => report_token(c, ctx).await,
        Auth::Key => report_key(c, ctx).await,
    }
}

async fn report_token(c: &Client, ctx: &Ctx) -> Result<()> {
    let (owner, verified) = ui::spin(
        "Verifying the token",
        token::verify(c, ctx.profile.owner, &ctx.profile.account),
    )
    .await?;
    let id = str_of(&verified, "id");

    // Reading a token's own policies needs the API Tokens Read permission,
    // which a well-scoped audit token deliberately does not have. Not knowing
    // the policies is a normal outcome, not a failure — and the path differs
    // per store, so it is asked for rather than built here.
    let detail = match token::detail_path(owner, &ctx.profile.account, &id) {
        Some(path) if !id.is_empty() => ui::spin(
            "Reading the token policies",
            c.request(Method::GET, &path, &[], None),
        )
        .await
        .ok(),
        _ => None,
    };

    let policies: Vec<Value> = detail
        .as_ref()
        .and_then(|d| d.get("policies"))
        .and_then(Value::as_array)
        .map(|ps| ps.iter().map(flatten_policy).collect())
        .unwrap_or_default();

    // The one thing that turns a read-only audit into a change: any permission
    // group that is not a read.
    let writes: Vec<String> = policies
        .iter()
        .filter(|p| p["effect"] == "allow")
        .flat_map(|p| {
            p["permissionList"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
        })
        .filter_map(|g| g.as_str().map(str::to_string))
        .filter(|g| !g.ends_with(" Read"))
        .collect();

    let (accounts, zones) = reach(c).await;

    let out = json!({
        "auth": "token",
        "store": owner.to_string(),
        "id": id,
        "name": detail.as_ref().map(|d| str_of(d, "name")).unwrap_or_default(),
        "status": str_of(&verified, "status"),
        "issuedOn": detail.as_ref().map(|d| str_of(d, "issued_on")).unwrap_or_default(),
        "expiresOn": detail
            .as_ref()
            .map(|d| str_of(d, "expires_on"))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| str_of(&verified, "expires_on")),
        "notBefore": str_of(&verified, "not_before"),
        "lastUsedOn": detail.as_ref().map(|d| str_of(d, "last_used_on")).unwrap_or_default(),
        "ipFilter": detail.as_ref().map(ip_filter).unwrap_or_default(),
        "policiesReadable": detail.is_some(),
        "policies": policies,
        "writePermissions": writes,
        "accounts": accounts,
        "zones": zones,
    });

    if render::is_json() {
        render::print_json(&out);
        return Ok(());
    }

    render::heading("Credential");
    // Verification answers the id, the status and the expiry; everything else
    // comes from the token's own record. When that record cannot be read, those
    // rows are unknown rather than empty — and an empty "name" row reads as a
    // token with no name, which is a different and wrong statement.
    let mut rows = vec![
        ("profile", ctx.name.clone()),
        ("kind", format!("API token, {owner}-owned")),
        ("token id", str_of(&out, "id")),
        ("status", str_of(&out, "status")),
        (
            "expires",
            match str_of(&out, "expiresOn") {
                s if s.is_empty() => "never".to_string(),
                s => s,
            },
        ),
    ];
    if detail.is_some() {
        rows.insert(3, ("name", str_of(&out, "name")));
        rows.push(("issued", str_of(&out, "issuedOn")));
        rows.push(("last used", str_of(&out, "lastUsedOn")));
        rows.push((
            "ip filter",
            match str_of(&out, "ipFilter") {
                s if s.is_empty() => "none".to_string(),
                s => s,
            },
        ));
    }
    render::pairs(&rows);

    if detail.is_none() {
        ui::info(
            "this token cannot read its own policies (no \"User API Tokens Read\" permission), \
             so what follows is what it could reach, not what it was granted",
        );
    } else {
        render::heading("Grants");
        render::list(&policies, render::POLICY_COLS);
        render::count(policies.len(), "policy");
    }

    if !writes.is_empty() {
        ui::warning(&format!("this token can write: {}", writes.join(", ")));
    } else if detail.is_some() {
        ui::success("read-only: every granted permission group is a read");
    }

    render::heading("Reach");
    render::pairs(&[
        ("accounts", summarize(&accounts)),
        ("zones", summarize(&zones)),
    ]);
    if str_of(&out, "expiresOn").is_empty() {
        ui::warning("this token has no expiry date");
    }
    if owner == Owner::Account {
        ui::info(
            "this token belongs to the account rather than to a person: removing its creator \
             from the account does not revoke it",
        );
    }
    Ok(())
}

async fn report_key(c: &Client, ctx: &Ctx) -> Result<()> {
    let user = ui::spin(
        "Reading the user",
        c.request(Method::GET, "/user", &[], None),
    )
    .await?;
    let memberships = ui::spin("Listing memberships", c.list("/memberships", &[], None))
        .await
        .unwrap_or_default();
    let (accounts, zones) = reach(c).await;

    let out = json!({
        "auth": "key",
        "id": str_of(&user, "id"),
        "email": str_of(&user, "email"),
        "twoFactor": user.get("two_factor_authentication_enabled").and_then(Value::as_bool),
        "memberships": memberships.len(),
        "accounts": accounts,
        "zones": zones,
    });

    if render::is_json() {
        render::print_json(&out);
        return Ok(());
    }

    render::heading("Credential");
    render::pairs(&[
        ("profile", ctx.name.clone()),
        ("kind", "Global API Key".to_string()),
        ("user", str_of(&out, "email")),
        ("user id", str_of(&out, "id")),
        (
            "two-factor",
            match out["twoFactor"].as_bool() {
                Some(true) => "on".to_string(),
                Some(false) => "off".to_string(),
                None => String::new(),
            },
        ),
    ]);

    render::heading("Reach");
    render::pairs(&[
        ("accounts", summarize(&accounts)),
        ("zones", summarize(&zones)),
    ]);

    ui::warning(
        "a Global API Key holds every permission of its user on every account it reaches; \
         nothing below is out of its write scope",
    );
    if out["twoFactor"].as_bool() == Some(false) {
        ui::warning("two-factor authentication is off on the user behind this key");
    }
    Ok(())
}

/// What the credential can actually see, whatever it was granted on paper.
///
/// Both listings are allowed to fail: a token scoped to one zone gets a 403 on
/// `/accounts` and still works perfectly for that zone.
async fn reach(c: &Client) -> (Vec<Value>, Vec<Value>) {
    let accounts = ui::spin("Listing accounts", c.list("/accounts", &[], None))
        .await
        .unwrap_or_default();
    let zones = ui::spin("Listing zones", c.list("/zones", &[], None))
        .await
        .unwrap_or_default();
    let name = |v: &Value| json!({"id": str_of(v, "id"), "name": str_of(v, "name")});
    (
        accounts.iter().map(name).collect(),
        zones.iter().map(name).collect(),
    )
}

/// Turn one token policy into a row: effect, what it covers, what it grants.
fn flatten_policy(p: &Value) -> Value {
    let groups: Vec<String> = p
        .get("permission_groups")
        .and_then(Value::as_array)
        .map(|gs| gs.iter().map(|g| str_of(g, "name")).collect())
        .unwrap_or_default();

    json!({
        "effect": str_of(p, "effect"),
        "scope": scope_of(p.get("resources")),
        "permissions": groups.join(", "),
        // Kept apart from the joined string so `-o json` stays machine-readable
        // and the write check below has something to iterate.
        "permissionList": groups,
    })
}

/// Render a policy's `resources` map as something a human can check.
///
/// The keys are URNs — `com.cloudflare.api.account.zone.<id>` — and a value
/// that is itself a map means "every child of this one", which is the case
/// worth spotting: a policy on all zones of an account rather than on a zone.
fn scope_of(resources: Option<&Value>) -> String {
    let Some(Value::Object(map)) = resources else {
        return String::new();
    };
    let mut parts = Vec::new();
    for (urn, v) in map {
        let (kind, id) = split_urn(urn);
        match v {
            Value::Object(inner) => {
                let children: Vec<String> =
                    inner.keys().map(|k| split_urn(k).0.to_string()).collect();
                parts.push(format!("all {} in {kind} {id}", children.join("+")));
            }
            _ => parts.push(format!("{kind} {id}")),
        }
    }
    parts.join(", ")
}

/// `com.cloudflare.api.account.zone.023e10…` -> ("zone", "023e10…"), and the
/// wildcard forms (`…zone.*`) keep their star so a blanket grant reads as one.
fn split_urn(urn: &str) -> (&str, &str) {
    let rest = urn.strip_prefix("com.cloudflare.api.").unwrap_or(urn);
    match rest.rsplit_once('.') {
        Some((kind, id)) => (kind.rsplit('.').next().unwrap_or(kind), id),
        None => (rest, "*"),
    }
}

/// The source-IP condition on a token, if it has one.
fn ip_filter(detail: &Value) -> String {
    let Some(ip) = detail
        .get("condition")
        .and_then(|c| c.get("request.ip"))
        .and_then(Value::as_object)
    else {
        return String::new();
    };
    let list = |k: &str| -> String {
        ip.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let (allow, deny) = (list("in"), list("not_in"));
    match (allow.is_empty(), deny.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!("only from {allow}"),
        (true, false) => format!("never from {deny}"),
        (false, false) => format!("only from {allow}, never from {deny}"),
    }
}

/// "3 (a, b, c)", truncated, or "none" — the reach line has to fit one row.
fn summarize(items: &[Value]) -> String {
    if items.is_empty() {
        return "none, or not listable with this credential".to_string();
    }
    let names: Vec<String> = items.iter().take(5).map(|v| str_of(v, "name")).collect();
    let more = items.len().saturating_sub(names.len());
    let mut s = format!("{} ({}", items.len(), names.join(", "));
    if more > 0 {
        s.push_str(&format!(", +{more} more"));
    }
    s.push(')');
    s
}

fn str_of(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_urn_splits_into_the_kind_and_the_id() {
        assert_eq!(
            split_urn("com.cloudflare.api.account.zone.1a2b3c4d5e6f708192a3b4c5d6e7f809"),
            ("zone", "1a2b3c4d5e6f708192a3b4c5d6e7f809")
        );
        assert_eq!(
            split_urn("com.cloudflare.api.account.a1b2c3d4e5f60718293a4b5c6d7e8f90"),
            ("account", "a1b2c3d4e5f60718293a4b5c6d7e8f90")
        );
        assert_eq!(split_urn("com.cloudflare.api.account.zone.*").1, "*");
    }

    #[test]
    fn a_nested_resource_reads_as_the_blanket_grant_it_is() {
        // This is the shape that matters: not "one zone", but "every zone this
        // account will ever have", including ones added after the token was.
        let r = serde_json::json!({
            "com.cloudflare.api.account.a1b2c3d4e5f60718293a4b5c6d7e8f90": {
                "com.cloudflare.api.account.zone.*": "*"
            }
        });
        assert_eq!(
            scope_of(Some(&r)),
            "all zone in account a1b2c3d4e5f60718293a4b5c6d7e8f90"
        );
    }

    #[test]
    fn a_flat_resource_names_just_that_object() {
        let r = serde_json::json!({
            "com.cloudflare.api.account.zone.1a2b3c4d5e6f708192a3b4c5d6e7f809": "*"
        });
        assert_eq!(scope_of(Some(&r)), "zone 1a2b3c4d5e6f708192a3b4c5d6e7f809");
        assert_eq!(scope_of(None), "");
    }

    #[test]
    fn an_ip_condition_is_reported_in_both_directions() {
        let d = serde_json::json!({
            "condition": {"request.ip": {"in": ["203.0.113.1/32"], "not_in": ["198.51.100.0/24"]}}
        });
        assert_eq!(
            ip_filter(&d),
            "only from 203.0.113.1/32, never from 198.51.100.0/24"
        );
        assert_eq!(
            ip_filter(&serde_json::json!({"condition": {}})),
            "",
            "no condition is the common case, and must not print as one"
        );
    }

    #[test]
    fn a_policy_keeps_its_permissions_both_joined_and_listed() {
        let p = serde_json::json!({
            "effect": "allow",
            "resources": {"com.cloudflare.api.account.zone.abc": "*"},
            "permission_groups": [{"name": "Zone Read"}, {"name": "DNS Write"}]
        });
        let row = flatten_policy(&p);
        assert_eq!(row["permissions"], "Zone Read, DNS Write");
        assert_eq!(row["permissionList"][1], "DNS Write");
    }

    #[test]
    fn an_empty_reach_says_why_it_might_be_empty() {
        // A zone-scoped token gets a 403 on /accounts, and reporting a bare
        // "0" would read as "this credential reaches nothing".
        assert!(summarize(&[]).contains("not listable"));
        let two = vec![
            serde_json::json!({"name": "a"}),
            serde_json::json!({"name": "b"}),
        ];
        assert_eq!(summarize(&two), "2 (a, b)");
    }
}
