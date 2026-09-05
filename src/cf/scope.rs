//! Scope resolution: which account, which zone.
//!
//! Almost every endpoint hangs off `/accounts/{id}` or `/zones/{id}`, and
//! nobody remembers a 32-character hex id. A profile may therefore hold an id,
//! a name, or nothing at all, and this turns whichever it is into the id the
//! API wants.

use anyhow::{bail, Context, Result};
use serde_json::Value;

use crate::cf::Client;
use crate::ui;

/// Turn an account name, or an empty setting, into an account id.
pub async fn account(c: &Client, want: &str) -> Result<String> {
    if looks_like_id(want) {
        return Ok(want.to_string());
    }

    let accounts = ui::spin("Resolving the account", c.list("/accounts", &[], None))
        .await
        .context("listing accounts")?;
    let names = || {
        accounts
            .iter()
            .map(|a| field(a, "name"))
            .collect::<Vec<_>>()
            .join(", ")
    };

    if want.is_empty() {
        return match accounts.len() {
            0 => bail!("this credential reaches no account"),
            1 => Ok(field(&accounts[0], "id")),
            // A scan covers one account. With several reachable there is no
            // sensible default to guess, so the choice is the operator's — and
            // the answer is worth saving, since every later run asks the same
            // question.
            _ => bail!(
                "several accounts are in scope, and a scan covers one account.\n\n{}\n\n\
                 Pass --account <NAME|ID> for a single run, or save it as this profile's \
                 default with:\n\n    mlab-cloudflare login --account <NAME|ID>",
                listing(&accounts)
            ),
        };
    }

    for a in &accounts {
        if field(a, "id") == want || field(a, "name").eq_ignore_ascii_case(want) {
            return Ok(field(a, "id"));
        }
    }
    bail!("no account named {want:?} (in scope: {})", names())
}

/// Turn a zone name, or an empty setting, into a zone id.
///
/// The lookup is a server-side filter rather than a full listing: an account
/// can hold thousands of zones, and `?name=` is exact.
pub async fn zone(c: &Client, want: &str) -> Result<String> {
    if looks_like_id(want) {
        return Ok(want.to_string());
    }
    if want.is_empty() {
        bail!("no zone selected; pass --zone NAME or set one with `mlab-cloudflare login`");
    }

    let q = vec![("name".to_string(), want.to_ascii_lowercase())];
    let found = ui::spin("Resolving the zone", c.list("/zones", &q, None))
        .await
        .context("looking up the zone")?;

    match found.len() {
        0 => bail!("no zone named {want:?} is in this credential's scope"),
        1 => Ok(field(&found[0], "id")),
        // One name can exist twice when the credential reaches two accounts
        // that both hold it, which is exactly when picking the wrong one is
        // worst.
        _ => bail!(
            "{want:?} matches {} zones; pass the zone id instead ({})",
            found.len(),
            found
                .iter()
                .map(|z| field(z, "id"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The reachable accounts as an indented block, name and id per line, so the
/// operator can copy either into `--account`.
fn listing(accounts: &[Value]) -> String {
    let width = accounts
        .iter()
        .map(|a| field(a, "name").chars().count())
        .max()
        .unwrap_or(0);
    accounts
        .iter()
        .map(|a| format!("    {:<width$}  {}", field(a, "name"), field(a, "id")))
        .collect::<Vec<_>>()
        .join("\n")
}

fn field(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// A Cloudflare account or zone id is 32 lowercase hex characters; anything
/// else is treated as a name to look up.
fn looks_like_id(s: &str) -> bool {
    s.len() == 32
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_choice_is_offered_as_something_copyable() {
        let accounts = vec![
            serde_json::json!({"name": "acme-corp", "id": "a1b2c3d4e5f60718293a4b5c6d7e8f90"}),
            serde_json::json!({"name": "labs", "id": "b2c3d4e5f60718293a4b5c6d7e8f90a1"}),
        ];
        let out = listing(&accounts);
        assert!(out.contains("acme-corp  a1b2c3d4e5f60718293a4b5c6d7e8f90"));
        assert!(
            out.contains("labs       b2c3"),
            "names are padded so the ids line up: {out}"
        );
    }

    #[test]
    fn only_a_32_hex_id_skips_the_lookup() {
        assert!(looks_like_id("1a2b3c4d5e6f708192a3b4c5d6e7f809"));
        assert!(!looks_like_id("example.com"));
        assert!(
            !looks_like_id(""),
            "an empty setting means: go and find out"
        );
        assert!(
            !looks_like_id("023E105F4ECEF8AD9CA31A8372D0C353"),
            "the API emits lowercase; an uppercase string is more likely a name"
        );
        assert!(
            !looks_like_id("023e105f4ecef8ad9ca31a8372d0c35"),
            "31 characters is not an id"
        );
    }
}
