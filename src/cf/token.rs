//! Finding out which token store a credential belongs to, and asking that one.
//!
//! Cloudflare keeps user-owned and account-owned tokens in two namespaces that
//! cannot see each other, and the store that does not hold a token answers
//! `401` with code `1000 Invalid API Token` — the same answer a mistyped
//! credential gets. So a rejection is not evidence of a bad token until both
//! stores have been asked.

use anyhow::{anyhow, bail, Result};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::cf::client::ApiError;
use crate::cf::config::Owner;
use crate::cf::{esc, Client};

/// The endpoint that verifies a token held in `owner`'s store.
///
/// `None` for an account-owned token with no account: that store is addressed
/// by account id, so without one there is nothing to ask.
pub fn verify_path(owner: Owner, account: &str) -> Option<String> {
    match owner {
        Owner::User => Some("/user/tokens/verify".to_string()),
        Owner::Account if !account.is_empty() => {
            Some(format!("/accounts/{}/tokens/verify", esc(account)))
        }
        Owner::Account => None,
    }
}

/// The endpoint that returns a token's own name, policies and conditions.
pub fn detail_path(owner: Owner, account: &str, token_id: &str) -> Option<String> {
    match owner {
        Owner::User => Some(format!("/user/tokens/{}", esc(token_id))),
        Owner::Account if !account.is_empty() => Some(format!(
            "/accounts/{}/tokens/{}",
            esc(account),
            esc(token_id)
        )),
        Owner::Account => None,
    }
}

/// Verify a token, asking the store it is expected to be in first.
///
/// Returns the store that answered — which the caller should remember, so the
/// next run does not pay for a rejection to learn it again.
pub async fn verify(c: &Client, expected: Owner, account: &str) -> Result<(Owner, Value)> {
    let order = match expected {
        Owner::User => [Owner::User, Owner::Account],
        Owner::Account => [Owner::Account, Owner::User],
    };

    let mut rejected_by = Vec::new();
    for owner in order {
        let Some(path) = verify_path(owner, account) else {
            continue;
        };
        match c.request(Method::GET, &path, &[], None).await {
            Ok(v) => return Ok((owner, v)),
            // Only a refusal means "not in this store". A timeout or a 502 is
            // a fact about the network and must not be reported as a bad token.
            Err(e) if refusal(&e) => rejected_by.push(owner),
            Err(e) => return Err(e),
        }
    }

    if rejected_by.contains(&Owner::User) && account.is_empty() {
        bail!(
            "the token is not in your user token store, and there is no account to check the \
             other one against.\n\
             Tokens created under Manage Account -> Account API tokens belong to the account \
             rather than to you — that page is also where the R2 credentials now come from — \
             and they can only be verified against their own account.\n\
             Re-run with --account <ACCOUNT ID>: the 32-character id in the dashboard URL, \
             dash.cloudflare.com/<id>, or on the right of the account home page."
        );
    }
    Err(anyhow!(
        "the token was rejected by {} token store{}; check that it was pasted whole and has not \
         been revoked",
        rejected_by
            .iter()
            .map(Owner::to_string)
            .collect::<Vec<_>>()
            .join(" and the "),
        if rejected_by.len() > 1 { "s" } else { "" }
    ))
}

/// Whether a failure means "this store does not hold that token".
fn refusal(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<ApiError>(),
        Some(a) if a.status == StatusCode::UNAUTHORIZED || a.status == StatusCode::FORBIDDEN
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCT: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f809";

    #[test]
    fn each_store_is_addressed_differently() {
        assert_eq!(verify_path(Owner::User, "").unwrap(), "/user/tokens/verify");
        assert_eq!(
            verify_path(Owner::Account, ACCT).unwrap(),
            format!("/accounts/{ACCT}/tokens/verify")
        );
    }

    #[test]
    fn the_account_store_has_no_address_without_an_account() {
        // Which is why the caller has to ask for one rather than retry blindly.
        assert!(verify_path(Owner::Account, "").is_none());
        assert!(detail_path(Owner::Account, "", "abc").is_none());
    }

    #[test]
    fn a_token_id_is_escaped_into_its_path() {
        assert_eq!(
            detail_path(Owner::User, "", "ab/cd").unwrap(),
            "/user/tokens/ab%2Fcd"
        );
    }

    #[test]
    fn only_a_refusal_counts_as_the_wrong_store() {
        let err = |status| {
            anyhow::Error::new(ApiError {
                status,
                code: 1000,
                message: "Invalid API Token".into(),
                retry_after: None,
            })
        };
        assert!(refusal(&err(StatusCode::UNAUTHORIZED)));
        assert!(refusal(&err(StatusCode::FORBIDDEN)));
        assert!(
            !refusal(&err(StatusCode::BAD_GATEWAY)),
            "an outage is not evidence about which store holds the token"
        );
        assert!(
            !refusal(&anyhow!("connection refused")),
            "a transport failure is not an API refusal"
        );
    }
}
