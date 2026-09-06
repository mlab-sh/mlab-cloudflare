//! One module per command.
//!
//! Each exposes a `run` taking whatever it needs — a [`Client`](crate::cf::Client)
//! and the resolved [`Ctx`](crate::cli::Ctx) for the API commands, nothing but
//! its own arguments for the ones that only touch the config file.

pub mod accounts;
pub mod activity;
pub mod api;
pub mod cache;
pub mod dns;
pub mod egress;
pub mod identity;
pub mod login;
pub mod network;
pub mod ping;
pub mod platform;
pub mod posture;
pub mod profile;
pub mod prompt;
pub mod settings;
pub mod snapshot;
pub mod tls;
pub mod whoami;
pub mod zerotrust;
pub mod zones;

/// The names of the rows matching `pred`, for the one-line observations the
/// list commands make about data they already fetched.
pub fn named_where(
    rows: &[serde_json::Value],
    pred: impl Fn(&serde_json::Value) -> bool,
) -> Vec<String> {
    rows.iter()
        .filter(|r| pred(r))
        .map(|r| {
            r.get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("(unnamed)")
                .to_string()
        })
        .collect()
}

/// The zones this run covers: the one named by `--zone`, or every zone of the
/// account being scanned.
///
/// Four planes ask this same question, and four copies of the answer is four
/// chances for them to disagree about what a run covered.
pub async fn zones_in_scope(
    c: &crate::cf::Client,
    ctx: &crate::cli::Ctx,
) -> anyhow::Result<Vec<serde_json::Value>> {
    use crate::cf::{esc, scope};

    if ctx.profile.zone.is_empty() {
        let account = scope::account(c, &ctx.profile.account).await?;
        crate::ui::spin(
            "Listing zones",
            c.cached_list("/zones", &[("account.id".to_string(), account)], None),
        )
        .await
    } else {
        let id = scope::zone(c, &ctx.profile.zone).await?;
        Ok(vec![c.cached(&format!("/zones/{}", esc(&id)), &[]).await?])
    }
}

/// Shorten the 32-character ids inside a request so the endpoint stays visible.
///
/// A cache row is only useful if you can see what was asked for, and a full
/// zone id eats the width the path needs. Eight characters still tell two zones
/// apart at a glance.
pub fn abbreviate(request: &str) -> String {
    let short = |seg: &str| {
        if seg.len() == 32 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
            format!("{}…", &seg[..8])
        } else {
            seg.to_string()
        }
    };
    request
        .split('/')
        // An id can follow a `/` in a path or a `=` in a query parameter, and
        // both eat the width the endpoint needs.
        .map(|seg| match seg.split_once('=') {
            Some((k, v)) => format!("{k}={}", short(v)),
            None => short(seg),
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_shortened_and_the_endpoint_is_kept() {
        // A row is only useful if you can see which endpoint it is about, and
        // a full zone id eats the width the path needs.
        assert_eq!(
            abbreviate("LIST /zones/1a2b3c4d5e6f708192a3b4c5d6e7f809/dns_records"),
            "LIST /zones/1a2b3c4d…/dns_records"
        );
    }

    #[test]
    fn an_id_in_a_query_parameter_is_shortened_too() {
        assert_eq!(
            abbreviate("LIST /zones account.id=1a2b3c4d5e6f708192a3b4c5d6e7f809"),
            "LIST /zones account.id=1a2b3c4d…"
        );
    }

    #[test]
    fn a_path_segment_that_is_not_an_id_is_left_alone() {
        assert_eq!(abbreviate("LIST /accounts"), "LIST /accounts");
        assert_eq!(
            abbreviate("GET /zones/example.com/dnssec"),
            "GET /zones/example.com/dnssec"
        );
    }
}
