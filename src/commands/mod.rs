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
pub mod identity;
pub mod login;
pub mod ping;
pub mod platform;
pub mod posture;
pub mod profile;
pub mod prompt;
pub mod settings;
pub mod tls;
pub mod whoami;
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
