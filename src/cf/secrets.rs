//! The fields that must never be written to disk, and how to remove them.
//!
//! One list, used by everything that persists an API response, so a field
//! cannot be redacted in one place and stored in another.

use serde_json::Value;

/// Field names holding an actual credential in a GET response.
///
/// Deliberately an explicit list of exact names rather than a substring rule.
/// The audit log alone carries `actor_token_id` and `actor_token_name` on every
/// entry, and a redactor that blanks those is one that gets switched off.
///
/// What is on the list is what the API really hands back on a read: the
/// connector token of a Cloudflare Tunnel, a Turnstile widget's server-side
/// secret, an Access identity provider's OIDC client secret, the TSIG key of a
/// secondary DNS peer, an Images or Stream signing key, the object-store
/// credentials embedded in a Logpush destination.
pub const SECRET_FIELDS: [&str; 16] = [
    "secret",
    "client_secret",
    "secret_access_key",
    "private_key",
    "credentials_file",
    "token",
    "site_token",
    "api_token",
    "api_key",
    "auth_key",
    "service_key",
    "password",
    "passphrase",
    "signing_key",
    "tsig_secret",
    "webhook_secret",
];

/// What replaces a secret: its length, and nothing else.
///
/// A length is not a secret and it is what a strength check needs, so a
/// redacted snapshot can still be audited, or counted for how much the
/// credential exposes. The value itself never reaches the disk.
pub fn marker(len: usize) -> String {
    format!("<redacted:{len}>")
}

/// Replace every secret in a document, at any depth.
///
/// Returns how many were replaced, which is itself worth recording: it is the
/// measure of what a credential hands over.
pub fn redact(v: &mut Value) -> usize {
    match v {
        Value::Object(map) => {
            let mut n = 0;
            for (k, val) in map.iter_mut() {
                if SECRET_FIELDS.contains(&k.as_str()) {
                    if let Some(s) = val.as_str() {
                        if !s.is_empty() {
                            *val = Value::String(marker(s.chars().count()));
                            n += 1;
                            continue;
                        }
                    }
                }
                n += redact(val);
            }
            n
        }
        Value::Array(items) => items.iter_mut().map(redact).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_secret_is_replaced_by_its_length_and_nothing_else() {
        let mut v = json!({"secret": "0x4AAF00000000"});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(v["secret"], json!("<redacted:14>"));
    }

    #[test]
    fn secrets_are_found_however_deeply_they_sit() {
        let mut v = json!({"result": [{"config": {"client_secret": "abcdef"}}]});
        assert_eq!(redact(&mut v), 1);
        assert_eq!(
            v["result"][0]["config"]["client_secret"],
            json!("<redacted:6>")
        );
    }

    #[test]
    fn a_token_identifier_is_not_a_token() {
        // Every audit log entry carries these; a substring rule on "token"
        // would blank the field that says which credential did the thing.
        let mut v = json!({"actor_token_id": "ab12", "actor_token_name": "ci-deploy"});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["actor_token_name"], json!("ci-deploy"));
    }

    #[test]
    fn an_empty_secret_is_left_alone_rather_than_marked() {
        // Marking it would turn "this widget has no secret" into "this widget
        // has a secret of length zero", which reads as configured.
        let mut v = json!({"secret": ""});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["secret"], json!(""));
    }

    #[test]
    fn everything_else_survives_untouched() {
        let mut v = json!({"name": "example.com", "status": "active", "proxied": true});
        assert_eq!(redact(&mut v), 0);
        assert_eq!(v["name"], json!("example.com"));
        assert_eq!(v["proxied"], json!(true));
    }
}
