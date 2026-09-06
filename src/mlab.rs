//! The mlab.sh API, for the half of an audit Cloudflare cannot answer.
//!
//! Cloudflare knows what an account is *configured* to serve. It does not know
//! what the outside world can see, whether an origin address sits on a
//! datacenter or on somebody's home connection, or that a name nobody
//! configured here still resolves. This client fetches that second half so the
//! two can be compared.
//!
//! Everything here **spends someone's quota** — 50 IP scans and 25 domain scans
//! a day on a Pro plan — which is why nothing in this module is called without
//! a budget, and why results are cached for a week rather than for the fifteen
//! minutes the Cloudflare cache uses.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};

use crate::cf::cache::{Cache, Hit};

/// The subdirectory the results are held in, kept apart from the Cloudflare
/// cache so emptying that one does not throw these away.
pub const CACHE_DIR: &str = "mlab";

/// Base URL, overridable through `MLAB_API_URL` for testing.
const API_BASE: &str = "https://mlab.sh/api/v1";

/// How long a scan stays usable. The service refreshes an address lookup after
/// seven days of its own accord, so asking again inside that window spends
/// quota for the same answer.
pub const TTL: Duration = Duration::from_secs(7 * 24 * 3600);

/// One thing to look up, and the quota it comes out of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    /// An address the DNS plane found published.
    Ip(String),
    /// A zone, or the third-party target of a dangling record.
    Domain(String),
}

impl Scan {
    pub fn target(&self) -> &str {
        match self {
            Scan::Ip(t) | Scan::Domain(t) => t,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Scan::Ip(_) => "ip",
            Scan::Domain(_) => "domain",
        }
    }

    fn key(&self) -> String {
        format!("{} {}", self.kind(), self.target())
    }
}

/// A configured connection to mlab.sh.
pub struct Mlab {
    http: reqwest::Client,
    base: String,
    cache: Option<Cache>,
    tag: String,
}

impl Mlab {
    pub fn new(key: &str, timeout: Duration, cache: Option<Cache>) -> Result<Mlab> {
        if key.trim().is_empty() {
            bail!(
                "no mlab API key (set --mlab-key, MLAB_API_KEY, or add one with \
                 `mlab-cloudflare login --mlab-key`); it needs a Pro plan or above"
            );
        }
        let base = std::env::var("MLAB_API_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| API_BASE.to_string())
            .trim_end_matches('/')
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        let mut bearer = HeaderValue::from_str(&format!("Bearer {}", key.trim()))
            .context("the mlab key contains characters that cannot go in a header")?;
        bearer.set_sensitive(true);
        headers.insert(AUTHORIZATION, bearer);

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .user_agent(concat!("mlab-cloudflare/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the mlab HTTP client")?;

        Ok(Mlab {
            http,
            base,
            cache,
            tag: key.to_string(),
        })
    }

    /// A result already held, which costs nothing to use.
    ///
    /// Separate from [`Mlab::fetch`] so a command can say what a run will spend
    /// *before* it spends it.
    pub fn held(&self, s: &Scan) -> Option<Value> {
        let cache = self.cache.as_ref()?;
        match cache.get(&crate::cf::cache::key(&self.tag, &s.key())) {
            Some(Hit::Body(v)) => Some(v),
            _ => None,
        }
    }

    /// Look something up, spending one unit of its quota.
    pub async fn fetch(&self, s: &Scan) -> Result<Value> {
        if let Some(held) = self.held(s) {
            return Ok(held);
        }
        let fresh = match s {
            Scan::Ip(ip) => {
                self.call(Method::GET, "/scan/ip", &[("ip", ip)], None)
                    .await?
            }
            Scan::Domain(d) => self.domain(d).await?,
        };
        if let Some(cache) = &self.cache {
            cache.put(
                &crate::cf::cache::key(&self.tag, &s.key()),
                &s.key(),
                &fresh,
            );
        }
        Ok(fresh)
    }

    /// A domain scan is two calls: one to start it, one to collect it.
    ///
    /// The service returns a finished scan immediately when it has a recent
    /// one, so the poll below usually does not run at all.
    async fn domain(&self, domain: &str) -> Result<Value> {
        let started = self
            .call(
                Method::POST,
                "/scan/domain",
                &[],
                Some(&json!({ "domain": domain })),
            )
            .await?;
        if is_complete(&started) {
            return Ok(started);
        }

        // A scan of a large or heavily rate-limited domain can take a while;
        // this waits a bounded time rather than either blocking forever or
        // reporting a pending scan as an empty one.
        for wait in [2u64, 3, 5, 8, 13, 21] {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            let got = self
                .call(
                    Method::GET,
                    "/scan/domain/results",
                    &[("domain", domain)],
                    None,
                )
                .await?;
            if is_complete(&got) {
                return Ok(got);
            }
        }
        Err(anyhow!(
            "the scan of {domain} was still running after a minute; \
             run the command again to collect it"
        ))
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.request(method.clone(), &url).query(query);
        if let Some(b) = body {
            req = req.json(b);
        }

        let resp = req
            .send()
            .await
            .with_context(|| format!("{method} {url}"))?;
        let status = resp.status();
        let bytes = resp.bytes().await.context("reading the mlab response")?;

        if !status.is_success() {
            let msg = serde_json::from_slice::<Value>(&bytes)
                .ok()
                .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| String::from_utf8_lossy(&bytes).chars().take(120).collect());
            return Err(match status {
                StatusCode::UNAUTHORIZED => anyhow!("mlab rejected the key: {msg}"),
                StatusCode::FORBIDDEN => {
                    anyhow!("mlab refused: {msg}\nhint: the API needs a Pro plan or above")
                }
                StatusCode::TOO_MANY_REQUESTS => anyhow!(
                    "mlab quota exhausted: {msg}\nhint: limits are per day and shared \
                     across the organisation; cached results still work"
                ),
                s => anyhow!("mlab error {}: {msg}", s.as_u16()),
            });
        }

        let v: Value = serde_json::from_slice(&bytes).with_context(|| {
            let preview: String = String::from_utf8_lossy(&bytes).chars().take(160).collect();
            format!("decoding {method} {url}: {preview}")
        })?;
        Ok(unwrap(v))
    }
}

/// The payload of an mlab response.
///
/// The REST API wraps a result as `{"status": "ok", "data": {…}}`, while some
/// surfaces answer with the object directly. Unwrapping only the documented
/// envelope leaves both readable.
pub fn unwrap(v: Value) -> Value {
    match v.get("status").and_then(Value::as_str) {
        Some("ok") => v.get("data").cloned().unwrap_or(v),
        _ => v,
    }
}

/// Whether a domain scan has finished.
fn is_complete(v: &Value) -> bool {
    match v.get("status").and_then(Value::as_str) {
        Some("completed") => true,
        Some("pending" | "scanning" | "started") => false,
        // A body carrying results and no status is a finished scan.
        _ => v.get("results").is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scan_names_the_quota_it_spends() {
        assert_eq!(Scan::Ip("1.1.1.1".into()).kind(), "ip");
        assert_eq!(Scan::Domain("example.com".into()).kind(), "domain");
        assert_eq!(Scan::Ip("1.1.1.1".into()).target(), "1.1.1.1");
    }

    #[test]
    fn the_two_quotas_never_share_a_cache_entry() {
        // A domain and an address can be the same string in principle, and one
        // costing the other's quota would be the worst kind of surprise.
        assert_ne!(
            Scan::Ip("example".into()).key(),
            Scan::Domain("example".into()).key()
        );
    }

    #[test]
    fn only_the_documented_envelope_is_unwrapped() {
        assert_eq!(
            unwrap(json!({"status": "ok", "data": {"domain": "a.test"}})),
            json!({"domain": "a.test"})
        );
        // A finished scan answers with its own status and no envelope.
        let direct = json!({"status": "completed", "results": {"subdomains": []}});
        assert_eq!(unwrap(direct.clone()), direct);
    }

    #[test]
    fn a_scan_is_finished_when_it_says_so_or_carries_results() {
        assert!(is_complete(&json!({"status": "completed"})));
        assert!(is_complete(&json!({"results": {"subdomains": []}})));
        assert!(!is_complete(&json!({"status": "started"})));
        assert!(!is_complete(&json!({"status": "scanning"})));
        assert!(!is_complete(&json!({})));
    }

    #[test]
    fn a_missing_key_is_refused_before_any_request() {
        assert!(Mlab::new("", Duration::from_secs(5), None).is_err());
        assert!(Mlab::new("   ", Duration::from_secs(5), None).is_err());
        assert!(Mlab::new("k", Duration::from_secs(5), None).is_ok());
    }
}
