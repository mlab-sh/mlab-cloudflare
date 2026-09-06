//! HTTP handler for the Cloudflare v4 API.
//!
//! One base URL, one envelope, two ways to authenticate. Everything the CLI
//! sends goes through [`Client::request`], which checks the envelope and hands
//! back only the `result`.

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::cf::cache::{self, Cache, Hit, Refusal};
use crate::cf::config::{Auth, Profile};
use crate::cf::record::Recorder;

/// Cap on a response body, so a misbehaving endpoint cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Default page size. The API caps most collections at 100 per page and a few
/// (zones) at 50.
const PAGE_SIZE: u32 = 50;

/// The size to fall back to when an endpoint rejects [`PAGE_SIZE`].
///
/// A few endpoints validate list options strictly rather than ignoring what
/// they do not use: `/accounts/{id}/pages/projects` answers `400 Invalid list
/// options provided` for a `per_page` of 25 or 50, and accepts 10. Rather than
/// slow every collection down to that, the first refusal drops this one call to
/// a size the strict endpoints take.
const STRICT_PAGE_SIZE: u32 = 10;

/// Base URL, overridable through `CLOUDFLARE_API_URL` for testing.
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// How many times a 429 or a 5xx is retried before giving up.
///
/// The API allows 1200 requests per five minutes per user, shared with every
/// other tool on the same credential. An audit walks hundreds of endpoints
/// across every zone, so hitting the ceiling is normal operation rather than
/// an error, and a bounded wait is the right answer to it.
const MAX_RETRIES: u32 = 3;

/// A non-2xx response, or a 200 the envelope declares a failure.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    /// Cloudflare's numeric error code, e.g. 10000 for an authentication error.
    pub code: i64,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status.is_success() {
            // A 2xx carrying `success: false`. The transport worked and the
            // request did not, and "API error 200" reads as a contradiction.
            f.write_str("API refused the request")?;
        } else {
            write!(f, "API error {}", self.status.as_u16())?;
        }
        if self.code != 0 {
            write!(f, " [{}]", self.code)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(ra) = self.retry_after {
            write!(f, " (retry after {ra}s)")?;
        }
        match self.status {
            StatusCode::UNAUTHORIZED => write!(
                f,
                "\nhint: the credential was rejected; check it with `mlab-cloudflare whoami`"
            )?,
            StatusCode::FORBIDDEN => write!(
                f,
                "\nhint: the credential is valid but lacks the permission for this endpoint, \
                 or the account/zone is out of its scope"
            )?,
            StatusCode::TOO_MANY_REQUESTS => write!(
                f,
                "\nhint: 1200 requests per five minutes are allowed per credential, \
                 shared with every other tool using it"
            )?,
            _ => {}
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A configured connection to the Cloudflare API.
pub struct Client {
    http: reqwest::Client,
    base: String,
    auth: Auth,
    /// Absent when caching is switched off entirely.
    cache: Option<Cache>,
    /// A fingerprint of the credential, so two profiles never share entries.
    tag: String,
    /// Set by `snapshot` to keep what the API said. Sitting on the same path as
    /// the cache is what makes it capture configuration and never liveness.
    recorder: std::sync::OnceLock<std::sync::Arc<Recorder>>,
}

impl Client {
    /// Build a client from a validated profile.
    pub fn new(profile: &Profile, timeout: Duration) -> Result<Self> {
        Client::with_cache(profile, timeout, None)
    }

    /// The same, with an on-disk cache for the configuration reads.
    pub fn with_cache(profile: &Profile, timeout: Duration, cache: Option<Cache>) -> Result<Self> {
        profile.validate()?;

        let base = std::env::var("CLOUDFLARE_API_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| API_BASE.to_string())
            .trim_end_matches('/')
            .to_string();

        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        match profile.auth {
            Auth::Token => {
                let mut v = HeaderValue::from_str(&format!("Bearer {}", profile.token.trim()))
                    .context("the api token contains characters that cannot go in a header")?;
                v.set_sensitive(true);
                headers.insert(AUTHORIZATION, v);
            }
            Auth::Key => {
                headers.insert(
                    "X-Auth-Email",
                    HeaderValue::from_str(profile.email.trim())
                        .context("the email contains characters that cannot go in a header")?,
                );
                let mut v = HeaderValue::from_str(profile.api_key.trim())
                    .context("the api key contains characters that cannot go in a header")?;
                v.set_sensitive(true);
                headers.insert("X-Auth-Key", v);
            }
        }

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .user_agent(concat!("mlab-cloudflare/", env!("CARGO_PKG_VERSION")))
            // The credential rides in a default header, which reqwest would
            // replay on a cross-host redirect; refuse to follow one instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the HTTP client")?;

        // The credential itself never reaches the key; what identifies it is
        // enough to tell two profiles apart and to miss after a rotation.
        let tag = match profile.auth {
            Auth::Token => profile.token.clone(),
            Auth::Key => format!("{}:{}", profile.email, profile.api_key),
        };

        Ok(Client {
            http,
            base,
            auth: profile.auth,
            cache,
            tag,
            recorder: std::sync::OnceLock::new(),
        })
    }

    /// A GET whose answer is configuration rather than liveness, so it may be
    /// served from the cache.
    ///
    /// Deliberately a separate method from [`Client::request`]: `ping` and
    /// `whoami` exist to say whether a credential works *now*, and a cached
    /// answer would have them report a revoked token as active. Choosing the
    /// cache has to be a decision at the call site, not a default the liveness
    /// checks have to remember to opt out of.
    pub async fn cached(&self, path: &str, query: &[(String, String)]) -> Result<Value> {
        self.through_cache(&format!("GET {path}"), query, || {
            self.request(Method::GET, path, query, None)
        })
        .await
    }

    /// A cached collection, stored assembled rather than page by page.
    pub async fn cached_list(
        &self,
        path: &str,
        query: &[(String, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let v = self
            .through_cache(&format!("LIST {path}"), query, || async {
                Ok(Value::Array(self.list(path, query, limit).await?))
            })
            .await?;
        Ok(array_of(&v))
    }

    /// A cached cursor-paginated collection.
    pub async fn cached_list_cursor(
        &self,
        path: &str,
        query: &[(String, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let v = self
            .through_cache(&format!("CURSOR {path}"), query, || async {
                Ok(Value::Array(self.list_cursor(path, query, limit).await?))
            })
            .await?;
        Ok(array_of(&v))
    }

    /// Serve `label` + `query` from the cache, or run `fetch` and store it.
    async fn through_cache<F, Fut>(
        &self,
        label: &str,
        query: &[(String, String)],
        fetch: F,
    ) -> Result<Value>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Value>>,
    {
        let Some(cache) = &self.cache else {
            // Without a cache there is no shared path to record on, so the
            // fetch is recorded here instead.
            let got = fetch().await;
            if let Some(r) = self.recorder.get() {
                let label = format!("{label} {}", query_suffix(query));
                match &got {
                    Ok(v) => r.body(label.trim(), v),
                    Err(e) => r.refusal(label.trim(), &one_line(e)),
                }
            }
            return got;
        };
        // The query is part of what was asked for, so it is part of the key;
        // sorted, because two calls that differ only in argument order are the
        // same request.
        let request = format!("{label} {}", query_suffix(query));
        let key = cache::key(&self.tag, &request);

        // A recorded run wants what the API said for this request, whether the
        // answer came from the cache or from the network.
        let keep = |v: &Value| {
            if let Some(r) = self.recorder.get() {
                r.body(request.trim(), v);
            }
        };
        let keep_refusal = |why: &str| {
            if let Some(r) = self.recorder.get() {
                r.refusal(request.trim(), why);
            }
        };

        match cache.get(&key) {
            Some(Hit::Body(v)) => {
                keep(&v);
                return Ok(v);
            }
            // Replayed with its own status and message, so a report says the
            // same thing it would have said after asking again.
            Some(Hit::Refused(r)) => {
                keep_refusal(&format!("{} {}", r.status, r.message));
                return Err(ApiError {
                    status: StatusCode::from_u16(r.status).unwrap_or(StatusCode::BAD_REQUEST),
                    code: r.code,
                    message: r.message,
                    retry_after: None,
                }
                .into());
            }
            None => {}
        }

        match fetch().await {
            Ok(fresh) => {
                cache.put(&key, request.trim(), &fresh);
                keep(&fresh);
                Ok(fresh)
            }
            Err(e) => {
                keep_refusal(&one_line(&e));
                if let Some(api) = e.downcast_ref::<ApiError>() {
                    if worth_remembering(api) {
                        cache.put_refusal(
                            &key,
                            request.trim(),
                            Refusal {
                                status: api.status.as_u16(),
                                code: api.code,
                                message: api.message.clone(),
                            },
                        );
                    }
                }
                Err(e)
            }
        }
    }

    /// Keep every configuration read of this run. Called once, by `snapshot`.
    pub fn record_into(&self, recorder: std::sync::Arc<Recorder>) {
        let _ = self.recorder.set(recorder);
    }

    pub fn auth(&self) -> Auth {
        self.auth
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    /// One request, one checked envelope, the `result` field on its own.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let v = self.envelope(method, path, query, body).await?;
        Ok(result_of(v))
    }

    /// The same, but keeping `success`, `errors`, `messages` and `result_info`.
    /// Only the paging code and `api --raw` need those.
    pub async fn envelope(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let mut attempt = 0;
        loop {
            match self.once(method.clone(), path, query, body).await {
                Err(e) => match e.downcast_ref::<ApiError>() {
                    Some(api) if retryable(api) && attempt < MAX_RETRIES => {
                        let wait = api.retry_after.unwrap_or(1 << attempt).clamp(1, 60);
                        crate::ui::info(&format!(
                            "{} {path}: {}, retrying in {wait}s",
                            method,
                            api.status.as_u16()
                        ));
                        tokio::time::sleep(Duration::from_secs(wait)).await;
                        attempt += 1;
                    }
                    _ => return Err(e),
                },
                ok => return ok,
            }
        }
    }

    async fn once(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.request(method.clone(), &url);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.header(CONTENT_TYPE, "application/json").json(b);
        }

        let resp = req.send().await.map_err(|e| {
            // reqwest hides the interesting part (DNS, refused, TLS) in the
            // source chain, so flatten it before adding a hint.
            let cause = error_chain(&e);
            let mut msg = format!("{method} {url}: {cause}");
            if e.is_timeout() {
                msg.push_str("\nhint: raise --timeout");
            } else if e.is_connect() {
                msg.push_str("\nhint: is api.cloudflare.com reachable from here?");
            }
            anyhow!(msg)
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(anyhow!(
                "{method} {url} redirected to {to}; not following it, the credential would leak to the new host"
            ));
        }

        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = resp.bytes().await.context("reading the response body")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!("response body over {MAX_RESPONSE_BYTES} bytes"));
        }

        if !status.is_success() {
            return Err(parse_error(status, &bytes, retry_after).into());
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }

        let v: Value = serde_json::from_slice(&bytes).with_context(|| {
            let preview: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
            format!("decoding the response of {method} {url}: {preview}")
        })?;

        // A 200 with `success: false` is a refusal, not a result. The status
        // code alone would let it through as an empty list.
        if v.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(parse_error(status, &bytes, retry_after).into());
        }
        Ok(v)
    }

    /// A collection endpoint, with every page walked.
    ///
    /// Most of the API does not paginate at all and answers with the whole
    /// collection; the ones that do use `page`/`per_page` and report
    /// `result_info.total_pages`. Both are handled here so callers never see
    /// the difference. `limit` takes a single page of that size instead.
    pub async fn list(
        &self,
        path: &str,
        query: &[(String, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let mut per_page = limit.unwrap_or(PAGE_SIZE);
        let mut out = Vec::new();
        let mut page = 1u32;

        loop {
            let mut q = query.to_vec();
            q.push(("page".into(), page.to_string()));
            q.push(("per_page".into(), per_page.to_string()));

            let env = match self.envelope(Method::GET, path, &q, None).await {
                Ok(env) => env,
                // A few endpoints validate list options rather than ignoring
                // the ones they do not use, and refuse a page size they
                // consider too large. Ask the same page again at a size they
                // take, rather than slowing every other collection to it.
                Err(e) if limit.is_none() && per_page > STRICT_PAGE_SIZE && rejects_paging(&e) => {
                    per_page = STRICT_PAGE_SIZE;
                    q.pop();
                    q.push(("per_page".into(), per_page.to_string()));
                    self.envelope(Method::GET, path, &q, None).await?
                }
                Err(e) => return Err(e),
            };
            let items = array_of(&result_of(env.clone()));
            let got = items.len();
            out.extend(items);

            // An endpoint that ignores paging returns the same body forever;
            // total_pages is what tells the two cases apart.
            let total = env
                .get("result_info")
                .and_then(|i| i.get("total_pages"))
                .and_then(Value::as_u64)
                .unwrap_or(1);
            if limit.is_some() || got == 0 || u64::from(page) >= total {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// A cursor-paginated endpoint: audit logs, and the newer log surfaces.
    pub async fn list_cursor(
        &self,
        path: &str,
        query: &[(String, String)],
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut q = query.to_vec();
            if let Some(n) = limit {
                q.push(("limit".into(), n.to_string()));
            }
            if let Some(c) = &cursor {
                q.push(("cursor".into(), c.clone()));
            }

            let env = self.envelope(Method::GET, path, &q, None).await?;
            let items = array_of(&result_of(env.clone()));
            let got = items.len();
            out.extend(items);

            cursor = env
                .get("result_info")
                .and_then(|i| i.get("cursor"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if limit.is_some() || got == 0 || cursor.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

/// The query part of a request key: sorted, because two calls that differ only
/// in argument order are the same request.
fn query_suffix(query: &[(String, String)]) -> String {
    let mut parts: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
    parts.sort();
    parts.join("&")
}

/// The first line of an error, which is the one that names the cause.
fn one_line(e: &anyhow::Error) -> String {
    format!("{e:#}")
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Whether a refusal is the endpoint objecting to the page size we asked for.
///
/// Matched on the message rather than the status alone: a `400` covers a great
/// many things, and retrying an unrelated one at a different page size would
/// only ask a bad question twice.
fn rejects_paging(e: &anyhow::Error) -> bool {
    matches!(
        e.downcast_ref::<ApiError>(),
        Some(a) if a.status == StatusCode::BAD_REQUEST
            && {
                let m = a.message.to_ascii_lowercase();
                // Two wordings for the same objection: "Invalid list options
                // provided" from Pages, "per_page (3) must be a multiple of 5"
                // from the alert history.
                m.contains("list options") || m.contains("per_page")
            }
    )
}

/// Whether a refusal is a fact rather than a moment, and so worth remembering.
///
/// A `4xx` here is almost always about the plan or the token: a free zone will
/// still answer `404` on the managed-ruleset phase in a second, and a token
/// without a permission will still lack it. A `429` is the opposite — it is
/// entirely about the moment — and a `5xx` says nothing about the request at
/// all, so neither is stored.
fn worth_remembering(e: &ApiError) -> bool {
    e.status.is_client_error() && e.status != StatusCode::TOO_MANY_REQUESTS
}

/// Whether a failure is worth waiting out rather than reporting.
fn retryable(e: &ApiError) -> bool {
    e.status == StatusCode::TOO_MANY_REQUESTS || e.status.is_server_error()
}

/// The payload of an envelope, or the body itself when there is no envelope.
///
/// A handful of endpoints (`/zones/{id}/dns_records/export`, the log surfaces)
/// answer with bare content, so an unwrap that insisted on `result` would drop
/// them.
pub fn result_of(v: Value) -> Value {
    match v {
        Value::Object(ref map) if map.contains_key("result") && map.contains_key("success") => {
            map.get("result").cloned().unwrap_or(Value::Null)
        }
        other => other,
    }
}

/// Turn an error body into a typed error. Cloudflare answers failures with the
/// same envelope it uses for results, so both paths land here.
fn parse_error(status: StatusCode, body: &[u8], retry_after: Option<u64>) -> ApiError {
    // Never echo an unparsed body whole: an edge refusal is a full HTML page,
    // which buries the status code under a stylesheet.
    let text = summarize(&String::from_utf8_lossy(body));

    let (code, message) = match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let errors = v.get("errors").and_then(Value::as_array).cloned();
            match errors.as_deref() {
                Some([first, rest @ ..]) => {
                    let code = first.get("code").and_then(Value::as_i64).unwrap_or(0);
                    let mut msg = first
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    // Several distinct refusals often arrive together, one per
                    // scope the credential could not reach; reporting the first
                    // alone hides which of them actually failed.
                    for e in rest {
                        if let Some(m) = e.get("message").and_then(Value::as_str) {
                            msg.push_str("; ");
                            msg.push_str(m);
                        }
                    }
                    (code, if msg.is_empty() { text.clone() } else { msg })
                }
                // Not every refusal uses the envelope. A few endpoints answer
                // with a bare `{"message": ...}`, and echoing that as JSON puts
                // braces and quotes in front of the sentence that explains the
                // problem.
                _ => (
                    0,
                    v.get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| text.clone()),
                ),
            }
        }
        Err(_) => (0, text),
    };

    ApiError {
        status,
        code,
        message,
        retry_after,
    }
}

/// Reduce a response body to one readable line: markup stripped, whitespace
/// collapsed, truncated.
fn summarize(body: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut tag = String::new();
    // <style> and <script> hold text that is not prose; stripping their tags
    // alone would leave a stylesheet in the error message.
    let mut in_opaque = false;
    let mut last_space = true;

    for ch in body.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let name = tag.trim().to_ascii_lowercase();
                if name.starts_with("style") || name.starts_with("script") {
                    in_opaque = true;
                } else if name.starts_with("/style") || name.starts_with("/script") {
                    in_opaque = false;
                }
            }
            c if in_tag => tag.push(c),
            _ if in_opaque => {}
            c if c.is_whitespace() => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c => {
                out.push(c);
                last_space = false;
                if out.chars().count() >= 160 {
                    out.push('…');
                    break;
                }
            }
        }
    }

    let trimmed = out.trim();
    if trimmed.is_empty() && !body.is_empty() {
        return format!("non-JSON body, {} bytes", body.len());
    }
    trimmed.to_string()
}

/// Flatten an error and its sources into one line.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

/// A JSON value as a vector: arrays pass through, `null` is empty.
///
/// One shape needs unwrapping. A few collections arrive nested under a single
/// name — `/r2/buckets` answers `{"buckets": [...]}` rather than an array — and
/// treating that as one item makes ten buckets read as one. The rule is
/// deliberately narrow: an object with exactly one field, whose value is an
/// array. Anything else is a single object and stays one.
pub fn array_of(v: &Value) -> Vec<Value> {
    match v {
        Value::Array(a) => a.clone(),
        Value::Null => Vec::new(),
        Value::Object(map) if map.len() == 1 => match map.values().next() {
            Some(Value::Array(a)) => a.clone(),
            _ => vec![v.clone()],
        },
        other => vec![other.clone()],
    }
}

/// Percent-escape one path segment.
pub fn esc(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn esc_escapes_path_separators() {
        assert_eq!(esc("abc-123_x.y~z"), "abc-123_x.y~z");
        assert_eq!(esc("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn the_envelope_is_only_unwrapped_when_it_is_one() {
        assert_eq!(
            result_of(json!({"success": true, "errors": [], "result": {"id": 1}})),
            json!({"id": 1})
        );
        // An object that happens to carry a `result` field is not an envelope.
        let plain = json!({"result": "pass", "name": "check"});
        assert_eq!(result_of(plain.clone()), plain);
    }

    #[test]
    fn a_null_result_survives_as_null_rather_than_the_envelope() {
        assert_eq!(
            result_of(json!({"success": true, "errors": [], "result": null})),
            Value::Null
        );
    }

    #[test]
    fn every_error_in_the_envelope_is_reported_not_just_the_first() {
        let body = br#"{"success":false,"errors":[
            {"code":10000,"message":"Authentication error"},
            {"code":9109,"message":"Zone not owned by this account"}]}"#;
        let e = parse_error(StatusCode::FORBIDDEN, body, None);
        assert_eq!(e.code, 10000);
        assert!(e.message.contains("Authentication error"));
        assert!(
            e.message.contains("Zone not owned"),
            "the second refusal is the one that says why: {}",
            e.message
        );
    }

    #[test]
    fn a_refusal_that_arrived_with_a_200_does_not_read_as_an_error_code() {
        let e = parse_error(
            StatusCode::OK,
            br#"{"success":false,"errors":[{"code":7003,"message":"Could not route"}]}"#,
            None,
        );
        let shown = e.to_string();
        assert!(shown.starts_with("API refused the request"), "{shown}");
        assert!(
            !shown.contains("200"),
            "the status is not the story: {shown}"
        );
        assert!(shown.contains("Could not route"));
    }

    #[test]
    fn a_bare_message_is_read_rather_than_echoed_as_json() {
        // What /accounts/{id}/logs/audit answers when a parameter is missing.
        let e = parse_error(
            StatusCode::BAD_REQUEST,
            br#"{"message":"query parameter 'before' is required"}"#,
            None,
        );
        assert_eq!(e.message, "query parameter 'before' is required");
        assert!(!e.to_string().contains('{'), "no JSON in the sentence");
    }

    #[test]
    fn a_refusal_with_no_error_list_still_says_something() {
        let e = parse_error(StatusCode::BAD_GATEWAY, b"<html>nope</html>", None);
        assert_eq!(e.message, "nope");
        assert_eq!(e.code, 0);
    }

    #[test]
    fn only_a_complaint_about_list_options_reduces_the_page_size() {
        let err = |status, message: &str| {
            anyhow::Error::new(ApiError {
                status,
                code: 0,
                message: message.into(),
                retry_after: None,
            })
        };
        assert!(rejects_paging(&err(
            StatusCode::BAD_REQUEST,
            "Invalid list options provided. Review the documentation."
        )));
        assert!(
            rejects_paging(&err(
                StatusCode::BAD_REQUEST,
                "per_page (3) must be a multiple of 5"
            )),
            "the same objection, worded differently"
        );
        assert!(
            !rejects_paging(&err(
                StatusCode::BAD_REQUEST,
                "Plan level does not allow this"
            )),
            "another 400 is a different problem, and asking it again at page size 10 \
             only asks a bad question twice"
        );
        assert!(!rejects_paging(&err(
            StatusCode::FORBIDDEN,
            "Invalid list options"
        )));
    }

    #[test]
    fn only_refusals_that_are_facts_are_remembered() {
        let at = |status| ApiError {
            status,
            code: 0,
            message: String::new(),
            retry_after: None,
        };
        assert!(worth_remembering(&at(StatusCode::FORBIDDEN)));
        assert!(worth_remembering(&at(StatusCode::NOT_FOUND)));
        assert!(
            worth_remembering(&at(StatusCode::BAD_REQUEST)),
            "the plan-level refusal arrives as a 400"
        );
        assert!(
            !worth_remembering(&at(StatusCode::TOO_MANY_REQUESTS)),
            "a rate limit is entirely about the moment"
        );
        assert!(
            !worth_remembering(&at(StatusCode::BAD_GATEWAY)),
            "an outage says nothing about the request"
        );
    }

    #[test]
    fn only_rate_limits_and_server_faults_are_waited_out() {
        let at = |status| ApiError {
            status,
            code: 0,
            message: String::new(),
            retry_after: None,
        };
        assert!(retryable(&at(StatusCode::TOO_MANY_REQUESTS)));
        assert!(retryable(&at(StatusCode::BAD_GATEWAY)));
        assert!(
            !retryable(&at(StatusCode::FORBIDDEN)),
            "a missing permission will still be missing in a second"
        );
        assert!(!retryable(&at(StatusCode::NOT_FOUND)));
    }

    #[test]
    fn an_html_error_page_is_reduced_to_a_line() {
        let page = "<!doctype html><html><head><title>Error 1015</title>\
                    <style>body {font-family:Tahoma;}</style></head>\
                    <body><h1>You are being rate limited</h1></body></html>";
        let got = summarize(page);
        assert!(
            got.contains("rate limited"),
            "the useful part survives: {got}"
        );
        assert!(!got.contains('<'), "no markup survives");
        assert!(!got.contains("Tahoma"), "the stylesheet goes with its tag");
    }

    #[test]
    fn a_body_with_no_text_at_all_is_described_rather_than_echoed() {
        assert_eq!(
            summarize("<html><body></body></html>"),
            "non-JSON body, 26 bytes"
        );
        assert_eq!(summarize(""), "");
    }

    #[test]
    fn array_of_normalizes_page_results() {
        assert_eq!(array_of(&json!([1, 2])).len(), 2);
        assert!(array_of(&Value::Null).is_empty());
        assert_eq!(
            array_of(&json!({"id": 1})).len(),
            1,
            "a single object is a list of one"
        );
    }

    #[test]
    fn a_collection_nested_under_one_name_is_the_collection() {
        // `/r2/buckets` answers this shape; counting it as one item makes ten
        // buckets read as one.
        assert_eq!(
            array_of(&json!({"buckets": [{"name": "a"}, {"name": "b"}]})).len(),
            2
        );
    }

    #[test]
    fn the_unwrapping_does_not_swallow_ordinary_objects() {
        // One field that is not an array, or more than one field: a real object.
        assert_eq!(array_of(&json!({"subdomain": "acme"})).len(), 1);
        assert_eq!(array_of(&json!({"names": ["a"], "count": 1})).len(), 1);
        assert_eq!(
            array_of(&json!({"hosts": []})).len(),
            0,
            "an empty one is empty"
        );
    }
}
