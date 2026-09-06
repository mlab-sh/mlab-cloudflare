//! `api` — the raw handler, for every endpoint the CLI does not wrap.
//!
//! This is the lab bench: try an endpoint here, and once it earns its place,
//! give it a module of its own next to this one. The Cloudflare API has some
//! 1700 readable endpoints and this CLI will never wrap them all, so this
//! command is a permanent part of the surface rather than a stopgap.

use anyhow::{bail, Context, Result};
use clap::Args;
use reqwest::Method;
use serde_json::Value;

use crate::cf::{esc, scope, secrets, Client};
use crate::cli::Ctx;
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct ApiArgs {
    /// HTTP method: GET, POST, PUT, PATCH, DELETE
    pub method: String,
    /// Path relative to the API base, e.g. /user/tokens or /accounts/{account}/members
    pub path: String,
    /// JSON body: inline, @file, or - for stdin
    #[arg(long, short = 'd', value_name = "JSON")]
    pub data: Option<String>,
    /// Extra query parameter, repeatable: --query key=value
    ///
    /// No short form: `-q` is the global --quiet.
    #[arg(long, value_name = "K=V")]
    pub query: Vec<String>,
    /// Treat the response as a paginated list and return the items
    #[arg(long)]
    pub list: bool,
    /// With --list, page by cursor rather than by page number (audit logs, log surfaces)
    #[arg(long, requires = "list")]
    pub cursor: bool,
    /// With --list, return a single page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Print the whole envelope: success, errors, messages and result_info
    #[arg(long)]
    pub raw: bool,
    /// Replace every credential in the response by its length, before printing
    #[arg(long)]
    pub redact: bool,
    /// Serve this read from the response cache, and store it
    ///
    /// Off by default: this is the command you probe an endpoint from, and a
    /// stale answer here is far more confusing than a slow one.
    #[arg(long)]
    pub cache: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, a: ApiArgs) -> Result<()> {
    let method = Method::from_bytes(a.method.to_ascii_uppercase().as_bytes())
        .with_context(|| format!("{:?} is not an HTTP method", a.method))?;

    let mut path = a.path.clone();
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    // Resolved lazily: a path that names neither placeholder must not pay for
    // an account listing, and a zone-scoped token cannot do one anyway.
    if path.contains("{account}") {
        let id = scope::account(c, &ctx.profile.account).await?;
        path = path.replace("{account}", &esc(&id));
    }
    if path.contains("{zone}") {
        let id = scope::zone(c, &ctx.profile.zone).await?;
        path = path.replace("{zone}", &esc(&id));
    }

    let mut query = Vec::new();
    for kv in &a.query {
        let (k, v) = kv
            .split_once('=')
            .with_context(|| format!("--query expects key=value, got {kv:?}"))?;
        query.push((k.to_string(), v.to_string()));
    }

    let body = match &a.data {
        None => None,
        Some(d) => Some(read_json(d)?),
    };

    let label = format!("{method} {path}");

    if a.list {
        if body.is_some() {
            bail!("--list cannot be combined with --data");
        }
        let mut rows = match (a.cursor, a.cache) {
            (true, true) => ui::spin(&label, c.cached_list_cursor(&path, &query, a.limit)).await?,
            (true, false) => ui::spin(&label, c.list_cursor(&path, &query, a.limit)).await?,
            (false, true) => ui::spin(&label, c.cached_list(&path, &query, a.limit)).await?,
            (false, false) => ui::spin(&label, c.list(&path, &query, a.limit)).await?,
        };
        if a.redact {
            let mut all = Value::Array(rows);
            let n = secrets::redact(&mut all);
            ui::info(&format!("redacted {n} credential(s)"));
            rows = crate::cf::client::array_of(&all);
        }
        render::heading(&label);
        render::list_auto(&rows);
        render::count(rows.len(), "item");
        return Ok(());
    }

    let mut v = match (a.raw, a.cache && method == Method::GET && body.is_none()) {
        (true, _) => ui::spin(&label, c.envelope(method, &path, &query, body.as_ref())).await?,
        // Only a plain GET is cacheable, and only its result: the envelope is
        // what `--raw` is for, and a body makes the request something else.
        (false, true) => ui::spin(&label, c.cached(&path, &query)).await?,
        (false, false) => ui::spin(&label, c.request(method, &path, &query, body.as_ref())).await?,
    };
    // Several readable endpoints hand back a live credential — a tunnel's
    // connector token, a Turnstile widget's secret. `--redact` is what makes
    // the output of this command safe to paste into a ticket.
    if a.redact {
        let n = secrets::redact(&mut v);
        ui::info(&format!("redacted {n} credential(s)"));
    }
    render::one(&v);
    Ok(())
}

/// Read a JSON body from an inline string, `@file`, or `-` (stdin).
fn read_json(spec: &str) -> Result<Value> {
    let raw = if spec == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .context("reading the body from stdin")?;
        s
    } else if let Some(file) = spec.strip_prefix('@') {
        std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?
    } else {
        spec.to_string()
    };
    serde_json::from_str(&raw).context("the request body is not valid JSON")
}
