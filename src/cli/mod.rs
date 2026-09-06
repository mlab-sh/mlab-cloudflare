//! The command line surface, and the dispatch behind it.
//!
//! Adding a command means: a module under [`crate::commands`], a variant in
//! [`Cmd`], and one arm in [`run`].

mod context;

pub use context::{Ctx, Overrides};

use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::{Args, Parser, Subcommand};

use crate::cf::{cache, config, Client};
use crate::commands;
use crate::ui::{self, render};

#[derive(Parser, Debug)]
#[command(
    name = "mlab-cloudflare",
    version,
    about = "Read a Cloudflare account and its zones over the v4 API",
    long_about = "Read a Cloudflare account and its zones over the v4 API.\n\n\
                  Credentials live in profiles in $HOME/.mlab/cloudflare.conf; run \
                  `mlab-cloudflare login` once to create one. Flags override environment \
                  variables (MLAB_CLOUDFLARE_*, then CLOUDFLARE_*, then CF_*), which \
                  override the profile.",
    after_help = "Create a read-only API token at dash.cloudflare.com/profile/api-tokens \
                  (the \"Read all resources\" template is the closest fit).\n\n\
                  A token created under Manage Account -> Account API tokens instead belongs \
                  to the account, not to you, and needs --account to be verified at all."
)]
pub struct Cli {
    /// Profile to use (default: the one marked default in the config)
    #[arg(long, short = 'p', global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Credential kind: a scoped API token, or the Global API Key
    #[arg(long, global = true, value_name = "token|key")]
    pub auth: Option<String>,

    /// API token; prefer CLOUDFLARE_API_TOKEN, a command line is visible to other users
    #[arg(long, global = true, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Account email, required by the Global API Key
    #[arg(long, global = true, value_name = "EMAIL")]
    pub email: Option<String>,

    /// Global API Key; prefer CLOUDFLARE_API_KEY, and prefer a token to either
    #[arg(long, global = true, value_name = "KEY")]
    pub api_key: Option<String>,

    /// Account id or name; required for an account-owned token
    #[arg(long, short = 'a', global = true, value_name = "ACCOUNT")]
    pub account: Option<String>,

    /// Zone id or name
    #[arg(long, short = 'z', global = true, value_name = "ZONE")]
    pub zone: Option<String>,

    /// Output format: a terminal render, or raw JSON for scripting
    #[arg(long, short = 'o', global = true, value_parser = ["human", "json"], value_name = "FORMAT")]
    pub output: Option<String>,

    /// Silence progress and status lines on stderr
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Per-request timeout, in seconds
    #[arg(long, global = true, default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    /// Read nothing from the cache; entries are still refreshed
    #[arg(long, global = true)]
    pub no_cache: bool,

    /// How long a cached configuration read stays usable, in seconds
    #[arg(long, global = true, default_value_t = cache::DEFAULT_TTL_SECS, value_name = "SECS")]
    pub cache_ttl: u64,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create or update a profile, test it, and save it to the config file
    #[command(alias = "configure", alias = "setup")]
    Login(commands::login::LoginArgs),

    /// Manage saved profiles
    Profile {
        #[command(subcommand)]
        cmd: commands::profile::ProfileCmd,
    },

    /// Inspect the config file
    Config {
        #[command(subcommand)]
        cmd: commands::settings::ConfigCmd,
    },

    /// Inspect and empty the response cache
    Cache {
        #[command(subcommand)]
        cmd: commands::cache::CacheCmd,
    },

    /// Check that the current profile can reach the API
    Ping,

    /// What this credential is, and exactly what it may do
    #[command(alias = "verify")]
    Whoami,

    /// Accounts this credential reaches
    Accounts(ListArgs),

    /// Zones of the account being scanned
    Zones(commands::zones::ZonesArgs),

    /// What the account's zones point at, and what points nowhere
    Dns {
        #[command(subcommand)]
        cmd: Option<commands::dns::DnsCmd>,
    },

    /// One dated, credential-free record of everything the account holds
    Snapshot(commands::snapshot::SnapshotArgs),

    /// What changed between two snapshots
    Diff(commands::snapshot::DiffArgs),

    /// The routed estate: tunnels, static routes, announced space, balancers
    Network {
        #[command(subcommand)]
        cmd: Option<commands::network::NetworkCmd>,
    },

    /// Where the request data goes, and whether any of it is kept
    Egress {
        #[command(subcommand)]
        cmd: Option<commands::egress::EgressCmd>,
    },

    /// Whether anyone is told when something breaks
    #[command(alias = "notifications")]
    Alerts {
        #[command(subcommand)]
        cmd: Option<commands::egress::AlertsCmd>,
    },

    /// Who reaches internal systems, and whether fleet traffic is inspected
    #[command(alias = "zt")]
    Zerotrust {
        #[command(subcommand)]
        cmd: Option<commands::zerotrust::ZeroTrustCmd>,
    },

    /// What developers provisioned, and what it is reachable on
    Platform {
        #[command(subcommand)]
        cmd: Option<commands::platform::PlatformCmd>,
    },

    /// What browsers are served, and whether the origin will talk to anyone
    Tls {
        #[command(subcommand)]
        cmd: Option<commands::tls::TlsCmd>,
    },

    /// What the edge is configured to do, and what is carved out of it
    Posture {
        #[command(subcommand)]
        cmd: Option<commands::posture::PostureCmd>,
    },

    /// Who can change this account, and with what
    #[command(alias = "iam")]
    Identity {
        #[command(subcommand)]
        cmd: Option<commands::identity::IdentityCmd>,
    },

    /// What was actually done to this account, and by whom
    #[command(alias = "audit-log", alias = "log")]
    Activity(commands::activity::ActivityArgs),

    /// Raw request against the API base, for anything not wrapped yet
    #[command(
        after_help = "PATH is relative to https://api.cloudflare.com/client/v4 and may\n\
                      contain {account} and {zone}, replaced by the resolved ids.\n\n\
                      Examples:\n  \
                      mlab-cloudflare api GET /user/tokens --list\n  \
                      mlab-cloudflare api GET '/accounts/{account}/members' --list\n  \
                      mlab-cloudflare api GET '/zones/{zone}/settings'\n  \
                      mlab-cloudflare api GET '/accounts/{account}/logs/audit' --cursor --limit 50"
    )]
    Api(commands::api::ApiArgs),
}

/// Paging flags, shared by every list command.
///
/// Everything is fetched by default; `--limit` takes one page of that size
/// instead, which is what you want when probing an account with 4000 zones.
#[derive(Args, Debug, Clone, Default)]
pub struct ListArgs {
    /// Return a single page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

/// Parse, set up output, then hand over to a command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    ui::init(cli.quiet);
    // Resolved again from the profile in `Ctx::build` when neither the flag nor
    // the environment picked a format.
    render::init(cli.output.as_deref().or(config::env("OUTPUT").as_deref()));

    // Commands that only touch the config file need no credential.
    match &cli.command {
        Cmd::Login(args) => return commands::login::run(&Overrides::from(&cli), args).await,
        Cmd::Profile { cmd } => return commands::profile::run(cmd),
        Cmd::Config { cmd } => return commands::settings::run(cmd),
        Cmd::Cache { cmd } => return commands::cache::run(cmd, Duration::from_secs(cli.cache_ttl)),
        // Comparing two files needs no credential and no network.
        Cmd::Diff(a) => return commands::snapshot::diff(a),
        _ => {}
    }

    if let Some(w) = config::perms_warning() {
        ui::warning(&w);
    }

    let ctx = Ctx::build(&cli)?;
    // A zero TTL is how the cache is turned off without deleting it: nothing is
    // young enough to serve, so nothing is stored either.
    let cache = (cli.cache_ttl > 0)
        .then(|| cache::Cache::new(Duration::from_secs(cli.cache_ttl), !cli.no_cache));
    let c = Client::with_cache(&ctx.profile, ctx.timeout, cache)
        .with_context(|| format!("profile {:?}", ctx.name))?;

    match cli.command {
        Cmd::Login(_)
        | Cmd::Profile { .. }
        | Cmd::Config { .. }
        | Cmd::Cache { .. }
        | Cmd::Diff(_) => unreachable!(),
        Cmd::Ping => commands::ping::run(&c, &ctx).await,
        Cmd::Whoami => commands::whoami::run(&c, &ctx).await,
        Cmd::Accounts(a) => commands::accounts::run(&c, &ctx, &a).await,
        Cmd::Zones(a) => commands::zones::run(&c, &ctx, &a).await,
        Cmd::Dns { cmd } => commands::dns::run(&c, &ctx, cmd).await,
        Cmd::Snapshot(a) => commands::snapshot::run(&c, &ctx, &a).await,
        Cmd::Network { cmd } => commands::network::run(&c, &ctx, cmd).await,
        Cmd::Egress { cmd } => commands::egress::run_egress(&c, &ctx, cmd).await,
        Cmd::Alerts { cmd } => commands::egress::run_alerts(&c, &ctx, cmd).await,
        Cmd::Zerotrust { cmd } => commands::zerotrust::run(&c, &ctx, cmd).await,
        Cmd::Platform { cmd } => commands::platform::run(&c, &ctx, cmd).await,
        Cmd::Tls { cmd } => commands::tls::run(&c, &ctx, cmd).await,
        Cmd::Posture { cmd } => commands::posture::run(&c, &ctx, cmd).await,
        Cmd::Identity { cmd } => commands::identity::run(&c, &ctx, cmd).await,
        Cmd::Activity(a) => commands::activity::run(&c, &ctx, &a).await,
        Cmd::Api(a) => commands::api::run(&c, &ctx, a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// `debug_assert` runs the validation clap otherwise only does on the first
    /// parse: duplicate short options, conflicting argument ids, bad value
    /// parsers. Without this test a collision between a global flag and a
    /// subcommand flag ships, and the first person to run that subcommand gets
    /// a panic instead of a command — which is exactly what `-q` on both
    /// `--quiet` and `api --query` did.
    #[test]
    fn the_command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }
}
