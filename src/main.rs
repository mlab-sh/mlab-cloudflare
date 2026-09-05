//! `mlab-cloudflare` — a CLI over the Cloudflare v4 API, meant to be driven by
//! a scoped read-only API token.
//!
//! Layout:
//!
//! | module     | role                                                        |
//! | ---------- | ----------------------------------------------------------- |
//! | `cf`       | the API: HTTP handler, profiles, account and zone resolution |
//! | `audit`    | the graded checks, as pure functions over fetched data       |
//! | `ui`       | everything the user sees: progress on stderr, rendering      |
//! | `cli`      | the clap surface and the dispatch                            |
//! | `commands` | one module per command                                       |

mod audit;
mod cf;
mod cli;
mod commands;
mod ui;

use colored::Colorize;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        // A spinner may own a half-drawn line; wipe it before the message.
        ui::restore();
        eprintln!("  {} {e:#}", "✖".red().bold());
        std::process::exit(1);
    }
}
