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
mod providers;
mod ui;

use colored::Colorize;

#[tokio::main]
async fn main() {
    match cli::run().await {
        // Only `audit --fail-on` returns anything but zero, and it returns 2 —
        // so a pipeline can tell "the audit found things" from "the tool
        // broke", which is exit 1 below.
        Ok(code) => std::process::exit(code),
        Err(e) => {
            // A spinner may own a half-drawn line; wipe it before the message.
            ui::restore();
            eprintln!("  {} {e:#}", "✖".red().bold());
            std::process::exit(1);
        }
    }
}
