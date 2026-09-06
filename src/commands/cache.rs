//! `cache` — what the response cache holds, and how to empty it.

use std::time::Duration;

use anyhow::Result;
use clap::Subcommand;
use serde_json::{json, Value};

use crate::cf::cache::Cache;
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum CacheCmd {
    /// Print the path of the cache directory
    Path,
    /// What is held, and how old it is
    #[command(alias = "show", alias = "list")]
    Status,
    /// Delete every Cloudflare entry
    #[command(alias = "purge")]
    Clear {
        /// Also delete the mlab results, which cost quota to fetch again
        #[arg(long)]
        all: bool,
    },
}

pub fn run(cmd: &CacheCmd, ttl: Duration) -> Result<()> {
    let cache = Cache::new(ttl, true);
    // The mlab results are read at their own TTL: a week, because that is how
    // long mlab keeps them, and re-fetching one costs a unit of a daily quota.
    let enriched = Cache::named(crate::mlab::CACHE_DIR, crate::mlab::TTL, true);

    match cmd {
        // Plain, so it composes into another command.
        CacheCmd::Path => println!("{}", crate::cf::cache::path().display()),
        CacheCmd::Clear { all } => {
            let n = cache.clear()?;
            ui::success(&format!("removed {n} cached {}", plural(n, "response")));
            let held = enriched.entries().len();
            if *all {
                let m = enriched.clear()?;
                ui::success(&format!("removed {m} mlab {}", plural(m, "result")));
            } else if held > 0 {
                // Silently keeping them would be worse than saying so: the
                // reader asked for the cache to be emptied and it was not.
                ui::info(&format!(
                    "kept {held} mlab {} — they cost quota to fetch again; --all removes them too",
                    plural(held, "result")
                ));
            }
        }
        CacheCmd::Status => {
            let entries = cache.entries();
            let rows: Vec<Value> = entries
                .iter()
                .map(|(request, age, size, refused)| {
                    json!({
                        "request": crate::commands::abbreviate(request),
                        "age": ui::elapsed(Duration::from_secs(*age)),
                        "state": match (*age < ttl.as_secs(), refused) {
                            (false, _) => "stale",
                            (true, true) => "refused",
                            (true, false) => "usable",
                        },
                        "kb": size / 1024,
                    })
                })
                .collect();

            render::heading(&crate::cf::cache::path().display().to_string());
            render::list(&rows, render::CACHE_COLS);
            render::count(entries.len(), "entry");

            if !render::is_json() {
                let usable = entries
                    .iter()
                    .filter(|(_, age, _, _)| *age < ttl.as_secs())
                    .count();
                let refused = entries.iter().filter(|(_, _, _, r)| *r).count();
                let bytes: u64 = entries.iter().map(|(_, _, size, _)| size).sum();
                ui::gap();
                ui::info(&format!(
                    "{usable} usable at a {}s TTL, {refused} of them remembered refusals, {} on disk",
                    ttl.as_secs(),
                    human(bytes)
                ));
                // Entries hold whatever the API returned, and some endpoints
                // return live credentials.
                ui::info("entries hold raw API responses, some of which carry credentials; the directory is 0700 and the files 0600");

                let mlab = enriched.entries();
                if !mlab.is_empty() {
                    ui::gap();
                    ui::info(&format!(
                        "{} mlab {} held for {} days, in {}",
                        mlab.len(),
                        plural(mlab.len(), "result"),
                        crate::mlab::TTL.as_secs() / 86_400,
                        enriched_path().display()
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Where the mlab results are held, for the status line.
fn enriched_path() -> std::path::PathBuf {
    crate::cf::cache::path().join(crate::mlab::CACHE_DIR)
}

fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        noun.to_string()
    } else {
        format!("{noun}s")
    }
}

fn human(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} kB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_read_as_the_unit_they_belong_to() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(2048), "2.0 kB");
        assert_eq!(human(3 << 20), "3.0 MB");
    }
}
