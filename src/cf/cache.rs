//! An on-disk cache for responses that describe configuration.
//!
//! The point is the rate ceiling: 1,200 requests per five minutes per
//! credential, shared with every other tool using it. A DNS sweep over twenty
//! zones is sixty calls, and running `dns`, then `dns mail`, then `dns
//! takeover` fetches the same records three times over. Configuration does not
//! change between those, so it is read once.
//!
//! Two rules decide what may be cached, and both are about not lying:
//!
//! 1. **Only configuration, never liveness.** `ping` and `whoami` exist to say
//!    whether a credential works *now*; a cached answer would make them report
//!    a revoked token as active. Those calls never consult the cache, and
//!    neither does the audit log, where staleness is the bug.
//! 2. **Keyed by credential.** Two profiles with different scopes see different
//!    answers to the same request, so the credential is part of the key. A
//!    rotated token therefore misses on everything, which is correct.
//!
//! Entries hold whatever the API returned, and some of that is a live secret —
//! a tunnel's connector token, a Turnstile widget's key. The directory is
//! created 0700 and the files 0600, exactly like the credential store, and
//! `cache clear` empties it.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Default lifetime of an entry, in seconds. Long enough that the several
/// commands of one audit share their reads, short enough that a change made
/// during the audit is picked up by the next one.
pub const DEFAULT_TTL_SECS: u64 = 900;

/// One stored response.
#[derive(Serialize, Deserialize)]
struct Entry {
    /// Unix seconds. Compared against the TTL at read time rather than at write
    /// time, so changing `--cache-ttl` re-ages what is already stored.
    fetched_at: u64,
    /// What was asked for, so `cache status` can say what is held. Ids are not
    /// secrets; the values under them may be, which is what the mode is for.
    request: String,
    body: Value,
}

/// A configured cache directory.
pub struct Cache {
    dir: PathBuf,
    ttl: Duration,
    /// False under `--no-cache`: entries are still written, so the run
    /// refreshes what it read, but none are served.
    read: bool,
}

impl Cache {
    pub fn new(ttl: Duration, read: bool) -> Cache {
        Cache {
            dir: path(),
            ttl,
            read,
        }
    }

    /// The stored body for `key`, if it is present and young enough.
    ///
    /// Every failure here is a miss rather than an error: a cache that can
    /// break a command is worse than no cache.
    pub fn get(&self, key: &str) -> Option<Value> {
        if !self.read {
            return None;
        }
        let entry: Entry = serde_json::from_slice(&fs::read(self.file(key)).ok()?).ok()?;
        // Strictly younger than the TTL, so `--cache-ttl 0` means no cache at
        // all rather than "one second of cache".
        let age = now().checked_sub(entry.fetched_at)?;
        (age < self.ttl.as_secs()).then_some(entry.body)
    }

    /// Store a response. A write failure is ignored for the same reason.
    pub fn put(&self, key: &str, request: &str, body: &Value) {
        let entry = Entry {
            fetched_at: now(),
            request: request.to_string(),
            body: body.clone(),
        };
        let Ok(data) = serde_json::to_vec(&entry) else {
            return;
        };
        if fs::create_dir_all(&self.dir).is_err() {
            return;
        }
        let _ = set_mode(&self.dir, 0o700);
        let file = self.file(key);
        if fs::write(&file, data).is_ok() {
            let _ = set_mode(&file, 0o600);
        }
    }

    fn file(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    /// Delete every entry, returning how many went.
    pub fn clear(&self) -> Result<usize> {
        let mut n = 0;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Ok(0);
        };
        for e in entries.flatten() {
            if e.path().extension().is_some_and(|x| x == "json") {
                fs::remove_file(e.path())
                    .with_context(|| format!("removing {}", e.path().display()))?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// What is held: one row per entry, newest first.
    pub fn entries(&self) -> Vec<(String, u64, u64)> {
        let mut out = Vec::new();
        let Ok(dir) = fs::read_dir(&self.dir) else {
            return out;
        };
        for e in dir.flatten() {
            let Ok(data) = fs::read(e.path()) else {
                continue;
            };
            let size = data.len() as u64;
            if let Ok(entry) = serde_json::from_slice::<Entry>(&data) {
                out.push((entry.request, now().saturating_sub(entry.fetched_at), size));
            }
        }
        out.sort_by_key(|(_, age, _)| *age);
        out
    }
}

/// `$MLAB_CLOUDFLARE_CACHE`, else `$HOME/.mlab/cache/cloudflare`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_CLOUDFLARE_CACHE") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".mlab")
        .join("cache")
        .join("cloudflare")
}

/// A cache key from the credential and the request.
///
/// The credential is part of it because two profiles see different answers to
/// the same request; hashing means the key does not carry it, and a rotated
/// token misses on everything it used to hold.
///
/// FNV-1a rather than a cryptographic digest: the directory mode is the
/// boundary here, and this only has to avoid collisions among a few hundred
/// keys on one machine.
pub fn key(credential: &str, request: &str) -> String {
    format!(
        "{:016x}{:016x}",
        fnv1a(credential.as_bytes()),
        fnv1a(request.as_bytes())
    )
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(name: &str) -> Cache {
        let dir = std::env::temp_dir().join(format!("mlab-cf-cache-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        Cache {
            dir,
            ttl: Duration::from_secs(900),
            read: true,
        }
    }

    #[test]
    fn a_stored_response_comes_back() {
        let c = scratch("roundtrip");
        assert!(c.get("k1").is_none(), "nothing is held yet");
        c.put("k1", "GET /zones", &json!({"a": 1}));
        assert_eq!(c.get("k1"), Some(json!({"a": 1})));
        let _ = c.clear();
    }

    #[test]
    fn a_ttl_of_zero_means_no_cache_rather_than_one_second_of_cache() {
        let mut c = scratch("ttl");
        c.put("k1", "GET /zones", &json!(1));
        assert!(c.get("k1").is_some(), "fresh, with the default ttl");
        c.ttl = Duration::from_secs(0);
        assert!(c.get("k1").is_none());
        let _ = c.clear();
    }

    #[test]
    fn an_entry_written_in_the_future_is_a_miss() {
        // A clock that moved backwards must not hand back an entry forever.
        let c = scratch("future");
        fs::create_dir_all(&c.dir).unwrap();
        let entry = json!({"fetched_at": now() + 10_000, "request": "GET /a", "body": 1});
        fs::write(c.file("k1"), serde_json::to_vec(&entry).unwrap()).unwrap();
        assert!(c.get("k1").is_none());
        let _ = c.clear();
    }

    #[test]
    fn no_cache_stops_reads_but_not_writes() {
        // So a `--no-cache` run refreshes what it read rather than leaving the
        // next run to fetch it all again.
        let mut c = scratch("nocache");
        c.put("k1", "GET /zones", &json!(1));
        c.read = false;
        assert!(c.get("k1").is_none());
        c.put("k2", "GET /accounts", &json!(2));
        c.read = true;
        assert_eq!(c.get("k2"), Some(json!(2)));
        let _ = c.clear();
    }

    #[test]
    fn a_corrupt_entry_is_a_miss_rather_than_a_failure() {
        // A cache that can break a command is worse than no cache.
        let c = scratch("corrupt");
        fs::create_dir_all(&c.dir).unwrap();
        fs::write(c.file("k1"), b"not json at all").unwrap();
        assert!(c.get("k1").is_none());
        let _ = c.clear();
    }

    #[test]
    fn the_credential_is_part_of_the_key() {
        // Two profiles see different answers to the same request, and a
        // rotated token must not read what the old one stored.
        assert_ne!(key("token-a", "GET /zones"), key("token-b", "GET /zones"));
        assert_ne!(
            key("token-a", "GET /zones"),
            key("token-a", "GET /accounts")
        );
        assert_eq!(key("token-a", "GET /zones"), key("token-a", "GET /zones"));
    }

    #[test]
    fn a_key_is_a_plain_hex_name_that_cannot_escape_the_directory() {
        let k = key("t", "GET /zones/../../etc/passwd");
        assert_eq!(k.len(), 32);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn clearing_reports_what_it_removed_and_is_safe_on_an_empty_directory() {
        let c = scratch("clear");
        assert_eq!(c.clear().unwrap(), 0, "no directory yet");
        c.put("k1", "GET /a", &json!(1));
        c.put("k2", "GET /b", &json!(2));
        assert_eq!(c.entries().len(), 2);
        assert_eq!(c.clear().unwrap(), 2);
        assert!(c.entries().is_empty());
    }
}
