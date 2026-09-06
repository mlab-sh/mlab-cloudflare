//! Recording what the API said, for a snapshot.
//!
//! A snapshot keeps the **responses**, not this tool's reading of them. Two
//! reasons, and both are about the record still being worth something later:
//!
//! 1. A check added next month can be run against a snapshot taken today,
//!    because the snapshot is not shaped like the checks that existed when it
//!    was written.
//! 2. A diff over responses says what Cloudflare changed. A diff over findings
//!    would say what this tool concluded, which is a different and much less
//!    useful sentence when the two disagree.
//!
//! The recorder sits on the same path as the response cache, so it captures
//! exactly the configuration reads and never the liveness checks — a snapshot
//! containing "the token was valid at 14:02" would be recording the weather.

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{json, Value};

/// What one run of the collectors read.
#[derive(Default)]
pub struct Recorder {
    reads: Mutex<BTreeMap<String, Value>>,
}

impl Recorder {
    pub fn new() -> Recorder {
        Recorder::default()
    }

    /// Keep a response.
    pub fn body(&self, request: &str, v: &Value) {
        if let Ok(mut m) = self.reads.lock() {
            m.insert(request.to_string(), v.clone());
        }
    }

    /// Keep a refusal.
    ///
    /// Recorded rather than dropped because "this was not readable" is part of
    /// the record: a diff where a `403` becomes a body is a permission that was
    /// granted, which is exactly the kind of change a snapshot exists to catch.
    pub fn refusal(&self, request: &str, why: &str) {
        if let Ok(mut m) = self.reads.lock() {
            m.insert(request.to_string(), json!({ UNREAD: why }));
        }
    }

    /// Everything read, in request order.
    pub fn take(&self) -> BTreeMap<String, Value> {
        self.reads.lock().map(|m| m.clone()).unwrap_or_default()
    }
}

/// The key a refused read is stored under, so a diff can tell one from a body.
pub const UNREAD: &str = "__unread";

/// Whether a recorded value is a refusal rather than a response.
pub fn is_unread(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|m| m.len() == 1 && m.contains_key(UNREAD))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorder_keeps_bodies_and_refusals_apart() {
        let r = Recorder::new();
        r.body("LIST /zones", &json!([{"id": "z1"}]));
        r.refusal("LIST /accounts/x/logpush/jobs", "API error 403");

        let taken = r.take();
        assert_eq!(taken.len(), 2);
        assert!(!is_unread(&taken["LIST /zones"]));
        assert!(is_unread(&taken["LIST /accounts/x/logpush/jobs"]));
    }

    #[test]
    fn a_body_that_happens_to_carry_the_marker_is_still_a_body() {
        // The marker only means "refusal" when it is the whole object.
        let v = json!({UNREAD: "x", "id": "z1"});
        assert!(!is_unread(&v));
        assert!(!is_unread(&json!([])));
    }

    #[test]
    fn the_same_request_read_twice_keeps_the_later_answer() {
        let r = Recorder::new();
        r.body("GET /a", &json!(1));
        r.body("GET /a", &json!(2));
        assert_eq!(r.take()["GET /a"], json!(2));
    }
}
