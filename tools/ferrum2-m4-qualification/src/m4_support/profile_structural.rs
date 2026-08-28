use std::collections::BTreeMap;

use serde_json::{Map, Value};

const FIELDS: [&str; 11] = [
    "allocations",
    "copy_bytes",
    "zero_bytes",
    "wakeups",
    "lock_wait_nanoseconds",
    "replay_words_touched",
    "inflight_peak",
    "drop_count",
    "cache_scan_entries",
    "request_count",
    "encode_failure_count",
];

/// Closed structural observations for one bounded profile trial.
///
/// Every unavailable value carries an explicit reason. Scenario runners only
/// set values they directly observe; allocator and system-profiler evidence is
/// joined later by the controller.
pub(super) struct StructuralMetrics {
    values: BTreeMap<&'static str, Option<u64>>,
    closed: BTreeMap<&'static str, &'static str>,
}

impl StructuralMetrics {
    pub(super) fn unavailable() -> Self {
        let mut metrics = Self {
            values: FIELDS.into_iter().map(|field| (field, None)).collect(),
            closed: BTreeMap::new(),
        };
        metrics.close("allocations", "external_artifact");
        for field in [
            "copy_bytes",
            "zero_bytes",
            "wakeups",
            "lock_wait_nanoseconds",
        ] {
            metrics.close(field, "not_exposed");
        }
        for field in [
            "replay_words_touched",
            "inflight_peak",
            "drop_count",
            "cache_scan_entries",
            "request_count",
            "encode_failure_count",
        ] {
            metrics.close(field, "not_applicable");
        }
        metrics
    }

    pub(super) fn network(inflight_peak: u64, drop_count: u64) -> Self {
        Self::unavailable()
            .observe("inflight_peak", inflight_peak)
            .observe("drop_count", drop_count)
    }

    pub(super) fn replay(words_touched: u64, drop_count: u64) -> Self {
        Self::unavailable()
            .observe("replay_words_touched", words_touched)
            .observe("drop_count", drop_count)
    }

    pub(super) fn cache(scan_entries: u64) -> Self {
        Self::unavailable().observe("cache_scan_entries", scan_entries)
    }

    pub(super) fn dns_listener(
        request_count: u64,
        inflight_peak: u64,
        drop_count: u64,
        encode_failure_count: u64,
    ) -> Self {
        Self::unavailable()
            .observe("request_count", request_count)
            .observe("inflight_peak", inflight_peak)
            .observe("drop_count", drop_count)
            .observe("encode_failure_count", encode_failure_count)
    }

    fn close(&mut self, field: &'static str, reason: &'static str) {
        self.closed.insert(field, reason);
    }

    fn observe(mut self, field: &'static str, value: u64) -> Self {
        *self.values.get_mut(field).expect("structural metric field") = Some(value);
        self.closed.remove(field);
        self
    }

    pub(super) fn json(&self) -> String {
        debug_assert_eq!(
            self.closed.keys().copied().collect::<Vec<_>>(),
            self.values
                .iter()
                .filter_map(|(field, value)| value.is_none().then_some(*field))
                .collect::<Vec<_>>()
        );
        let mut object = Map::new();
        for (field, value) in &self.values {
            object.insert((*field).to_owned(), value.map_or(Value::Null, Value::from));
        }
        object.insert(
            "closed".to_owned(),
            Value::Object(
                self.closed
                    .iter()
                    .map(|(field, reason)| {
                        ((*field).to_owned(), Value::String((*reason).to_owned()))
                    })
                    .collect(),
            ),
        );
        Value::Object(object).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::{FIELDS, StructuralMetrics};

    #[test]
    fn closed_map_exactly_names_null_metrics() {
        let parsed: serde_json::Value =
            serde_json::from_str(&StructuralMetrics::network(8, 0).json()).unwrap();
        let object = parsed.as_object().unwrap();
        let closed = object["closed"].as_object().unwrap();
        for field in FIELDS {
            assert_eq!(object[field].is_null(), closed.contains_key(field));
        }
        assert_eq!(object["inflight_peak"], 8);
        assert_eq!(object["drop_count"], 0);
    }
}
