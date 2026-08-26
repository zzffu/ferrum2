use tracing::Metadata;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt as _;

use super::CLOSED_TRACE_TARGET;
use super::schema::LogLevel;

const CLOSED_TRACE_MODULE: &str = "ferrum2_observability::trace::emit";
const TRACE_FIELDS: &[&str] = &[
    "event",
    "role",
    "transport",
    "stage",
    "outcome",
    "session_id",
    "duration_ms",
    "bytes",
];
const TRACE_FIELDS_WITH_REASON: &[&str] = &[
    "event",
    "role",
    "transport",
    "stage",
    "outcome",
    "reason",
    "session_id",
    "duration_ms",
    "bytes",
];
const SNIFF_TRACE_FIELDS: &[&str] = &["event", "role", "transport", "stage", "outcome", "protocol"];
const TUN_TRACE_FIELDS: &[&str] = &["event", "role", "stage", "outcome", "reason", "family"];
const NETWORK_LIFECYCLE_TRACE_FIELDS: &[&str] = &[
    "event",
    "role",
    "stage",
    "operation",
    "reason",
    "result",
    "generation",
    "tcp_associations",
    "udp_associations",
];
const STRICT_ROUTE_TRACE_FIELDS: &[&str] =
    &["event", "role", "stage", "requested", "effective", "status"];
const INTERFACE_RESOLUTION_TRACE_FIELDS: &[&str] =
    &["event", "role", "stage", "source", "result", "cache_hit"];

/// Builds a caller-owned newline JSON subscriber without installing it globally.
pub fn json_subscriber<W>(writer: W, max_level: LogLevel) -> impl tracing::Subscriber + Send + Sync
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let filter = filter_fn(move |metadata| approved_trace_metadata(metadata, max_level));
    let format = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(writer)
        .with_ansi(false)
        .with_target(false)
        .with_file(false)
        .with_line_number(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .flatten_event(true)
        .with_current_span(false)
        .with_span_list(false)
        .with_filter(filter);
    tracing_subscriber::registry().with(format)
}

fn approved_trace_metadata(metadata: &Metadata<'_>, max_level: LogLevel) -> bool {
    metadata.is_event()
        && metadata.target() == CLOSED_TRACE_TARGET
        && metadata.module_path() == Some(CLOSED_TRACE_MODULE)
        && max_level.enables(metadata.level())
        && (has_exact_fields(metadata, TRACE_FIELDS)
            || has_exact_fields(metadata, TRACE_FIELDS_WITH_REASON)
            || has_exact_fields(metadata, SNIFF_TRACE_FIELDS)
            || has_exact_fields(metadata, TUN_TRACE_FIELDS)
            || has_exact_fields(metadata, NETWORK_LIFECYCLE_TRACE_FIELDS)
            || has_exact_fields(metadata, STRICT_ROUTE_TRACE_FIELDS)
            || has_exact_fields(metadata, INTERFACE_RESOLUTION_TRACE_FIELDS))
}

fn has_exact_fields(metadata: &Metadata<'_>, expected: &[&str]) -> bool {
    let fields = metadata.fields();
    fields.len() == expected.len() && expected.iter().all(|name| fields.field(name).is_some())
}
