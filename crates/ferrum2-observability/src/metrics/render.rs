use std::error::Error;
use std::fmt;

use prometheus_client::encoding::text;

use super::Metrics;

/// Closed text-encoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetricsEncodeError;

impl fmt::Display for MetricsEncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("metrics encoding failed")
    }
}

impl Error for MetricsEncodeError {}

impl Metrics {
    /// Encodes a stable OpenMetrics text representation.
    ///
    /// Family blocks and samples are sorted so output does not inherit hash-map
    /// iteration or update order.
    pub fn encode_text(&self) -> Result<String, MetricsEncodeError> {
        let mut encoded = String::new();
        text::encode(&mut encoded, &self.registry).map_err(|_| MetricsEncodeError)?;
        Ok(canonicalize_text(&encoded))
    }
}

fn canonicalize_text(encoded: &str) -> String {
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current = Vec::new();
    for line in encoded.lines() {
        if line == "# EOF" {
            continue;
        }
        if line.starts_with("# HELP ") && !current.is_empty() {
            blocks.push(current);
            current = Vec::new();
        }
        current.push(line);
    }
    if !current.is_empty() {
        blocks.push(current);
    }

    for block in &mut blocks {
        let sample_start = block
            .iter()
            .position(|line| !line.starts_with('#'))
            .unwrap_or(block.len());
        block[sample_start..].sort_unstable();
    }
    blocks.sort_unstable_by(|left, right| left.first().cmp(&right.first()));

    let mut canonical = String::new();
    for block in blocks {
        for line in block {
            canonical.push_str(line);
            canonical.push('\n');
        }
    }
    canonical.push_str("# EOF\n");
    canonical
}
