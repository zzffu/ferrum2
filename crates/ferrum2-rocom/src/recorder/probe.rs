use zeroize::Zeroizing;

use crate::Direction;
use crate::wire::{HEADER_LEN, Header};

use super::{Event, Queued};

pub(super) enum Decision {
    Pending,
    Matched,
    Rejected,
}

#[derive(Default)]
struct Prefix {
    bytes: [u8; HEADER_LEN],
    len: usize,
}

/// No file or writer event exists before a valid first GCP header is observed.
/// Before selection, each direction retains fewer than HEADER_LEN bytes. The
/// completing observation can also carry a bounded relay chunk, preserved whole.
pub(super) struct Probe {
    prefixes: [Prefix; 2],
    pub source: Option<String>,
    pub target: String,
    pub opened_us: u64,
    pub pending: Vec<Queued>,
}

impl Probe {
    pub fn new(source: Option<String>, target: String, opened_us: u64) -> Self {
        Self {
            prefixes: [Prefix::default(), Prefix::default()],
            source,
            target,
            opened_us,
            pending: Vec::new(),
        }
    }

    pub fn observe(
        &mut self,
        connection_id: u64,
        direction: Direction,
        offset: u64,
        elapsed_us: u64,
        bytes: &[u8],
    ) -> Decision {
        let prefix = &mut self.prefixes[match direction {
            Direction::Upload => 0,
            Direction::Download => 1,
        }];
        let take = (HEADER_LEN - prefix.len).min(bytes.len());
        prefix.bytes[prefix.len..prefix.len + take].copy_from_slice(&bytes[..take]);
        prefix.len += take;
        if (prefix.len >= 1 && prefix.bytes[0] != 0x33)
            || (prefix.len >= 2 && prefix.bytes[1] != 0x66)
        {
            return Decision::Rejected;
        }
        let decision = if prefix.len == HEADER_LEN {
            if Header::parse(&prefix.bytes).is_err() {
                return Decision::Rejected;
            }
            Decision::Matched
        } else {
            Decision::Pending
        };
        self.pending.push(Queued {
            elapsed_us,
            event: Event::Data {
                connection_id,
                direction,
                offset,
                bytes: Zeroizing::new(bytes.to_vec()),
            },
        });
        decision
    }
}
