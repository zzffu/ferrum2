//! Handshake facts adapted from tsf4g_codec/src/codec/key.rs. Malformed
//! handshakes deliberately invalidate state instead of retaining a stale key.
use crate::{
    Direction,
    wire::{ACK, HEADER_LEN, Header, SYN},
};
use zeroize::Zeroize;

pub struct KeySnapshot {
    pub direction: Direction,
    pub offset: u64,
    pub key_method: u8,
    pub enc_method: Option<u8>,
    pub source_sequence: u32,
    pub key_hex: Option<String>,
}
impl std::fmt::Debug for KeySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeySnapshot").finish_non_exhaustive()
    }
}
impl Drop for KeySnapshot {
    fn drop(&mut self) {
        if let Some(key) = &mut self.key_hex {
            key.zeroize();
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct KeyState {
    pub method: u8,
    pub encryption: Option<u8>,
    pub key: Option<[u8; 16]>,
    pub reference: Option<(Direction, u64, u32)>,
}
impl Drop for KeyState {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl KeyState {
    pub fn observe(
        &mut self,
        direction: Direction,
        offset: u64,
        header: Header,
        extension: &[u8],
    ) -> Option<KeySnapshot> {
        if !matches!(
            (direction, header.command),
            (Direction::Upload, SYN) | (Direction::Download, ACK)
        ) {
            return None;
        }
        self.method = extension.first().copied().unwrap_or(0);
        self.key.zeroize();
        self.key = None;
        if header.command == SYN {
            self.encryption = extension.get(1).copied();
        } else if self.method == 2 && extension.get(1) == Some(&16) && extension.len() >= 18 {
            self.key = Some(extension[2..18].try_into().expect("checked key length"));
        }
        self.reference = Some((direction, offset, header.sequence));
        Some(KeySnapshot {
            direction,
            offset,
            key_method: self.method,
            enc_method: self.encryption,
            source_sequence: header.sequence,
            key_hex: self.key.as_ref().map(hex::encode),
        })
    }
}

#[derive(Default)]
struct Stream {
    prefix: Vec<u8>,
    header: Option<Header>,
    position: usize,
    offset: u64,
    stopped: bool,
    observed: bool,
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.prefix.zeroize();
    }
}
impl Stream {
    fn observe(
        &mut self,
        direction: Direction,
        mut bytes: &[u8],
        keys: &mut KeyState,
        output: &mut Vec<KeySnapshot>,
    ) {
        while !bytes.is_empty() && !self.stopped {
            if self.header.is_none() {
                let take = (HEADER_LEN - self.prefix.len()).min(bytes.len());
                self.prefix.extend_from_slice(&bytes[..take]);
                self.position += take;
                bytes = &bytes[take..];
                if self.prefix.len() < HEADER_LEN {
                    break;
                }
                match Header::parse(&self.prefix) {
                    Ok(header) => self.header = Some(header),
                    Err(_) => {
                        self.stopped = true;
                        break;
                    }
                }
            }
            let header = self.header.expect("header parsed");
            let wanted = if matches!(header.command, SYN | ACK) {
                header.head_len.min(HEADER_LEN + 18)
            } else {
                HEADER_LEN
            };
            if self.position < wanted {
                let take = (wanted - self.position).min(bytes.len());
                self.prefix.extend_from_slice(&bytes[..take]);
                self.position += take;
                bytes = &bytes[take..];
                if self.position < wanted {
                    break;
                }
            }
            if !self.observed {
                if let Some(snapshot) =
                    keys.observe(direction, self.offset, header, &self.prefix[HEADER_LEN..])
                {
                    output.push(snapshot);
                }
                self.observed = true;
                self.prefix.zeroize();
                self.prefix.clear();
            }
            let take = (header.total() - self.position).min(bytes.len());
            self.position += take;
            bytes = &bytes[take..];
            if self.position == header.total() {
                self.offset += header.total() as u64;
                self.position = 0;
                self.header = None;
                self.observed = false;
            }
        }
    }
}

/// Bounded per-connection SYN/ACK observation. Invalid framing permanently
/// disables interpretation for that direction; callers still retain raw bytes.
#[derive(Default)]
pub struct KeyTracker {
    upload: Stream,
    download: Stream,
    keys: KeyState,
}
impl KeyTracker {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn observe(&mut self, direction: Direction, bytes: &[u8]) -> Vec<KeySnapshot> {
        let mut output = Vec::new();
        let stream = match direction {
            Direction::Upload => &mut self.upload,
            Direction::Download => &mut self.download,
        };
        stream.observe(direction, bytes, &mut self.keys, &mut output);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(crate) fn packet(command: u16, extension: &[u8], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x33, 0x66, 0, 1, 0, 1];
        bytes.extend_from_slice(&command.to_be_bytes());
        bytes.push(0);
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&((HEADER_LEN + extension.len()) as u32).to_be_bytes());
        bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
        bytes.extend_from_slice(extension);
        bytes.extend_from_slice(body);
        bytes
    }
    #[test]
    fn split_handshakes_rotate_invalidate_and_isolate_keys() {
        let mut tracker = KeyTracker::new();
        let syn = packet(SYN, &[2, 3], &[]);
        let mut events = Vec::new();
        for byte in syn {
            events.extend(tracker.observe(Direction::Upload, &[byte]));
        }
        assert_eq!(events[0].enc_method, Some(3));
        let mut extension = vec![2, 16];
        extension.extend_from_slice(&[7; 16]);
        let ack = packet(ACK, &extension, &[]);
        assert_eq!(
            tracker.observe(Direction::Download, &ack)[0]
                .key_hex
                .as_deref(),
            Some("07070707070707070707070707070707")
        );
        extension[2..].fill(9);
        assert_eq!(
            tracker.observe(Direction::Download, &packet(ACK, &extension, &[]))[0]
                .key_hex
                .as_deref(),
            Some("09090909090909090909090909090909")
        );
        assert!(
            tracker.observe(Direction::Download, &packet(ACK, &[], &[]))[0]
                .key_hex
                .is_none()
        );
        let mut isolated = KeyTracker::new();
        assert_eq!(
            isolated.observe(Direction::Download, &ack)[0].enc_method,
            None
        );
        assert!(tracker.observe(Direction::Upload, &[0; 21]).is_empty());
        assert!(
            tracker
                .observe(Direction::Upload, &packet(SYN, &[2, 0], &[]))
                .is_empty()
        );
    }
}
