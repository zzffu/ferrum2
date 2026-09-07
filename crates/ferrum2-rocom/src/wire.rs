//! Wire facts adapted from rocom_tool's tsf4g_parse/src/gcp.rs and app_frame.rs.
//! No FFI, application logic, capture material, or source-tree dependency is imported.

pub(crate) const HEADER_LEN: usize = 21;
pub(crate) const MAX_PACKET: usize = 16 * 1024 * 1024;
pub(crate) const SYN: u16 = 0x1001;
pub(crate) const ACK: u16 = 0x1002;
#[cfg(feature = "decode")]
pub(crate) const DATA: u16 = 0x4013;

#[derive(Clone, Copy)]
pub(crate) struct Header {
    #[cfg(feature = "decode")]
    pub head_version: u16,
    #[cfg(feature = "decode")]
    pub body_version: u16,
    pub command: u16,
    pub encrypted: u8,
    pub sequence: u32,
    pub head_len: usize,
    pub body_len: usize,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < HEADER_LEN {
            return Err("short_header");
        }
        if bytes[..2] != [0x33, 0x66] {
            return Err("invalid_magic");
        }
        let header = Self {
            #[cfg(feature = "decode")]
            head_version: u16::from_be_bytes([bytes[2], bytes[3]]),
            #[cfg(feature = "decode")]
            body_version: u16::from_be_bytes([bytes[4], bytes[5]]),
            command: u16::from_be_bytes([bytes[6], bytes[7]]),
            encrypted: bytes[8],
            sequence: be32(bytes, 9),
            head_len: be32(bytes, 13) as usize,
            body_len: be32(bytes, 17) as usize,
        };
        if header.encrypted > 1 {
            return Err("invalid_encrypted_flag");
        }
        if header.head_len < HEADER_LEN {
            return Err("invalid_head_length");
        }
        if header
            .head_len
            .checked_add(header.body_len)
            .is_none_or(|n| n > MAX_PACKET)
        {
            return Err("packet_limit");
        }
        Ok(header)
    }
    pub fn total(self) -> usize {
        self.head_len + self.body_len
    }
}

pub(crate) fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("checked header range"),
    )
}

#[cfg(feature = "decode")]
pub(crate) fn app_header(
    direction: crate::Direction,
    bytes: &[u8],
) -> Result<(&'static str, u32, Option<u32>, usize), &'static str> {
    match direction {
        crate::Direction::Download if bytes.len() >= 10 && bytes[4..6] == [0x55, 0xaa] => {
            Ok(("s2c", be32(bytes, 0), Some(be32(bytes, 6)), 10))
        }
        crate::Direction::Upload if bytes.len() >= 14 && bytes[8..10] == [0x7c, 0xa2] => {
            Ok(("c2s", be32(bytes, 4), Some(be32(bytes, 10)), 14))
        }
        crate::Direction::Upload if bytes.len() >= 8 => {
            let command = u32::from(u16::from_be_bytes([bytes[6], bytes[7]]));
            if command == 0 {
                return Err("unknown_application_header");
            }
            if bytes[..6].iter().any(|b| *b != 0) {
                if bytes.len() < 14 {
                    return Err("short_compact_header");
                }
                Ok(("c2s_compact", command, Some(be32(bytes, 10)), 14))
            } else {
                Ok(("c2s_short", command, None, 8))
            }
        }
        _ => Err("unknown_application_header"),
    }
}
