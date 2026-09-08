// Compare the fixed identity and copied options, not per-fragment IHL or padding.
// The complete offset-zero header is retained separately by the reassembly owner.
pub(super) fn normalized_ipv4_header(header: &[u8], first: bool) -> Option<([u8; 60], usize)> {
    if !(20..=60).contains(&header.len()) || !header.len().is_multiple_of(4) {
        return None;
    }
    let mut normalized = [0; 60];
    normalized[..20].copy_from_slice(&header[..20]);
    normalized[0] &= 0xf0;
    normalized[2..4].fill(0);
    normalized[6..8].fill(0);
    normalized[10..12].fill(0);
    let mut written = 20;
    let mut cursor = 20;
    while cursor < header.len() {
        let kind = header[cursor];
        match kind {
            0 => {
                if header[cursor + 1..].iter().any(|byte| *byte != 0) {
                    return None;
                }
                break;
            }
            1 => cursor += 1,
            _ => {
                let length = usize::from(*header.get(cursor + 1)?);
                let end = cursor.checked_add(length)?;
                if length < 2 || end > header.len() {
                    return None;
                }
                if kind & 0x80 != 0 {
                    normalized[written..written + length].copy_from_slice(&header[cursor..end]);
                    written += length;
                } else if !first {
                    return None;
                }
                cursor = end;
            }
        }
    }
    Some((normalized, written))
}
