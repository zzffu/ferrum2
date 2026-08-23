use ferrum2_wintun::{ErrorKind, FUZZ_MAX_WFP_APP_ID_BYTES, fuzz_strict_route_rule_plan};

/// Hard input bound for strict-route semantic rule-plan generation.
pub const MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES: usize = 4 * 1024;

/// Exercises the production, platform-neutral strict-route WFP rule-plan builder at every input
/// boundary without opening the Windows Filtering Platform or creating any platform object.
pub fn fuzz_strict_route_rule_builder(input: &[u8]) {
    if input.len() > MAX_STRICT_ROUTE_FUZZ_INPUT_BYTES {
        return;
    }
    let length_selector = input.first().copied().unwrap_or_default() % 6;
    let flags = input.get(1).copied().unwrap_or_default() % 16;
    let has_ipv4 = flags & 0x01 != 0;
    let has_ipv6 = flags & 0x02 != 0;
    let has_managed_dns = flags & 0x04 != 0;
    let interface_luid = if flags & 0x08 != 0 {
        0
    } else {
        read_u64(input.get(2..10).unwrap_or_default())
    };
    let app_id_len = match length_selector {
        0 => 0,
        1 => 1,
        2 => FUZZ_MAX_WFP_APP_ID_BYTES - 1,
        3 => FUZZ_MAX_WFP_APP_ID_BYTES,
        4 => FUZZ_MAX_WFP_APP_ID_BYTES + 1,
        _ => {
            read_u32(input.get(2..6).unwrap_or_default()) as usize % (FUZZ_MAX_WFP_APP_ID_BYTES + 2)
        }
    };
    let pattern = input.get(10).copied().unwrap_or(0xa5);
    let app_id = vec![pattern; app_id_len];
    let result =
        fuzz_strict_route_rule_plan(has_ipv4, has_ipv6, has_managed_dns, &app_id, interface_luid);
    let valid = (has_ipv4 || has_ipv6)
        && !app_id.is_empty()
        && app_id.len() <= FUZZ_MAX_WFP_APP_ID_BYTES
        && interface_luid != 0;
    if !valid {
        assert_eq!(result.unwrap_err().kind(), ErrorKind::InvalidInput);
        return;
    }

    let observation = result.expect("bounded strict-route input must produce a rule plan");
    let family_blocks = usize::from(!has_ipv4) + usize::from(!has_ipv6);
    let dns_blocks = if has_managed_dns { 4 } else { 0 };
    assert_eq!(observation.rule_count(), 4 + family_blocks + dns_blocks);
    assert_eq!(observation.permit_count(), 4);
    assert_eq!(observation.block_count(), family_blocks + dns_blocks);
    assert_eq!(observation.app_id_condition_count(), 2);
    assert_eq!(observation.interface_condition_count(), 2);
    assert_eq!(observation.dns_protocol_condition_count(), dns_blocks);
    assert_eq!(observation.dns_port_condition_count(), dns_blocks);
    assert_eq!(observation.empty_condition_count(), family_blocks);
}

fn read_u32(input: &[u8]) -> u32 {
    let mut bytes = [0_u8; 4];
    let count = input.len().min(bytes.len());
    bytes[..count].copy_from_slice(&input[..count]);
    u32::from_le_bytes(bytes)
}

fn read_u64(input: &[u8]) -> u64 {
    let mut bytes = [0_u8; 8];
    let count = input.len().min(bytes.len());
    bytes[..count].copy_from_slice(&input[..count]);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_boundaries_cover_invalid_and_maximal_app_ids() {
        for input in [
            &b"03nonzero-luid"[..],
            &b"13nonzero-luid"[..],
            &b"23nonzero-luid"[..],
            &b"33nonzero-luid"[..],
            &b"43nonzero-luid"[..],
            &b"50nonzero-luid"[..],
            &b"19zero-luid"[..],
            &b"17dns-rules"[..],
        ] {
            fuzz_strict_route_rule_builder(input);
        }
    }
}
