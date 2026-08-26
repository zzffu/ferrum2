use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::primitives::{read_be_u64, read_byte, read_exact, read_uvarint};
use crate::srs::{SrsError, SrsErrorKind};

pub(super) fn read_ip_set<R: Read>(reader: &mut R) -> Result<Vec<IpNet>, SrsError> {
    if read_byte(reader)? != 1 {
        return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
    }
    let range_count = read_be_u64(reader)?;
    let capacity =
        usize::try_from(range_count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut networks = Vec::new();
    networks
        .try_reserve(capacity)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    let mut previous: Option<IpNumber> = None;
    for _ in 0..range_count {
        let from = read_ip_number(reader)?;
        let to = read_ip_number(reader)?;
        if from.family() != to.family() || from > to {
            return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
        }
        if previous.is_some_and(|end| end.family() > from.family() || end >= from) {
            return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
        }
        decompose_ip_range(from, to, &mut networks)?;
        previous = Some(to);
    }
    Ok(networks)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IpNumber {
    V4(u32),
    V6(u128),
}

impl IpNumber {
    const fn family(self) -> u8 {
        match self {
            Self::V4(_) => 4,
            Self::V6(_) => 6,
        }
    }
}

fn read_ip_number<R: Read>(reader: &mut R) -> Result<IpNumber, SrsError> {
    match read_uvarint(reader)? {
        4 => {
            let mut bytes = [0_u8; 4];
            read_exact(reader, &mut bytes)?;
            Ok(IpNumber::V4(u32::from_be_bytes(bytes)))
        }
        16 => {
            let mut bytes = [0_u8; 16];
            read_exact(reader, &mut bytes)?;
            Ok(IpNumber::V6(u128::from_be_bytes(bytes)))
        }
        _ => Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
    }
}

fn decompose_ip_range(
    from: IpNumber,
    to: IpNumber,
    networks: &mut Vec<IpNet>,
) -> Result<(), SrsError> {
    match (from, to) {
        (IpNumber::V4(mut current), IpNumber::V4(end)) => loop {
            let alignment = current.trailing_zeros();
            let remaining = u64::from(end) - u64::from(current) + 1;
            let size = 63 - remaining.leading_zeros();
            let host_bits = alignment.min(size) as u8;
            networks
                .try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            let prefix = 32 - host_bits;
            let network = Ipv4Net::new(Ipv4Addr::from(current), prefix)
                .map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            networks.push(IpNet::V4(network));
            let step = 1_u64 << host_bits;
            let next = u64::from(current) + step;
            if next > u64::from(end) {
                break;
            }
            current = u32::try_from(next).map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
        },
        (IpNumber::V6(mut current), IpNumber::V6(end)) => loop {
            let alignment = current.trailing_zeros();
            let size = if current == 0 && end == u128::MAX {
                128
            } else {
                let remaining = end
                    .checked_sub(current)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidIpSet))?;
                127 - remaining.leading_zeros()
            };
            let host_bits = alignment.min(size) as u8;
            networks
                .try_reserve(1)
                .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
            let prefix = 128 - host_bits;
            let network = Ipv6Net::new(Ipv6Addr::from(current), prefix)
                .map_err(|_| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            networks.push(IpNet::V6(network));
            if host_bits == 128 {
                break;
            }
            let next = current
                .checked_add(1_u128 << host_bits)
                .ok_or_else(|| SrsError::new(SrsErrorKind::InvalidIpSet))?;
            if next > end {
                break;
            }
            current = next;
        },
        _ => return Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
    }
    Ok(())
}
