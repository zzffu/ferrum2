use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use super::SystemResolutionError;

const CANDIDATES_PER_FAMILY: usize = 16;

pub(super) struct Candidates {
    pub(super) ordered: Vec<SocketAddr>,
    pub(super) families: Vec<IpAddr>,
}

impl Candidates {
    pub(super) fn collect(addresses: impl IntoIterator<Item = SocketAddr>) -> Self {
        let mut ordered = Vec::with_capacity(CANDIDATES_PER_FAMILY);
        let mut families = Vec::with_capacity(CANDIDATES_PER_FAMILY * 2);
        let mut ipv4 = 0;
        let mut ipv6 = 0;
        for address in addresses {
            if ordered.len() < CANDIDATES_PER_FAMILY {
                ordered.push(address);
            }
            let count = match address.ip() {
                IpAddr::V4(_) => &mut ipv4,
                IpAddr::V6(_) => &mut ipv6,
            };
            if *count < CANDIDATES_PER_FAMILY && !families.contains(&address.ip()) {
                families.push(address.ip());
                *count += 1;
            }
            if ipv4 == CANDIDATES_PER_FAMILY && ipv6 == CANDIDATES_PER_FAMILY {
                break;
            }
        }
        Self { ordered, families }
    }
}

/// Private synchronous OS seam. Implementors return only bounded candidate
/// storage and closed errors; calls run exclusively inside owned blocking tasks.
pub(super) trait NativeLookup: Send + Sync + 'static {
    fn resolve(&self, host: &str, port: u16) -> Result<Candidates, SystemResolutionError>;
}

pub(super) struct SystemLookup;
impl NativeLookup for SystemLookup {
    fn resolve(&self, host: &str, port: u16) -> Result<Candidates, SystemResolutionError> {
        // The OS allocates its own result storage before this bounded collection.
        // Neither that allocation nor native resolver latency is forcibly bounded.
        let candidates = Candidates::collect(
            (host, port)
                .to_socket_addrs()
                .map_err(|_| SystemResolutionError::Resolution)?,
        );
        if candidates.ordered.is_empty() {
            Err(SystemResolutionError::Resolution)
        } else {
            Ok(candidates)
        }
    }
}
