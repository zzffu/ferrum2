#![deny(unsafe_code)]

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const DLL_BYTES: u64 = 427_552;
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const DLL_SHA256: [u8; 32] = [
    0xe5, 0xda, 0x84, 0x47, 0xdc, 0x2c, 0x32, 0x0e, 0xdc, 0x0f, 0xc5, 0x2f, 0xa0, 0x18, 0x85, 0xc1,
    0x03, 0xde, 0x8c, 0x11, 0x84, 0x81, 0xf6, 0x83, 0x64, 0x3c, 0xac, 0xc3, 0x22, 0x0d, 0xaf, 0xce,
];
#[cfg(any(all(windows, target_arch = "x86_64"), test))]
const ABI_EXPORTS: [&[u8]; 11] = [
    b"WintunCreateAdapter\0",
    b"WintunCloseAdapter\0",
    b"WintunGetAdapterLUID\0",
    b"WintunGetRunningDriverVersion\0",
    b"WintunStartSession\0",
    b"WintunEndSession\0",
    b"WintunGetReadWaitEvent\0",
    b"WintunReceivePacket\0",
    b"WintunReleaseReceivePacket\0",
    b"WintunAllocateSendPacket\0",
    b"WintunSendPacket\0",
];

/// Complete validated setup input for one newly-created Wintun adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterConfig {
    pub name: Box<str>,
    pub ipv4: Ipv4Addr,
    pub ipv4_prefix: u8,
    pub ipv6: Ipv6Addr,
    pub ipv6_prefix: u8,
    pub mtu: u16,
    pub ring_capacity: u32,
    pub ready_timeout: Duration,
}

impl AdapterConfig {
    /// Checks the platform Adapter's trust-boundary invariants without touching the OS.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: Box<str>,
        ipv4: Ipv4Addr,
        ipv4_prefix: u8,
        ipv6: Ipv6Addr,
        ipv6_prefix: u8,
        mtu: u16,
        ring_capacity: u32,
        ready_timeout: Duration,
    ) -> Result<Self, Error> {
        if name.is_empty()
            || name.encode_utf16().count() >= 128
            || name.chars().any(char::is_control)
            || ipv4_prefix > 32
            || ipv6_prefix > 128
            || !(1280..=1500).contains(&mtu)
            || !(131_072..=67_108_864).contains(&ring_capacity)
            || !ring_capacity.is_power_of_two()
            || !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&ready_timeout)
        {
            return Err(Error);
        }
        Ok(Self {
            name,
            ipv4,
            ipv4_prefix,
            ipv6,
            ipv6_prefix,
            mtu,
            ring_capacity,
            ready_timeout,
        })
    }
}

/// Redacted platform failure. Raw paths, identities and Win32 text are never retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error;

/// Redacted adapter-creation failure that preserves only rollback integrity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateError {
    cleanup_failed: bool,
}

impl CreateError {
    pub(crate) const fn operation() -> Self {
        Self {
            cleanup_failed: false,
        }
    }

    #[cfg(any(all(windows, target_arch = "x86_64"), test))]
    pub(crate) const fn cleanup() -> Self {
        Self {
            cleanup_failed: true,
        }
    }

    /// Reports only whether reverse cleanup failed, without exposing platform detail.
    pub const fn is_cleanup_failure(self) -> bool {
        self.cleanup_failed
    }
}

impl fmt::Display for CreateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Wintun adapter creation failed")
    }
}

impl std::error::Error for CreateError {}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Wintun operation failed")
    }
}

impl std::error::Error for Error {}

#[cfg(all(windows, target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows::{Adapter, ReceivedPacket, StopSignal};

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod unsupported;
#[cfg(not(all(windows, target_arch = "x86_64")))]
pub use unsupported::{Adapter, ReceivedPacket, StopSignal};

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::{ABI_EXPORTS, AdapterConfig, CreateError, DLL_BYTES, DLL_SHA256, Error};

    #[test]
    fn exact_artifact_and_eleven_export_contract_is_fixed() {
        assert_eq!(DLL_BYTES, 427_552);
        assert_eq!(
            DLL_SHA256,
            hex_literal("e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
        );
        assert_eq!(ABI_EXPORTS.len(), 11);
        assert!(ABI_EXPORTS.iter().all(|name| name.ends_with(&[0])));
        assert!(
            !ABI_EXPORTS
                .iter()
                .any(|name| name == b"WintunOpenAdapter\0")
        );
    }

    #[test]
    fn safe_config_rejects_ring_and_name_mutations_without_os_work() {
        let make = |name: &str, ring| {
            AdapterConfig::new(
                name.into(),
                Ipv4Addr::new(198, 18, 0, 2),
                30,
                Ipv6Addr::LOCALHOST,
                126,
                1420,
                ring,
                Duration::from_secs(10),
            )
        };
        assert!(make("Ferrum2", 8_388_608).is_ok());
        assert!(make("Ferrum2", 131_073).is_err());
        assert!(make("Ferrum2\0", 8_388_608).is_err());
        assert_eq!(
            format!("{:?} {}", Error, Error),
            "Error Wintun operation failed"
        );
        assert!(!CreateError::operation().is_cleanup_failure());
        assert!(CreateError::cleanup().is_cleanup_failure());
        assert_eq!(
            CreateError::cleanup().to_string(),
            "Wintun adapter creation failed"
        );
    }

    fn hex_literal(value: &str) -> [u8; 32] {
        let mut result = [0_u8; 32];
        for (slot, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
        }
        result
    }
}
