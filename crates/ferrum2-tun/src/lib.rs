#![forbid(unsafe_code)]

#[cfg(feature = "fuzzing")]
mod fuzzing;
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod lifecycle;
mod model;
mod network;
#[cfg(test)]
mod owner_harness_tests;
#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "fuzzing"
))]
mod packet;
mod process;
#[cfg(any(
    all(windows, target_arch = "x86_64", feature = "live-backend"),
    test,
    feature = "fuzzing"
))]
mod reassembly;
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod scheduler;
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod stack;
mod supervisor;
mod tcp;
mod udp;
mod wake;

#[cfg(feature = "fuzzing")]
pub use fuzzing::{
    MAX_FUZZ_INPUT_BYTES, MAX_UDP_RESET_FUZZ_INPUT_BYTES, fuzz_packet_reassembly,
    fuzz_udp_reset_races,
};
pub(crate) use model::TunEventSink;
pub use model::{
    Config, TunDiagnosticReason, TunEvent, TunIpFamily, TunNetworkFullRebuildReason,
    TunNetworkLifecycle, TunNetworkResetError, TunNetworkResetReason, TunRejectReason,
    UdpResponseDropReason,
};
pub use network::UnderlayPublisher;
#[cfg(test)]
pub(crate) use packet::map_packet_reject;
pub use process::process_root;
pub use supervisor::SessionCancellation;
pub use tcp::TcpFlow;
#[cfg(test)]
use udp::GenerationTable;
#[cfg(test)]
use udp::{Admission as UdpAdmission, InjectOutcome as UdpInjectOutcome, UdpDatagramEndpoints};
pub use udp::{
    UdpAssociation, UdpCandidate, UdpCommitError, UdpDatagram, UdpFiltering, UdpPeerAuthorization,
    UdpPeerPolicyHandle, UdpPeerReservation, UdpPeerReservationOutcome, UdpResponseSendOutcome,
    UdpResponseSink,
};
pub use wake::OwnerWake;

#[cfg(test)]
use ferrum2_runtime::OwnerRegistry;
#[cfg(test)]
use packet::{Families, PacketParser, ParsedPacket};
#[cfg(test)]
use scheduler::{FairScheduler, WorkStage};
#[cfg(test)]
use stack::{
    MemoryDevice, MemoryTx, OutputFlushOutcome, OutputSendOutcome, OutputSlot, PacketValidator,
    Stack, TcpTuple, udp_datagram,
};
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
mod runtime;
#[cfg(any(all(windows, target_arch = "x86_64", feature = "live-backend"), test))]
pub(crate) use runtime::*;

#[cfg(test)]
mod tests;
