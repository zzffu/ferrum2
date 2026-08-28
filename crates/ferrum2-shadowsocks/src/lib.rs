#![forbid(unsafe_code)]

//! SIP022 TCP flow plus socket-free bounded UDP packet and security state.

mod tcp;
mod udp;

#[cfg(feature = "tokio")]
pub mod tokio;

pub use tcp::{
    BoxedClientFlow, BufferObserver, BufferRole, ClientFlow, ClientTcpOutbound,
    ConnectedClientOpen, DetectionReason, FlowObserver, FlowTerminal, FrameError,
    MAX_DECRYPT_WIRE_LEN, MAX_ENCODE_PAYLOAD_LEN, MAX_ENCRYPT_WIRE_LEN, MAX_PADDING_LEN,
    MAX_PAYLOAD_LEN, MethodKeyAdapter, NoReply, PlainBufferedDuplex, PlainDuplex, ProtocolReason,
    REQUEST_FIRST_READ_LEN, RESPONSE_FIRST_READ_LEN, ReplayCapacityError, ServerFlow,
    ShadowsocksError, ShadowsocksTcpInbound, TAG_LEN, TCP_SALT_LEN, TcpKeyError, TcpKeyProvider,
    TcpReplayStore, TransportIo, TransportPhase, encode_request_first_write,
    encode_response_first_write, open_data_frame,
};
pub use udp::{
    AcceptedUdpRequest, BorrowedPendingUdpResponse, ClientAssociationSnapshot, EncodedUdpResponse,
    MAX_UDP_WIRE_LEN, PendingUdpRequest, PendingUdpResponse, ServerResponseCapability,
    ServerSessionSnapshot, UDP_ASSOCIATION_RETENTION, UDP_REPLAY_LAG, UdpClientSession,
    UdpPacketError, UdpPacketScratch, UdpReplayWindow, UdpRequestCommit, UdpResponseCommit,
    UdpServer, max_udp_payload_len, max_udp_payload_len_for_encoded_target,
};
