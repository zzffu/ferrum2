mod error;
mod flow;
mod handshake;
mod observe;
mod replay;
pub(crate) mod wire;

pub use error::{
    DetectionReason, FlowTerminal, FrameError, ProtocolReason, ShadowsocksError, TransportPhase,
};
pub use flow::{
    BoxedClientFlow, ClientFlow, PlainBufferedDuplex, PlainDuplex, ServerFlow, TransportIo,
};
pub use handshake::{
    ClientTcpOutbound, ConnectedClientOpen, MethodKeyAdapter, NoReply, ShadowsocksTcpInbound,
    TcpKeyError, TcpKeyProvider,
};
pub use observe::{BufferObserver, BufferRole, FlowObserver};
pub use replay::{ReplayCapacityError, TcpReplayStore};
pub use wire::{
    MAX_DECRYPT_WIRE_LEN, MAX_ENCODE_PAYLOAD_LEN, MAX_ENCRYPT_WIRE_LEN, MAX_PADDING_LEN,
    MAX_PAYLOAD_LEN, REQUEST_FIRST_READ_LEN, RESPONSE_FIRST_READ_LEN, TAG_LEN, TCP_SALT_LEN,
    encode_request_first_write, encode_response_first_write, open_data_frame,
};

#[cfg(test)]
mod tests;
