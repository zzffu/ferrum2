use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Bytes, BytesMut};
use ferrum2_core::TargetAddr;
use ferrum2_crypto::{MethodProfile, MethodTcpSalt, SecureRandom, TcpOpener, TcpSealer};

use super::error::{DetectionReason, FrameError, frame_from_open_aead, frame_from_seal_aead};
use super::handshake::TcpKeyProvider;

pub const TCP_SALT_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const REQUEST_FIRST_READ_LEN: usize = 43;
pub const RESPONSE_FIRST_READ_LEN: usize = 59;
pub const MAX_PAYLOAD_LEN: usize = u16::MAX as usize;
pub const MAX_DECRYPT_WIRE_LEN: usize = MAX_PAYLOAD_LEN + TAG_LEN;
const FRAME_16K_PAYLOAD_LEN: usize = 16 * 1024;
const FRAME_32K_PAYLOAD_LEN: usize = 32 * 1024;
pub const ADAPTIVE_FRAME_GROW_BYTES: u64 = 512 * 1024;

#[cfg(any(
    all(
        feature = "__frame-size-16k",
        feature = "__frame-size-65535",
        not(feature = "__frame-size-adaptive")
    ),
    all(
        feature = "__frame-size-16k",
        feature = "__frame-size-adaptive",
        not(feature = "__frame-size-65535")
    ),
    all(
        feature = "__frame-size-65535",
        feature = "__frame-size-adaptive",
        not(feature = "__frame-size-16k")
    )
))]
compile_error!("frame-size experiment features are mutually exclusive");

// Cargo's all-features gate intentionally selects the ordinary 32 KiB
// behavior. It is a compile-only feature-closure check, never a qualifying
// frame build identity. Every qualifying artifact uses either no experiment
// feature or exactly one experiment feature.
const FEATURE_CLOSURE_CHECK: bool = cfg!(all(
    feature = "__frame-size-16k",
    feature = "__frame-size-65535",
    feature = "__frame-size-adaptive"
));
const FRAME_16K_ENABLED: bool = cfg!(feature = "__frame-size-16k") && !FEATURE_CLOSURE_CHECK;
const FRAME_65535_ENABLED: bool = cfg!(feature = "__frame-size-65535") && !FEATURE_CLOSURE_CHECK;
const FRAME_ADAPTIVE_ENABLED: bool =
    cfg!(feature = "__frame-size-adaptive") && !FEATURE_CLOSURE_CHECK;

/// Payload limit used before any adaptive growth.
pub const INITIAL_ENCODE_PAYLOAD_LEN: usize = if FRAME_16K_ENABLED {
    FRAME_16K_PAYLOAD_LEN
} else if FRAME_65535_ENABLED {
    MAX_PAYLOAD_LEN
} else {
    FRAME_32K_PAYLOAD_LEN
};

/// Largest payload this exact build may encode after any adaptive growth.
pub const MAX_ENCODE_PAYLOAD_LEN: usize = if FRAME_65535_ENABLED || FRAME_ADAPTIVE_ENABLED {
    MAX_PAYLOAD_LEN
} else {
    INITIAL_ENCODE_PAYLOAD_LEN
};

/// Closed artifact identity for the qualifying frame-size build axis.
pub const FRAME_SIZE_BUILD_IDENTITY: &str = if FRAME_16K_ENABLED {
    "frame16k"
} else if FRAME_65535_ENABLED {
    "frame65535"
} else if FRAME_ADAPTIVE_ENABLED {
    "adaptive"
} else if FEATURE_CLOSURE_CHECK {
    "all-features-compile-check"
} else {
    "default32"
};

pub const INITIAL_ENCRYPT_WIRE_LEN: usize = MAX_TCP_SALT_LEN
    + MAX_RESPONSE_FIXED_PLAINTEXT_LEN
    + TAG_LEN
    + INITIAL_ENCODE_PAYLOAD_LEN
    + TAG_LEN;
pub const MAX_ENCRYPT_WIRE_LEN: usize = MAX_TCP_SALT_LEN
    + MAX_RESPONSE_FIXED_PLAINTEXT_LEN
    + TAG_LEN
    + MAX_ENCODE_PAYLOAD_LEN
    + TAG_LEN;
pub const MAX_PADDING_LEN: usize = 900;

pub(crate) const REQUEST_TYPE: u8 = 0;
pub(crate) const RESPONSE_TYPE: u8 = 1;
const IPV4_ATYP: u8 = 1;
const DOMAIN_ATYP: u8 = 3;
const IPV6_ATYP: u8 = 4;
pub(super) const REQUEST_FIXED_PLAINTEXT_LEN: usize = 11;
const MAX_TCP_SALT_LEN: usize = 32;
pub(super) const MAX_RESPONSE_FIXED_PLAINTEXT_LEN: usize = 43;
pub(super) const ENCRYPTED_LENGTH_LEN: usize = 2 + TAG_LEN;

/// Per-direction frame cap state. It never batches reads: callers ask for the
/// current limit once, issue one read, seal exactly the returned bytes, and
/// only then account progress for the next frame.
pub(super) struct EncodeFrameSizer {
    encoded_plaintext_bytes: u64,
}

impl EncodeFrameSizer {
    pub(super) const fn new() -> Self {
        Self {
            encoded_plaintext_bytes: 0,
        }
    }

    pub(super) const fn payload_limit(&self) -> usize {
        if FRAME_ADAPTIVE_ENABLED && self.encoded_plaintext_bytes >= ADAPTIVE_FRAME_GROW_BYTES {
            MAX_ENCODE_PAYLOAD_LEN
        } else {
            INITIAL_ENCODE_PAYLOAD_LEN
        }
    }

    pub(super) fn prepare_scratch(&self, scratch: &mut BytesMut) -> Result<(), FrameError> {
        let required = encrypt_wire_len(self.payload_limit())?;
        if scratch.capacity() < required {
            if !scratch.is_empty() {
                return Err(FrameError::Bounds);
            }
            *scratch = BytesMut::with_capacity(required);
        }
        if scratch.capacity() < required {
            return Err(FrameError::Bounds);
        }
        Ok(())
    }

    pub(super) fn record(&mut self, payload_len: usize) -> Result<(), FrameError> {
        if payload_len > self.payload_limit() {
            return Err(FrameError::Bounds);
        }
        self.encoded_plaintext_bytes = self
            .encoded_plaintext_bytes
            .saturating_add(payload_len as u64);
        Ok(())
    }
}

fn encrypt_wire_len(payload_len: usize) -> Result<usize, FrameError> {
    match MAX_TCP_SALT_LEN
        .checked_add(MAX_RESPONSE_FIXED_PLAINTEXT_LEN)
        .and_then(|length| length.checked_add(TAG_LEN))
        .and_then(|length| length.checked_add(payload_len))
        .and_then(|length| length.checked_add(TAG_LEN))
    {
        Some(length) => Ok(length),
        None => Err(FrameError::Bounds),
    }
}

pub(super) struct ParsedRequest {
    pub(super) target: TargetAddr,
    pub(super) initial_payload: Bytes,
}

pub(super) fn parse_request_variable(variable: &[u8]) -> Result<ParsedRequest, DetectionReason> {
    let (target, address_len) = validate_target(variable)?;
    let padding_end = address_len
        .checked_add(2)
        .ok_or(DetectionReason::FrameBounds)?;
    if padding_end > variable.len() {
        return Err(DetectionReason::AddressBounds);
    }
    let padding_len = usize::from(u16::from_be_bytes(
        variable[address_len..padding_end]
            .try_into()
            .expect("padding width"),
    ));
    if padding_len > MAX_PADDING_LEN {
        return Err(DetectionReason::PaddingBounds);
    }
    let payload_start = padding_end
        .checked_add(padding_len)
        .ok_or(DetectionReason::FrameBounds)?;
    if payload_start > variable.len() {
        return Err(DetectionReason::PaddingBounds);
    }
    let initial_payload = &variable[payload_start..];
    if padding_len == 0 && initial_payload.is_empty() {
        return Err(DetectionReason::EmptyRequest);
    }
    let target = target.into_owned()?;
    Ok(ParsedRequest {
        target,
        initial_payload: Bytes::copy_from_slice(initial_payload),
    })
}

pub(crate) enum ValidatedTarget<'a> {
    Ip(SocketAddr),
    Domain(&'a str, u16),
}

impl ValidatedTarget<'_> {
    pub(crate) fn into_owned(self) -> Result<TargetAddr, DetectionReason> {
        match self {
            Self::Ip(address) => {
                TargetAddr::ip(address).map_err(|_| DetectionReason::AddressBounds)
            }
            Self::Domain(host, port) => {
                TargetAddr::domain(host, port).map_err(|_| DetectionReason::AddressBounds)
            }
        }
    }
}

pub(crate) fn validate_target(
    variable: &[u8],
) -> Result<(ValidatedTarget<'_>, usize), DetectionReason> {
    let atyp = *variable.first().ok_or(DetectionReason::AddressBounds)?;
    match atyp {
        IPV4_ATYP => {
            if variable.len() < 7 {
                return Err(DetectionReason::AddressBounds);
            }
            let address = Ipv4Addr::new(variable[1], variable[2], variable[3], variable[4]);
            let port = u16::from_be_bytes([variable[5], variable[6]]);
            if port == 0 {
                return Err(DetectionReason::AddressBounds);
            }
            Ok((
                ValidatedTarget::Ip(SocketAddr::new(address.into(), port)),
                7,
            ))
        }
        IPV6_ATYP => {
            if variable.len() < 19 {
                return Err(DetectionReason::AddressBounds);
            }
            let address =
                Ipv6Addr::from(<[u8; 16]>::try_from(&variable[1..17]).expect("fixed IPv6 region"));
            let port = u16::from_be_bytes([variable[17], variable[18]]);
            if port == 0 {
                return Err(DetectionReason::AddressBounds);
            }
            Ok((
                ValidatedTarget::Ip(SocketAddr::new(address.into(), port)),
                19,
            ))
        }
        DOMAIN_ATYP => {
            let length = usize::from(*variable.get(1).ok_or(DetectionReason::AddressBounds)?);
            let host_end = 2_usize
                .checked_add(length)
                .ok_or(DetectionReason::FrameBounds)?;
            let port_end = host_end
                .checked_add(2)
                .ok_or(DetectionReason::FrameBounds)?;
            if port_end > variable.len() {
                return Err(DetectionReason::AddressBounds);
            }
            let host = std::str::from_utf8(&variable[2..host_end])
                .map_err(|_| DetectionReason::AddressBounds)?;
            let port =
                u16::from_be_bytes(variable[host_end..port_end].try_into().expect("port width"));
            if host.is_empty() || !host.is_ascii() || port == 0 {
                return Err(DetectionReason::AddressBounds);
            }
            Ok((ValidatedTarget::Domain(host, port), port_end))
        }
        _ => Err(DetectionReason::AddressBounds),
    }
}

/// Builds a deterministic contiguous request first-write for reviewed fixtures.
pub fn encode_request_first_write<K: TcpKeyProvider>(
    keys: &K,
    salt: &MethodTcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(MAX_TCP_SALT_LEN + 27 + MAX_DECRYPT_WIRE_LEN);
    let _ = encode_request_state_into(
        keys,
        salt,
        timestamp,
        target,
        padding,
        initial_payload,
        &mut scratch,
    )?;
    Ok(scratch.freeze())
}

pub(super) fn encode_request_state_into<K: TcpKeyProvider>(
    keys: &K,
    salt: &MethodTcpSalt,
    timestamp: u64,
    target: &TargetAddr,
    padding: &[u8],
    initial_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    if padding.len() > MAX_PADDING_LEN {
        return Err(FrameError::PaddingBounds);
    }
    if padding.is_empty() && initial_payload.is_empty() {
        return Err(FrameError::EmptyRequest);
    }
    if keys.tcp_profile() != salt.profile() {
        return Err(FrameError::KeyUnavailable);
    }
    let address_len = encoded_target_len(target)?;
    let variable_len = address_len
        .checked_add(2)
        .and_then(|length| length.checked_add(padding.len()))
        .and_then(|length| length.checked_add(initial_payload.len()))
        .ok_or(FrameError::Bounds)?;
    let variable_u16 = u16::try_from(variable_len).map_err(|_| FrameError::Bounds)?;
    let request_first_read_len = salt.profile().initial_request_read_bytes();
    let salt_len = salt.profile().salt_bytes();
    let variable_wire_len = variable_len
        .checked_add(TAG_LEN)
        .ok_or(FrameError::Bounds)?;
    let total = request_first_read_len
        .checked_add(variable_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    let mut sealer = sealer_for(keys, salt)?;

    scratch.clear();
    scratch.resize(total, 0);
    scratch[..salt_len].copy_from_slice(salt.as_bytes());

    let fixed_end = salt_len + REQUEST_FIXED_PLAINTEXT_LEN;
    scratch[salt_len] = REQUEST_TYPE;
    scratch[salt_len + 1..salt_len + 9].copy_from_slice(&timestamp.to_be_bytes());
    scratch[salt_len + 9..fixed_end].copy_from_slice(&variable_u16.to_be_bytes());

    let variable_end = request_first_read_len + variable_len;
    encode_target_into_slice(
        target,
        &mut scratch[request_first_read_len..request_first_read_len + address_len],
    )?;
    let padding_length_start = request_first_read_len + address_len;
    let padding_start = padding_length_start + 2;
    let payload_start = padding_start + padding.len();
    scratch[padding_length_start..padding_start].copy_from_slice(
        &u16::try_from(padding.len())
            .map_err(|_| FrameError::PaddingBounds)?
            .to_be_bytes(),
    );
    scratch[padding_start..payload_start].copy_from_slice(padding);
    scratch[payload_start..variable_end].copy_from_slice(initial_payload);

    seal_wire_region(
        &mut sealer,
        &mut scratch[salt_len..request_first_read_len],
        REQUEST_FIXED_PLAINTEXT_LEN,
    )?;
    seal_wire_region(
        &mut sealer,
        &mut scratch[request_first_read_len..total],
        variable_len,
    )?;
    Ok(sealer)
}

fn encode_target_into_slice(target: &TargetAddr, destination: &mut [u8]) -> Result<(), FrameError> {
    if destination.len() != encoded_target_len(target)? {
        return Err(FrameError::Bounds);
    }
    match target.host() {
        ferrum2_core::TargetHostRef::Ip(IpAddr::V4(address)) => {
            destination[0] = IPV4_ATYP;
            destination[1..5].copy_from_slice(&address.octets());
            destination[5..].copy_from_slice(&target.port().get().to_be_bytes());
        }
        ferrum2_core::TargetHostRef::Ip(IpAddr::V6(address)) => {
            destination[0] = IPV6_ATYP;
            destination[1..17].copy_from_slice(&address.octets());
            destination[17..].copy_from_slice(&target.port().get().to_be_bytes());
        }
        ferrum2_core::TargetHostRef::Domain(host) => {
            let host_len = u8::try_from(host.len()).map_err(|_| FrameError::AddressUnsupported)?;
            destination[0] = DOMAIN_ATYP;
            destination[1] = host_len;
            let host_end = 2 + host.len();
            destination[2..host_end].copy_from_slice(host.as_bytes());
            destination[host_end..].copy_from_slice(&target.port().get().to_be_bytes());
        }
    }
    Ok(())
}

pub(crate) fn encoded_target_len(target: &TargetAddr) -> Result<usize, FrameError> {
    match target.host() {
        ferrum2_core::TargetHostRef::Ip(IpAddr::V4(_)) => Ok(7),
        ferrum2_core::TargetHostRef::Ip(IpAddr::V6(_)) => Ok(19),
        ferrum2_core::TargetHostRef::Domain(host) => {
            4_usize.checked_add(host.len()).ok_or(FrameError::Bounds)
        }
    }
}

/// Builds a deterministic contiguous response first-write for reviewed fixtures.
pub fn encode_response_first_write<K: TcpKeyProvider>(
    keys: &K,
    response_salt: &MethodTcpSalt,
    timestamp: u64,
    request_salt: &MethodTcpSalt,
    first_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(MAX_ENCRYPT_WIRE_LEN);
    let _ = encode_response_state_into(
        keys,
        response_salt,
        timestamp,
        request_salt,
        first_payload,
        &mut scratch,
    )?;
    Ok(scratch.freeze())
}

pub(super) fn encode_response_state_into<K: TcpKeyProvider>(
    keys: &K,
    response_salt: &MethodTcpSalt,
    timestamp: u64,
    request_salt: &MethodTcpSalt,
    first_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    if first_payload.is_empty() {
        return Err(FrameError::EmptyResponse);
    }
    if first_payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    if response_salt == request_salt {
        return Err(FrameError::ResponseSaltReuse);
    }
    if response_salt.profile() != request_salt.profile()
        || keys.tcp_profile() != response_salt.profile()
    {
        return Err(FrameError::KeyUnavailable);
    }
    let mut sealer =
        prepare_response_state_into(keys, response_salt, timestamp, request_salt, scratch)?;
    scratch.extend_from_slice(first_payload);
    seal_prepared_response_state_into(
        &mut sealer,
        response_salt.profile(),
        first_payload.len(),
        scratch,
    )?;
    Ok(sealer)
}

/// Prepares the fixed response header while leaving the final payload region
/// as the next append position.
pub(super) fn prepare_response_state_into<K: TcpKeyProvider>(
    keys: &K,
    response_salt: &MethodTcpSalt,
    timestamp: u64,
    request_salt: &MethodTcpSalt,
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    let response_first_read_len = response_salt.profile().initial_response_read_bytes();
    if response_first_read_len > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.resize(response_first_read_len, 0);
    prepare_response_state_in_place(keys, response_salt, timestamp, request_salt, scratch)
}

/// Populates a fixed response header without moving a payload that already
/// occupies its final offset.
pub(super) fn prepare_response_state_in_place<K: TcpKeyProvider>(
    keys: &K,
    response_salt: &MethodTcpSalt,
    timestamp: u64,
    request_salt: &MethodTcpSalt,
    scratch: &mut BytesMut,
) -> Result<TcpSealer, FrameError> {
    if response_salt == request_salt {
        return Err(FrameError::ResponseSaltReuse);
    }
    if response_salt.profile() != request_salt.profile()
        || keys.tcp_profile() != response_salt.profile()
    {
        return Err(FrameError::KeyUnavailable);
    }
    let profile = response_salt.profile();
    let fixed_plaintext_len = response_fixed_plaintext_len(profile);
    let response_first_read_len = profile.initial_response_read_bytes();
    let salt_len = profile.salt_bytes();
    if response_first_read_len > scratch.len() {
        return Err(FrameError::Bounds);
    }
    let sealer = sealer_for(keys, response_salt)?;

    scratch[..salt_len].copy_from_slice(response_salt.as_bytes());
    scratch[salt_len] = RESPONSE_TYPE;
    scratch[salt_len + 1..salt_len + 9].copy_from_slice(&timestamp.to_be_bytes());
    let binding_end = salt_len + 9 + request_salt.as_bytes().len();
    scratch[salt_len + 9..binding_end].copy_from_slice(request_salt.as_bytes());
    debug_assert_eq!(binding_end + 2, salt_len + fixed_plaintext_len);
    Ok(sealer)
}

/// Seals a response whose payload was appended directly after the prepared
/// fixed header.
pub(super) fn seal_prepared_response_state_into(
    sealer: &mut TcpSealer,
    profile: MethodProfile,
    payload_len: usize,
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if payload_len == 0 {
        return Err(FrameError::EmptyResponse);
    }
    if payload_len > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    let payload_u16 = u16::try_from(payload_len).map_err(|_| FrameError::Bounds)?;
    let fixed_plaintext_len = response_fixed_plaintext_len(profile);
    let response_first_read_len = profile.initial_response_read_bytes();
    let salt_len = profile.salt_bytes();
    let payload_end = response_first_read_len
        .checked_add(payload_len)
        .ok_or(FrameError::Bounds)?;
    if scratch.len() != payload_end {
        return Err(FrameError::Bounds);
    }
    let total = payload_end.checked_add(TAG_LEN).ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN || total > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    let length_start = salt_len + fixed_plaintext_len - 2;
    scratch[length_start..length_start + 2].copy_from_slice(&payload_u16.to_be_bytes());
    scratch.resize(total, 0);
    seal_wire_region(
        sealer,
        &mut scratch[salt_len..response_first_read_len],
        fixed_plaintext_len,
    )?;
    seal_wire_region(
        sealer,
        &mut scratch[response_first_read_len..total],
        payload_len,
    )
}

pub(super) fn seal_data_chunk_into(
    sealer: &mut TcpSealer,
    payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    prepare_data_chunk_into(scratch)?;
    scratch.extend_from_slice(payload);
    seal_prepared_data_chunk_into(sealer, payload.len(), scratch)
}

/// Positions the next plaintext read directly at the final data-frame payload
/// offset.
pub(super) fn prepare_data_chunk_into(scratch: &mut BytesMut) -> Result<(), FrameError> {
    if ENCRYPTED_LENGTH_LEN > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.resize(ENCRYPTED_LENGTH_LEN, 0);
    Ok(())
}

/// Seals a data frame whose payload was appended directly into its final wire
/// layout.
pub(super) fn seal_prepared_data_chunk_into(
    sealer: &mut TcpSealer,
    payload_len: usize,
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if payload_len > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    let payload_u16 = u16::try_from(payload_len).map_err(|_| FrameError::Bounds)?;
    let payload_end = ENCRYPTED_LENGTH_LEN
        .checked_add(payload_len)
        .ok_or(FrameError::Bounds)?;
    if scratch.len() != payload_end {
        return Err(FrameError::Bounds);
    }
    let total = payload_end.checked_add(TAG_LEN).ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN || total > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    scratch[..2].copy_from_slice(&payload_u16.to_be_bytes());
    scratch.resize(total, 0);
    seal_wire_region(sealer, &mut scratch[..ENCRYPTED_LENGTH_LEN], 2)?;
    seal_wire_region(
        sealer,
        &mut scratch[ENCRYPTED_LENGTH_LEN..total],
        payload_len,
    )
}

fn seal_wire_region(
    sealer: &mut TcpSealer,
    wire: &mut [u8],
    plaintext_len: usize,
) -> Result<(), FrameError> {
    let expected_len = plaintext_len
        .checked_add(TAG_LEN)
        .ok_or(FrameError::Bounds)?;
    if wire.len() != expected_len {
        return Err(FrameError::Bounds);
    }
    let (plaintext, tag) = wire.split_at_mut(plaintext_len);
    let tag: &mut [u8; TAG_LEN] = tag.try_into().map_err(|_| FrameError::Bounds)?;
    sealer
        .seal_in_place_detached(plaintext, tag)
        .map_err(frame_from_seal_aead)
}

/// Authenticates one complete subsequent frame for deterministic codec tests.
pub fn open_data_frame(
    opener: &mut TcpOpener,
    encrypted_length: &[u8],
    encrypted_payload: &[u8],
) -> Result<Bytes, FrameError> {
    let mut scratch = BytesMut::with_capacity(MAX_DECRYPT_WIRE_LEN);
    open_data_frame_into(opener, encrypted_length, encrypted_payload, &mut scratch)?;
    Ok(scratch.freeze())
}

pub(super) fn open_data_frame_into(
    opener: &mut TcpOpener,
    encrypted_length: &[u8],
    encrypted_payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if encrypted_length.len() != ENCRYPTED_LENGTH_LEN
        || encrypted_payload.len() > MAX_DECRYPT_WIRE_LEN
    {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.extend_from_slice(encrypted_length);
    opener
        .open_in_place(scratch)
        .map_err(frame_from_open_aead)?;
    if scratch.len() != 2 {
        return Err(FrameError::Bounds);
    }
    let payload_len = usize::from(u16::from_be_bytes([scratch[0], scratch[1]]));
    if encrypted_payload.len() != payload_len.checked_add(TAG_LEN).ok_or(FrameError::Bounds)? {
        return Err(FrameError::Bounds);
    }
    scratch.clear();
    scratch.extend_from_slice(encrypted_payload);
    opener
        .open_in_place(scratch)
        .map_err(frame_from_open_aead)?;
    if scratch.len() != payload_len {
        return Err(FrameError::Bounds);
    }
    Ok(())
}

pub(super) fn response_fixed_plaintext_len(profile: MethodProfile) -> usize {
    11 + profile.salt_bytes()
}

pub(super) fn sealer_for<K: TcpKeyProvider>(
    keys: &K,
    salt: &MethodTcpSalt,
) -> Result<TcpSealer, FrameError> {
    keys.tcp_sealer(salt)
        .map_err(|_| FrameError::KeyUnavailable)
}

pub(super) fn opener_for<K: TcpKeyProvider>(
    keys: &K,
    salt: &MethodTcpSalt,
) -> Result<TcpOpener, DetectionReason> {
    keys.tcp_opener(salt)
        .map_err(|_| DetectionReason::KeyUnavailable)
}

pub(super) fn sample_nonzero_padding(
    random: &(impl SecureRandom + ?Sized),
    padding: &mut [u8; MAX_PADDING_LEN],
) -> Result<usize, FrameError> {
    const SAMPLE_RANGE: u32 = (u16::MAX as u32) + 1;
    const ACCEPTED_RANGE: u32 = (SAMPLE_RANGE / MAX_PADDING_LEN as u32) * MAX_PADDING_LEN as u32;
    let mut sample = [0_u8; 2];
    let length = loop {
        random.fill(&mut sample).map_err(|_| FrameError::Bounds)?;
        let value = u32::from(u16::from_be_bytes(sample));
        if value < ACCEPTED_RANGE {
            break (value % MAX_PADDING_LEN as u32) as usize + 1;
        }
    };
    random
        .fill(&mut padding[..length])
        .map_err(|_| FrameError::Bounds)?;
    Ok(length)
}

#[cfg(test)]
mod frame_size_tests {
    use super::*;

    #[test]
    fn qualifying_build_identity_has_exact_frame_bounds() {
        if FRAME_16K_ENABLED {
            assert_eq!(FRAME_SIZE_BUILD_IDENTITY, "frame16k");
            assert_eq!(INITIAL_ENCODE_PAYLOAD_LEN, 16_384);
            assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 16_384);
        } else if FRAME_65535_ENABLED {
            assert_eq!(FRAME_SIZE_BUILD_IDENTITY, "frame65535");
            assert_eq!(INITIAL_ENCODE_PAYLOAD_LEN, 65_535);
            assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 65_535);
        } else if FRAME_ADAPTIVE_ENABLED {
            assert_eq!(FRAME_SIZE_BUILD_IDENTITY, "adaptive");
            assert_eq!(INITIAL_ENCODE_PAYLOAD_LEN, 32_768);
            assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 65_535);
        } else {
            let expected = if FEATURE_CLOSURE_CHECK {
                "all-features-compile-check"
            } else {
                "default32"
            };
            assert_eq!(FRAME_SIZE_BUILD_IDENTITY, expected);
            assert_eq!(INITIAL_ENCODE_PAYLOAD_LEN, 32_768);
            assert_eq!(MAX_ENCODE_PAYLOAD_LEN, 32_768);
        }
        assert_eq!(
            INITIAL_ENCRYPT_WIRE_LEN,
            encrypt_wire_len(INITIAL_ENCODE_PAYLOAD_LEN).expect("initial wire bound")
        );
        assert_eq!(
            MAX_ENCRYPT_WIRE_LEN,
            encrypt_wire_len(MAX_ENCODE_PAYLOAD_LEN).expect("maximum wire bound")
        );
        assert!(MAX_ENCODE_PAYLOAD_LEN <= u16::MAX as usize);
    }

    #[cfg(all(
        feature = "__frame-size-adaptive",
        not(feature = "__frame-size-16k"),
        not(feature = "__frame-size-65535")
    ))]
    #[test]
    fn adaptive_capacity_grows_only_after_exact_direction_threshold() {
        let mut sizer = EncodeFrameSizer::new();
        let mut scratch = BytesMut::with_capacity(INITIAL_ENCRYPT_WIRE_LEN);
        let initial_pointer = scratch.as_ptr();

        for _ in 0..15 {
            sizer
                .record(INITIAL_ENCODE_PAYLOAD_LEN)
                .expect("initial frame");
        }
        sizer
            .record(INITIAL_ENCODE_PAYLOAD_LEN - 1)
            .expect("threshold minus one");
        assert_eq!(sizer.payload_limit(), INITIAL_ENCODE_PAYLOAD_LEN);
        sizer.prepare_scratch(&mut scratch).expect("no early grow");
        assert_eq!(scratch.capacity(), INITIAL_ENCRYPT_WIRE_LEN);
        assert_eq!(scratch.as_ptr(), initial_pointer);

        sizer.record(1).expect("exact threshold");
        assert_eq!(sizer.payload_limit(), MAX_ENCODE_PAYLOAD_LEN);
        sizer.prepare_scratch(&mut scratch).expect("exact grow");
        assert_eq!(scratch.capacity(), MAX_ENCRYPT_WIRE_LEN);
        assert_ne!(scratch.as_ptr(), initial_pointer);
    }

    #[cfg(not(all(
        feature = "__frame-size-adaptive",
        not(feature = "__frame-size-16k"),
        not(feature = "__frame-size-65535")
    )))]
    #[test]
    fn fixed_candidate_capacity_never_changes_with_cumulative_bytes() {
        let mut sizer = EncodeFrameSizer::new();
        let mut scratch = BytesMut::with_capacity(INITIAL_ENCRYPT_WIRE_LEN);
        let initial_pointer = scratch.as_ptr();
        for _ in 0..64 {
            sizer
                .record(INITIAL_ENCODE_PAYLOAD_LEN)
                .expect("bounded frame");
        }
        sizer.prepare_scratch(&mut scratch).expect("fixed capacity");
        assert_eq!(sizer.payload_limit(), INITIAL_ENCODE_PAYLOAD_LEN);
        assert_eq!(scratch.capacity(), INITIAL_ENCRYPT_WIRE_LEN);
        assert_eq!(scratch.as_ptr(), initial_pointer);
    }
}
