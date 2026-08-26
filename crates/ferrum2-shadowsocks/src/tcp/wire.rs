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
pub const MAX_ENCODE_PAYLOAD_LEN: usize = 32_768;
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

    scratch.clear();
    scratch.extend_from_slice(&[REQUEST_TYPE]);
    scratch.extend_from_slice(&timestamp.to_be_bytes());
    scratch.extend_from_slice(&variable_u16.to_be_bytes());
    let mut sealer = sealer_for(keys, salt)?;
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let fixed: [u8; REQUEST_FIXED_PLAINTEXT_LEN + TAG_LEN] = scratch[..]
        .try_into()
        .expect("fixed encrypted request width");

    scratch.clear();
    encode_target_into(target, scratch)?;
    scratch.extend_from_slice(
        &u16::try_from(padding.len())
            .map_err(|_| FrameError::PaddingBounds)?
            .to_be_bytes(),
    );
    scratch.extend_from_slice(padding);
    scratch.extend_from_slice(initial_payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let variable_wire_len = scratch.len();
    let request_first_read_len = salt.profile().initial_request_read_bytes();
    let salt_len = salt.profile().salt_bytes();
    let total = request_first_read_len
        .checked_add(variable_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > scratch.capacity() {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..variable_wire_len, request_first_read_len);
    scratch[..salt_len].copy_from_slice(salt.as_bytes());
    scratch[salt_len..request_first_read_len].copy_from_slice(&fixed);
    Ok(sealer)
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

pub(crate) fn encode_target_into(
    target: &TargetAddr,
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    match target.host() {
        ferrum2_core::TargetHostRef::Ip(IpAddr::V4(address)) => {
            scratch.extend_from_slice(&[IPV4_ATYP]);
            scratch.extend_from_slice(&address.octets());
        }
        ferrum2_core::TargetHostRef::Ip(IpAddr::V6(address)) => {
            scratch.extend_from_slice(&[IPV6_ATYP]);
            scratch.extend_from_slice(&address.octets());
        }
        ferrum2_core::TargetHostRef::Domain(host) => {
            let length = u8::try_from(host.len()).map_err(|_| FrameError::AddressUnsupported)?;
            scratch.extend_from_slice(&[DOMAIN_ATYP, length]);
            scratch.extend_from_slice(host.as_bytes());
        }
    }
    scratch.extend_from_slice(&target.port().get().to_be_bytes());
    Ok(())
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
    let payload_len = u16::try_from(first_payload.len()).map_err(|_| FrameError::Bounds)?;

    scratch.clear();
    scratch.extend_from_slice(&[RESPONSE_TYPE]);
    scratch.extend_from_slice(&timestamp.to_be_bytes());
    scratch.extend_from_slice(request_salt.as_bytes());
    scratch.extend_from_slice(&payload_len.to_be_bytes());
    let mut sealer = sealer_for(keys, response_salt)?;
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let fixed_len = response_fixed_plaintext_len(response_salt.profile()) + TAG_LEN;
    let mut fixed = [0_u8; MAX_RESPONSE_FIXED_PLAINTEXT_LEN + TAG_LEN];
    fixed[..fixed_len].copy_from_slice(scratch);

    scratch.clear();
    scratch.extend_from_slice(first_payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let payload_wire_len = scratch.len();
    let response_first_read_len = response_salt.profile().initial_response_read_bytes();
    let salt_len = response_salt.profile().salt_bytes();
    let total = response_first_read_len
        .checked_add(payload_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..payload_wire_len, response_first_read_len);
    scratch[..salt_len].copy_from_slice(response_salt.as_bytes());
    scratch[salt_len..response_first_read_len].copy_from_slice(&fixed[..fixed_len]);
    Ok(sealer)
}

pub(super) fn seal_data_chunk_into(
    sealer: &mut TcpSealer,
    payload: &[u8],
    scratch: &mut BytesMut,
) -> Result<(), FrameError> {
    if payload.len() > MAX_ENCODE_PAYLOAD_LEN {
        return Err(FrameError::Bounds);
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| FrameError::Bounds)?;
    scratch.clear();
    scratch.extend_from_slice(&payload_len.to_be_bytes());
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let length: [u8; ENCRYPTED_LENGTH_LEN] =
        scratch[..].try_into().expect("encrypted length width");

    scratch.clear();
    scratch.extend_from_slice(payload);
    sealer
        .seal_in_place(scratch)
        .map_err(frame_from_seal_aead)?;
    let payload_wire_len = scratch.len();
    let total = ENCRYPTED_LENGTH_LEN
        .checked_add(payload_wire_len)
        .ok_or(FrameError::Bounds)?;
    if total > MAX_ENCRYPT_WIRE_LEN {
        return Err(FrameError::Bounds);
    }
    scratch.resize(total, 0);
    scratch.copy_within(0..payload_wire_len, ENCRYPTED_LENGTH_LEN);
    scratch[..ENCRYPTED_LENGTH_LEN].copy_from_slice(&length);
    Ok(())
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
