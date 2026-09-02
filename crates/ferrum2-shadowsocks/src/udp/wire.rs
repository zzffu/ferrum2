use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr};
use ferrum2_crypto::{
    Clock, KeySelector, MethodKeyProvider, MethodProfile, SecureRandom, UdpCrypto, UdpCryptoError,
    UdpOutboundSession, UdpSessionId,
};

use super::{
    COMMON_HEADER_LEN, MAX_UDP_WIRE_LEN, PADDING_LEN, RESPONSE_BINDING_LEN, SESSION_ID_LEN,
    TIMESTAMP_LEN, UdpPacketError, UdpPacketScratch,
};
use crate::tcp::wire::{
    RESPONSE_TYPE, ValidatedTarget, encode_target_into, encoded_target_len, validate_target,
};
use crate::{DetectionReason, FrameError};

pub(super) struct OpenedPacket {
    pub(super) session_id: UdpSessionId,
    pub(super) packet_id: u64,
    pub(super) datagram: Datagram,
}

pub(super) struct BorrowedOpenedPacket<'a> {
    pub(super) session_id: UdpSessionId,
    pub(super) packet_id: u64,
    pub(super) target: ValidatedTarget<'a>,
    pub(super) payload: &'a [u8],
}

/// Computes the largest payload fitting the complete 65,507-byte wire bound.
pub fn max_udp_payload_len(
    profile: MethodProfile,
    response: bool,
    target: &TargetAddr,
    padding_len: usize,
) -> Result<usize, UdpPacketError> {
    let address_len = encoded_target_len(target).map_err(map_frame)?;
    max_udp_payload_len_for_encoded_target(profile, response, address_len, padding_len)
}

/// Computes the largest payload from an already validated encoded target width.
pub fn max_udp_payload_len_for_encoded_target(
    profile: MethodProfile,
    response: bool,
    encoded_target_len: usize,
    padding_len: usize,
) -> Result<usize, UdpPacketError> {
    let semantic_overhead = COMMON_HEADER_LEN
        .checked_add(if response { RESPONSE_BINDING_LEN } else { 0 })
        .and_then(|length| length.checked_add(padding_len))
        .and_then(|length| length.checked_add(encoded_target_len))
        .ok_or(UdpPacketError::Bounds)?;
    if padding_len > usize::from(u16::MAX) {
        return Err(UdpPacketError::Bounds);
    }
    MAX_UDP_WIRE_LEN
        .checked_sub(profile.udp_wire_overhead_bytes())
        .and_then(|length| length.checked_sub(semantic_overhead))
        .ok_or(UdpPacketError::Bounds)
}
pub(super) fn udp_wire_len(
    profile: MethodProfile,
    response: bool,
    target: &TargetAddr,
    payload_len: usize,
    padding_len: usize,
) -> Result<usize, UdpPacketError> {
    let max_payload = max_udp_payload_len(profile, response, target, padding_len)?;
    let unused_payload = max_payload
        .checked_sub(payload_len)
        .ok_or(UdpPacketError::Bounds)?;
    MAX_UDP_WIRE_LEN
        .checked_sub(unused_payload)
        .ok_or(UdpPacketError::Bounds)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encode_packet(
    crypto: &UdpCrypto,
    outbound: &mut UdpOutboundSession,
    clock: &(impl Clock + ?Sized),
    random: &(impl SecureRandom + ?Sized),
    message_type: u8,
    binding: Option<&UdpSessionId>,
    target: &TargetAddr,
    payload: &[u8],
    padding_len: usize,
    output: &mut [u8],
    scratch: &mut UdpPacketScratch,
) -> Result<usize, UdpPacketError> {
    let response = message_type == RESPONSE_TYPE;
    let max_payload = max_udp_payload_len(crypto.profile(), response, target, padding_len)?;
    if payload.len() > max_payload {
        return Err(UdpPacketError::Bounds);
    }
    let body_len = MAX_UDP_WIRE_LEN
        - crypto.profile().udp_wire_overhead_bytes()
        - (max_payload - payload.len());
    let wire_len = body_len
        .checked_add(crypto.profile().udp_wire_overhead_bytes())
        .ok_or(UdpPacketError::Bounds)?;
    if output.len() < wire_len {
        return Err(UdpPacketError::Bounds);
    }
    let timestamp = clock.unix_seconds().map_err(|_| UdpPacketError::Clock)?;

    scratch.body.clear();
    scratch.body.extend_from_slice(&[message_type]);
    scratch.body.extend_from_slice(&timestamp.to_be_bytes());
    if let Some(binding) = binding {
        let start = scratch.body.len();
        scratch.body.resize(start + SESSION_ID_LEN, 0);
        binding
            .write_wire(&mut scratch.body[start..])
            .map_err(map_crypto)?;
    }
    scratch.body.extend_from_slice(
        &u16::try_from(padding_len)
            .map_err(|_| UdpPacketError::Bounds)?
            .to_be_bytes(),
    );
    let padding_start = scratch.body.len();
    scratch.body.resize(padding_start + padding_len, 0);
    if padding_len != 0 {
        random
            .fill(&mut scratch.body[padding_start..])
            .map_err(|_| UdpPacketError::Random)?;
    }
    encode_target_into(target, &mut scratch.body).map_err(map_frame)?;
    scratch.body.extend_from_slice(payload);
    debug_assert_eq!(scratch.body.len(), body_len);

    crypto
        .seal(outbound, &scratch.body, output, random)
        .map(|sealed| sealed.wire_len())
        .map_err(map_crypto)
}

pub(super) fn open_packet(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<OpenedPacket, UdpPacketError> {
    let opened = open_packet_borrowed(crypto, clock, wire, scratch, expected_type, binding)?;
    let target = opened.target.into_owned().map_err(map_target)?;
    let payload_len = opened.payload.len();
    let datagram = Datagram::new(target, BytesMut::from(opened.payload), payload_len)
        .map_err(|_| UdpPacketError::Bounds)?;
    Ok(OpenedPacket {
        session_id: opened.session_id,
        packet_id: opened.packet_id,
        datagram,
    })
}

pub(super) fn open_packet_borrowed<'a>(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &[u8],
    scratch: &'a mut UdpPacketScratch,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<BorrowedOpenedPacket<'a>, UdpPacketError> {
    if wire.len() > MAX_UDP_WIRE_LEN {
        return Err(UdpPacketError::Bounds);
    }
    scratch.body.clear();
    scratch.body.resize(wire.len(), 0);
    let opened = crypto
        .open_with_cache(wire, &mut scratch.body, &mut scratch.open_cache)
        .map_err(map_crypto)?;
    scratch.body.truncate(opened.plaintext_len());
    let (target, payload_start) = parse_body(&scratch.body, clock, expected_type, binding)?;
    Ok(BorrowedOpenedPacket {
        session_id: opened.session_id().clone(),
        packet_id: opened.packet_id(),
        target,
        payload: &scratch.body[payload_start..],
    })
}

fn parse_body<'a>(
    body: &'a [u8],
    clock: &(impl Clock + ?Sized),
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<(ValidatedTarget<'a>, usize), UdpPacketError> {
    let message_type = *body.first().ok_or(UdpPacketError::Bounds)?;
    if message_type != expected_type {
        return Err(UdpPacketError::Type);
    }
    let timestamp_end = 1 + TIMESTAMP_LEN;
    let timestamp = u64::from_be_bytes(
        body.get(1..timestamp_end)
            .ok_or(UdpPacketError::Bounds)?
            .try_into()
            .expect("timestamp width"),
    );
    let now = clock.unix_seconds().map_err(|_| UdpPacketError::Clock)?;
    if now.abs_diff(timestamp) > 30 {
        return Err(UdpPacketError::Timestamp);
    }
    let mut cursor = timestamp_end;
    if let Some(binding) = binding {
        let end = cursor
            .checked_add(SESSION_ID_LEN)
            .ok_or(UdpPacketError::Bounds)?;
        let encoded = body.get(cursor..end).ok_or(UdpPacketError::Bounds)?;
        if !binding.matches_wire(encoded) {
            return Err(UdpPacketError::Binding);
        }
        cursor = end;
    }
    let padding_end = cursor
        .checked_add(PADDING_LEN)
        .ok_or(UdpPacketError::Bounds)?;
    let padding_len = usize::from(u16::from_be_bytes(
        body.get(cursor..padding_end)
            .ok_or(UdpPacketError::Padding)?
            .try_into()
            .expect("padding width"),
    ));
    let address_start = padding_end
        .checked_add(padding_len)
        .ok_or(UdpPacketError::Padding)?;
    let address = body.get(address_start..).ok_or(UdpPacketError::Padding)?;
    let (target, address_len) = validate_target(address).map_err(map_target)?;
    let payload_start = address_start
        .checked_add(address_len)
        .ok_or(UdpPacketError::Bounds)?;
    Ok((target, payload_start))
}

pub(super) fn udp_crypto<K: MethodKeyProvider>(keys: &K) -> Result<UdpCrypto, UdpPacketError> {
    keys.with_method_key(KeySelector::Default, |key| key.udp_crypto())
        .map_err(|_| UdpPacketError::Key)
}

fn map_frame(error: FrameError) -> UdpPacketError {
    match error {
        FrameError::AddressUnsupported => UdpPacketError::Address,
        _ => UdpPacketError::Bounds,
    }
}

fn map_target(error: DetectionReason) -> UdpPacketError {
    match error {
        DetectionReason::AddressBounds => UdpPacketError::Address,
        _ => UdpPacketError::Bounds,
    }
}

fn map_crypto(error: UdpCryptoError) -> UdpPacketError {
    match error {
        UdpCryptoError::AuthenticationFailed => UdpPacketError::Authentication,
        UdpCryptoError::RandomUnavailable => UdpPacketError::Random,
        UdpCryptoError::CounterExhausted => UdpPacketError::Counter,
        UdpCryptoError::InputTooShort | UdpCryptoError::OutputTooSmall => UdpPacketError::Bounds,
        UdpCryptoError::MethodMismatch | UdpCryptoError::OperationFailed => UdpPacketError::Key,
    }
}
