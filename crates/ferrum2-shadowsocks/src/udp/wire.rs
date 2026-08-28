use std::net::IpAddr;
use std::ops::Range;

use bytes::BytesMut;
use ferrum2_core::{Datagram, TargetAddr, TargetHostRef};
use ferrum2_crypto::{
    Clock, KeySelector, MethodKeyProvider, MethodProfile, SecureRandom, UdpCrypto, UdpCryptoError,
    UdpOutboundSession, UdpSessionId,
};
use zeroize::Zeroize;

use super::{
    COMMON_HEADER_LEN, MAX_UDP_WIRE_LEN, PADDING_LEN, RESPONSE_BINDING_LEN, SESSION_ID_LEN,
    TIMESTAMP_LEN, UdpPacketError, UdpPacketScratch,
};
use crate::tcp::wire::{RESPONSE_TYPE, ValidatedTarget, encoded_target_len, validate_target};
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

pub(super) struct OwnedOpenedPacket {
    session_id: UdpSessionId,
    packet_id: u64,
    wire: Option<BytesMut>,
    authenticated_range: Range<usize>,
    target_range: Range<usize>,
    payload_range: Range<usize>,
}

impl OwnedOpenedPacket {
    pub(super) const fn session_id(&self) -> &UdpSessionId {
        &self.session_id
    }

    pub(super) const fn packet_id(&self) -> u64 {
        self.packet_id
    }

    pub(super) fn into_opened_packet(mut self) -> Result<OpenedPacket, UdpPacketError> {
        let wire = self
            .wire
            .as_ref()
            .expect("owned opened packet retains its wire until release");
        let (target, encoded_len) =
            validate_target(&wire[self.target_range.clone()]).map_err(map_target)?;
        debug_assert_eq!(encoded_len, self.target_range.len());
        let target = target.into_owned().map_err(map_target)?;
        let payload_len = self.payload_range.len();
        let payload_start = self.payload_range.start;
        let mut wire = self
            .wire
            .take()
            .expect("owned opened packet releases its wire once");
        let mut payload = wire.split_off(payload_start);
        payload.truncate(payload_len);
        let datagram = match Datagram::new(target, payload, payload_len) {
            Ok(datagram) => datagram,
            Err(_) => {
                wire.zeroize();
                return Err(UdpPacketError::Bounds);
            }
        };
        Ok(OpenedPacket {
            session_id: self.session_id.clone(),
            packet_id: self.packet_id,
            datagram,
        })
    }
}

impl Drop for OwnedOpenedPacket {
    fn drop(&mut self) {
        if let Some(wire) = &mut self.wire {
            wire[self.authenticated_range.clone()].zeroize();
        }
    }
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
) -> Result<usize, UdpPacketError> {
    let response = message_type == RESPONSE_TYPE;
    let address_len = encoded_target_len(target).map_err(map_frame)?;
    let max_payload = max_udp_payload_len_for_encoded_target(
        crypto.profile(),
        response,
        address_len,
        padding_len,
    )?;
    if payload.len() > max_payload {
        return Err(UdpPacketError::Bounds);
    }
    let body_len = COMMON_HEADER_LEN
        .checked_add(if response { RESPONSE_BINDING_LEN } else { 0 })
        .and_then(|length| length.checked_add(padding_len))
        .and_then(|length| length.checked_add(address_len))
        .and_then(|length| length.checked_add(payload.len()))
        .ok_or(UdpPacketError::Bounds)?;
    let timestamp = clock.unix_seconds().map_err(|_| UdpPacketError::Clock)?;
    let padding_len = u16::try_from(padding_len).map_err(|_| UdpPacketError::Bounds)?;
    let mut reservation = crypto
        .reserve_seal(outbound, body_len, output)
        .map_err(map_crypto)?;
    encode_semantic_body(
        reservation.body_mut(),
        random,
        message_type,
        timestamp,
        binding,
        target,
        payload,
        padding_len,
    )?;
    reservation
        .seal(random)
        .map(|sealed| sealed.wire_len())
        .map_err(map_crypto)
}

#[allow(clippy::too_many_arguments)]
fn encode_semantic_body(
    body: &mut [u8],
    random: &(impl SecureRandom + ?Sized),
    message_type: u8,
    timestamp: u64,
    binding: Option<&UdpSessionId>,
    target: &TargetAddr,
    payload: &[u8],
    padding_len: u16,
) -> Result<(), UdpPacketError> {
    let mut writer = BodyWriter::new(body);
    writer.write(&[message_type])?;
    writer.write(&timestamp.to_be_bytes())?;
    if let Some(binding) = binding {
        binding
            .write_wire(writer.take(SESSION_ID_LEN)?)
            .map_err(map_crypto)?;
    }
    writer.write(&padding_len.to_be_bytes())?;
    let padding = writer.take(usize::from(padding_len))?;
    if !padding.is_empty() {
        random.fill(padding).map_err(|_| UdpPacketError::Random)?;
    }
    encode_target(target, &mut writer)?;
    writer.write(payload)?;
    writer.finish()
}

struct BodyWriter<'a> {
    body: &'a mut [u8],
    cursor: usize,
}

impl<'a> BodyWriter<'a> {
    const fn new(body: &'a mut [u8]) -> Self {
        Self { body, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&mut [u8], UdpPacketError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(UdpPacketError::Bounds)?;
        let output = self
            .body
            .get_mut(self.cursor..end)
            .ok_or(UdpPacketError::Bounds)?;
        self.cursor = end;
        Ok(output)
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), UdpPacketError> {
        self.take(bytes.len())?.copy_from_slice(bytes);
        Ok(())
    }

    fn finish(self) -> Result<(), UdpPacketError> {
        if self.cursor == self.body.len() {
            Ok(())
        } else {
            Err(UdpPacketError::Bounds)
        }
    }
}

fn encode_target(target: &TargetAddr, writer: &mut BodyWriter<'_>) -> Result<(), UdpPacketError> {
    match target.host() {
        TargetHostRef::Ip(IpAddr::V4(address)) => {
            writer.write(&[1])?;
            writer.write(&address.octets())?;
        }
        TargetHostRef::Ip(IpAddr::V6(address)) => {
            writer.write(&[4])?;
            writer.write(&address.octets())?;
        }
        TargetHostRef::Domain(host) => {
            let length = u8::try_from(host.len()).map_err(|_| UdpPacketError::Address)?;
            writer.write(&[3, length])?;
            writer.write(host.as_bytes())?;
        }
    }
    writer.write(&target.port().get().to_be_bytes())
}

pub(super) fn open_packet(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &[u8],
    scratch: &mut UdpPacketScratch,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
    validate_identity: impl FnOnce(&UdpSessionId, u64) -> Result<(), UdpPacketError>,
) -> Result<OpenedPacket, UdpPacketError> {
    let opened = open_packet_borrowed(
        crypto,
        clock,
        wire,
        scratch,
        expected_type,
        binding,
        validate_identity,
    )?;
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
    validate_identity: impl FnOnce(&UdpSessionId, u64) -> Result<(), UdpPacketError>,
) -> Result<BorrowedOpenedPacket<'a>, UdpPacketError> {
    if wire.len() > MAX_UDP_WIRE_LEN {
        return Err(UdpPacketError::Bounds);
    }
    scratch.body.clear();
    scratch.body.extend_from_slice(wire);
    open_packet_in_place_borrowed(
        crypto,
        clock,
        &mut scratch.body,
        expected_type,
        binding,
        validate_identity,
    )
}

pub(super) fn open_packet_in_place(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &mut BytesMut,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
    validate_identity: impl FnOnce(&UdpSessionId, u64) -> Result<(), UdpPacketError>,
) -> Result<OpenedPacket, UdpPacketError> {
    let result = (|| {
        let opened = open_packet_in_place_borrowed(
            crypto,
            clock,
            wire,
            expected_type,
            binding,
            validate_identity,
        )?;
        let target = opened.target.into_owned().map_err(map_target)?;
        let payload_len = opened.payload.len();
        let datagram = Datagram::new(target, BytesMut::from(opened.payload), payload_len)
            .map_err(|_| UdpPacketError::Bounds)?;
        Ok(OpenedPacket {
            session_id: opened.session_id,
            packet_id: opened.packet_id,
            datagram,
        })
    })();
    wire.zeroize();
    result
}

pub(super) fn open_packet_in_place_borrowed<'a>(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    wire: &'a mut BytesMut,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
    validate_identity: impl FnOnce(&UdpSessionId, u64) -> Result<(), UdpPacketError>,
) -> Result<BorrowedOpenedPacket<'a>, UdpPacketError> {
    if wire.len() > MAX_UDP_WIRE_LEN {
        wire.zeroize();
        return Err(UdpPacketError::Bounds);
    }
    let opened = match crypto.open_in_place(wire) {
        Ok(opened) => opened,
        Err(error) => {
            wire.zeroize();
            return Err(map_crypto(error));
        }
    };
    let plaintext_range = opened.plaintext_range();
    let parsed = match parse_body(
        &wire[plaintext_range.clone()],
        clock,
        expected_type,
        binding,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            wire.zeroize();
            return Err(error);
        }
    };
    if let Err(error) = validate_identity(opened.session_id(), opened.packet_id()) {
        wire.zeroize();
        return Err(error);
    }
    let payload_start = plaintext_range.start + parsed.payload_start;
    let (target, encoded_len) = validate_target(
        &wire[plaintext_range.start + parsed.target_range.start
            ..plaintext_range.start + parsed.target_range.end],
    )
    .unwrap_or_else(|_| unreachable!("semantic body target was already validated"));
    debug_assert_eq!(encoded_len, parsed.target_range.len());
    Ok(BorrowedOpenedPacket {
        session_id: opened.session_id().clone(),
        packet_id: opened.packet_id(),
        target,
        payload: &wire[payload_start..plaintext_range.end],
    })
}

pub(super) fn open_packet_owned(
    crypto: &UdpCrypto,
    clock: &(impl Clock + ?Sized),
    mut wire: BytesMut,
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<OwnedOpenedPacket, UdpPacketError> {
    if wire.len() > MAX_UDP_WIRE_LEN {
        return Err(UdpPacketError::Bounds);
    }
    let opened = crypto.open_in_place(&mut wire).map_err(map_crypto)?;
    let plaintext_range = opened.plaintext_range();
    let authenticated_range = opened.authenticated_range();
    let parsed = match parse_body(
        &wire[plaintext_range.clone()],
        clock,
        expected_type,
        binding,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            wire[authenticated_range].zeroize();
            return Err(error);
        }
    };
    let target_range = plaintext_range.start + parsed.target_range.start
        ..plaintext_range.start + parsed.target_range.end;
    let payload_range = plaintext_range.start + parsed.payload_start..plaintext_range.end;
    Ok(OwnedOpenedPacket {
        session_id: opened.session_id().clone(),
        packet_id: opened.packet_id(),
        wire: Some(wire),
        authenticated_range,
        target_range,
        payload_range,
    })
}

struct ParsedBody {
    target_range: Range<usize>,
    payload_start: usize,
}

fn parse_body(
    body: &[u8],
    clock: &(impl Clock + ?Sized),
    expected_type: u8,
    binding: Option<&UdpSessionId>,
) -> Result<ParsedBody, UdpPacketError> {
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
    let (_, address_len) = validate_target(address).map_err(map_target)?;
    let payload_start = address_start
        .checked_add(address_len)
        .ok_or(UdpPacketError::Bounds)?;
    Ok(ParsedBody {
        target_range: address_start..payload_start,
        payload_start,
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum2_crypto::{
        ClockError, MethodPsk, MethodSinglePskProvider, MonotonicInstant, RandomError,
    };

    struct FixedClock;

    impl Clock for FixedClock {
        fn unix_seconds(&self) -> Result<u64, ClockError> {
            Ok(1_700_000_000)
        }

        fn monotonic_now(&self) -> MonotonicInstant {
            MonotonicInstant::ZERO
        }
    }

    struct FixedRandom;

    impl SecureRandom for FixedRandom {
        fn fill(&self, destination: &mut [u8]) -> Result<(), RandomError> {
            destination.fill(0x5a);
            Ok(())
        }
    }

    #[test]
    fn replay_rejection_clears_complete_authenticated_range_for_every_profile() {
        let mut body = vec![crate::tcp::wire::REQUEST_TYPE];
        body.extend_from_slice(&1_700_000_000_u64.to_be_bytes());
        body.extend_from_slice(&0_u16.to_be_bytes());
        body.extend_from_slice(&[1, 192, 0, 2, 1, 0, 53]);
        body.extend_from_slice(b"payload");

        for profile in MethodProfile::ALL {
            let key = vec![profile as u8 + 1; profile.key_bytes()];
            let keys = MethodSinglePskProvider::new(
                MethodPsk::try_from_slice(profile, &key).expect("profile-width key"),
            );
            let crypto = udp_crypto(&keys).expect("UDP crypto");
            let mut outbound = crypto
                .generate_outbound_session(&FixedRandom, |_| false)
                .expect("outbound session");
            let mut wire = vec![0xa5; body.len() + profile.udp_wire_overhead_bytes()];
            let sealed = crypto
                .seal(&mut outbound, &body, &mut wire, &FixedRandom)
                .expect("wire seals");
            let mut scratch = UdpPacketScratch::new();

            let error = match open_packet_borrowed(
                &crypto,
                &FixedClock,
                &wire[..sealed.wire_len()],
                &mut scratch,
                crate::tcp::wire::REQUEST_TYPE,
                None,
                |_, _| Err(UdpPacketError::Duplicate),
            ) {
                Ok(_) => panic!("replay rejection must not release a view"),
                Err(error) => error,
            };
            assert_eq!(error, UdpPacketError::Duplicate);
            let authenticated_start = match profile {
                MethodProfile::Blake3Aes128Gcm2022 | MethodProfile::Blake3Aes256Gcm2022 => 16,
                MethodProfile::Blake3ChaCha20Poly13052022 => 24,
            };
            assert!(
                scratch.body[authenticated_start..sealed.wire_len() - 16]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
}
