use std::io::{self, Read};

use super::context::{ByteLimit, DecodeContext};
use crate::srs::{SrsError, SrsErrorKind, SrsLimitKind};

pub(super) fn read_interface_address_map<R: Read>(
    reader: &mut DecodeContext<R>,
) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 2)?;
    for _ in 0..count {
        read_byte(reader)?;
        read_prefix_slice(reader)?;
    }
    Ok(())
}

pub(super) fn read_prefix_slice<R: Read>(reader: &mut DecodeContext<R>) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 6)?;
    for _ in 0..count {
        let length = read_uvarint(reader)?;
        match length {
            4 => {
                let mut bytes = [0_u8; 4];
                read_exact(reader, &mut bytes)?;
                if read_byte(reader)? > 32 {
                    return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
                }
            }
            16 => {
                let mut bytes = [0_u8; 16];
                read_exact(reader, &mut bytes)?;
                if read_byte(reader)? > 128 {
                    return Err(SrsError::new(SrsErrorKind::InvalidIpSet));
                }
            }
            _ => return Err(SrsError::new(SrsErrorKind::InvalidIpSet)),
        }
    }
    Ok(())
}

pub(super) fn read_keywords<R: Read>(
    reader: &mut DecodeContext<R>,
) -> Result<Vec<String>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 1)?;
    let mut values = Vec::new();
    for _ in 0..count {
        let length = string_length(reader, SrsLimitKind::KeywordLength)?;
        reader.charge(SrsLimitKind::KeywordBytes, length as u64)?;
        reader.entry(length)?;
        let value = read_bytes(reader, length)?;
        let value =
            String::from_utf8(value).map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?;
        values
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        values.push(value);
    }
    Ok(values)
}

pub(super) fn skip_string_slice<R: Read>(reader: &mut DecodeContext<R>) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 1)?;
    // Unsupported text still requires strict UTF-8 validation. Its independent
    // 8 KiB maximum permits fixed scratch, without retaining discarded strings.
    let mut scratch = [0_u8; 8 * 1024];
    for _ in 0..count {
        let length = string_length(reader, SrsLimitKind::UnsupportedStringBytes)?;
        read_exact(reader, &mut scratch[..length])?;
        std::str::from_utf8(&scratch[..length])
            .map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?;
    }
    Ok(())
}

fn string_length<R: Read>(
    reader: &mut DecodeContext<R>,
    kind: SrsLimitKind,
) -> Result<usize, SrsError> {
    let length = read_uvarint(reader)?;
    if length > reader.limits.maximum(kind) {
        return Err(SrsError::limit(kind));
    }
    reader.require_payload(length)?;
    usize::try_from(length).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))
}

pub(super) fn read_u8_slice<R: Read>(reader: &mut DecodeContext<R>) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 1)?;
    skip_bytes(reader, count)
}

pub(super) fn read_u16_slice<R: Read>(reader: &mut DecodeContext<R>) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 2)?;
    let bytes = count
        .checked_mul(2)
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    skip_bytes(reader, bytes)
}

fn skip_bytes<R: Read>(
    reader: &mut DecodeContext<R>,
    mut remaining: usize,
) -> Result<(), SrsError> {
    let mut buffer = [0_u8; 4096];
    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        read_exact(reader, &mut buffer[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

pub(super) fn read_u64_words<R: Read>(reader: &mut DecodeContext<R>) -> Result<Vec<u64>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = reader.collection(count, 8)?;
    let mut values = Vec::new();
    for _ in 0..count {
        let value = read_be_u64(reader)?;
        values
            .try_reserve(1)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        values.push(value);
    }
    Ok(values)
}

pub(super) fn read_byte_vec<R: Read>(reader: &mut DecodeContext<R>) -> Result<Vec<u8>, SrsError> {
    let length = read_uvarint(reader)?;
    let length = reader.collection(length, 1)?;
    read_bytes(reader, length)
}

fn read_bytes<R: Read>(
    reader: &mut DecodeContext<R>,
    mut length: usize,
) -> Result<Vec<u8>, SrsError> {
    let mut value = Vec::new();
    let mut scratch = [0_u8; 4096];
    while length != 0 {
        let chunk = length.min(scratch.len());
        read_exact(reader, &mut scratch[..chunk])?;
        value
            .try_reserve(chunk)
            .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
        value.extend_from_slice(&scratch[..chunk]);
        length -= chunk;
    }
    Ok(value)
}

pub(super) fn read_bool<R: Read>(reader: &mut DecodeContext<R>) -> Result<bool, SrsError> {
    match read_byte(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SrsError::new(SrsErrorKind::InvalidBoolean)),
    }
}

pub(super) fn read_uvarint<R: Read>(reader: &mut DecodeContext<R>) -> Result<u64, SrsError> {
    let mut value = 0_u64;
    for index in 0..10_u32 {
        let byte = read_byte(reader)?;
        if index == 9 && byte > 1 {
            return Err(SrsError::new(SrsErrorKind::IntegerOverflow));
        }
        value |= u64::from(byte & 0x7f) << (index * 7);
        if byte < 0x80 {
            if index != 0 && byte == 0 {
                return Err(SrsError::new(SrsErrorKind::NonCanonicalVarint));
            }
            return Ok(value);
        }
    }
    Err(SrsError::new(SrsErrorKind::IntegerOverflow))
}

pub(super) fn read_be_u64<R: Read>(reader: &mut DecodeContext<R>) -> Result<u64, SrsError> {
    let mut bytes = [0_u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

pub(super) fn read_byte<R: Read>(reader: &mut DecodeContext<R>) -> Result<u8, SrsError> {
    let mut byte = [0_u8; 1];
    read_exact(reader, &mut byte)?;
    Ok(byte[0])
}

pub(super) fn read_exact<R: Read>(
    reader: &mut DecodeContext<R>,
    buffer: &mut [u8],
) -> Result<(), SrsError> {
    reader.require_payload(buffer.len() as u64)?;
    reader.work(buffer.len() as u64)?;
    reader.reader.read_exact(buffer).map_err(map_payload_io)?;
    reader.charge(SrsLimitKind::DecodedBytes, buffer.len() as u64)
}

pub(super) fn map_source_io(error: io::Error) -> SrsError {
    if let Some(limit) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<ByteLimit>())
    {
        return SrsError::limit(limit.0);
    }
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        _ => SrsError::new(SrsErrorKind::Io),
    }
}

pub(super) fn map_payload_io(error: io::Error) -> SrsError {
    if let Some(limit) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<ByteLimit>())
    {
        return SrsError::limit(limit.0);
    }
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            SrsError::new(SrsErrorKind::Compression)
        }
        _ => SrsError::new(SrsErrorKind::Io),
    }
}
