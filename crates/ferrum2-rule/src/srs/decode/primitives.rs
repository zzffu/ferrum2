use std::io::{self, Read};

use crate::srs::{SrsError, SrsErrorKind};

pub(super) fn read_interface_address_map<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let size = read_uvarint(reader)?;
    for _ in 0..size {
        read_byte(reader)?;
        read_prefix_slice(reader)?;
    }
    Ok(())
}

pub(super) fn read_prefix_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
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

pub(super) fn read_string_slice<R: Read>(reader: &mut R) -> Result<Vec<String>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for _ in 0..count {
        let value = read_byte_vec(reader)?;
        values
            .push(String::from_utf8(value).map_err(|_| SrsError::new(SrsErrorKind::InvalidUtf8))?);
    }
    Ok(values)
}

pub(super) fn read_u8_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut buffer = [0_u8; 4096];
    let mut remaining = count;
    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        read_exact(reader, &mut buffer[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

pub(super) fn read_u16_slice<R: Read>(reader: &mut R) -> Result<(), SrsError> {
    let count = read_uvarint(reader)?;
    let bytes = count
        .checked_mul(2)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut buffer = [0_u8; 4096];
    let mut remaining = bytes;
    while remaining != 0 {
        let chunk = remaining.min(buffer.len());
        read_exact(reader, &mut buffer[..chunk])?;
        remaining -= chunk;
    }
    Ok(())
}

pub(super) fn read_u64_words<R: Read>(reader: &mut R) -> Result<Vec<u64>, SrsError> {
    let count = read_uvarint(reader)?;
    let count = usize::try_from(count).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    for _ in 0..count {
        values.push(read_be_u64(reader)?);
    }
    Ok(values)
}

pub(super) fn read_byte_vec<R: Read>(reader: &mut R) -> Result<Vec<u8>, SrsError> {
    let length = read_uvarint(reader)?;
    let length =
        usize::try_from(length).map_err(|_| SrsError::new(SrsErrorKind::IntegerOverflow))?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .map_err(|_| SrsError::new(SrsErrorKind::Allocation))?;
    value.resize(length, 0);
    read_exact(reader, &mut value)?;
    Ok(value)
}

pub(super) fn read_bool<R: Read>(reader: &mut R) -> Result<bool, SrsError> {
    match read_byte(reader)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SrsError::new(SrsErrorKind::InvalidBoolean)),
    }
}

pub(super) fn read_uvarint<R: Read>(reader: &mut R) -> Result<u64, SrsError> {
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

pub(super) fn read_be_u64<R: Read>(reader: &mut R) -> Result<u64, SrsError> {
    let mut bytes = [0_u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_be_bytes(bytes))
}

pub(super) fn read_byte<R: Read>(reader: &mut R) -> Result<u8, SrsError> {
    let mut byte = [0_u8; 1];
    read_exact(reader, &mut byte)?;
    Ok(byte[0])
}

pub(super) fn read_exact<R: Read>(reader: &mut R, buffer: &mut [u8]) -> Result<(), SrsError> {
    reader.read_exact(buffer).map_err(map_payload_io)
}

pub(super) fn map_source_io(error: io::Error) -> SrsError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        _ => SrsError::new(SrsErrorKind::Io),
    }
}

pub(super) fn map_payload_io(error: io::Error) -> SrsError {
    match error.kind() {
        io::ErrorKind::UnexpectedEof => SrsError::new(SrsErrorKind::Truncated),
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => {
            SrsError::new(SrsErrorKind::Compression)
        }
        _ => SrsError::new(SrsErrorKind::Io),
    }
}
