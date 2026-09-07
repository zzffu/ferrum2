use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

/// Wire fields are not guessed business messages. Length-delimited data remains
/// exact bytes, including unknown fields, ordering, duplicates and varint forms.
pub(super) fn fields(input: &[u8]) -> Result<Value, (&'static str, usize)> {
    let mut cursor = 0;
    let mut fields = Vec::new();
    while cursor < input.len() {
        if fields.len() >= 65536 {
            return Err(("field_limit", cursor));
        }
        let start = cursor;
        let tag = varint(input, &mut cursor)?;
        let number = tag >> 3;
        if number == 0 || number > 0x1fff_ffff {
            return Err(("invalid_field_number", start));
        }
        let wire = tag & 7;
        let value = match wire {
            0 => json!({"unsigned": varint(input, &mut cursor)?.to_string()}),
            1 | 5 => {
                let size = if wire == 1 { 8 } else { 4 };
                let end = cursor
                    .checked_add(size)
                    .filter(|n| *n <= input.len())
                    .ok_or(("truncated_fixed", cursor))?;
                let value = json!({"bytes": STANDARD.encode(&input[cursor..end])});
                cursor = end;
                value
            }
            2 => {
                let size = usize::try_from(varint(input, &mut cursor)?)
                    .map_err(|_| ("length_overflow", cursor))?;
                let end = cursor
                    .checked_add(size)
                    .filter(|n| *n <= input.len())
                    .ok_or(("truncated_bytes", cursor))?;
                let value = json!({"bytes": STANDARD.encode(&input[cursor..end])});
                cursor = end;
                value
            }
            _ => return Err(("unsupported_wire_type", start)),
        };
        fields.push(json!({"field":number,"wire_type":wire,"offset":start,"raw":STANDARD.encode(&input[start..cursor]),"value":value}));
    }
    Ok(json!({"format":"protobuf_wire_fields","fields":fields}))
}
fn varint(input: &[u8], cursor: &mut usize) -> Result<u64, (&'static str, usize)> {
    let start = *cursor;
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*cursor).ok_or(("truncated_varint", start))?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(("varint_overflow", start));
        }
        value |= u64::from(byte & 127) << shift;
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(("varint_overflow", start))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn arbitrary_bytes_are_not_guessed_strings_or_nested_messages() {
        let value = fields(&[0x12, 3, 0xff, 0, 0x80, 0x08, 0x81, 0]).unwrap();
        assert_eq!(value["fields"][0]["value"], json!({"bytes":"/wCA"}));
        assert_eq!(value["fields"][1]["raw"], "CIEA");
        assert_eq!(fields(&[0xff, 0]), Err(("unsupported_wire_type", 0)));
    }
}
