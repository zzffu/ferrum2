use super::{Error, Report, emit, protobuf::Schemas};
use crate::{
    Direction,
    keys::KeyState,
    wire::{self, ACK, DATA, HEADER_LEN, Header, SYN},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::io::Write;
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct Stream {
    pub offset: u64,
    pub buffer: Zeroizing<Vec<u8>>,
    header: Option<Header>,
    packet_keys: Option<KeyState>,
    observed: bool,
    stopped: bool,
    source_event: u64,
}
pub(super) struct Context<'a> {
    pub connection: u64,
    pub direction: Direction,
    pub event: u64,
    pub schemas: Option<&'a Schemas>,
    pub capacity_limit: usize,
}
impl Stream {
    pub fn feed(
        &mut self,
        mut input: &[u8],
        keys: &mut KeyState,
        context: &Context<'_>,
        writer: &mut impl Write,
        report: &mut Report,
    ) -> Result<(), Error> {
        while !input.is_empty() {
            if self.stopped {
                self.failure(input, "framing_stopped", context, writer, report)?;
                self.offset += input.len() as u64;
                break;
            }
            if self.buffer.is_empty() {
                self.source_event = context.event;
            }
            let target = self.header.map_or(HEADER_LEN, |header| {
                if self.observed {
                    header.total()
                } else {
                    header.head_len.min(HEADER_LEN + 18)
                }
            });
            let take = (target - self.buffer.len()).min(input.len());
            let needed = self.buffer.len() + take;
            if needed > self.buffer.capacity() {
                if needed > context.capacity_limit {
                    report.integrity_errors += 1;
                    self.reject(
                        input,
                        self.offset + self.buffer.len() as u64,
                        "buffer_limit",
                        context,
                        writer,
                        report,
                    )?;
                    break;
                }
                let capacity = needed
                    .max(self.buffer.capacity().saturating_mul(2))
                    .min(context.capacity_limit);
                let additional = capacity - self.buffer.len();
                self.buffer.reserve_exact(additional);
            }
            self.buffer.extend_from_slice(&input[..take]);
            input = &input[take..];
            if self.buffer.len() < target {
                break;
            }
            if self.header.is_none() {
                match Header::parse(&self.buffer) {
                    Ok(header) => {
                        if !matches!(header.command, SYN | ACK) {
                            self.packet_keys = Some(keys.clone());
                        }
                        self.header = Some(header);
                    }
                    Err(code) => {
                        self.failure(&self.buffer, code, context, writer, report)?;
                        self.offset += self.buffer.len() as u64;
                        self.buffer = Zeroizing::new(Vec::new());
                        self.stopped = true;
                        continue;
                    }
                }
            }
            let header = self.header.expect("parsed header");
            if !self.observed && self.buffer.len() >= header.head_len.min(HEADER_LEN + 18) {
                keys.observe(
                    context.direction,
                    self.offset,
                    header,
                    &self.buffer[HEADER_LEN..],
                );
                if matches!(header.command, SYN | ACK) {
                    // A later opposite-direction handshake must not change the
                    // evidence attached to this still-incomplete packet.
                    self.packet_keys = Some(keys.clone());
                }
                self.observed = true;
            }
            if self.buffer.len() == header.total() {
                let mut message = json!({"kind":"message","connection_id":context.connection,"direction":context.direction,
                    "stream_offset":self.offset,"source_event":self.source_event,"completed_event":context.event,
                    "head_version":header.head_version,"body_version":header.body_version,"gcp_command":header.command,
                    "encrypted":header.encrypted,"gcp_sequence":header.sequence,"head_length":header.head_len,"body_length":header.body_len,
                    "raw":STANDARD.encode(&*self.buffer),"status":"decoded"});
                decode_packet(
                    &mut message,
                    header,
                    &self.buffer,
                    self.packet_keys
                        .as_ref()
                        .expect("parsed packet key snapshot"),
                    context,
                );
                report.messages += 1;
                if message["status"] != "decoded" {
                    report.failed += 1;
                }
                emit(writer, &message)?;
                self.offset += header.total() as u64;
                self.buffer = Zeroizing::new(Vec::new());
                self.header = None;
                self.observed = false;
                self.packet_keys = None;
            }
        }
        Ok(())
    }
    fn failure(
        &self,
        bytes: &[u8],
        code: &'static str,
        context: &Context<'_>,
        writer: &mut impl Write,
        report: &mut Report,
    ) -> Result<(), Error> {
        report.messages += 1;
        report.failed += 1;
        emit(
            writer,
            &json!({"kind":"message","connection_id":context.connection,"direction":context.direction,
            "stream_offset":self.offset,"source_event":if self.buffer.is_empty() {context.event} else {self.source_event},
            "completed_event":context.event,"status":"failed","failure_stage":"framing",
            "failure_code":code,"failure_offset":self.offset,"raw":STANDARD.encode(bytes)}),
        )
    }
    pub fn finish(
        &mut self,
        context: &Context<'_>,
        writer: &mut impl Write,
        report: &mut Report,
    ) -> Result<(), Error> {
        if !self.buffer.is_empty() {
            self.failure(&self.buffer, "truncated_packet", context, writer, report)?;
            self.offset += self.buffer.len() as u64;
            self.buffer = Zeroizing::new(Vec::new());
        }
        Ok(())
    }
    pub fn reject(
        &mut self,
        bytes: &[u8],
        offset: u64,
        code: &'static str,
        context: &Context<'_>,
        writer: &mut impl Write,
        report: &mut Report,
    ) -> Result<(), Error> {
        self.finish(context, writer, report)?;
        self.offset = offset;
        self.failure(bytes, code, context, writer, report)?;
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        self.stopped = true;
        self.header = None;
        self.packet_keys = None;
        Ok(())
    }
}
fn fail(message: &mut Value, stage: &'static str, code: &'static str, offset: usize) {
    message["status"] = json!("partial");
    message["failure_stage"] = json!(stage);
    message["failure_code"] = json!(code);
    message["failure_offset"] = json!(offset);
}
fn decode_packet(
    message: &mut Value,
    header: Header,
    raw: &[u8],
    keys: &KeyState,
    context: &Context<'_>,
) {
    if let Some((direction, offset, sequence)) = keys.reference {
        message["key_direction"] = json!(direction);
        message["key_offset"] = json!(offset);
        message["key_sequence"] = json!(sequence);
    }
    message["key_method"] = json!(keys.method);
    message["enc_method"] = json!(keys.encryption);
    if matches!(header.command, SYN | ACK) {
        if !matches!(
            (context.direction, header.command),
            (Direction::Upload, SYN) | (Direction::Download, ACK)
        ) {
            fail(message, "handshake", "unexpected_handshake_direction", 6);
            return;
        }
        message["key_hex"] = json!(keys.key.as_ref().map(hex::encode));
        if (header.command == SYN && keys.encryption.is_none())
            || (header.command == ACK && keys.key.is_none())
        {
            fail(message, "handshake", "unsupported_handshake", HEADER_LEN);
        }
        if header.body_len != 0 {
            fail(
                message,
                "handshake",
                "unsupported_handshake_body",
                header.head_len,
            );
        }
        return;
    }
    if header.command != DATA {
        fail(message, "gcp", "unsupported_command", 6);
        return;
    }
    let body = &raw[header.head_len..];
    let decrypted;
    let payload = match keys.encryption {
        Some(0) if header.encrypted == 0 => {
            message["decryption"] = json!("plaintext");
            message["plaintext"] = json!(STANDARD.encode(body));
            body
        }
        Some(3) => {
            let Some(key) = &keys.key else {
                fail(message, "crypto", "missing_key", header.head_len);
                return;
            };
            decrypted = crate::crypto::decrypt(key, body);
            message["plaintext"] = json!(STANDARD.encode(&*decrypted.bytes));
            if let Some(code) = decrypted.error {
                fail(message, "crypto", code, header.head_len);
                return;
            }
            message["decryption"] = json!("aes128_cbc_method3");
            &decrypted.bytes[decrypted.payload.clone().expect("validated plaintext")]
        }
        Some(0) => {
            fail(message, "crypto", "encryption_flag_mismatch", 8);
            return;
        }
        Some(_) => {
            fail(message, "crypto", "unsupported_encryption", header.head_len);
            return;
        }
        None => {
            fail(message, "crypto", "unknown_encryption", header.head_len);
            return;
        }
    };
    let (kind, command, sequence, length) = match wire::app_header(context.direction, payload) {
        Ok(header) => header,
        Err(code) => {
            fail(message, "application", code, 0);
            return;
        }
    };
    message["application_header"] = json!(kind);
    message["command"] = json!(command);
    message["application_sequence"] = json!(sequence);
    message["application_header_length"] = json!(length);
    let bytes = &payload[length..];
    message["payload_raw"] = json!(STANDARD.encode(bytes));
    let fields = match super::payload::fields(bytes) {
        Ok(fields) => fields,
        Err((code, offset)) => {
            message["payload"] =
                json!({"format":"nonstandard_bytes","bytes":STANDARD.encode(bytes)});
            fail(message, "payload", code, length + offset);
            return;
        }
    };
    if let Some(schemas) = context.schemas {
        match schemas.decode(command, bytes) {
            Ok((name, value)) => {
                message["message_name"] = json!(name);
                message["payload"] = value;
                message["wire_fields"] = fields;
            }
            Err(code) => {
                message["payload"] = fields;
                fail(message, "protobuf", code, length);
            }
        }
    } else {
        message["payload"] = fields;
    }
}
