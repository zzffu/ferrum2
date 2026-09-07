//! Legacy normalization and command naming adapted from rocom_tool's
//! apps/tsf4g_proxy/src/session_trace/protobuf.rs. Only temporary copies change.
use super::Error;
use prost_reflect::{DescriptorPool, DynamicMessage, SerializeOptions};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub(super) struct Schemas {
    pool: DescriptorPool,
    pub digest: String,
}
impl Schemas {
    pub fn load(directory: &Path) -> Result<Self, Error> {
        let temporary = tempfile::tempdir().map_err(|_| Error("schema_io"))?;
        let mut pending = vec![directory.to_path_buf()];
        let mut files = Vec::new();
        let mut identities = Vec::new();
        let mut total = 0u64;
        let mut entries = 0usize;
        while let Some(parent) = pending.pop() {
            for entry in fs::read_dir(&parent).map_err(|_| Error("schema_io"))? {
                entries += 1;
                if entries > 4096 {
                    return Err(Error("schema_limit"));
                }
                let entry = entry.map_err(|_| Error("schema_io"))?;
                let kind = entry.file_type().map_err(|_| Error("schema_io"))?;
                if kind.is_symlink() {
                    return Err(Error("schema_symlink"));
                }
                let path = entry.path();
                if kind.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "proto") {
                    continue;
                }
                let size = entry.metadata().map_err(|_| Error("schema_io"))?.len();
                total = total.checked_add(size).ok_or(Error("schema_limit"))?;
                if total > 32 * 1024 * 1024 {
                    return Err(Error("schema_limit"));
                }
                let relative = path
                    .strip_prefix(directory)
                    .map_err(|_| Error("schema_path"))?;
                let destination = temporary.path().join(relative);
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent).map_err(|_| Error("schema_io"))?;
                }
                let source = fs::read_to_string(&path).map_err(|_| Error("schema_io"))?;
                let name = relative
                    .to_str()
                    .ok_or(Error("schema_path_encoding"))?
                    .replace('\\', "/");
                identities.push((name, source.len() as u64, Sha256::digest(source.as_bytes())));
                fs::write(&destination, normalize(&source)).map_err(|_| Error("schema_io"))?;
                files.push(destination);
            }
        }
        if files.is_empty() {
            return Err(Error("schema_empty"));
        }
        files.sort();
        identities.sort_by(|left, right| left.0.cmp(&right.0));
        let mut digest = Sha256::new();
        digest.update(b"ferrum2-rocom-schema-inputs-v1");
        for (name, length, content) in identities {
            digest.update((name.len() as u64).to_be_bytes());
            digest.update(name.as_bytes());
            digest.update(length.to_be_bytes());
            digest.update(content);
        }
        let descriptors =
            protox::compile(files, [temporary.path()]).map_err(|_| Error("schema_compile"))?;
        let pool = DescriptorPool::from_file_descriptor_set(descriptors)
            .map_err(|_| Error("schema_descriptors"))?;
        if pool.get_enum_by_name("Next.ZoneSvrCmd").is_none() {
            return Err(Error("schema_commands"));
        }
        Ok(Self {
            pool,
            digest: hex::encode(digest.finalize()),
        })
    }
    pub fn decode(&self, command: u32, bytes: &[u8]) -> Result<(String, Value), &'static str> {
        let commands = self
            .pool
            .get_enum_by_name("Next.ZoneSvrCmd")
            .ok_or("schema_commands")?;
        let value = commands
            .get_value(i32::try_from(command).map_err(|_| "unmapped_command")?)
            .ok_or("unmapped_command")?;
        let name = format!("Next.{}", message_name(value.name()));
        let descriptor = self
            .pool
            .get_message_by_name(&name)
            .ok_or("unmapped_message")?;
        let message = DynamicMessage::decode(descriptor, bytes).map_err(|_| "protobuf_decode")?;
        let mut encoded = Vec::new();
        message
            .serialize_with_options(
                &mut serde_json::Serializer::new(&mut encoded),
                &SerializeOptions::new()
                    .use_proto_field_name(true)
                    .stringify_64_bit_integers(true),
            )
            .map_err(|_| "protobuf_json")?;
        let payload = serde_json::from_slice(&encoded).map_err(|_| "protobuf_json")?;
        Ok((name, payload))
    }
}
fn normalize(source: &str) -> String {
    if source
        .lines()
        .any(|line| line.trim_start().starts_with("syntax"))
    {
        return source.to_owned();
    }
    let mut output = String::from("syntax = \"proto2\";\n");
    let mut blocks = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        let field = blocks.last() == Some(&true)
            && trimmed.contains(" = ")
            && trimmed.ends_with(';')
            && ![
                "repeated ",
                "optional ",
                "required ",
                "option ",
                "reserved ",
                "extensions ",
            ]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix));
        if field {
            output.push_str(&line[..line.len() - trimmed.len()]);
            output.push_str("optional ");
            output.push_str(trimmed);
        } else {
            output.push_str(line);
        }
        output.push('\n');
        if (trimmed.starts_with("message ") || trimmed.starts_with("enum "))
            && trimmed.ends_with('{')
        {
            blocks.push(trimmed.starts_with("message "));
            if trimmed.starts_with("enum ") {
                output.push_str("option allow_alias = true;\n");
            }
        }
        for _ in trimmed.bytes().filter(|b| *b == b'}') {
            blocks.pop();
        }
    }
    output
}
fn message_name(name: &str) -> String {
    let mut words = name.split('_').filter(|w| !w.is_empty()).peekable();
    let mut output = String::new();
    while let Some(word) = words.next() {
        let mut word = word.to_ascii_uppercase();
        if word.len() == 1 {
            while words.peek().is_some_and(|w| w.len() == 1) {
                word.push_str(words.next().expect("peeked word"));
            }
        }
        if word == "AI" {
            output.push_str("AI");
        } else {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                output.push(first);
                output.extend(chars.flat_map(char::to_lowercase));
            }
        }
    }
    output
}
