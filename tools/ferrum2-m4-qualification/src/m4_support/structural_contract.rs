use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, TcpStream};
use std::time::Instant;

use ferrum2_structural::{StructuralCounter, StructuralUnit};
use serde_json::{Value, json};

use super::process_support::{IO_TIMEOUT, clean_io, remaining};

#[cfg(not(feature = "tcp-pending-surface-diagnostic"))]
pub(super) const STRUCTURAL_SCHEMA_VERSION: u8 = 7;
#[cfg(feature = "tcp-pending-surface-diagnostic")]
pub(super) const STRUCTURAL_SCHEMA_VERSION: u8 = 8;
pub(super) const STRUCTURAL_KIND: &str = "m18_structural_trial";
#[cfg(not(feature = "tcp-pending-surface-diagnostic"))]
pub(super) const STRUCTURAL_SCENARIO: &str = "tcp-stream-64k";
#[cfg(feature = "tcp-pending-surface-diagnostic")]
pub(super) const STRUCTURAL_SCENARIO: &str = "tcp-bulk";
pub(super) const STRUCTURAL_AGGREGATION: &str = "checked_sum_of_client_and_server_checked_deltas";

#[cfg(not(feature = "tcp-pending-surface-diagnostic"))]
const STRUCTURAL_COUNTER_COUNT: usize = 49;
#[cfg(feature = "tcp-pending-surface-diagnostic")]
const STRUCTURAL_COUNTER_COUNT: usize = 53;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StructuralSnapshot {
    pub(super) values: BTreeMap<String, u64>,
    pub(super) overflowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StructuralMeasurement {
    pub(super) client_before: StructuralSnapshot,
    pub(super) client_after: StructuralSnapshot,
    pub(super) server_before: StructuralSnapshot,
    pub(super) server_after: StructuralSnapshot,
    pub(super) client_delta: BTreeMap<String, u64>,
    pub(super) server_delta: BTreeMap<String, u64>,
    pub(super) merged_delta: BTreeMap<String, u64>,
}

pub(super) fn capture(
    address: SocketAddrV4,
    deadline: Instant,
) -> Result<StructuralSnapshot, String> {
    let response = fetch_response(address, deadline)?;
    parse_response(&response)
}

pub(super) fn parse_response(response: &[u8]) -> Result<StructuralSnapshot, String> {
    parse_body(metrics_body(response)?)
}

fn fetch_response(address: SocketAddrV4, deadline: Instant) -> Result<Vec<u8>, String> {
    let timeout = remaining(deadline)?.min(IO_TIMEOUT);
    let mut stream = TcpStream::connect_timeout(&SocketAddr::V4(address), timeout)
        .map_err(|_| "structural metrics connection failed".to_owned())?;
    stream
        .set_write_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
        .map_err(clean_io)?;
    stream
        .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .map_err(clean_io)?;
    let mut response = Vec::with_capacity(16 * 1024);
    let mut chunk = [0_u8; 4096];
    loop {
        if response.len() >= 256 * 1024 {
            return Err("structural metrics response exceeded bound".to_owned());
        }
        stream
            .set_read_timeout(Some(remaining(deadline)?.min(IO_TIMEOUT)))
            .map_err(clean_io)?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&chunk[..read]),
            Err(error) => return Err(clean_io(error)),
        }
    }
    remaining(deadline)?;
    Ok(response)
}

fn metrics_body(response: &[u8]) -> Result<&str, String> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "structural metrics response is malformed".to_owned())?;
    let headers = std::str::from_utf8(&response[..header_end])
        .map_err(|_| "structural metrics response is malformed".to_owned())?;
    let mut status = headers
        .lines()
        .next()
        .ok_or_else(|| "structural metrics response is malformed".to_owned())?
        .split_whitespace();
    if !status
        .next()
        .is_some_and(|value| value.starts_with("HTTP/"))
        || status.next() != Some("200")
    {
        return Err("structural metrics response status is not 200".to_owned());
    }
    let body = std::str::from_utf8(&response[header_end + 4..])
        .map_err(|_| "structural metrics body is not UTF-8".to_owned())?;
    if !body.ends_with("# EOF\n") || body.lines().filter(|line| *line == "# EOF").count() != 1 {
        return Err("structural metrics exposition is incomplete".to_owned());
    }
    Ok(body)
}

fn parse_body(body: &str) -> Result<StructuralSnapshot, String> {
    const PREFIX: &str = "ferrum2_structural_";
    const OVERFLOW: &str = "ferrum2_structural_overflow";

    let expected: BTreeMap<_, _> = StructuralCounter::ALL
        .iter()
        .copied()
        .map(|counter| {
            (
                format!("{PREFIX}{}", counter.name()),
                structural_unit(counter),
            )
        })
        .collect();
    if expected.len() != StructuralCounter::COUNT
        || StructuralCounter::COUNT != STRUCTURAL_COUNTER_COUNT
    {
        return Err(format!(
            "structural counter schema is not the fixed {STRUCTURAL_COUNTER_COUNT}-family contract"
        ));
    }

    let mut help = BTreeSet::new();
    let mut types = BTreeSet::new();
    let mut values = BTreeMap::new();
    let mut overflow_help = false;
    let mut overflow_type = false;
    let mut overflowed = None;
    for line in body.lines() {
        if !line.contains(PREFIX) {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# HELP ") {
            let (family, _) = rest
                .split_once(' ')
                .ok_or_else(|| "structural HELP line is malformed".to_owned())?;
            if family == OVERFLOW {
                if overflow_help
                    || line
                        != "# HELP ferrum2_structural_overflow Whether a structural counter saturated."
                {
                    return Err("structural overflow HELP is malformed or duplicated".to_owned());
                }
                overflow_help = true;
                continue;
            }
            let unit = expected
                .get(family)
                .ok_or_else(|| "structural HELP names an unknown family".to_owned())?;
            let expected_line = format!(
                "# HELP {family} Closed structural performance evidence measured in {unit}."
            );
            if line != expected_line || !help.insert(family.to_owned()) {
                return Err("structural HELP is malformed or duplicated".to_owned());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            let (family, kind) = rest
                .split_once(' ')
                .ok_or_else(|| "structural TYPE line is malformed".to_owned())?;
            if family == OVERFLOW {
                if overflow_type || kind != "gauge" {
                    return Err("structural overflow TYPE is malformed or duplicated".to_owned());
                }
                overflow_type = true;
                continue;
            }
            if !expected.contains_key(family)
                || kind != "counter"
                || !types.insert(family.to_owned())
            {
                return Err("structural TYPE is malformed or duplicated".to_owned());
            }
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let sample = fields
            .next()
            .ok_or_else(|| "structural sample is malformed".to_owned())?;
        let raw_value = fields
            .next()
            .ok_or_else(|| "structural sample is malformed".to_owned())?;
        if fields.next().is_some() {
            return Err("structural sample has labels, a timestamp, or an exemplar".to_owned());
        }
        if sample == OVERFLOW {
            if overflowed.is_some() || !matches!(raw_value, "0" | "1") {
                return Err("structural overflow sample is malformed or duplicated".to_owned());
            }
            overflowed = Some(raw_value == "1");
            continue;
        }
        let family = sample
            .strip_suffix("_total")
            .ok_or_else(|| "structural counter sample lacks the counter suffix".to_owned())?;
        if !expected.contains_key(family) {
            return Err("structural sample names an unknown family".to_owned());
        }
        let value = parse_u64(raw_value)?;
        let name = family
            .strip_prefix(PREFIX)
            .expect("validated structural family prefix")
            .to_owned();
        if values.insert(name, value).is_some() {
            return Err("structural sample is duplicated".to_owned());
        }
    }

    if help.len() != StructuralCounter::COUNT
        || types.len() != StructuralCounter::COUNT
        || values.len() != StructuralCounter::COUNT
        || !overflow_help
        || !overflow_type
        || overflowed.is_none()
    {
        return Err("structural exposition is missing a required fixed family".to_owned());
    }
    Ok(StructuralSnapshot {
        values,
        overflowed: overflowed.expect("validated overflow sample"),
    })
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("structural sample is not an unsigned decimal integer".to_owned());
    }
    value
        .parse()
        .map_err(|_| "structural sample exceeds the u64 range".to_owned())
}

pub(super) fn measure(
    client_before: StructuralSnapshot,
    client_after: StructuralSnapshot,
    server_before: StructuralSnapshot,
    server_after: StructuralSnapshot,
) -> Result<StructuralMeasurement, String> {
    if [&client_before, &client_after, &server_before, &server_after]
        .into_iter()
        .any(|snapshot| snapshot.overflowed)
    {
        return Err("structural counter overflow invalidates the diagnostic".to_owned());
    }
    let client_delta = delta(&client_before.values, &client_after.values, "client")?;
    let server_delta = delta(&server_before.values, &server_after.values, "server")?;
    let mut merged_delta = BTreeMap::new();
    for counter in StructuralCounter::ALL {
        let name = counter.name();
        let merged = client_delta[name]
            .checked_add(server_delta[name])
            .ok_or_else(|| format!("merged structural delta overflowed: {name}"))?;
        merged_delta.insert(name.to_owned(), merged);
    }
    Ok(StructuralMeasurement {
        client_before,
        client_after,
        server_before,
        server_after,
        client_delta,
        server_delta,
        merged_delta,
    })
}

fn delta(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
    endpoint: &str,
) -> Result<BTreeMap<String, u64>, String> {
    if before.len() != StructuralCounter::COUNT || after.len() != StructuralCounter::COUNT {
        return Err(format!("{endpoint} structural snapshot is not closed"));
    }
    StructuralCounter::ALL
        .iter()
        .map(|counter| {
            let name = counter.name();
            let before = before
                .get(name)
                .ok_or_else(|| format!("{endpoint} before snapshot is missing {name}"))?;
            let after = after
                .get(name)
                .ok_or_else(|| format!("{endpoint} after snapshot is missing {name}"))?;
            let value = after.checked_sub(*before).ok_or_else(|| {
                format!("{endpoint} structural counter decreased during workload: {name}")
            })?;
            Ok((name.to_owned(), value))
        })
        .collect()
}

pub(super) fn counter_schema_json() -> Value {
    Value::Object(
        StructuralCounter::ALL
            .iter()
            .map(|counter| {
                (
                    counter.name().to_owned(),
                    json!({
                        "unit": structural_unit(*counter),
                        "aggregation": STRUCTURAL_AGGREGATION,
                        "range": {"minimum": 0_u64, "maximum": u64::MAX},
                    }),
                )
            })
            .collect(),
    )
}

fn structural_unit(counter: StructuralCounter) -> &'static str {
    match counter.unit() {
        StructuralUnit::Count => "events",
        StructuralUnit::Bytes => "bytes",
        StructuralUnit::Nanoseconds => "nanoseconds",
    }
}

pub(super) fn run_self_check() -> Result<(), String> {
    let response = valid_response(1);
    let parsed = parse_response(response.as_bytes())?;
    if parsed.values.len() != STRUCTURAL_COUNTER_COUNT || parsed.overflowed {
        return Err("valid structural exposition did not preserve its closure".to_owned());
    }

    let missing = response.replacen(
        "ferrum2_structural_tcp_decrypt_prepare_copy_bytes_total 1\n",
        "",
        1,
    );
    expect_rejected("missing structural family", || {
        parse_response(missing.as_bytes())
    })?;
    let duplicate = response.replace(
        "# EOF\n",
        "ferrum2_structural_tcp_decrypt_prepare_copy_bytes_total 1\n# EOF\n",
    );
    expect_rejected("duplicate structural sample", || {
        parse_response(duplicate.as_bytes())
    })?;
    let labelled = response.replace(
        "ferrum2_structural_tcp_decrypt_prepare_copy_bytes_total 1",
        "ferrum2_structural_tcp_decrypt_prepare_copy_bytes_total{peer=\"x\"} 1",
    );
    expect_rejected("labelled structural sample", || {
        parse_response(labelled.as_bytes())
    })?;
    let overflow = response.replace(
        "ferrum2_structural_overflow 0",
        "ferrum2_structural_overflow 1",
    );
    let overflow = parse_response(overflow.as_bytes())?;
    expect_rejected("overflowed structural snapshot", || {
        measure(parsed.clone(), parsed.clone(), parsed.clone(), overflow)
    })?;

    let mut decreased = parsed.clone();
    *decreased
        .values
        .get_mut(StructuralCounter::ALL[0].name())
        .expect("closed structural map") = 0;
    expect_rejected("decreasing structural counter", || {
        measure(parsed.clone(), decreased, parsed.clone(), parsed.clone())
    })?;
    let mut maximum = parsed.clone();
    *maximum
        .values
        .get_mut(StructuralCounter::ALL[0].name())
        .expect("closed structural map") = u64::MAX;
    expect_rejected("merged structural delta overflow", || {
        measure(parsed.clone(), maximum.clone(), parsed.clone(), maximum)
    })?;
    Ok(())
}

fn valid_response(value: u64) -> String {
    let mut body = String::new();
    for counter in StructuralCounter::ALL {
        let family = format!("ferrum2_structural_{}", counter.name());
        body.push_str(&format!(
            "# HELP {family} Closed structural performance evidence measured in {}.\n",
            structural_unit(*counter)
        ));
        body.push_str(&format!("# TYPE {family} counter\n"));
        body.push_str(&format!("{family}_total {value}\n"));
    }
    body.push_str(
        "# HELP ferrum2_structural_overflow Whether a structural counter saturated.\n\
         # TYPE ferrum2_structural_overflow gauge\n\
         ferrum2_structural_overflow 0\n\
         # EOF\n",
    );
    format!("HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text\r\n\r\n{body}")
}

fn expect_rejected<T>(
    name: &str,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<(), String> {
    if operation().is_ok() {
        return Err(format!("structural self-check mutation survived: {name}"));
    }
    Ok(())
}
