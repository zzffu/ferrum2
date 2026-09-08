use super::contract::{Args, parse, validate_reset_release};
use super::socket_io::{
    BULK, FRAGMENT, IO_LIMIT, connect, datagram, duplex, exchange, pause_reader, payload, publish,
    runtime, udp,
};
use serde_json::{Value, json};
use std::ffi::OsString;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn flow(
    args: &Args,
    generation: u8,
    flow: u8,
    established: &tokio::sync::Barrier,
) -> Result<Value, String> {
    let mut tcp = connect(args.tcp).await?;
    let local = tcp.local_addr().map_err(|e| e.to_string())?;
    exchange(&mut tcp, &payload(1024, generation, flow, 1)).await?;
    let bulk = payload(BULK, generation, flow, 2);
    established.wait().await;
    let paused = pause_reader(&tcp, &bulk).await?;
    // Both datagram classes complete while this TCP connection has outstanding
    // checked data and its application reader remains paused.
    let udp = udp(args.udp).await?;
    for sequence in 0..4 {
        datagram(&udp, &payload(256, generation, flow, 10 + sequence)).await?;
        datagram(&udp, &payload(FRAGMENT, generation, flow, 20 + sequence)).await?;
    }
    duplex(&mut tcp, &bulk, paused).await?;
    exchange(&mut tcp, &payload(1024, generation, flow, 3)).await?;
    // FIN is sent with data outstanding: read the final checked response after
    // shutting down only the write half, then require remote termination.
    let last = payload(1024, generation, flow, 4);
    tokio::time::timeout(IO_LIMIT, async {
        tcp.write_all(&last).await.map_err(|e| e.to_string())?;
        tcp.shutdown().await.map_err(|e| e.to_string())?;
        let mut reply = vec![0; last.len()];
        tcp.read_exact(&mut reply)
            .await
            .map_err(|e| e.to_string())?;
        if reply != last {
            return Err("half-close payload mismatch".to_owned());
        }
        let mut extra = [0];
        if tcp.read(&mut extra).await.map_err(|e| e.to_string())? != 0 {
            return Err("TCP sent unexpected data after half-close".into());
        }
        Ok(())
    })
    .await
    .map_err(|_| "half-close termination deadline")??;
    Ok(json!({
        "flow": flow, "generation": generation, "local_endpoint": local.to_string(),
        "same_connection_phases": ["request_before", "paused_reader", "full_duplex", "request_after", "half_close"],
        "bulk_bytes": BULK, "paused_bytes_sent": paused, "paused_unwritable_milliseconds": 100,
        "resumed_bytes_sent": BULK - paused, "checked_tcp_bytes": BULK + 3072,
        "udp_replies_during_tcp": 4, "fragment_replies_during_tcp": 4,
        "fragment_request_bytes": FRAGMENT, "payload_exact": true,
        "half_close_reply_checked": true, "remote_eof": true
    }))
}

async fn generation(args: &Args, generation: u8) -> Result<Value, String> {
    // Borrowed futures avoid detached tasks and join/cancellation ownership.
    let established = tokio::sync::Barrier::new(4);
    let (a, b, c, d) = tokio::try_join!(
        flow(args, generation, 0, &established),
        flow(args, generation, 1, &established),
        flow(args, generation, 2, &established),
        flow(args, generation, 3, &established)
    )?;
    Ok(
        json!({"generation": generation, "payload_identity": format!("generation-{generation}"),
        "concurrent_flows": 4, "all_flows_established_barrier": true, "flows": [a,b,c,d]}),
    )
}

async fn reset(args: &Args) -> Result<Value, String> {
    let (ready, release) = args.reset.as_ref().ok_or("missing reset markers")?;
    let mut old_tcp = connect(args.tcp).await?;
    exchange(&mut old_tcp, &payload(1024, 1, 4, 1)).await?;
    let bytes = payload(BULK, 1, 4, 2);
    let sent = pause_reader(&old_tcp, &bytes).await?;
    let old_udp = udp(args.udp).await?;
    let pending = payload(256, 1, 4, 30);
    if old_udp.send(&pending).await.map_err(|e| e.to_string())? != pending.len() {
        return Err("reset pending UDP partial send".into());
    }
    // Pending denotes unsatisfied harness reads, not a claim about which
    // product queue currently owns the bytes or datagram.
    publish(
        ready,
        &json!({"schema_version":1,"kind":"ferrum2.windows-tun-reset-ready",
        "address_family":args.address_family,
        "generation":1,"tcp_pending":true,"udp_pending":true,
        "tcp_paused_bytes_sent":sent,"tcp_unwritable_milliseconds":100,
        "udp_pending_datagrams":1,
        "udp_local_endpoint":old_udp.local_addr().map_err(|e| e.to_string())?.to_string()}),
    )?;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match tokio::fs::symlink_metadata(release).await {
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.file_type().is_symlink()
                        || metadata.len() > 1024
                    {
                        return Err("invalid reset release marker file".to_owned());
                    }
                    let content = tokio::fs::read(release).await.map_err(|e| e.to_string())?;
                    let value: Value =
                        serde_json::from_slice(&content).map_err(|e| e.to_string())?;
                    validate_reset_release(&value, args.address_family)?;
                    return Ok(());
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error.to_string()),
            }
        }
    })
    .await
    .map_err(|_| "reset release deadline")??;
    // Buffered old-generation replies may precede retirement. Account and check
    // them, but never accept timeout or a successful new request as retirement.
    let mut drained = 0;
    let retirement = tokio::time::timeout(IO_LIMIT, async {
        let mut buffer = [0; 16 * 1024];
        loop {
            match old_tcp.read(&mut buffer).await {
                Ok(0) => return Ok("eof"),
                Ok(count) => {
                    if drained + count > sent || buffer[..count] != bytes[drained..drained + count]
                    {
                        return Err("old-generation TCP payload mismatch".to_owned());
                    }
                    drained += count;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::BrokenPipe
                            | ErrorKind::NotConnected
                    ) =>
                {
                    return Ok("reset");
                }
                Err(error) => return Err(format!("old TCP retirement failed: {error}")),
            }
        }
    })
    .await
    .map_err(|_| {
        format!("old TCP did not retire after route reset: checked buffered bytes {drained}/{sent}")
    })??;
    drop(old_tcp);
    let udp_local = old_udp.local_addr().map_err(|e| e.to_string())?;
    let fresh = payload(256, 2, 4, 30);
    let expected_fresh = super::socket_io::udp_ack(&fresh)?;
    let expected_old = super::socket_io::udp_ack(&pending)?;
    let buffered = tokio::time::timeout(IO_LIMIT, async {
        if old_udp.send(&fresh).await.map_err(|e| e.to_string())? != fresh.len() {
            return Err("same-tuple UDP fresh send was partial".to_owned());
        }
        let mut reply = [0; 257];
        for old_replies in 0..2 {
            let count = old_udp.recv(&mut reply).await.map_err(|e| e.to_string())?;
            if reply[..count] == expected_fresh {
                return Ok(old_replies);
            }
            if reply[..count] != expected_old || old_replies != 0 {
                return Err("same-tuple UDP received stale, duplicate, or corrupt payload".into());
            }
        }
        Err("same-tuple UDP fresh reply missing".into())
    })
    .await
    .map_err(|_| "same-tuple UDP fresh reply deadline")??;
    drop(old_udp);
    Ok(
        json!({"ready_generation":1,"release_generation":2,"old_tcp_retired":true,
        "old_tcp_retirement":retirement,"old_tcp_pending_bytes":sent,"old_tcp_drained_bytes":drained,
        "old_udp_pending_datagrams":1,"old_udp_buffered_replies":buffered,
        "same_tuple_udp_fresh_reply_checked":true,"udp_local_endpoint":udp_local.to_string(),
        "udp_fresh_payload_identity":"generation-2"}),
    )
}

pub(crate) fn run_qualification(arguments: &[OsString]) -> Result<String, String> {
    let args = parse(arguments, "qualification")?;
    let result = runtime()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(55), async {
            let first = generation(&args, 1).await?;
            let mut generations = vec![first];
            let reset = if args.reset.is_some() {
                let witness = reset(&args).await?;
                generations.push(generation(&args, 2).await?);
                witness
            } else {
                Value::Null
            };
            Ok::<_, String>(
                json!({"schema_version":1,"kind":"ferrum2.windows-tun-qualification",
                "address_family":args.address_family,"status":"PASS","generations":generations,"reset":reset}),
            )
        })
        .await
        .map_err(|_| "qualification global deadline".to_owned())?
    });
    let output = args.output.as_ref().ok_or("missing output")?;
    match result {
        Ok(witness) => {
            publish(output, &witness)?;
            Ok(format!(
                "windows_tun_qualification status=PASS address_family={}",
                args.address_family.as_str()
            ))
        }
        Err(error) => {
            publish(
                output,
                &json!({"schema_version":1,"kind":"ferrum2.windows-tun-qualification",
                "address_family":args.address_family,"status":"FAIL","error":error}),
            )?;
            Err(error)
        }
    }
}

pub(crate) fn run_probe(arguments: &[OsString]) -> Result<String, String> {
    let args = parse(arguments, "probe")?;
    runtime()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut stream = connect(args.tcp).await?;
            exchange(&mut stream, &payload(1024, 1, 0, 0)).await?;
            let socket = udp(args.udp).await?;
            datagram(&socket, &payload(256, 1, 0, 0)).await?;
            datagram(&socket, &payload(FRAGMENT, 1, 0, 1)).await
        })
        .await
        .map_err(|_| "probe deadline")?
    })?;
    Ok(format!(
        "windows_tun_probe status=PASS protocols=tcp,udp address_family={}",
        args.address_family.as_str()
    ))
}
