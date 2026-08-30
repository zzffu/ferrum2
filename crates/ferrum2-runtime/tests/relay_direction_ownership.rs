use std::time::Duration;

use ferrum2_runtime::{RelayStats, relay_bidirectional};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

const FLOW_COUNT: usize = 8;
const ROUND_COUNT: usize = 12;
const DUPLEX_CAPACITY: usize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_persistent_relays_make_progress_and_preserve_half_close() {
    tokio::time::timeout(Duration::from_secs(30), exercise_persistent_relays())
        .await
        .expect("relay liveness scenario exceeded its deadlock watchdog");
}

async fn exercise_persistent_relays() {
    let (completed_tx, mut completed_rx) = mpsc::channel(FLOW_COUNT);
    let mut round_gates = Vec::with_capacity(FLOW_COUNT);
    let mut tasks = Vec::with_capacity(FLOW_COUNT);

    for flow in 0..FLOW_COUNT {
        let (application, mut relay_inbound) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (mut relay_outbound, target) = tokio::io::duplex(DUPLEX_CAPACITY);
        let (round_tx, round_rx) = mpsc::channel(1);
        let completed_tx = completed_tx.clone();

        let relay = tokio::spawn(async move {
            relay_bidirectional(&mut relay_inbound, &mut relay_outbound).await
        });
        let driver = tokio::spawn(drive_flow(
            flow,
            application,
            target,
            round_rx,
            completed_tx,
        ));

        round_gates.push(round_tx);
        tasks.push((driver, relay));
    }
    drop(completed_tx);

    for round in 0..ROUND_COUNT {
        for gate in &round_gates {
            gate.send(round).await.expect("flow remains active");
        }

        let mut progressed = [false; FLOW_COUNT];
        for _ in 0..FLOW_COUNT {
            let (flow, completed_round) = completed_rx
                .recv()
                .await
                .expect("every flow reports round progress");
            assert_eq!(completed_round, round, "flow completed the gated round");
            assert!(!progressed[flow], "flow reported the round only once");
            progressed[flow] = true;
        }
        assert!(
            progressed.into_iter().all(|made_progress| made_progress),
            "every persistent flow made progress in the gated round"
        );
    }
    drop(round_gates);

    for (driver, relay) in tasks {
        let expected = driver.await.expect("flow driver task");
        let observed = relay
            .await
            .expect("relay task")
            .expect("relay completes after both half-closes");
        assert_eq!(observed, expected);
    }
    assert!(
        completed_rx.recv().await.is_none(),
        "completion channel closes after all flow drivers exit"
    );
}

async fn drive_flow(
    flow: usize,
    mut application: DuplexStream,
    mut target: DuplexStream,
    mut round_gate: mpsc::Receiver<usize>,
    completed: mpsc::Sender<(usize, usize)>,
) -> RelayStats {
    let mut expected = RelayStats {
        inbound_to_outbound: 0,
        outbound_to_inbound: 0,
    };
    let mut next_round = 0;

    while let Some(round) = round_gate.recv().await {
        assert_eq!(round, next_round, "flow observes each gate in order");

        let request = payload(b'Q', flow, round, 11 + (flow + round) % 17);
        let response = payload(b'R', flow, round, 13 + (flow * 3 + round) % 19);

        application
            .write_all(&request)
            .await
            .expect("write gated request");
        target
            .write_all(&response)
            .await
            .expect("write gated response");

        let mut observed_request = vec![0; request.len()];
        target
            .read_exact(&mut observed_request)
            .await
            .expect("read exact gated request");
        assert_eq!(observed_request, request);

        let mut observed_response = vec![0; response.len()];
        application
            .read_exact(&mut observed_response)
            .await
            .expect("read exact gated response");
        assert_eq!(observed_response, response);

        expected.inbound_to_outbound += request.len() as u64;
        expected.outbound_to_inbound += response.len() as u64;
        completed
            .send((flow, round))
            .await
            .expect("round coordinator remains active");
        next_round += 1;
    }

    assert_eq!(next_round, ROUND_COUNT, "flow completed every gated round");

    application
        .shutdown()
        .await
        .expect("half-close request direction");
    let mut unexpected_request_suffix = Vec::new();
    target
        .read_to_end(&mut unexpected_request_suffix)
        .await
        .expect("observe propagated request EOF");
    assert!(
        unexpected_request_suffix.is_empty(),
        "request direction ended at the exact byte boundary"
    );

    let response_after_eof = payload(b'T', flow, ROUND_COUNT, 9 + flow);
    target
        .write_all(&response_after_eof)
        .await
        .expect("write response after request EOF");
    target
        .shutdown()
        .await
        .expect("half-close response direction");

    let mut observed_response_after_eof = Vec::new();
    application
        .read_to_end(&mut observed_response_after_eof)
        .await
        .expect("drain response after request EOF");
    assert_eq!(observed_response_after_eof, response_after_eof);
    expected.outbound_to_inbound += response_after_eof.len() as u64;

    expected
}

fn payload(marker: u8, flow: usize, round: usize, length: usize) -> Vec<u8> {
    (0..length)
        .map(|offset| {
            marker
                .wrapping_add((flow * 17) as u8)
                .wrapping_add((round * 31) as u8)
                .wrapping_add(offset as u8)
        })
        .collect()
}
