use std::sync::mpsc;
use std::time::Duration;

use serde_json::json;

use super::super::diagnostic::{
    FRAGMENT_BATCH, FRAGMENT_MINIMUM_DATAGRAMS, TCP_FAIRNESS_FLOWS, TCP_FAIRNESS_PAYLOAD,
    TCP_REQUEST_MINIMUM_TRANSACTIONS, TCP_SINGLE_MINIMUM_BYTES, TCP_SINGLE_PAYLOAD,
    UDP_MINIMUM_DATAGRAMS,
};
use super::super::measurement::{ActiveWorkWindow, MeasuredWork, fairness_measurements};
use super::super::workload::wait_for_fairness_warmup;

pub(super) fn check() -> Result<(), String> {
    check_warmup_completion()?;
    let active = Duration::from_secs(10);
    let before = Duration::from_secs(9);
    let after = Duration::from_secs(12);
    let mut window = ActiveWorkWindow::new(active);
    if !window.admits(Duration::ZERO)
        || !window.admits(before)
        || window.admits(active)
        || window.admits(after)
    {
        return Err("active-window admission deadline is invalid".to_owned());
    }
    window.complete(Duration::ZERO, before, 1)?;
    window.complete(before, active, 1)?;
    window.complete(before, after, 1)?;
    if window.finish(3, "self-check")?
        != (MeasuredWork {
            checked_units: 3,
            tail_checked_units: 1,
            elapsed: after,
        })
    {
        return Err("active-window completed work or tail was lost".to_owned());
    }
    for minimum in [TCP_REQUEST_MINIMUM_TRANSACTIONS, UDP_MINIMUM_DATAGRAMS] {
        let mut insufficient = ActiveWorkWindow::new(active);
        insufficient.complete(before, after, minimum - 1)?;
        if insufficient.admits(active) || insufficient.finish(minimum, "self-check").is_ok() {
            return Err(
                "active-window sample shortage extended admission or was accepted".to_owned(),
            );
        }
        let mut enough = ActiveWorkWindow::new(active);
        enough.complete(before, active, minimum)?;
        if enough.finish(minimum, "self-check")?
            != (MeasuredWork {
                checked_units: minimum,
                tail_checked_units: 0,
                elapsed: active,
            })
        {
            return Err("active-window exact coverage is invalid".to_owned());
        }
    }
    for (started, completed, units) in [
        (active, after, 1),
        (before, Duration::ZERO, 1),
        (before, active, 0),
    ] {
        let mut invalid = ActiveWorkWindow::new(active);
        if invalid.complete(started, completed, units).is_ok() {
            return Err("invalid active-window completion was accepted".to_owned());
        }
    }
    let mut overflow = ActiveWorkWindow::new(active);
    overflow.complete(before, after, u64::MAX)?;
    if overflow.complete(before, after, 1).is_ok()
        || overflow.finish(1, "self-check")?
            != (MeasuredWork {
                checked_units: u64::MAX,
                tail_checked_units: u64::MAX,
                elapsed: after,
            })
    {
        return Err("active-window overflow changed accepted work".to_owned());
    }
    check_fragments(active, before, after)?;
    check_single_flow(active, before, after)?;
    check_fairness(active, after)
}

fn check_single_flow(active: Duration, before: Duration, after: Duration) -> Result<(), String> {
    let mut window = ActiveWorkWindow::new(active);
    window.complete(
        Duration::ZERO,
        before,
        TCP_SINGLE_MINIMUM_BYTES - TCP_SINGLE_PAYLOAD as u64,
    )?;
    window.complete(before, after, TCP_SINGLE_PAYLOAD as u64)?;
    if window.admits(active)
        || window.finish(TCP_SINGLE_MINIMUM_BYTES, "single-flow self-check")?
            != (MeasuredWork {
                checked_units: TCP_SINGLE_MINIMUM_BYTES,
                tail_checked_units: TCP_SINGLE_PAYLOAD as u64,
                elapsed: after,
            })
    {
        return Err("single-flow completion window lost its final transaction".to_owned());
    }
    let mut insufficient = ActiveWorkWindow::new(active);
    insufficient.complete(before, after, TCP_SINGLE_PAYLOAD as u64)?;
    if insufficient
        .finish(TCP_SINGLE_MINIMUM_BYTES, "single-flow self-check")
        .is_ok()
    {
        return Err("single-flow sample shortage was accepted".to_owned());
    }
    Ok(())
}

fn check_warmup_completion() -> Result<(), String> {
    for completed_workers in [0, TCP_FAIRNESS_FLOWS - 1, TCP_FAIRNESS_FLOWS] {
        let (sender, receiver) = mpsc::sync_channel(TCP_FAIRNESS_FLOWS);
        for _ in 0..completed_workers {
            sender
                .send(Ok(()))
                .map_err(|_| "warmup self-check receiver ended".to_owned())?;
        }
        drop(sender);
        if wait_for_fairness_warmup(receiver).is_ok() != (completed_workers == TCP_FAIRNESS_FLOWS) {
            return Err(
                "fairness active admission did not require every warmup completion".to_owned(),
            );
        }
    }
    let (sender, receiver) = mpsc::sync_channel(TCP_FAIRNESS_FLOWS);
    sender
        .send(Err("injected warmup failure".to_owned()))
        .map_err(|_| "warmup self-check receiver ended".to_owned())?;
    drop(sender);
    if wait_for_fairness_warmup(receiver) != Err("injected warmup failure".to_owned()) {
        return Err("fairness warmup failure was hidden".to_owned());
    }
    Ok(())
}

fn check_fragments(active: Duration, before: Duration, after: Duration) -> Result<(), String> {
    let mut window = ActiveWorkWindow::new(active);
    window.complete(
        Duration::ZERO,
        before,
        FRAGMENT_MINIMUM_DATAGRAMS - FRAGMENT_BATCH as u64,
    )?;
    window.complete(before, after, FRAGMENT_BATCH as u64)?;
    if window.admits(active)
        || window.finish(FRAGMENT_MINIMUM_DATAGRAMS, "fragment self-check")?
            != (MeasuredWork {
                checked_units: FRAGMENT_MINIMUM_DATAGRAMS,
                tail_checked_units: FRAGMENT_BATCH as u64,
                elapsed: after,
            })
    {
        return Err("fragment tail batch was discarded or extended admission".to_owned());
    }
    let mut insufficient = ActiveWorkWindow::new(active);
    insufficient.complete(before, after, FRAGMENT_BATCH as u64)?;
    if insufficient
        .finish(FRAGMENT_MINIMUM_DATAGRAMS, "fragment self-check")
        .is_ok()
    {
        return Err("fragment sample shortage was accepted".to_owned());
    }
    Ok(())
}

fn check_fairness(active: Duration, after: Duration) -> Result<(), String> {
    let mut flows = vec![
        MeasuredWork {
            checked_units: TCP_FAIRNESS_PAYLOAD as u64,
            tail_checked_units: 0,
            elapsed: active,
        };
        TCP_FAIRNESS_FLOWS
    ];
    flows[0] = MeasuredWork {
        checked_units: (TCP_FAIRNESS_PAYLOAD * 2) as u64,
        tail_checked_units: TCP_FAIRNESS_PAYLOAD as u64,
        elapsed: after,
    };
    if fairness_measurements(&flows)?
        != json!({
            "measurements": {
                "fairness": 996_154_078,
                "aggregate_throughput": 350_890,
                "active_elapsed_nanoseconds": 12_000_000_000_u64,
                "tail_checked_units": 16_384,
                "io_completions": 514,
            },
            "checked_units": 4_210_688,
            "checks": {
                "all_256_flows_ready": true,
                "all_256_flows_nonzero": true,
                "payload_exact": true,
                "no_gso": true,
            },
        })
    {
        return Err("fairness completion window did not include the slowest tail".to_owned());
    }
    if fairness_measurements(&flows[..TCP_FAIRNESS_FLOWS - 1]).is_ok() {
        return Err("missing fairness flow was accepted".to_owned());
    }
    flows[0].checked_units = 0;
    if fairness_measurements(&flows).is_ok() {
        return Err("starved fairness flow was accepted".to_owned());
    }
    Ok(())
}
