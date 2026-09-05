use std::time::Duration;

use crate::OwnerWake;
use crate::runtime::{OwnerControl, OwnerExit, OwnerThread};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_reap_waits_for_native_cleanup_before_the_owner_returns() {
    assert_cancelled_reap_joins().await;
}

#[test]
fn cancelling_reap_joins_when_the_blocking_pool_is_busy() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("bounded test runtime");
    runtime.block_on(async {
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let (entered, entering) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _ = entered.send(());
            released
                .recv_timeout(Duration::from_secs(3))
                .expect("release blocking pool");
        });
        entering.await.expect("blocking pool occupied");
        assert_cancelled_reap_joins().await;
        release.send(()).expect("release blocking worker");
        blocker.await.expect("blocking worker joined");
    });
}

async fn assert_cancelled_reap_joins() {
    let (release, released) = std::sync::mpsc::sync_channel(1);
    let (cleaned, cleanup) = tokio::sync::oneshot::channel();
    let thread = std::thread::spawn(move || {
        released
            .recv_timeout(Duration::from_secs(3))
            .expect("bounded cleanup gate");
        let _ = cleaned.send(());
        OwnerExit::Stopped
    });
    let owner = OwnerThread {
        control: OwnerControl::new(),
        work: OwnerWake::default(),
        thread: Some(thread),
    };
    let (polled, first_poll) = tokio::sync::oneshot::channel();
    let mut reaper = tokio::spawn(async move {
        let reap = owner.reap();
        tokio::pin!(reap);
        // Reach the suspended join before cancelling, so this exercises the
        // handoff window rather than cancellation before the first poll.
        assert!(
            std::future::poll_fn(|context| {
                std::task::Poll::Ready(reap.as_mut().poll(context).is_pending())
            })
            .await
        );
        let _ = polled.send(());
        reap.await
    });
    first_poll.await.expect("join wait started");
    reaper.abort();
    let returned_before_cleanup = tokio::time::timeout(Duration::from_millis(50), &mut reaper)
        .await
        .is_ok();
    release.send(()).expect("release native cleanup");
    if !returned_before_cleanup {
        assert!(reaper.await.expect_err("cancelled reaper").is_cancelled());
    }
    cleanup.await.expect("native cleanup completed");
    assert!(
        !returned_before_cleanup,
        "cancelled owner returned while its native cleanup was still blocked"
    );
}
