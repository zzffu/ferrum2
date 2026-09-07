use std::future::Future;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt as _};
use tokio::sync::watch;
use tokio::time::Instant;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SocksSendError {
    Io,
    Cancelled,
    Idle,
    ControlClosed,
}

/// Retains the control reader and send future in one stack frame. No watcher
/// task can outlive the association or hide EOF while resolution/readiness waits.
pub(super) async fn send_with_control(
    send: impl Future<Output = io::Result<usize>>,
    control: &mut (impl AsyncRead + Unpin),
    cancelled: impl Future<Output = ()>,
    session: &mut watch::Receiver<bool>,
    deadline: Instant,
) -> Result<usize, SocksSendError> {
    if *session.borrow() {
        return Err(SocksSendError::Cancelled);
    }
    tokio::pin!(send, cancelled);
    let idle = tokio::time::sleep_until(deadline);
    tokio::pin!(idle);
    let mut byte = [0];
    loop {
        tokio::select! {
            biased;
            _ = &mut cancelled => return Err(SocksSendError::Cancelled),
            _ = session.changed() => return Err(SocksSendError::Cancelled),
            _ = &mut idle => return Err(SocksSendError::Idle),
            read = control.read(&mut byte) => { if !matches!(read, Ok(1)) { return Err(SocksSendError::ControlClosed); } }
            sent = &mut send => return sent.map_err(|_| SocksSendError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    struct Released(Arc<AtomicBool>);
    impl Drop for Released {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn control_eof_releases_a_pending_send_without_waiting_for_its_deadline() {
        let (mut control, peer) = tokio::io::duplex(16);
        let (_session, mut session) = watch::channel(false);
        let released = Arc::new(AtomicBool::new(false));
        let guard = Released(released.clone());
        let send = async move {
            let _guard = guard;
            std::future::pending::<io::Result<usize>>().await
        };
        let start = Instant::now();
        let sending = send_with_control(
            send,
            &mut control,
            std::future::pending(),
            &mut session,
            start + Duration::from_secs(60),
        );
        tokio::pin!(sending);
        std::future::poll_fn(|cx| {
            assert!(sending.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(peer);
        assert_eq!(sending.await, Err(SocksSendError::ControlClosed));
        assert!(released.load(Ordering::Acquire));
        assert_eq!(Instant::now(), start);
    }
}
