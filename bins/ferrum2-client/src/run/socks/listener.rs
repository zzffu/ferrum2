use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, PreparedProcessRoot, ProcessCancellation, ProcessFuture,
};
use tokio::net::TcpListener;

use crate::run::RunError;
use crate::run::context::{ClientContext, ClientRouting};
use crate::run::observation::{record_forced_udp_sessions, run_error_for_supervisor};

use super::tcp_command::client_connection;

pub(in crate::run) struct ClientTcpListeners {
    pub(in crate::run) listeners: Vec<TcpListener>,
    pub(in crate::run) next: AtomicUsize,
    #[cfg(test)]
    pub(in crate::run) accept_errors:
        Option<Arc<std::sync::Mutex<std::collections::VecDeque<io::ErrorKind>>>>,
}

impl AcceptListener for ClientTcpListeners {
    type Stream = (usize, tokio::net::TcpStream);

    async fn accept(&self) -> io::Result<Self::Stream> {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.listeners.len();
        std::future::poll_fn(|task| {
            #[cfg(test)]
            if let Some(kind) = self
                .accept_errors
                .as_ref()
                .and_then(|errors| errors.lock().expect("accept error lock").pop_front())
            {
                return Poll::Ready(Err(io::Error::from(kind)));
            }
            for offset in 0..self.listeners.len() {
                let inbound = (start + offset) % self.listeners.len();
                match self.listeners[inbound].poll_accept(task) {
                    Poll::Ready(Ok((stream, _))) => {
                        if let Err(error) = stream.set_nodelay(true) {
                            return Poll::Ready(Err(error));
                        }
                        return Poll::Ready(Ok((inbound, stream)));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    fn connection_runtime_cpu_hint(&self, stream: &Self::Stream) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            incoming_cpu_hint(rustix::net::sockopt::socket_incoming_cpu(&stream.1).ok())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _stream = stream;
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn incoming_cpu_hint(incoming_cpu: Option<u32>) -> Option<usize> {
    incoming_cpu
        .filter(|cpu_id| *cpu_id != u32::MAX)
        .and_then(|cpu_id| usize::try_from(cpu_id).ok())
}

pub(in crate::run) struct ClientTcpRoot {
    pub(in crate::run) supervisor: Option<BoundedSupervisor<ClientTcpListeners>>,
    pub(in crate::run) context: Arc<ClientContext>,
    pub(in crate::run) routing: Arc<ClientRouting>,
    pub(in crate::run) reregister_accepted_stream: bool,
}

impl PreparedProcessRoot<RunError> for ClientTcpRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let supervisor = self.supervisor.take().expect("prepared TCP root");
        let context = Arc::clone(&self.context);
        let routing = Arc::clone(&self.routing);
        let reregister_accepted_stream = self.reregister_accepted_stream;
        let handler_context = Arc::clone(&context);
        let mut quiescing = cancellation.clone();
        let mut forced = cancellation.clone();
        Box::pin(async move {
            let running = supervisor.run_with_cancellation(
                move |(inbound, stream), cancellation| {
                    let context = Arc::clone(&handler_context);
                    let routing = Arc::clone(&routing);
                    async move {
                        let stream = if reregister_accepted_stream {
                            let Ok(stream) = stream.into_std() else {
                                return;
                            };
                            let Ok(stream) = tokio::net::TcpStream::from_std(stream) else {
                                return;
                            };
                            stream
                        } else {
                            stream
                        };
                        client_connection(stream, cancellation, context, inbound, routing).await;
                    }
                },
                cancellation,
            );
            tokio::pin!(running);
            let result = tokio::select! {
                biased;
                _ = forced.forced() => {
                    record_forced_udp_sessions(&context);
                    if let Some(udp) = &context.egress.udp {
                        udp.cancel_all();
                    }
                    running.await
                }
                _ = quiescing.cancelled() => {
                    if context.runtime.shutdown_grace.is_zero() {
                        forced.forced().await;
                        record_forced_udp_sessions(&context);
                    }
                    if let Some(udp) = &context.egress.udp {
                        udp.cancel_all();
                    }
                    running.await
                }
                result = &mut running => result,
            };
            result.map_err(run_error_for_supervisor)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::incoming_cpu_hint;

    #[test]
    fn incoming_cpu_hint_rejects_kernel_sentinel_and_query_errors() {
        assert_eq!(incoming_cpu_hint(Some(7)), Some(7));
        assert_eq!(incoming_cpu_hint(Some(u32::MAX)), None);
        assert_eq!(incoming_cpu_hint(None), None);
    }
}
