use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use ferrum2_runtime::{
    AcceptListener, BoundedSupervisor, PreparedProcessRoot, ProcessCancellation, ProcessFuture,
};
use tokio::net::TcpListener;

use super::connection::server_connection;
use super::outbound::ServerContext;
use crate::run::RunError;
use crate::run::observation::run_error_for_supervisor;

pub(in crate::run) struct ServerTcpListeners {
    pub(in crate::run) listeners: Vec<TcpListener>,
    pub(in crate::run) next: AtomicUsize,
}

impl AcceptListener for ServerTcpListeners {
    type Stream = (usize, tokio::net::TcpStream);

    async fn accept(&self) -> io::Result<Self::Stream> {
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.listeners.len();
        std::future::poll_fn(|context| {
            for offset in 0..self.listeners.len() {
                let inbound = (start + offset) % self.listeners.len();
                match self.listeners[inbound].poll_accept(context) {
                    Poll::Ready(Ok((stream, _))) => {
                        if stream.set_nodelay(true).is_err() {
                            return Poll::Ready(Err(io::Error::from(io::ErrorKind::Other)));
                        }
                        return Poll::Ready(Ok((inbound, stream)));
                    }
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::from(io::ErrorKind::Other)));
                    }
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }
}

pub(in crate::run) struct ServerTcpRoot {
    pub(in crate::run) supervisor: Option<BoundedSupervisor<ServerTcpListeners>>,
    pub(in crate::run) contexts: Arc<Vec<Arc<ServerContext>>>,
}

impl PreparedProcessRoot<RunError> for ServerTcpRoot {
    fn activate(&mut self) -> Result<(), RunError> {
        Ok(())
    }

    fn run(
        mut self: Box<Self>,
        cancellation: ProcessCancellation,
    ) -> ProcessFuture<Result<(), RunError>> {
        let supervisor = self.supervisor.take().expect("prepared TCP root");
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            supervisor
                .run_with_cancellation(
                    move |(inbound, stream), cancellation| {
                        let contexts = Arc::clone(&contexts);
                        async move {
                            if let Some(context) = contexts.get(inbound) {
                                server_connection(stream, cancellation, Arc::clone(context)).await;
                            }
                        }
                    },
                    cancellation,
                )
                .await
                .map_err(run_error_for_supervisor)
        })
    }

    fn rollback(self: Box<Self>) -> ProcessFuture<Result<(), RunError>> {
        Box::pin(async { Ok(()) })
    }
}
