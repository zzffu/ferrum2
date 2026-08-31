use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

use ferrum2_runtime::{
    AcceptListener, AffineAcceptListener, AffineConnectionExecutor, PreparedProcessRoot,
    ProcessCancellation, ProcessFuture,
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
impl AffineAcceptListener for ServerTcpListeners {
    type Transfer = (usize, std::net::TcpStream);
    type AffineStream = (usize, tokio::net::TcpStream);

    fn into_transfer((inbound, stream): Self::Stream) -> io::Result<Self::Transfer> {
        stream.into_std().map(|stream| (inbound, stream))
    }

    fn from_transfer((inbound, stream): Self::Transfer) -> io::Result<Self::AffineStream> {
        tokio::net::TcpStream::from_std(stream).map(|stream| (inbound, stream))
    }
}

pub(in crate::run) struct ServerTcpRoot {
    pub(in crate::run) executor: Option<AffineConnectionExecutor<ServerTcpListeners>>,
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
        let executor = self.executor.take().expect("prepared TCP root");
        let contexts = Arc::clone(&self.contexts);
        Box::pin(async move {
            executor
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
