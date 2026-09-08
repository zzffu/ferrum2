use super::{
    GenerationBoundUdpSocket, close_generation_bound_udp_resource, closed_io_error,
    closed_resource_io_error,
};
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

impl GenerationBoundUdpSocket<UdpSocket> {
    /// Binds the peer filter without bypassing the socket's generation fence.
    pub async fn connect_peer(&self, peer: SocketAddr) -> io::Result<()> {
        let mut cancellation = self.cancellation.clone();
        let mut stop = self.stop.clone();
        let outcome = tokio::select! {
            biased;
            cancellation = cancellation.cancelled() => Err(cancellation),
            () = stop.stopped() => {
                close_generation_bound_udp_resource(&self.resource, &self.closed, None);
                return Err(closed_resource_io_error());
            }
            result = async {
                let resource = self.live_resource()?;
                resource.socket().connect(peer).await
            } => Ok(result),
        };
        match outcome {
            Err(cancellation) => {
                self.close(cancellation);
                Err(closed_io_error(cancellation))
            }
            Ok(result) => {
                if let Some(cancellation) = self.cancellation.terminal_now() {
                    self.close(cancellation);
                    Err(closed_io_error(cancellation))
                } else {
                    result
                }
            }
        }
    }

    /// Attempts one connected receive without retaining a buffer while waiting.
    /// Generation cancellation is checked before and after the nonblocking IO.
    pub fn try_receive_connected(&self, destination: &mut [u8]) -> io::Result<usize> {
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close(cancellation);
            return Err(closed_io_error(cancellation));
        }
        let resource = self.try_live_resource()?;
        let result = resource.socket().try_recv(destination);
        drop(resource);
        if let Some(cancellation) = self.cancellation.terminal_now() {
            self.close(cancellation);
            Err(closed_io_error(cancellation))
        } else {
            result
        }
    }
}
