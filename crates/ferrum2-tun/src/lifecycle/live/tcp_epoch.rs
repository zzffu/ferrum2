use crate::stack::Stack;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TcpEpochError {
    Runtime,
    Cleanup,
}

pub(super) fn start(
    stack: &mut Stack,
    adapter: &mut ferrum2_platform_windows::Adapter,
    runtime: &tokio::runtime::Handle,
) -> Result<(), TcpEpochError> {
    let endpoints = match stack.start_tcp(runtime) {
        Ok(endpoints) => endpoints,
        Err(_) => {
            return if stop(stack, adapter).is_err() {
                Err(TcpEpochError::Cleanup)
            } else {
                Err(TcpEpochError::Runtime)
            };
        }
    };
    let setup = endpoints
        .iter()
        .try_for_each(|endpoint| adapter.verify_tcp_peer_route(endpoint.peer()))
        .and_then(|()| adapter.install_tcp_ingress(&endpoints))
        .and_then(|()| adapter.verify_tcp_ingress());
    if setup.is_ok() && !stack.tcp_failed() {
        return Ok(());
    }
    let cleanup_error =
        setup.is_err_and(|error| error.kind() == ferrum2_platform_windows::ErrorKind::Cleanup);
    let stop_failed = stop(stack, adapter).is_err();
    if cleanup_error || stop_failed {
        Err(TcpEpochError::Cleanup)
    } else {
        Err(TcpEpochError::Runtime)
    }
}

pub(super) fn stop(
    stack: &mut Stack,
    adapter: &mut ferrum2_platform_windows::Adapter,
) -> Result<(), ()> {
    let stopped = stack.stop_tcp_and_join();
    let cleared = adapter.clear_tcp_ingress();
    if stopped.is_err() || cleared.is_err() {
        Err(())
    } else {
        Ok(())
    }
}
