use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::super::{AddressFamily, Binding, InterfaceAddresses, PortQuarantine};
use super::{AcceptedSocket, derive_ipv4_peer, derive_ipv6_peer};
use crate::OwnerWake;

struct AcceptExitGuard {
    clean: bool,
    failed: Arc<AtomicBool>,
    owner_wake: OwnerWake,
}

impl Drop for AcceptExitGuard {
    fn drop(&mut self) {
        if !self.clean {
            self.failed.store(true, Ordering::Release);
            self.owner_wake.signal();
        }
    }
}

pub(in crate::system_tcp) struct ListenerSet {
    pub(in crate::system_tcp) bindings: Vec<Binding>,
    cancellation: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    runtime: Handle,
    failed: Arc<AtomicBool>,
    stopping: bool,
}

impl ListenerSet {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::system_tcp) fn start(
        addresses: InterfaceAddresses,
        epoch: u64,
        backlog: usize,
        runtime: &Handle,
        accepted: mpsc::Sender<AcceptedSocket>,
        failed: Arc<AtomicBool>,
        dropped_accepts: Arc<AtomicUsize>,
        owner_wake: OwnerWake,
        quarantine: Arc<Mutex<PortQuarantine>>,
    ) -> io::Result<Self> {
        let ipv4 = match addresses.0 {
            Some((local, prefix)) => Some((
                AddressFamily::Ipv4,
                SocketAddr::new(IpAddr::V4(local), 0),
                IpAddr::V4(derive_ipv4_peer(local, prefix)?),
            )),
            None => None,
        };
        let ipv6 = match addresses.1 {
            Some((local, prefix)) => Some((
                AddressFamily::Ipv6,
                SocketAddr::V6(SocketAddrV6::new(local, 0, 0, 0)),
                IpAddr::V6(derive_ipv6_peer(local, prefix)?),
            )),
            None => None,
        };
        if ipv4.is_none() && ipv6.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "system TCP requires at least one address family",
            ));
        }

        let mut prepared = Vec::with_capacity(2);
        for (family, local, peer) in ipv4.into_iter().chain(ipv6) {
            match bind_available(family, local, peer, epoch, backlog, &quarantine) {
                Ok(listener) => prepared.push(listener),
                Err(error) => {
                    unclaim_bindings(&quarantine, prepared.iter().map(|(_, binding)| *binding));
                    return Err(error);
                }
            }
        }
        let claimed = prepared
            .iter()
            .map(|(_, binding)| *binding)
            .collect::<Vec<_>>();
        let (cancellation, _) = watch::channel(false);
        let mut ready = Vec::with_capacity(prepared.len());
        for (listener, binding) in prepared {
            let converted = {
                let _entered = runtime.enter();
                TcpListener::from_std(listener)
            };
            match converted {
                Ok(listener) => ready.push((listener, binding)),
                Err(error) => {
                    unclaim_bindings(&quarantine, claimed.iter().copied());
                    return Err(error);
                }
            }
        }
        let mut bindings = Vec::with_capacity(ready.len());
        let mut tasks = Vec::with_capacity(ready.len());
        for (listener, binding) in ready {
            bindings.push(binding);
            tasks.push(runtime.spawn(accept_loop(
                listener,
                binding,
                accepted.clone(),
                cancellation.subscribe(),
                Arc::clone(&failed),
                Arc::clone(&dropped_accepts),
                owner_wake.clone(),
            )));
        }

        Ok(Self {
            bindings,
            cancellation,
            tasks,
            runtime: runtime.clone(),
            failed,
            stopping: false,
        })
    }

    pub(in crate::system_tcp) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
            || (!self.stopping && self.tasks.iter().any(JoinHandle::is_finished))
    }

    pub(in crate::system_tcp) fn stop_and_join(&mut self) -> Result<(), ()> {
        self.stopping = true;
        let _ = self.cancellation.send(true);
        let mut result = Ok(());
        for task in self.tasks.drain(..) {
            if self.runtime.block_on(task).is_err() {
                result = Err(());
            }
        }
        self.bindings.clear();
        result
    }
}

impl Drop for ListenerSet {
    fn drop(&mut self) {
        let _ = self.cancellation.send(true);
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    binding: Binding,
    accepted: mpsc::Sender<AcceptedSocket>,
    mut cancellation: watch::Receiver<bool>,
    failed: Arc<AtomicBool>,
    dropped_accepts: Arc<AtomicUsize>,
    owner_wake: OwnerWake,
) {
    let mut exit = AcceptExitGuard {
        clean: false,
        failed: Arc::clone(&failed),
        owner_wake: owner_wake.clone(),
    };
    loop {
        tokio::select! {
            biased;
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    exit.clean = true;
                    break;
                }
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, peer)) => {
                        let event = AcceptedSocket {
                            epoch: binding.epoch,
                            local: binding.local,
                            peer: SocketAddr::new(peer.ip(), peer.port()),
                            stream: stream.into(),
                        };
                        match accepted.try_send(event) {
                            Ok(()) => owner_wake.signal(),
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                let _ = dropped_accepts.fetch_update(
                                    Ordering::Relaxed,
                                    Ordering::Relaxed,
                                    |count| Some(count.saturating_add(1)),
                                );
                                owner_wake.signal();
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                if !*cancellation.borrow() {
                                    failed.store(true, Ordering::Release);
                                    owner_wake.signal();
                                }
                                exit.clean = true;
                                break;
                            }
                        }
                    }
                    Err(error) if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::ConnectionReset
                    ) => {}
                    Err(_) => {
                        if !*cancellation.borrow() {
                            failed.store(true, Ordering::Release);
                            owner_wake.signal();
                        }
                        exit.clean = true;
                        break;
                    }
                }
            }
        }
    }
}

const LISTENER_BIND_ATTEMPTS: usize = 256;

fn bind_available(
    family: AddressFamily,
    address: SocketAddr,
    peer: IpAddr,
    epoch: u64,
    backlog: usize,
    quarantine: &Arc<Mutex<PortQuarantine>>,
) -> io::Result<(std::net::TcpListener, Binding)> {
    for _ in 0..LISTENER_BIND_ATTEMPTS {
        // Let Windows avoid its own excluded/in-use ports; the second check
        // prevents reuse of a wire identity whose old socket has already closed.
        let (listener, binding) = bind(family, address, peer, epoch, backlog)?;
        if quarantine
            .lock()
            .expect("system TCP port quarantine")
            .claim(family, binding.local.port())
        {
            return Ok((listener, binding));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "system TCP could not bind an available listener identity",
    ))
}

fn unclaim_bindings(
    quarantine: &Arc<Mutex<PortQuarantine>>,
    bindings: impl IntoIterator<Item = Binding>,
) {
    let mut quarantine = quarantine.lock().expect("system TCP port quarantine");
    for binding in bindings {
        quarantine.unclaim(binding.family, binding.local.port());
    }
}

fn bind(
    family: AddressFamily,
    address: SocketAddr,
    peer: IpAddr,
    epoch: u64,
    backlog: usize,
) -> io::Result<(std::net::TcpListener, Binding)> {
    let domain = match family {
        AddressFamily::Ipv4 => Domain::IPV4,
        AddressFamily::Ipv6 => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if family == AddressFamily::Ipv6 {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    let backlog = i32::try_from(backlog.max(1)).unwrap_or(i32::MAX);
    socket.listen(backlog)?;
    let listener: std::net::TcpListener = socket.into();
    let local = listener.local_addr()?;
    Ok((
        listener,
        Binding {
            family,
            local,
            peer,
            epoch,
        },
    ))
}
