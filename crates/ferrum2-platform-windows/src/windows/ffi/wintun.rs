use std::marker::PhantomData;
use std::ops::Deref;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, GetLastError,
    HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceLuidToGuid, CreateUnicastIpAddressEntry, GetIpInterfaceEntry,
    InitializeIpInterfaceEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_IN6_0,
};
use windows_sys::Win32::System::Threading::{ResetEvent, SetEvent, WaitForMultipleObjects};
use windows_sys::core::GUID;

use super::super::managed::{
    cleanup_transaction, finish_setup_transaction, install_managed_dns, install_managed_routes,
    managed_dns_matches, prepare_managed_intent, setup_transaction,
};
use super::super::network::{
    InterfaceIdentity, UnderlayPolicy, WindowsNetworkInterfaceCatalog, classify_underlay_refresh,
    refresh_underlay_with, underlay_matches_with,
};
use super::super::strict_route::{StrictRouteSession, strict_route_state_matches};
use super::super::wintun::SessionJournal;
use super::loader::{
    EventHandle, Library, OsVersionInfo, ReleaseReceivePacket, RtlGetVersion, WintunAdapter,
    WintunSession,
};
use super::managed::{
    DadProgress, ManagedNetworkValidation, ManagedNetworkValidationOutcome,
    ManagedOwnershipLedgerView, ManagedState, PlatformCleanup, PlatformManagedIpv4Dns,
    PlatformManagedIpv6Dns, PlatformManagedRouteCleanup, PlatformManagedRoutes, PlatformSetup,
    capture_route_row, dad_snapshot, initialize_managed_address, managed_address_matches,
    managed_device_health, managed_interface_identity_matches, managed_ownership_ledger_exact,
    managed_state_health, read_ip_interface, read_owned_address, require_address_absent,
    revalidate_managed_network,
};
use super::network::{PlatformUnderlay, snapshot_underlay};
use super::notification::subscribe_network_changes;
use super::strict_route::PlatformStrictRouteOperations;
use crate::{
    AdapterConfig, CreateError, Error, ManagedTunHealth, NetworkChangeOutcome, SendOutcome,
    WaitOutcome,
};

#[derive(Clone, Copy)]
pub(super) struct MtuState {
    pub(super) family: u16,
    pub(super) previous: u32,
    pub(super) configured: u32,
}

pub(super) struct SessionState {
    pub(super) handle: WintunSession,
    pub(super) read_event: HANDLE,
}

/// Safe RAII owner of the exact Wintun adapter, address, MTU, session and DLL transaction.
pub struct Adapter {
    pub(super) config: AdapterConfig,
    pub(super) library: Library,
    pub(super) adapter: Option<WintunAdapter>,
    pub(super) luid: NET_LUID_LH,
    pub(super) interface_index: u32,
    pub(super) mtus: [Option<MtuState>; 2],
    pub(super) pending_address: Option<MIB_UNICASTIPADDRESS_ROW>,
    pub(super) addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
    pub(super) session: Option<SessionState>,
    pub(super) session_journal: SessionJournal,
    pub(super) stop: StopSignal,
    pub(super) work: WorkSignal,
    pub(super) network_change: StopSignal,
    pub(super) network_catalog: WindowsNetworkInterfaceCatalog,
    pub(super) managed: Option<ManagedState>,
    _not_send: PhantomData<Rc<()>>,
}

impl Adapter {
    pub fn create(
        config: AdapterConfig,
        deadline: Instant,
        cancelled: &AtomicBool,
        network_catalog: WindowsNetworkInterfaceCatalog,
    ) -> Result<Self, CreateError> {
        require_windows_10().map_err(|_| CreateError::operation())?;
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(CreateError::operation());
        }
        let library = Library::load().map_err(|_| CreateError::operation())?;
        let stop = StopSignal(Arc::new(
            EventHandle::new(true).map_err(|_| CreateError::operation())?,
        ));
        let work = WorkSignal(Arc::new(
            EventHandle::new(false).map_err(|_| CreateError::operation())?,
        ));
        let network_change = StopSignal(Arc::new(
            EventHandle::new(true).map_err(|_| CreateError::operation())?,
        ));
        let mut owner = Self {
            config,
            library,
            adapter: None,
            luid: NET_LUID_LH::default(),
            interface_index: 0,
            mtus: [None, None],
            pending_address: None,
            addresses: Vec::with_capacity(2),
            session: None,
            session_journal: SessionJournal::default(),
            stop,
            work,
            network_change,
            network_catalog,
            managed: None,
            _not_send: PhantomData,
        };
        let mut strict_route_install_failed = false;
        let setup = setup_transaction(&mut PlatformSetup {
            owner: &mut owner,
            deadline,
            cancelled,
        })
        .and_then(|()| owner.prepare_managed())
        .and_then(|()| owner.finish_managed(deadline, cancelled, &mut strict_route_install_failed));
        match finish_setup_transaction(setup, strict_route_install_failed, || owner.cleanup_inner())
        {
            Ok(()) => Ok(owner),
            Err(error) => Err(error),
        }
    }

    pub fn stop_signal(&self) -> StopSignal {
        self.stop.clone()
    }

    pub fn work_signal(&self) -> WorkSignal {
        self.work.clone()
    }

    pub fn underlay_policy(&self) -> Option<UnderlayPolicy> {
        self.managed.as_ref().map(|state| state.policy.clone())
    }

    /// Returns a read-only platform catalog that recognizes this exact adapter as managed TUN.
    pub fn network_interface_catalog(&self) -> WindowsNetworkInterfaceCatalog {
        self.network_catalog.clone()
    }

    /// Replaces only the generation-bound underlay snapshot.
    ///
    /// The adapter, Wintun session, managed addresses and routes, DNS leases, notification
    /// subscriptions, and strict-route WFP session remain owned by this adapter.
    pub fn refresh_underlay(&mut self) -> Result<Option<UnderlayPolicy>, Error> {
        if self.managed_health()? != ManagedTunHealth::Healthy {
            return Err(Error::recoverable_session());
        }
        let Some(config) = self.config.managed_network().cloned() else {
            return Ok(None);
        };
        let owned = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        let state = self.managed.as_mut().ok_or(Error)?;
        let generation = state.notifications.generation_counter();
        let next = classify_underlay_refresh(refresh_underlay_with(
            &config,
            &state.policy,
            owned,
            &mut state.validated_generation,
            generation,
            &mut PlatformUnderlay,
        ))?;
        state.policy = next.clone();
        Ok(Some(next))
    }

    /// Reads back only Ferrum2-owned adapter, address, route, DNS, and strict-route state.
    pub fn managed_health(&self) -> Result<ManagedTunHealth, Error> {
        let device_health = self.managed_device_health();
        if device_health != ManagedTunHealth::Healthy {
            return Ok(device_health);
        }
        let Some(state) = self.managed.as_ref() else {
            return Ok(ManagedTunHealth::Healthy);
        };
        let ManagedState {
            routes,
            dns_interface,
            ipv4_dns,
            ipv6_dns,
            strict_route_intent,
            strict_route,
            ..
        } = state;
        let dns_interface = *dns_interface;
        managed_state_health(
            routes,
            &mut PlatformManagedRouteCleanup,
            || {
                let Some(interface) = dns_interface else {
                    return Ok(ipv4_dns.is_none() && ipv6_dns.is_none());
                };
                if let Some(lease) = ipv4_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv4Dns(interface), lease)?
                {
                    return Ok(false);
                }
                if let Some(lease) = ipv6_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv6Dns(interface), lease)?
                {
                    return Ok(false);
                }
                Ok(true)
            },
            || strict_route_state_matches(*strict_route_intent, strict_route.as_ref()),
        )
    }

    fn managed_device_health(&self) -> ManagedTunHealth {
        let expected_addresses = usize::from(self.config.ipv4.is_some())
            .saturating_add(usize::from(self.config.ipv6.is_some()));
        let owned = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        let managed = self
            .managed
            .as_ref()
            .map(|state| ManagedOwnershipLedgerView {
                capture_routes: &state.capture_routes,
                pending_route: state.pending_route.is_some(),
                route_count: state.routes.len(),
                ipv4_dns_address: state.ipv4_dns_address,
                ipv6_dns_address: state.ipv6_dns_address,
                dns_interface: state.dns_interface.is_some(),
                ipv4_dns_lease: state.ipv4_dns.is_some(),
                ipv6_dns_lease: state.ipv6_dns.is_some(),
                strict_route_intent: state.strict_route_intent,
                strict_route_session: state.strict_route.is_some(),
            });
        let ownership_ledger_exact = managed_ownership_ledger_exact(
            self.config.managed_network(),
            managed,
            self.pending_address.is_some(),
            self.addresses.len(),
            expected_addresses,
            self.network_catalog.managed_tun().ok().flatten(),
            owned,
        );
        managed_device_health(
            self.adapter.is_some_and(|adapter| !adapter.is_null()),
            self.session
                .as_ref()
                .is_some_and(|session| !session.handle.is_null()),
            ownership_ledger_exact,
            || managed_interface_identity_matches(self.luid, self.interface_index),
            || {
                self.addresses.iter().all(|intended| {
                    read_owned_address(intended)
                        .is_ok_and(|current| managed_address_matches(intended, &current))
                })
            },
        )
    }

    /// Revalidates one stable, debounced notification burst against managed state.
    pub fn revalidate_network_change(&mut self) -> Result<NetworkChangeOutcome, Error> {
        if let ManagedTunHealth::Damaged(reason) = self.managed_device_health() {
            if let Some(state) = &self.managed {
                state.policy.invalidate();
            }
            return Ok(NetworkChangeOutcome::ManagedStateDamaged(reason));
        }
        match self.revalidate_managed_network_state(true) {
            Ok(ManagedNetworkValidationOutcome::Unchanged) => Ok(NetworkChangeOutcome::Unchanged),
            Ok(ManagedNetworkValidationOutcome::UnderlayChanged) => {
                Ok(NetworkChangeOutcome::Changed)
            }
            Ok(ManagedNetworkValidationOutcome::ManagedStateDamaged(reason)) => {
                Ok(NetworkChangeOutcome::ManagedStateDamaged(reason))
            }
            Err(_) => {
                if let Some(state) = &self.managed {
                    state.policy.invalidate();
                }
                Err(Error::recoverable_session())
            }
        }
    }

    pub fn receive(&mut self) -> Result<Option<ReceivedPacket<'_>>, Error> {
        let session = self.session.as_ref().ok_or(Error)?.handle;
        let mut len = 0_u32;
        let packet = unsafe { (self.library.exports.receive_packet)(session, &mut len) };
        if packet.is_null() {
            return classify_receive_null(unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            })
            .map(|()| None);
        }
        if len == 0 || len > u32::from(u16::MAX) {
            unsafe { (self.library.exports.release_receive_packet)(session, packet) };
            return Err(Error);
        }
        Ok(Some(ReceivedPacket {
            session,
            packet,
            len: len as usize,
            release: self.library.exports.release_receive_packet,
            _borrow: PhantomData,
            _not_send: PhantomData,
        }))
    }

    pub fn wait(&mut self, timeout: Duration) -> Result<WaitOutcome, Error> {
        let read = self.session.as_ref().ok_or(Error)?.read_event;
        let handles = [
            self.stop.0.raw(),
            self.work.0.raw(),
            self.network_change.0.raw(),
            read,
        ];
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        let result = {
            let _wait = self.session_journal.begin_wait()?;
            unsafe { WaitForMultipleObjects(4, handles.as_ptr(), 0, millis) }
        };
        let outcome = classify_wait_result(result)?;
        if outcome == WaitOutcome::NetworkChanged
            && unsafe { ResetEvent(self.network_change.0.raw()) } == 0
        {
            return Err(Error);
        }
        Ok(outcome)
    }

    pub fn send(&mut self, packet: &[u8]) -> Result<SendOutcome, Error> {
        let len = u32::try_from(packet.len()).map_err(|_| Error)?;
        if len == 0 || len > u32::from(u16::MAX) {
            return Err(Error);
        }
        let session = self.session.as_ref().ok_or(Error)?.handle;
        let output = unsafe { (self.library.exports.allocate_send_packet)(session, len) };
        if output.is_null() {
            return classify_send_allocation_failure(unsafe { GetLastError() });
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), output, packet.len());
            (self.library.exports.send_packet)(session, output);
        }
        Ok(SendOutcome::Sent)
    }

    pub fn cleanup(mut self) -> Result<(), Error> {
        if self.cleanup_inner() {
            Err(Error::cleanup())
        } else {
            Ok(())
        }
    }

    pub(super) fn set_mtu(&mut self, family: u16, slot: usize) -> Result<(), Error> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = family;
        row.InterfaceLuid = self.luid;
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        let previous = row.NlMtu;
        if family == AF_INET {
            row.SitePrefixLength = 0;
        }
        row.NlMtu = u32::from(self.config.mtu);
        let status = unsafe { SetIpInterfaceEntry(&mut row) };
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        self.mtus[slot] = Some(MtuState {
            family,
            previous,
            configured: row.NlMtu,
        });
        let current = read_ip_interface(self.luid, family)?;
        (current.NlMtu == row.NlMtu).then_some(()).ok_or(Error)
    }

    pub(super) fn ipv4_address_row(&self) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
        let prefix = self.config.ipv4.ok_or(Error)?;
        let mut ipv4 = MIB_UNICASTIPADDRESS_ROW::default();
        initialize_managed_address(&mut ipv4);
        ipv4.InterfaceLuid = self.luid;
        ipv4.InterfaceIndex = self.interface_index;
        ipv4.OnLinkPrefixLength = prefix.length();
        ipv4.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(prefix.address().octets()),
                },
            },
            sin_zero: [0; 8],
        };
        Ok(ipv4)
    }

    pub(super) fn ipv6_address_row(&self) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
        let prefix = self.config.ipv6.ok_or(Error)?;
        let mut ipv6 = MIB_UNICASTIPADDRESS_ROW::default();
        initialize_managed_address(&mut ipv6);
        ipv6.InterfaceLuid = self.luid;
        ipv6.InterfaceIndex = self.interface_index;
        ipv6.OnLinkPrefixLength = prefix.length();
        ipv6.Address.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: prefix.address().octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };
        Ok(ipv6)
    }

    pub(super) fn create_address(&mut self, row: MIB_UNICASTIPADDRESS_ROW) -> Result<(), Error> {
        require_address_absent(&row)?;
        if unsafe { CreateUnicastIpAddressEntry(&row) } != ERROR_SUCCESS {
            return Err(Error);
        }
        self.pending_address = Some(row);
        let current = read_owned_address(&row)?;
        if !managed_address_matches(&row, &current) {
            return Err(Error);
        }
        self.addresses
            .push(self.pending_address.take().ok_or(Error)?);
        Ok(())
    }

    pub(super) fn wait_for_dad(
        &self,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error);
            }
            if self.addresses.is_empty() {
                return Err(Error);
            }
            let mut states = Vec::with_capacity(self.addresses.len());
            for address in &self.addresses {
                let row = read_owned_address(address)?;
                if !managed_address_matches(address, &row) {
                    return Err(Error);
                }
                states.push(row.DadState);
            }
            match dad_snapshot(self.session.is_some(), &states, Instant::now() >= deadline)? {
                DadProgress::Ready => return Ok(()),
                DadProgress::Waiting => {}
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn prepare_managed(&mut self) -> Result<(), Error> {
        let Some((
            notifications,
            snapshot_generation,
            policy,
            capture_routes,
            ipv4_dns_address,
            ipv6_dns_address,
            strict_route_intent,
        )) = prepare_managed_intent(self.config.managed_network(), |config| {
            let notifications = subscribe_network_changes(self.network_change.clone())?;
            let snapshot_generation = notifications.generation();
            let policy = snapshot_underlay(
                config,
                notifications.generation_counter(),
                snapshot_generation,
            )?;
            Ok((
                notifications,
                snapshot_generation,
                policy,
                config.capture_routes().to_vec(),
                config.ipv4_dns_address(),
                config.ipv6_dns_address(),
                config.strict_route(),
            ))
        })?
        else {
            return Ok(());
        };
        let route_capacity = capture_routes.len();
        self.managed = Some(ManagedState {
            notifications,
            validated_generation: snapshot_generation,
            policy,
            capture_routes,
            pending_route: None,
            routes: Vec::with_capacity(route_capacity),
            ipv4_dns_address,
            ipv6_dns_address,
            dns_interface: None,
            ipv4_dns: None,
            ipv6_dns: None,
            strict_route_intent,
            strict_route: None,
        });
        Ok(())
    }

    fn finish_managed(
        &mut self,
        deadline: Instant,
        cancelled: &AtomicBool,
        strict_route_install_failed: &mut bool,
    ) -> Result<(), Error> {
        let has_ipv4 = self.config.ipv4.is_some();
        let has_ipv6 = self.config.ipv6.is_some();
        let Some(state) = self.managed.as_mut() else {
            return Ok(());
        };
        state
            .notifications
            .set_owned_luid(self.luid, deadline, cancelled)?;
        let owned = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        state.policy.set_owned_identity(owned)?;
        if !underlay_matches_with(&state.policy, owned, &mut PlatformUnderlay)? {
            return Err(Error);
        }
        let rows = state
            .capture_routes
            .iter()
            .copied()
            .map(|prefix| capture_route_row(self.luid, self.interface_index, prefix))
            .collect::<Vec<_>>();
        install_managed_routes(&rows, &mut PlatformManagedRoutes(state))?;
        if state.ipv4_dns_address.is_some() || state.ipv6_dns_address.is_some() {
            let mut interface = GUID::default();
            if unsafe { ConvertInterfaceLuidToGuid(&self.luid, &mut interface) } != ERROR_SUCCESS {
                return Err(Error);
            }
            state.dns_interface = Some(interface);
        }
        if let Some(address) = state.ipv4_dns_address {
            install_managed_dns(
                address,
                &mut PlatformManagedIpv4Dns(state.dns_interface.ok_or(Error)?),
                &mut state.ipv4_dns,
            )?;
        }
        if let Some(address) = state.ipv6_dns_address {
            install_managed_dns(
                address,
                &mut PlatformManagedIpv6Dns(state.dns_interface.ok_or(Error)?),
                &mut state.ipv6_dns,
            )?;
        }
        if state.strict_route_intent {
            let install = (|| -> Result<(), Error> {
                state.strict_route = Some(StrictRouteSession::open(PlatformStrictRouteOperations)?);
                state.strict_route.as_mut().ok_or(Error)?.install(
                    has_ipv4,
                    has_ipv6,
                    state.ipv4_dns.is_some() || state.ipv6_dns.is_some(),
                    owned.luid,
                )
            })();
            if install.is_err() {
                *strict_route_install_failed = true;
            }
            install?;
        }
        state
            .notifications
            .wait_until_quiescent(deadline, cancelled)?;
        state.notifications.monitor_runtime();
        let dns_interface = state.dns_interface;
        let strict_route_intent = state.strict_route_intent;
        let strict_route = state.strict_route.as_ref();
        if revalidate_managed_network(
            ManagedNetworkValidation {
                policy: &state.policy,
                owned,
                routes: &state.routes,
                validated_generation: &mut state.validated_generation,
            },
            true,
            || state.notifications.generation(),
            &mut PlatformUnderlay,
            &mut PlatformManagedRouteCleanup,
            || {
                let Some(interface) = dns_interface else {
                    return Ok(state.ipv4_dns.is_none() && state.ipv6_dns.is_none());
                };
                if let Some(lease) = &state.ipv4_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv4Dns(interface), lease)?
                {
                    return Ok(false);
                }
                if let Some(lease) = &state.ipv6_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv6Dns(interface), lease)?
                {
                    return Ok(false);
                }
                Ok(true)
            },
            || strict_route_state_matches(strict_route_intent, strict_route),
        )? != ManagedNetworkValidationOutcome::Unchanged
        {
            return Err(Error);
        }
        Ok(())
    }

    fn revalidate_managed_network_state(
        &mut self,
        force: bool,
    ) -> Result<ManagedNetworkValidationOutcome, Error> {
        let Some(state) = self.managed.as_mut() else {
            return Ok(ManagedNetworkValidationOutcome::Unchanged);
        };
        let owned = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        let ManagedState {
            notifications,
            policy,
            routes,
            validated_generation,
            dns_interface,
            ipv4_dns,
            ipv6_dns,
            strict_route_intent,
            strict_route,
            ..
        } = state;
        let dns_interface = *dns_interface;
        revalidate_managed_network(
            ManagedNetworkValidation {
                policy,
                owned,
                routes,
                validated_generation,
            },
            force,
            || notifications.generation(),
            &mut PlatformUnderlay,
            &mut PlatformManagedRouteCleanup,
            || {
                let Some(interface) = dns_interface else {
                    return Ok(ipv4_dns.is_none() && ipv6_dns.is_none());
                };
                if let Some(lease) = ipv4_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv4Dns(interface), lease)?
                {
                    return Ok(false);
                }
                if let Some(lease) = ipv6_dns
                    && !managed_dns_matches(&mut PlatformManagedIpv6Dns(interface), lease)?
                {
                    return Ok(false);
                }
                Ok(true)
            },
            || strict_route_state_matches(*strict_route_intent, strict_route.as_ref()),
        )
    }

    fn cleanup_inner(&mut self) -> bool {
        let identity = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        let failed = cleanup_transaction(&mut PlatformCleanup(self));
        failed
            || (identity.luid != 0
                && identity.index != 0
                && self.network_catalog.clear_managed_tun(identity).is_err())
    }
}

pub(super) fn classify_receive_null(error: u32) -> Result<(), Error> {
    match error {
        ERROR_NO_MORE_ITEMS => Ok(()),
        ERROR_HANDLE_EOF => Err(Error::recoverable_session()),
        _ => Err(Error),
    }
}

pub(super) fn classify_wait_result(result: u32) -> Result<WaitOutcome, Error> {
    match result {
        WAIT_OBJECT_0 => Ok(WaitOutcome::Stop),
        value if value == WAIT_OBJECT_0 + 1 => Ok(WaitOutcome::Work),
        value if value == WAIT_OBJECT_0 + 2 => Ok(WaitOutcome::NetworkChanged),
        value if value == WAIT_OBJECT_0 + 3 => Ok(WaitOutcome::Readable),
        WAIT_TIMEOUT => Ok(WaitOutcome::Timeout),
        WAIT_FAILED => Err(Error),
        _ => Err(Error),
    }
}

pub(super) fn classify_send_allocation_failure(error: u32) -> Result<SendOutcome, Error> {
    if error == ERROR_BUFFER_OVERFLOW {
        Ok(SendOutcome::DroppedRingFull)
    } else {
        Err(Error)
    }
}

pub(super) fn require_windows_10() -> Result<(), Error> {
    let mut version = OsVersionInfo {
        size: size_of::<OsVersionInfo>() as u32,
        major: 0,
        minor: 0,
        build: 0,
        platform: 0,
        service_pack: [0; 128],
    };
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 || version.major < 10 {
        Err(Error)
    } else {
        Ok(())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        let _ = self.cleanup_inner();
    }
}

/// Cloneable safe signal for waking the owner out of its Wintun wait.
pub struct StopSignal(pub(super) Arc<EventHandle>);

impl Clone for StopSignal {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl StopSignal {
    pub fn signal(&self) -> Result<(), Error> {
        if unsafe { SetEvent(self.0.raw()) } == 0 {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

/// Cloneable auto-reset signal for waking the owner when adapter-owned work arrives.
pub struct WorkSignal(pub(super) Arc<EventHandle>);

impl Clone for WorkSignal {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl WorkSignal {
    pub fn signal(&self) -> Result<(), Error> {
        if unsafe { SetEvent(self.0.raw()) } == 0 {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

/// Borrowed receive packet whose pointer cannot outlive its release call or cross threads.
pub struct ReceivedPacket<'a> {
    session: WintunSession,
    packet: *mut u8,
    len: usize,
    release: ReleaseReceivePacket,
    _borrow: PhantomData<&'a mut Adapter>,
    _not_send: PhantomData<Rc<()>>,
}

impl Deref for ReceivedPacket<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.packet, self.len) }
    }
}

impl Drop for ReceivedPacket<'_> {
    fn drop(&mut self) {
        unsafe { (self.release)(self.session, self.packet) };
    }
}
