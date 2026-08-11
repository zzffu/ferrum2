use std::cell::Cell;
use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle};
use std::path::{Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW,
    ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_SUCCESS, FreeLibrary,
    GetLastError, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings, FreeMibTable, GetBestInterfaceEx,
    GetBestRoute2, GetIfTable2, GetInterfaceDnsSettings, GetIpForwardEntry2, GetIpForwardTable2,
    GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange,
    SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, NET_LUID_LH,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IP_UNICAST_IF, IPPROTO_IP,
    IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred,
    IpDadStateTentative, MIB_IPPROTO_NETMGMT, NL_DAD_STATE, NlroManual, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET, setsockopt,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptHash,
    BCryptOpenAlgorithmProvider,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, GetFileInformationByHandleEx,
    OPEN_EXISTING,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::GUID;

use crate::{ABI_EXPORTS, AdapterConfig, CreateError, DLL_BYTES, DLL_SHA256, Error, Ipv4Prefix};

type WintunAdapter = *mut c_void;
type WintunSession = *mut c_void;
type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> WintunAdapter;
type CloseAdapter = unsafe extern "system" fn(WintunAdapter);
type GetAdapterLuid = unsafe extern "system" fn(WintunAdapter, *mut NET_LUID_LH);
type GetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type StartSession = unsafe extern "system" fn(WintunAdapter, u32) -> WintunSession;
type EndSession = unsafe extern "system" fn(WintunSession);
type GetReadWaitEvent = unsafe extern "system" fn(WintunSession) -> HANDLE;
type ReceivePacket = unsafe extern "system" fn(WintunSession, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(WintunSession, *const u8);
type AllocateSendPacket = unsafe extern "system" fn(WintunSession, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(WintunSession, *const u8);

#[repr(C)]
struct OsVersionInfo {
    size: u32,
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
}

#[derive(Clone, Copy)]
struct Exports {
    create_adapter: CreateAdapter,
    close_adapter: CloseAdapter,
    get_adapter_luid: GetAdapterLuid,
    get_running_driver_version: GetRunningDriverVersion,
    start_session: StartSession,
    end_session: EndSession,
    get_read_wait_event: GetReadWaitEvent,
    receive_packet: ReceivePacket,
    release_receive_packet: ReleaseReceivePacket,
    allocate_send_packet: AllocateSendPacket,
    send_packet: SendPacket,
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct Library {
    module: HMODULE,
    exports: Exports,
    _file: File,
    _directories: Vec<OwnedHandle>,
}

impl Library {
    fn load() -> Result<Self, Error> {
        let mut loader = PlatformLoader::default();
        load_transaction(&mut loader)?;
        loader.finish()
    }
}

trait LoaderOperations {
    fn discover_executable(&mut self) -> Result<(), Error>;
    fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error>;
    fn open_sibling_dll(&mut self) -> Result<(), Error>;
    fn verify_dll_identity(&mut self) -> Result<(), Error>;
    fn verify_artifact(&mut self) -> Result<(), Error>;
    fn load_system32_scoped_library(&mut self) -> Result<(), Error>;
    fn resolve_exact_abi(&mut self) -> Result<(), Error>;
}

fn load_transaction(loader: &mut impl LoaderOperations) -> Result<(), Error> {
    loader.discover_executable()?;
    loader.reject_network_and_reparse_directories()?;
    loader.open_sibling_dll()?;
    loader.verify_dll_identity()?;
    loader.verify_artifact()?;
    loader.load_system32_scoped_library()?;
    loader.resolve_exact_abi()
}

#[derive(Default)]
struct PlatformLoader {
    directory: Option<PathBuf>,
    dll: Option<PathBuf>,
    directories: Option<Vec<OwnedHandle>>,
    file: Option<File>,
    module: HMODULE,
    exports: Option<Exports>,
}

impl PlatformLoader {
    fn finish(mut self) -> Result<Library, Error> {
        let exports = self.exports.take().ok_or(Error)?;
        let file = self.file.take().ok_or(Error)?;
        let directories = self.directories.take().ok_or(Error)?;
        let module = std::mem::replace(&mut self.module, null_mut());
        if module.is_null() {
            return Err(Error);
        }
        Ok(Library {
            module,
            exports,
            _file: file,
            _directories: directories,
        })
    }
}

impl Drop for PlatformLoader {
    fn drop(&mut self) {
        if !self.module.is_null() {
            unsafe { FreeLibrary(self.module) };
        }
    }
}

impl LoaderOperations for PlatformLoader {
    fn discover_executable(&mut self) -> Result<(), Error> {
        let executable = current_executable()?;
        let directory = executable.parent().ok_or(Error)?.to_path_buf();
        self.dll = Some(directory.join("wintun.dll"));
        self.directory = Some(directory);
        Ok(())
    }

    fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error> {
        let directory = self.directory.as_deref().ok_or(Error)?;
        reject_network_path(directory)?;
        self.directories = Some(hold_directories(directory)?);
        Ok(())
    }

    fn open_sibling_dll(&mut self) -> Result<(), Error> {
        self.file = Some(open_file(self.dll.as_deref().ok_or(Error)?)?);
        Ok(())
    }

    fn verify_dll_identity(&mut self) -> Result<(), Error> {
        let file = self.file.as_ref().ok_or(Error)?;
        verify_regular_non_reparse(file.as_raw_handle() as HANDLE)?;
        if file.metadata().map_err(|_| Error)?.is_file() {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn verify_artifact(&mut self) -> Result<(), Error> {
        let file = self.file.as_ref().ok_or(Error)?;
        let bytes = file.metadata().map_err(|_| Error)?.len();
        validate_artifact(bytes, cng_sha256(file)?)
    }

    fn load_system32_scoped_library(&mut self) -> Result<(), Error> {
        let dll_wide = wide(self.dll.as_deref().ok_or(Error)?);
        self.module =
            unsafe { LoadLibraryExW(dll_wide.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if self.module.is_null() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn resolve_exact_abi(&mut self) -> Result<(), Error> {
        let module = self.module;
        self.exports = Some(unsafe {
            require_exports(|name| GetProcAddress(module, name.as_ptr()).is_some())
                .and_then(|()| resolve_exports(module))?
        });
        Ok(())
    }
}

fn validate_artifact(bytes: u64, sha256: [u8; 32]) -> Result<(), Error> {
    if bytes == DLL_BYTES && sha256 == DLL_SHA256 {
        Ok(())
    } else {
        Err(Error)
    }
}

fn require_exports(mut present: impl FnMut(&[u8]) -> bool) -> Result<(), Error> {
    for name in ABI_EXPORTS {
        if !present(name) {
            return Err(Error);
        }
    }
    Ok(())
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

#[derive(Clone, Copy)]
struct MtuState {
    family: u16,
    previous: u32,
    configured: u32,
}

struct SessionState {
    handle: WintunSession,
    read_event: HANDLE,
}

#[derive(Default)]
struct SessionJournal {
    waiting: Cell<bool>,
}

impl SessionJournal {
    fn begin_wait(&self) -> Result<WaitGuard<'_>, Error> {
        if self.waiting.replace(true) {
            return Err(Error);
        }
        Ok(WaitGuard(&self.waiting))
    }

    fn cleanup_is_safe(&self) -> bool {
        !self.waiting.get()
    }
}

struct WaitGuard<'a>(&'a Cell<bool>);

impl Drop for WaitGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RouteFingerprint {
    interface_luid: u64,
    interface_index: u32,
    destination: u32,
    prefix_length: u8,
    next_hop: u32,
    metric: u32,
    source: Option<u32>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct InterfaceIdentity {
    luid: u64,
    index: u32,
}

/// Immutable, redacted IPv4 socket-binding policy frozen before capture.
#[derive(Clone)]
pub struct UnderlayPolicy {
    fixed: Arc<[(std::net::SocketAddrV4, RouteFingerprint)]>,
    default: Option<RouteFingerprint>,
    valid: Arc<AtomicBool>,
}

impl UnderlayPolicy {
    pub fn bind_fixed<T: AsRawSocket>(
        &self,
        socket: &T,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), Error> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error);
        }
        let route = self
            .fixed
            .iter()
            .find_map(|(candidate, route)| (*candidate == endpoint).then_some(*route))
            .ok_or(Error)?;
        bind_ipv4_socket(socket, route.interface_index)?;
        self.valid
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(Error)
    }

    pub fn bind_default<T: AsRawSocket>(&self, socket: &T) -> Result<(), Error> {
        if !self.valid.load(Ordering::Acquire) {
            return Err(Error);
        }
        bind_ipv4_socket(socket, self.default.ok_or(Error)?.interface_index)?;
        self.valid
            .load(Ordering::Acquire)
            .then_some(())
            .ok_or(Error)
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }
}

fn bind_ipv4_socket<T: AsRawSocket>(socket: &T, interface_index: u32) -> Result<(), Error> {
    let network_order = interface_index_option_value(interface_index);
    let status = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            IPPROTO_IP,
            IP_UNICAST_IF,
            (&raw const network_order).cast(),
            i32::try_from(std::mem::size_of_val(&network_order)).map_err(|_| Error)?,
        )
    };
    if status == 0 { Ok(()) } else { Err(Error) }
}

const fn interface_index_option_value(interface_index: u32) -> u32 {
    interface_index.to_be()
}

struct NotificationContext {
    generation: AtomicU64,
    owned_luid: AtomicU64,
    provisional_luid: AtomicU64,
    callbacks_in_flight: AtomicU64,
    monitor_runtime: AtomicBool,
    wake: Option<StopSignal>,
    #[cfg(test)]
    drain_wait_observed: AtomicBool,
}

impl NotificationContext {
    fn new(wake: Option<StopSignal>) -> Self {
        Self {
            generation: AtomicU64::new(0),
            owned_luid: AtomicU64::new(0),
            provisional_luid: AtomicU64::new(0),
            callbacks_in_flight: AtomicU64::new(0),
            monitor_runtime: AtomicBool::new(false),
            wake,
            #[cfg(test)]
            drain_wait_observed: AtomicBool::new(false),
        }
    }

    fn signal_owner(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(wake) = &self.wake {
            let _ = wake.signal();
        }
    }

    fn publish_owned_luid(
        &self,
        luid: u64,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        if luid == 0 {
            self.generation.fetch_add(1, Ordering::AcqRel);
            return Err(Error);
        }
        match self
            .owned_luid
            .compare_exchange(0, luid, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(current) if current == luid => {}
            Err(_) => {
                self.generation.fetch_add(1, Ordering::AcqRel);
                return Err(Error);
            }
        }
        while self.callbacks_in_flight.load(Ordering::SeqCst) != 0 {
            #[cfg(test)]
            self.drain_wait_observed.store(true, Ordering::SeqCst);
            if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(Error);
            }
            std::thread::yield_now();
        }
        let provisional = self.provisional_luid.swap(0, Ordering::SeqCst);
        if provisional != 0 && provisional != luid {
            self.generation.fetch_add(1, Ordering::AcqRel);
            return Err(Error);
        }
        Ok(())
    }
}

struct NotificationCallbackGuard<'a>(&'a AtomicU64);

impl<'a> NotificationCallbackGuard<'a> {
    fn enter(context: &'a NotificationContext) -> Self {
        context.callbacks_in_flight.fetch_add(1, Ordering::SeqCst);
        Self(&context.callbacks_in_flight)
    }
}

impl Drop for NotificationCallbackGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct NotificationOwners {
    handles: Vec<HANDLE>,
    context: Option<Box<NotificationContext>>,
}

impl NotificationOwners {
    fn generation(&self) -> u64 {
        self.context
            .as_ref()
            .expect("live notifications retain their callback context")
            .generation
            .load(Ordering::Acquire)
    }

    fn set_owned_luid(
        &self,
        luid: NET_LUID_LH,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<(), Error> {
        let context = self
            .context
            .as_ref()
            .expect("live notifications retain their callback context");
        context.publish_owned_luid(unsafe { luid.Value }, deadline, cancelled)
    }

    fn monitor_runtime(&self) {
        self.context
            .as_ref()
            .expect("live notifications retain their callback context")
            .monitor_runtime
            .store(true, Ordering::Release);
    }

    fn cancel_all(&mut self) -> bool {
        cancel_notification_handles(&mut self.handles, &mut self.context, |handle| unsafe {
            CancelMibChangeNotify2(*handle) == ERROR_SUCCESS
        })
    }
}

fn cancel_notification_handles<T, C>(
    handles: &mut Vec<T>,
    context: &mut Option<C>,
    mut cancel: impl FnMut(&T) -> bool,
) -> bool {
    let mut failed = Vec::new();
    while let Some(handle) = handles.pop() {
        if !cancel(&handle) {
            failed.push(handle);
        }
    }
    failed.reverse();
    handles.append(&mut failed);
    if handles.is_empty() {
        context.take();
    }
    !handles.is_empty()
}

fn leak_notification_owners<T, C>(handles: &mut Vec<T>, context: &mut Option<C>) {
    std::mem::forget(std::mem::take(handles));
    std::mem::forget(context.take());
}

fn subscribe_notification_sequence<H, C>(
    context: C,
    mut subscribe: impl FnMut(usize) -> Result<H, Error>,
    mut cancel: impl FnMut(&H) -> bool,
) -> Result<(Vec<H>, C), Error> {
    let mut handles = Vec::with_capacity(3);
    let mut context = Some(context);
    for ordinal in 0..3 {
        match subscribe(ordinal) {
            Ok(handle) => handles.push(handle),
            Err(error) => {
                if cancel_notification_handles(&mut handles, &mut context, &mut cancel) {
                    leak_notification_owners(&mut handles, &mut context);
                }
                return Err(error);
            }
        }
    }
    Ok((handles, context.take().ok_or(Error)?))
}

impl Drop for NotificationOwners {
    fn drop(&mut self) {
        if self.cancel_all() {
            leak_notification_owners(&mut self.handles, &mut self.context);
        }
    }
}

unsafe extern "system" fn route_changed(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

unsafe extern "system" fn interface_changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

unsafe extern "system" fn address_changed(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    classify_notification_luid(
        context,
        if row.is_null() {
            0
        } else {
            unsafe { (*row).InterfaceLuid.Value }
        },
        || {},
    );
}

fn classify_notification_luid(
    context: &NotificationContext,
    luid: u64,
    after_unpublished_load: impl FnOnce(),
) {
    let _in_flight = NotificationCallbackGuard::enter(context);
    if context.monitor_runtime.load(Ordering::Acquire) {
        context.signal_owner();
        return;
    }
    if luid == 0 {
        context.signal_owner();
        return;
    }
    let owned = context.owned_luid.load(Ordering::SeqCst);
    if owned != 0 {
        if owned != luid {
            context.signal_owner();
        }
        return;
    }
    after_unpublished_load();
    let provisional_mismatch =
        match context
            .provisional_luid
            .compare_exchange(0, luid, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => false,
            Err(current) => current != luid,
        };
    if provisional_mismatch {
        context.signal_owner();
    }
}

struct ManagedState {
    notifications: NotificationOwners,
    snapshot_generation: u64,
    validated_generation: u64,
    policy: UnderlayPolicy,
    capture_routes: Vec<Ipv4Prefix>,
    pending_route: Option<MIB_IPFORWARD_ROW2>,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    dns_interface: Option<GUID>,
    dns: Option<ManagedDnsLease<Ipv4DnsSettings>>,
}

/// Safe RAII owner of the exact Wintun adapter, address, MTU, session and DLL transaction.
pub struct Adapter {
    config: AdapterConfig,
    library: Library,
    adapter: Option<WintunAdapter>,
    luid: NET_LUID_LH,
    interface_index: u32,
    mtus: [Option<MtuState>; 2],
    addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
    session: Option<SessionState>,
    session_journal: SessionJournal,
    stop: StopSignal,
    network_change: StopSignal,
    managed: Option<ManagedState>,
    _not_send: PhantomData<Rc<()>>,
}

impl Adapter {
    pub fn create(
        config: AdapterConfig,
        deadline: Instant,
        cancelled: &AtomicBool,
    ) -> Result<Self, CreateError> {
        require_windows_10().map_err(|_| CreateError::operation())?;
        if cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err(CreateError::operation());
        }
        let library = Library::load().map_err(|_| CreateError::operation())?;
        let stop = StopSignal(Arc::new(OwnedHandle(
            create_event().map_err(|_| CreateError::operation())?,
        )));
        let network_change = StopSignal(Arc::new(OwnedHandle(
            create_event().map_err(|_| CreateError::operation())?,
        )));
        let mut owner = Self {
            config,
            library,
            adapter: None,
            luid: NET_LUID_LH::default(),
            interface_index: 0,
            mtus: [None, None],
            addresses: Vec::with_capacity(2),
            session: None,
            session_journal: SessionJournal::default(),
            stop,
            network_change,
            managed: None,
            _not_send: PhantomData,
        };
        let setup = owner
            .prepare_managed()
            .and_then(|()| {
                setup_transaction(&mut PlatformSetup {
                    owner: &mut owner,
                    deadline,
                    cancelled,
                })
            })
            .and_then(|()| owner.finish_managed(deadline, cancelled));
        match finish_setup_transaction(setup, || owner.cleanup_inner()) {
            Ok(()) => Ok(owner),
            Err(error) => Err(error),
        }
    }

    pub fn stop_signal(&self) -> StopSignal {
        self.stop.clone()
    }

    pub fn underlay_policy(&self) -> Option<UnderlayPolicy> {
        self.managed.as_ref().map(|state| state.policy.clone())
    }

    pub fn receive(&mut self) -> Result<Option<ReceivedPacket<'_>>, Error> {
        let session = self.session.as_ref().ok_or(Error)?.handle;
        let mut len = 0_u32;
        let packet = unsafe { (self.library.exports.receive_packet)(session, &mut len) };
        if packet.is_null() {
            return match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
                ERROR_NO_MORE_ITEMS => Ok(None),
                ERROR_HANDLE_EOF => Err(Error),
                _ => Err(Error),
            };
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

    /// Returns `true` for readable session data and `false` for stop/timeout.
    pub fn wait(&mut self, timeout: Duration) -> Result<bool, Error> {
        let read = self.session.as_ref().ok_or(Error)?.read_event;
        let handles = [self.stop.0.0, self.network_change.0.0, read];
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        let result = {
            let _wait = self.session_journal.begin_wait()?;
            unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, millis) }
        };
        match result {
            WAIT_OBJECT_0 => Ok(false),
            value if value == WAIT_OBJECT_0 + 1 => {
                let valid = unsafe { ResetEvent(self.network_change.0.0) } != 0
                    && self.revalidate_managed_network().unwrap_or(false);
                if !valid {
                    if let Some(state) = &self.managed {
                        state.policy.invalidate();
                    }
                    Err(Error)
                } else {
                    Ok(false)
                }
            }
            value if value == WAIT_OBJECT_0 + 2 => Ok(true),
            WAIT_FAILED => Err(Error),
            _ => Ok(false),
        }
    }

    pub fn send(&mut self, packet: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(packet.len()).map_err(|_| Error)?;
        if len == 0 || len > u32::from(u16::MAX) {
            return Err(Error);
        }
        let session = self.session.as_ref().ok_or(Error)?.handle;
        let output = unsafe { (self.library.exports.allocate_send_packet)(session, len) };
        if output.is_null() {
            return match unsafe { windows_sys::Win32::Foundation::GetLastError() } {
                ERROR_BUFFER_OVERFLOW => Ok(()),
                _ => Err(Error),
            };
        }
        unsafe {
            std::ptr::copy_nonoverlapping(packet.as_ptr(), output, packet.len());
            (self.library.exports.send_packet)(session, output);
        }
        Ok(())
    }

    pub fn cleanup(mut self) -> Result<(), Error> {
        if self.cleanup_inner() {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn set_mtu(&mut self, family: u16, slot: usize) -> Result<(), Error> {
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
        Ok(())
    }

    fn ipv4_address_row(&self) -> MIB_UNICASTIPADDRESS_ROW {
        let mut ipv4 = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut ipv4) };
        ipv4.InterfaceLuid = self.luid;
        ipv4.OnLinkPrefixLength = self.config.ipv4_prefix;
        ipv4.Address.Ipv4 = SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(self.config.ipv4.octets()),
                },
            },
            sin_zero: [0; 8],
        };
        ipv4
    }

    fn ipv6_address_row(&self) -> MIB_UNICASTIPADDRESS_ROW {
        let mut ipv6 = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut ipv6) };
        ipv6.InterfaceLuid = self.luid;
        ipv6.OnLinkPrefixLength = self.config.ipv6_prefix;
        ipv6.Address.Ipv6 = SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: self.config.ipv6.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        };
        ipv6
    }

    fn create_address(&mut self, row: MIB_UNICASTIPADDRESS_ROW) -> Result<(), Error> {
        if unsafe { CreateUnicastIpAddressEntry(&row) } != ERROR_SUCCESS {
            return Err(Error);
        }
        self.addresses.push(row);
        Ok(())
    }

    fn wait_for_dad(&self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), Error> {
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error);
            }
            if self.addresses.len() != 2 {
                return Err(Error);
            }
            let mut states = [IpDadStateInvalid; 2];
            for (state, address) in states.iter_mut().zip(&self.addresses) {
                let mut row = *address;
                if unsafe { GetUnicastIpAddressEntry(&mut row) } != ERROR_SUCCESS {
                    return Err(Error);
                }
                *state = row.DadState;
            }
            match dad_snapshot(self.session.is_some(), states, Instant::now() >= deadline)? {
                DadProgress::Ready => return Ok(()),
                DadProgress::Waiting => {}
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn prepare_managed(&mut self) -> Result<(), Error> {
        let Some((notifications, snapshot_generation, policy, capture_routes, ipv4_dns_address)) =
            prepare_managed_intent(self.config.managed_ipv4(), |config| {
                let notifications = subscribe_network_changes(self.network_change.clone())?;
                let snapshot_generation = notifications.generation();
                let policy = snapshot_underlay(config)?;
                Ok((
                    notifications,
                    snapshot_generation,
                    policy,
                    config.capture_routes().to_vec(),
                    config.ipv4_dns_address(),
                ))
            })?
        else {
            return Ok(());
        };
        let route_capacity = capture_routes.len();
        self.managed = Some(ManagedState {
            notifications,
            snapshot_generation,
            validated_generation: snapshot_generation,
            policy,
            capture_routes,
            pending_route: None,
            routes: Vec::with_capacity(route_capacity),
            ipv4_dns_address,
            dns_interface: None,
            dns: None,
        });
        Ok(())
    }

    fn finish_managed(&mut self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), Error> {
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
        if !underlay_snapshot_matches(
            &state.policy,
            owned,
            state.snapshot_generation,
            || state.notifications.generation(),
            &mut PlatformUnderlay,
        )? {
            return Err(Error);
        }
        if let Some(address) = state.ipv4_dns_address {
            let mut interface = GUID::default();
            if unsafe { ConvertInterfaceLuidToGuid(&self.luid, &mut interface) } != ERROR_SUCCESS {
                return Err(Error);
            }
            state.dns_interface = Some(interface);
            install_managed_dns(address, &mut PlatformManagedDns(interface), &mut state.dns)?;
        }
        let rows = state
            .capture_routes
            .iter()
            .copied()
            .map(|prefix| capture_route_row(self.luid, self.interface_index, prefix))
            .collect::<Vec<_>>();
        install_managed_routes(&rows, &mut PlatformManagedRoutes(state))?;
        if !underlay_snapshot_matches(
            &state.policy,
            owned,
            state.snapshot_generation,
            || state.notifications.generation(),
            &mut PlatformUnderlay,
        )? {
            return Err(Error);
        }
        state.notifications.monitor_runtime();
        if !managed_routes_match(&state.routes, &mut PlatformManagedRouteCleanup) {
            return Err(Error);
        }
        state.validated_generation = state.notifications.generation();
        Ok(())
    }

    fn revalidate_managed_network(&mut self) -> Result<bool, Error> {
        let Some(state) = self.managed.as_mut() else {
            return Ok(true);
        };
        let owned = InterfaceIdentity {
            luid: unsafe { self.luid.Value },
            index: self.interface_index,
        };
        revalidate_managed_network(
            &state.policy,
            owned,
            &state.routes,
            &mut state.validated_generation,
            || state.notifications.generation(),
            &mut PlatformUnderlay,
            &mut PlatformManagedRouteCleanup,
        )
    }

    fn cleanup_inner(&mut self) -> bool {
        cleanup_transaction(&mut PlatformCleanup(self))
    }
}

fn prepare_managed_intent<T>(
    config: Option<&crate::ManagedIpv4Config>,
    prepare: impl FnOnce(&crate::ManagedIpv4Config) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    config.map(prepare).transpose()
}

#[derive(Clone, Eq, PartialEq)]
struct Ipv4DnsSettings(Option<Box<[u16]>>);

struct ManagedDnsLease<S> {
    previous: S,
    applied: S,
}

trait ManagedDnsOperations {
    type Settings: Clone + Eq;

    fn snapshot(&mut self) -> Result<Self::Settings, Error>;
    fn apply(&mut self, address: std::net::Ipv4Addr) -> Result<Self::Settings, Error>;
    fn readback(&mut self) -> Result<Self::Settings, Error>;
    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error>;
}

fn install_managed_dns<O: ManagedDnsOperations>(
    address: std::net::Ipv4Addr,
    operations: &mut O,
    lease: &mut Option<ManagedDnsLease<O::Settings>>,
) -> Result<(), Error> {
    let previous = operations.snapshot()?;
    let applied = operations.apply(address)?;
    *lease = Some(ManagedDnsLease { previous, applied });
    if operations.readback()? == lease.as_ref().ok_or(Error)?.applied {
        Ok(())
    } else {
        Err(Error)
    }
}

fn restore_managed_dns<O: ManagedDnsOperations>(
    operations: &mut O,
    lease: &ManagedDnsLease<O::Settings>,
) -> bool {
    let Ok(current) = operations.readback() else {
        return true;
    };
    if current != lease.applied {
        return true;
    }
    if operations.restore(&lease.previous).is_err() {
        return true;
    }
    !matches!(operations.readback(), Ok(current) if current == lease.previous)
}

struct PlatformManagedDns(GUID);

impl ManagedDnsOperations for PlatformManagedDns {
    type Settings = Ipv4DnsSettings;

    fn snapshot(&mut self) -> Result<Self::Settings, Error> {
        read_ipv4_dns_settings(self.0)
    }

    fn apply(&mut self, address: std::net::Ipv4Addr) -> Result<Self::Settings, Error> {
        let settings = Ipv4DnsSettings(Some(
            address.to_string().encode_utf16().collect::<Box<[_]>>(),
        ));
        set_ipv4_dns_settings(self.0, &settings)?;
        Ok(settings)
    }

    fn readback(&mut self) -> Result<Self::Settings, Error> {
        read_ipv4_dns_settings(self.0)
    }

    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
        set_ipv4_dns_settings(self.0, settings)
    }
}

fn read_ipv4_dns_settings(interface: GUID) -> Result<Ipv4DnsSettings, Error> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        ..DNS_INTERFACE_SETTINGS::default()
    };
    if unsafe { GetInterfaceDnsSettings(interface, &mut settings) } != ERROR_SUCCESS {
        return Err(Error);
    }
    let result = copy_bounded_wide(settings.NameServer).map(Ipv4DnsSettings);
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    result
}

fn set_ipv4_dns_settings(interface: GUID, settings: &Ipv4DnsSettings) -> Result<(), Error> {
    let mut name_server = settings.0.as_ref().map(|value| {
        let mut terminated = Vec::with_capacity(value.len() + 1);
        terminated.extend_from_slice(value);
        terminated.push(0);
        terminated
    });
    let raw = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: name_server
            .as_mut()
            .map_or(null_mut(), |value| value.as_mut_ptr()),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}

fn copy_bounded_wide(value: *mut u16) -> Result<Option<Box<[u16]>>, Error> {
    if value.is_null() {
        return Ok(None);
    }
    for length in 0..=4096 {
        if unsafe { *value.add(length) } == 0 {
            if length == 0 {
                return Ok(None);
            }
            let value = unsafe { std::slice::from_raw_parts(value, length) };
            return Ok(Some(value.to_vec().into_boxed_slice()));
        }
    }
    Err(Error)
}

trait ManagedRouteOperations {
    type Row: Copy;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error>;
    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error>;
    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error>;
    fn commit_pending(&mut self) -> Result<(), Error>;
}

fn install_managed_routes<O: ManagedRouteOperations>(
    rows: &[O::Row],
    operations: &mut O,
) -> Result<(), Error> {
    for row in rows {
        operations.require_absent(row)?;
    }
    for row in rows {
        operations.create_pending(*row)?;
        if !operations.readback_exact(row)? {
            return Err(Error);
        }
        operations.commit_pending()?;
    }
    Ok(())
}

struct PlatformManagedRoutes<'a>(&'a mut ManagedState);

impl ManagedRouteOperations for PlatformManagedRoutes<'_> {
    type Row = MIB_IPFORWARD_ROW2;

    fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error> {
        require_route_absent(row)
    }

    fn create_pending(&mut self, row: Self::Row) -> Result<(), Error> {
        if unsafe { CreateIpForwardEntry2(&row) } != ERROR_SUCCESS {
            return Err(Error);
        }
        self.0.pending_route = Some(row);
        Ok(())
    }

    fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error> {
        Ok(route_matches(row, &read_owned_route(row)?))
    }

    fn commit_pending(&mut self) -> Result<(), Error> {
        self.0
            .routes
            .push(self.0.pending_route.take().ok_or(Error)?);
        Ok(())
    }
}

fn subscribe_network_changes(wake: StopSignal) -> Result<NotificationOwners, Error> {
    let context = Box::new(NotificationContext::new(Some(wake)));
    let context_pointer = (&raw const *context).cast::<c_void>();
    let (handles, context) = subscribe_notification_sequence(
        context,
        |ordinal| {
            let mut handle = null_mut();
            let status = match ordinal {
                0 => unsafe {
                    NotifyRouteChange2(
                        AF_INET,
                        Some(route_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                1 => unsafe {
                    NotifyIpInterfaceChange(
                        AF_INET,
                        Some(interface_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                2 => unsafe {
                    NotifyUnicastIpAddressChange(
                        AF_INET,
                        Some(address_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                _ => return Err(Error),
            };
            if status != ERROR_SUCCESS || handle.is_null() {
                Err(Error)
            } else {
                Ok(handle)
            }
        },
        |handle| unsafe { CancelMibChangeNotify2(*handle) == ERROR_SUCCESS },
    )?;
    Ok(NotificationOwners {
        handles,
        context: Some(context),
    })
}

fn snapshot_underlay(config: &crate::ManagedIpv4Config) -> Result<UnderlayPolicy, Error> {
    snapshot_underlay_with(config, &mut PlatformUnderlay)
}

trait UnderlayOperations {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error>;
    fn best_interface(&mut self, destination: std::net::Ipv4Addr) -> Result<u32, Error>;
    fn constrained_route(
        &mut self,
        destination: std::net::Ipv4Addr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error>;
    fn unique_default_route(
        &mut self,
        interfaces: &[InterfaceIdentity],
    ) -> Result<RouteFingerprint, Error>;
}

fn snapshot_underlay_with(
    config: &crate::ManagedIpv4Config,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    let interfaces = operations.eligible_interfaces(None)?;
    let mut fixed = Vec::with_capacity(config.physical_endpoints().len());
    for endpoint in config.physical_endpoints() {
        let index = operations.best_interface(*endpoint.ip())?;
        let identity = interfaces
            .iter()
            .find(|candidate| candidate.index == index)
            .ok_or(Error)?;
        let route = operations.constrained_route(*endpoint.ip(), index, true)?;
        if route.interface_luid != identity.luid || route.interface_index != identity.index {
            return Err(Error);
        }
        fixed.push((*endpoint, route));
    }
    let default = if config.needs_default_binder() {
        Some(operations.unique_default_route(&interfaces)?)
    } else {
        None
    };
    Ok(UnderlayPolicy {
        fixed: fixed.into(),
        default,
        valid: Arc::new(AtomicBool::new(true)),
    })
}

fn underlay_snapshot_matches(
    policy: &UnderlayPolicy,
    owned: InterfaceIdentity,
    expected_generation: u64,
    mut generation: impl FnMut() -> u64,
    operations: &mut impl UnderlayOperations,
) -> Result<bool, Error> {
    let before = generation();
    if before != expected_generation || !underlay_matches_with(policy, owned, operations)? {
        return Ok(false);
    }
    Ok(generation() == before)
}

fn underlay_matches_with(
    policy: &UnderlayPolicy,
    owned: InterfaceIdentity,
    operations: &mut impl UnderlayOperations,
) -> Result<bool, Error> {
    let interfaces = operations.eligible_interfaces(Some(owned))?;
    for (endpoint, expected) in policy.fixed.iter() {
        if !interfaces.iter().any(|candidate| {
            candidate.index == expected.interface_index && candidate.luid == expected.interface_luid
        }) || operations.constrained_route(*endpoint.ip(), expected.interface_index, true)?
            != *expected
        {
            return Ok(false);
        }
    }
    if let Some(expected) = policy.default
        && operations.unique_default_route(&interfaces)? != expected
    {
        return Ok(false);
    }
    Ok(true)
}

struct PlatformUnderlay;

impl UnderlayOperations for PlatformUnderlay {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error> {
        eligible_interfaces(excluded)
    }

    fn best_interface(&mut self, destination: std::net::Ipv4Addr) -> Result<u32, Error> {
        let destination = ipv4_sockaddr(destination);
        let mut index = 0;
        if unsafe { GetBestInterfaceEx((&raw const destination).cast::<SOCKADDR>(), &mut index) }
            != ERROR_SUCCESS
            || index == 0
        {
            Err(Error)
        } else {
            Ok(index)
        }
    }

    fn constrained_route(
        &mut self,
        destination: std::net::Ipv4Addr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error> {
        constrained_route(destination, interface_index, require_source)
    }

    fn unique_default_route(
        &mut self,
        interfaces: &[InterfaceIdentity],
    ) -> Result<RouteFingerprint, Error> {
        unique_default_route(interfaces)
    }
}

fn eligible_interfaces(
    excluded: Option<InterfaceIdentity>,
) -> Result<Vec<InterfaceIdentity>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows
        .iter()
        .filter_map(|row| eligible_interface_identity(row, excluded))
        .collect();
    drop(owner);
    Ok(result)
}

fn eligible_interface_identity(
    row: &MIB_IF_ROW2,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    let identity = InterfaceIdentity {
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
    };
    (row.InterfaceIndex != 0
        && row.Type != windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
        && row.OperStatus == IfOperStatusUp
        && row.AdminStatus == NET_IF_ADMIN_STATUS_UP
        && row.MediaConnectState == MediaConnectStateConnected
        && row.InterfaceAndOperStatusFlags._bitfield & 1 == 1
        && excluded != Some(identity))
    .then_some(identity)
}

struct MibTable(*mut c_void);

impl Drop for MibTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0) };
    }
}

fn unique_default_route(interfaces: &[InterfaceIdentity]) -> Result<RouteFingerprint, Error> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = select_unique_default_route(rows, interfaces);
    drop(owner);
    result
}

fn select_unique_default_route(
    rows: &[MIB_IPFORWARD_ROW2],
    interfaces: &[InterfaceIdentity],
) -> Result<RouteFingerprint, Error> {
    let mut defaults = rows.iter().filter(|row| {
        interfaces.iter().any(|candidate| {
            candidate.index == row.InterfaceIndex
                && candidate.luid == unsafe { row.InterfaceLuid.Value }
        }) && row.DestinationPrefix.PrefixLength == 0
            && unsafe { row.DestinationPrefix.Prefix.si_family } == AF_INET
            && unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr } == 0
    });
    let row = defaults.next().copied().ok_or(Error)?;
    if defaults.next().is_some() {
        return Err(Error);
    }
    route_fingerprint(&row, None)
}

fn constrained_route(
    destination: std::net::Ipv4Addr,
    interface_index: u32,
    require_source: bool,
) -> Result<RouteFingerprint, Error> {
    let destination = ipv4_sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    if unsafe {
        GetBestRoute2(
            null(),
            interface_index,
            null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    } != ERROR_SUCCESS
        || route.InterfaceIndex != interface_index
        || unsafe { source.si_family } != AF_INET
    {
        return Err(Error);
    }
    let source = unsafe { source.Ipv4.sin_addr.S_un.S_addr };
    if require_source && source == 0 {
        return Err(Error);
    }
    route_fingerprint(&route, require_source.then_some(source))
}

fn route_fingerprint(
    row: &MIB_IPFORWARD_ROW2,
    source: Option<u32>,
) -> Result<RouteFingerprint, Error> {
    if unsafe { row.DestinationPrefix.Prefix.si_family } != AF_INET
        || unsafe { row.NextHop.si_family } != AF_INET
    {
        return Err(Error);
    }
    Ok(RouteFingerprint {
        interface_luid: unsafe { row.InterfaceLuid.Value },
        interface_index: row.InterfaceIndex,
        destination: unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr },
        prefix_length: row.DestinationPrefix.PrefixLength,
        next_hop: unsafe { row.NextHop.Ipv4.sin_addr.S_un.S_addr },
        metric: row.Metric,
        source,
    })
}

fn ipv4_sockaddr(address: std::net::Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_port: 0,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(address.octets()),
                },
            },
            sin_zero: [0; 8],
        },
    }
}

fn capture_route_row(
    luid: NET_LUID_LH,
    interface_index: u32,
    prefix: Ipv4Prefix,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.InterfaceIndex = interface_index;
    row.DestinationPrefix.Prefix = ipv4_sockaddr(prefix.address());
    row.DestinationPrefix.PrefixLength = prefix.length();
    row.NextHop = ipv4_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
    row.SitePrefixLength = 0;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = 1;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row.Loopback = false;
    row.AutoconfigureAddress = false;
    row.Publish = false;
    row.Immortal = false;
    row.Age = 0;
    row.Origin = NlroManual;
    row
}

fn route_key(intended: &MIB_IPFORWARD_ROW2) -> MIB_IPFORWARD_ROW2 {
    let mut key = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut key) };
    key.InterfaceLuid = intended.InterfaceLuid;
    key.InterfaceIndex = intended.InterfaceIndex;
    key.DestinationPrefix = intended.DestinationPrefix;
    key.NextHop = intended.NextHop;
    key
}

fn require_route_absent(row: &MIB_IPFORWARD_ROW2) -> Result<(), Error> {
    let mut current = route_key(row);
    match unsafe { GetIpForwardEntry2(&mut current) } {
        ERROR_NOT_FOUND => Ok(()),
        _ => Err(Error),
    }
}

fn read_owned_route(row: &MIB_IPFORWARD_ROW2) -> Result<MIB_IPFORWARD_ROW2, Error> {
    let mut current = route_key(row);
    if unsafe { GetIpForwardEntry2(&mut current) } == ERROR_SUCCESS {
        Ok(current)
    } else {
        Err(Error)
    }
}

fn route_matches(expected: &MIB_IPFORWARD_ROW2, actual: &MIB_IPFORWARD_ROW2) -> bool {
    unsafe {
        actual.InterfaceLuid.Value == expected.InterfaceLuid.Value
            && actual.InterfaceIndex == expected.InterfaceIndex
            && actual.DestinationPrefix.Prefix.si_family == AF_INET
            && actual.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr
                == expected.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr
            && actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength
            && actual.NextHop.si_family == AF_INET
            && actual.NextHop.Ipv4.sin_addr.S_un.S_addr == 0
            && actual.SitePrefixLength == 0
            && actual.ValidLifetime == u32::MAX
            && actual.PreferredLifetime == u32::MAX
            && actual.Metric == 1
            && actual.Protocol == MIB_IPPROTO_NETMGMT
            && !actual.Loopback
            && !actual.AutoconfigureAddress
            && !actual.Publish
            && !actual.Immortal
            && actual.Origin == NlroManual
    }
}

enum ManagedRouteRead<R> {
    Absent,
    Present(R),
    Failed,
}

trait ManagedRouteCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedRouteRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

fn delete_managed_route<O: ManagedRouteCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedRouteRead::Absent => false,
        ManagedRouteRead::Present(current) if operations.matches(intended, &current) => {
            let delete_failed = operations.delete(&current).is_err();
            let final_read_failed = !matches!(operations.read(intended), ManagedRouteRead::Absent);
            delete_failed | final_read_failed
        }
        ManagedRouteRead::Present(_) | ManagedRouteRead::Failed => true,
    }
}

fn managed_routes_match<O: ManagedRouteCleanupOperations>(
    intended: &[O::Row],
    operations: &mut O,
) -> bool {
    intended.iter().all(|row| {
        matches!(
            operations.read(row),
            ManagedRouteRead::Present(current) if operations.matches(row, &current)
        )
    })
}

fn revalidate_managed_network<U: UnderlayOperations, O: ManagedRouteCleanupOperations>(
    policy: &UnderlayPolicy,
    owned: InterfaceIdentity,
    routes: &[O::Row],
    validated_generation: &mut u64,
    mut generation: impl FnMut() -> u64,
    underlay: &mut U,
    route_operations: &mut O,
) -> Result<bool, Error> {
    let mut before = generation();
    if before == *validated_generation {
        return Ok(true);
    }
    for _ in 0..2 {
        if !underlay_matches_with(policy, owned, underlay)?
            || !managed_routes_match(routes, route_operations)
        {
            policy.invalidate();
            return Ok(false);
        }
        let after = generation();
        if after == before {
            *validated_generation = after;
            return Ok(true);
        }
        before = after;
    }
    policy.invalidate();
    Ok(false)
}

struct PlatformManagedRouteCleanup;

impl ManagedRouteCleanupOperations for PlatformManagedRouteCleanup {
    type Row = MIB_IPFORWARD_ROW2;

    fn read(&mut self, intended: &Self::Row) -> ManagedRouteRead<Self::Row> {
        let mut current = route_key(intended);
        match unsafe { GetIpForwardEntry2(&mut current) } {
            ERROR_NOT_FOUND => ManagedRouteRead::Absent,
            ERROR_SUCCESS => ManagedRouteRead::Present(current),
            _ => ManagedRouteRead::Failed,
        }
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        route_matches(intended, current)
    }

    fn delete(&mut self, current: &Self::Row) -> Result<(), Error> {
        match unsafe { DeleteIpForwardEntry2(current) } {
            ERROR_SUCCESS | ERROR_NOT_FOUND => Ok(()),
            _ => Err(Error),
        }
    }
}

fn take_last_owned_route<R>(pending: &mut Option<R>, journal: &mut Vec<R>) -> Option<R> {
    pending.take().or_else(|| journal.pop())
}

fn finish_setup_transaction(
    setup: Result<(), Error>,
    cleanup: impl FnOnce() -> bool,
) -> Result<(), CreateError> {
    match setup {
        Ok(()) => Ok(()),
        Err(_) => {
            if cleanup() {
                Err(CreateError::cleanup())
            } else {
                Err(CreateError::operation())
            }
        }
    }
}

trait CleanupOperations {
    fn session_is_idle(&mut self) -> bool;
    fn cancel_notifications(&mut self) -> Option<bool> {
        None
    }
    fn delete_last_route(&mut self) -> Option<bool> {
        None
    }
    fn restore_dns(&mut self) -> Option<bool> {
        None
    }
    fn end_session(&mut self) -> Option<bool>;
    fn delete_last_address(&mut self) -> Option<bool>;
    fn restore_ipv6_mtu(&mut self) -> Option<bool>;
    fn restore_ipv4_mtu(&mut self) -> Option<bool>;
    fn close_adapter(&mut self) -> Option<bool>;
}

fn cleanup_transaction(cleanup: &mut impl CleanupOperations) -> bool {
    if !cleanup.session_is_idle() {
        return true;
    }
    let mut failed = cleanup.cancel_notifications().unwrap_or(false);
    while let Some(step_failed) = cleanup.delete_last_route() {
        failed |= step_failed;
    }
    failed |= cleanup.restore_dns().unwrap_or(false);
    failed |= cleanup.end_session().unwrap_or(false);
    while let Some(step_failed) = cleanup.delete_last_address() {
        failed |= step_failed;
    }
    failed |= cleanup.restore_ipv6_mtu().unwrap_or(false);
    failed |= cleanup.restore_ipv4_mtu().unwrap_or(false);
    failed |= cleanup.close_adapter().unwrap_or(false);
    failed
}

struct PlatformCleanup<'a>(&'a mut Adapter);

impl PlatformCleanup<'_> {
    fn restore_mtu(&mut self, slot: usize) -> Option<bool> {
        let state = self.0.mtus[slot].take()?;
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = state.family;
        row.InterfaceLuid = self.0.luid;
        let get_status = unsafe { GetIpInterfaceEntry(&mut row) };
        if get_status != ERROR_SUCCESS || row.NlMtu != state.configured {
            return Some(true);
        }
        if state.family == AF_INET {
            row.SitePrefixLength = 0;
        }
        row.NlMtu = state.previous;
        Some(unsafe { SetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS)
    }
}

impl CleanupOperations for PlatformCleanup<'_> {
    fn session_is_idle(&mut self) -> bool {
        self.0.session_journal.cleanup_is_safe()
    }

    fn cancel_notifications(&mut self) -> Option<bool> {
        self.0
            .managed
            .as_mut()
            .map(|state| state.notifications.cancel_all())
    }

    fn delete_last_route(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let intended = take_last_owned_route(&mut state.pending_route, &mut state.routes)?;
        Some(delete_managed_route(
            &mut PlatformManagedRouteCleanup,
            &intended,
        ))
    }

    fn restore_dns(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let lease = state.dns.take()?;
        let Some(interface) = state.dns_interface.take() else {
            return Some(true);
        };
        Some(restore_managed_dns(
            &mut PlatformManagedDns(interface),
            &lease,
        ))
    }

    fn end_session(&mut self) -> Option<bool> {
        let session = self.0.session.take()?;
        unsafe { (self.0.library.exports.end_session)(session.handle) };
        Some(false)
    }

    fn delete_last_address(&mut self) -> Option<bool> {
        let address = self.0.addresses.pop()?;
        Some(unsafe { DeleteUnicastIpAddressEntry(&address) } != ERROR_SUCCESS)
    }

    fn restore_ipv6_mtu(&mut self) -> Option<bool> {
        self.restore_mtu(1)
    }

    fn restore_ipv4_mtu(&mut self) -> Option<bool> {
        self.restore_mtu(0)
    }

    fn close_adapter(&mut self) -> Option<bool> {
        let adapter = self.0.adapter.take()?;
        unsafe { (self.0.library.exports.close_adapter)(adapter) };
        Some(false)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DadProgress {
    Waiting,
    Ready,
}

fn dad_progress(state: NL_DAD_STATE) -> Result<DadProgress, Error> {
    match state {
        value if value == IpDadStateTentative => Ok(DadProgress::Waiting),
        value if value == IpDadStatePreferred => Ok(DadProgress::Ready),
        value
            if value == IpDadStateDuplicate
                || value == IpDadStateInvalid
                || value == IpDadStateDeprecated =>
        {
            Err(Error)
        }
        _ => Err(Error),
    }
}

fn dad_poll(waiting: bool, deadline_elapsed: bool) -> Result<DadProgress, Error> {
    match (waiting, deadline_elapsed) {
        (false, _) => Ok(DadProgress::Ready),
        (true, false) => Ok(DadProgress::Waiting),
        (true, true) => Err(Error),
    }
}

fn dad_snapshot(
    session_started: bool,
    states: [NL_DAD_STATE; 2],
    deadline_elapsed: bool,
) -> Result<DadProgress, Error> {
    if !session_started {
        return Err(Error);
    }
    let mut waiting = false;
    for state in states {
        waiting |= dad_progress(state)? == DadProgress::Waiting;
    }
    dad_poll(waiting, deadline_elapsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdapterCreateFailure {
    NoAdmin,
    NameCollision,
    Other,
}

impl AdapterCreateFailure {
    const fn into_error(self) -> Error {
        Error
    }
}

fn classify_adapter_create_failure(error: u32) -> AdapterCreateFailure {
    match error {
        ERROR_ACCESS_DENIED => AdapterCreateFailure::NoAdmin,
        ERROR_ALREADY_EXISTS => AdapterCreateFailure::NameCollision,
        _ => AdapterCreateFailure::Other,
    }
}

trait SetupOperations {
    fn check_cancelled(&mut self) -> Result<(), Error>;
    fn check_deadline(&mut self) -> Result<(), Error>;
    fn create_adapter(&mut self) -> Result<(), Error>;
    fn check_driver(&mut self) -> Result<(), Error>;
    fn set_ipv4_mtu(&mut self) -> Result<(), Error>;
    fn set_ipv6_mtu(&mut self) -> Result<(), Error>;
    fn add_ipv4_address(&mut self) -> Result<(), Error>;
    fn add_ipv6_address(&mut self) -> Result<(), Error>;
    fn start_session(&mut self) -> Result<(), Error>;
    fn wait_for_dad(&mut self) -> Result<(), Error>;
}

fn setup_transaction(setup: &mut impl SetupOperations) -> Result<(), Error> {
    setup.check_cancelled()?;
    setup.check_deadline()?;
    setup.create_adapter()?;
    setup.check_driver()?;
    setup.set_ipv4_mtu()?;
    setup.set_ipv6_mtu()?;
    setup.add_ipv4_address()?;
    setup.add_ipv6_address()?;
    setup.start_session()?;
    setup.wait_for_dad()
}

struct PlatformSetup<'a> {
    owner: &'a mut Adapter,
    deadline: Instant,
    cancelled: &'a AtomicBool,
}

impl SetupOperations for PlatformSetup<'_> {
    fn check_cancelled(&mut self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn check_deadline(&mut self) -> Result<(), Error> {
        if Instant::now() >= self.deadline {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn create_adapter(&mut self) -> Result<(), Error> {
        let name = wide(Path::new(self.owner.config.name.as_ref()));
        let tunnel = wide(Path::new("Ferrum2"));
        let adapter = unsafe {
            (self.owner.library.exports.create_adapter)(name.as_ptr(), tunnel.as_ptr(), null())
        };
        if adapter.is_null() {
            return Err(classify_adapter_create_failure(unsafe { GetLastError() }).into_error());
        }
        self.owner.adapter = Some(adapter);
        unsafe { (self.owner.library.exports.get_adapter_luid)(adapter, &mut self.owner.luid) };
        if unsafe { ConvertInterfaceLuidToIndex(&self.owner.luid, &mut self.owner.interface_index) }
            != ERROR_SUCCESS
            || self.owner.interface_index == 0
        {
            return Err(Error);
        }
        if let Some(state) = &self.owner.managed {
            state
                .notifications
                .set_owned_luid(self.owner.luid, self.deadline, self.cancelled)?;
        }
        Ok(())
    }

    fn check_driver(&mut self) -> Result<(), Error> {
        if unsafe { (self.owner.library.exports.get_running_driver_version)() } == 0 {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn set_ipv4_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET, 0)
    }

    fn set_ipv6_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET6, 1)
    }

    fn add_ipv4_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv4_address_row();
        self.owner.create_address(row)
    }

    fn add_ipv6_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv6_address_row();
        self.owner.create_address(row)
    }

    fn start_session(&mut self) -> Result<(), Error> {
        let adapter = self.owner.adapter.ok_or(Error)?;
        let session = unsafe {
            (self.owner.library.exports.start_session)(adapter, self.owner.config.ring_capacity)
        };
        if session.is_null() {
            return Err(Error);
        }
        let read_event = unsafe { (self.owner.library.exports.get_read_wait_event)(session) };
        self.owner.session = Some(SessionState {
            handle: session,
            read_event,
        });
        if read_event.is_null() || read_event == INVALID_HANDLE_VALUE {
            Err(Error)
        } else {
            Ok(())
        }
    }

    fn wait_for_dad(&mut self) -> Result<(), Error> {
        self.owner.wait_for_dad(self.deadline, self.cancelled)
    }
}

fn require_windows_10() -> Result<(), Error> {
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
pub struct StopSignal(Arc<OwnedHandle>);

impl Clone for StopSignal {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl StopSignal {
    pub fn signal(&self) -> Result<(), Error> {
        if unsafe { SetEvent(self.0.0) } == 0 {
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

fn current_executable() -> Result<PathBuf, Error> {
    let mut buffer = vec![0_u16; 32_768];
    let len = unsafe { GetModuleFileNameW(null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return Err(Error);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
}

fn reject_network_path(path: &Path) -> Result<(), Error> {
    match path
        .components()
        .next()
        .and_then(|component| match component {
            std::path::Component::Prefix(prefix) => Some(prefix.kind()),
            _ => None,
        }) {
        Some(Prefix::Disk(_) | Prefix::VerbatimDisk(_)) => Ok(()),
        _ => Err(Error),
    }
}

fn hold_directories(directory: &Path) -> Result<Vec<OwnedHandle>, Error> {
    let mut paths = directory.ancestors().collect::<Vec<_>>();
    paths.reverse();
    paths
        .into_iter()
        .map(|path| {
            let handle = unsafe {
                CreateFileW(
                    wide(path).as_ptr(),
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(Error);
            }
            verify_directory_non_reparse(handle)?;
            Ok(OwnedHandle(handle))
        })
        .collect()
}

fn open_file(path: &Path) -> Result<File, Error> {
    let handle = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            windows_sys::Win32::Foundation::GENERIC_READ,
            FILE_SHARE_READ,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error);
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn verify_directory_non_reparse(handle: HANDLE) -> Result<(), Error> {
    let attributes = file_attributes(handle)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(Error)
    } else {
        Ok(())
    }
}

fn verify_regular_non_reparse(handle: HANDLE) -> Result<(), Error> {
    let attributes = file_attributes(handle)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(Error)
    } else {
        Ok(())
    }
}

fn file_attributes(handle: HANDLE) -> Result<FILE_ATTRIBUTE_TAG_INFO, Error> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    let success = unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    if success == 0 {
        Err(Error)
    } else {
        Ok(attributes)
    }
}

fn cng_sha256(file: &File) -> Result<[u8; 32], Error> {
    let mut file = file.try_clone().map_err(|_| Error)?;
    let mut bytes = Vec::with_capacity(DLL_BYTES as usize);
    file.read_to_end(&mut bytes).map_err(|_| Error)?;
    if bytes.len() != DLL_BYTES as usize {
        return Err(Error);
    }
    let mut algorithm: BCRYPT_ALG_HANDLE = null_mut();
    if unsafe { BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, null(), 0) }
        != 0
    {
        return Err(Error);
    }
    let mut digest = [0_u8; 32];
    let status = unsafe {
        BCryptHash(
            algorithm,
            null(),
            0,
            bytes.as_ptr(),
            bytes.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
        )
    };
    let close = unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
    if status != 0 || close != 0 {
        Err(Error)
    } else {
        Ok(digest)
    }
}

fn create_event() -> Result<HANDLE, Error> {
    let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
    if handle.is_null() {
        Err(Error)
    } else {
        Ok(handle)
    }
}

unsafe fn resolve_exports(module: HMODULE) -> Result<Exports, Error> {
    Ok(Exports {
        create_adapter: unsafe { symbol(module, ABI_EXPORTS[0])? },
        close_adapter: unsafe { symbol(module, ABI_EXPORTS[1])? },
        get_adapter_luid: unsafe { symbol(module, ABI_EXPORTS[2])? },
        get_running_driver_version: unsafe { symbol(module, ABI_EXPORTS[3])? },
        start_session: unsafe { symbol(module, ABI_EXPORTS[4])? },
        end_session: unsafe { symbol(module, ABI_EXPORTS[5])? },
        get_read_wait_event: unsafe { symbol(module, ABI_EXPORTS[6])? },
        receive_packet: unsafe { symbol(module, ABI_EXPORTS[7])? },
        release_receive_packet: unsafe { symbol(module, ABI_EXPORTS[8])? },
        allocate_send_packet: unsafe { symbol(module, ABI_EXPORTS[9])? },
        send_packet: unsafe { symbol(module, ABI_EXPORTS[10])? },
    })
}

unsafe fn symbol<T: Copy>(module: HMODULE, name: &[u8]) -> Result<T, Error> {
    let address = unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or(Error)?;
    if size_of::<T>() != size_of_val(&address) {
        return Err(Error);
    }
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::{
        ABI_EXPORTS, AdapterCreateFailure, CleanupOperations, DLL_BYTES, DLL_SHA256, DadProgress,
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, Error, InterfaceIdentity, IpDadStateDeprecated,
        IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative,
        LoaderOperations, MIB_IF_ROW2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
        MIB_UNICASTIPADDRESS_ROW, ManagedDnsOperations, ManagedRouteCleanupOperations,
        ManagedRouteOperations, ManagedRouteRead, NET_LUID_LH, NotificationContext,
        NotificationOwners, RouteFingerprint, SessionJournal, SetupOperations, UnderlayOperations,
        address_changed, cancel_notification_handles, capture_route_row,
        classify_adapter_create_failure, classify_notification_luid, cleanup_transaction,
        copy_bounded_wide, dad_snapshot, delete_managed_route, eligible_interface_identity,
        finish_setup_transaction, install_managed_dns, install_managed_routes, interface_changed,
        interface_index_option_value, leak_notification_owners, load_transaction,
        prepare_managed_intent, require_exports, restore_managed_dns, revalidate_managed_network,
        route_changed, route_matches, select_unique_default_route, setup_transaction,
        snapshot_underlay_with, subscribe_notification_sequence, take_last_owned_route,
        underlay_matches_with, underlay_snapshot_matches, validate_artifact,
    };
    use crate::Ipv4Prefix;

    enum PublicationObservation<T> {
        Blocked,
        Early(T),
        Disconnected,
        Timeout,
    }

    fn observe_publication<T>(
        context: &NotificationContext,
        receiver: &std::sync::mpsc::Receiver<T>,
        expected_luid: u64,
        deadline: std::time::Instant,
    ) -> (bool, bool, PublicationObservation<T>) {
        let mut owner_observed = false;
        let mut drain_observed = false;
        loop {
            owner_observed |=
                context.owned_luid.load(std::sync::atomic::Ordering::SeqCst) == expected_luid;
            drain_observed |= context
                .drain_wait_observed
                .load(std::sync::atomic::Ordering::SeqCst);
            match receiver.try_recv() {
                Ok(result) => {
                    return (
                        owner_observed,
                        drain_observed,
                        PublicationObservation::Early(result),
                    );
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return (
                        owner_observed,
                        drain_observed,
                        PublicationObservation::Disconnected,
                    );
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
            }
            if owner_observed && drain_observed {
                return (
                    owner_observed,
                    drain_observed,
                    PublicationObservation::Blocked,
                );
            }
            if std::time::Instant::now() >= deadline {
                return (
                    owner_observed,
                    drain_observed,
                    PublicationObservation::Timeout,
                );
            }
            std::thread::yield_now();
        }
    }

    #[test]
    fn notification_publication_waits_for_inflight_classifier() {
        const OWN_LUID: u64 = 0x1020_3040;
        const FOREIGN_LUID: u64 = 0x5060_7080;

        for (name, notified_luid, expected_generation, expected_ok) in [
            ("exact own", OWN_LUID, 0, true),
            ("foreign", FOREIGN_LUID, 1, false),
        ] {
            let context = NotificationContext::new(None);
            let entered = std::sync::Barrier::new(2);
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel(1);

            let outcome = std::thread::scope(|scope| {
                let callback_context = &context;
                let callback_entered = &entered;
                let callback = scope.spawn(move || {
                    classify_notification_luid(callback_context, notified_luid, || {
                        callback_entered.wait();
                        let _ = release_rx.recv();
                    });
                });
                entered.wait();
                let publisher = scope.spawn(|| {
                    let result = context.publish_owned_luid(
                        OWN_LUID,
                        std::time::Instant::now() + std::time::Duration::from_secs(1),
                        &std::sync::atomic::AtomicBool::new(false),
                    );
                    publisher_tx
                        .send((
                            result.is_ok(),
                            context
                                .generation
                                .load(std::sync::atomic::Ordering::Acquire),
                        ))
                        .unwrap();
                });
                let (owner_observed, drain_observed, observation) = observe_publication(
                    &context,
                    &publisher_rx,
                    OWN_LUID,
                    std::time::Instant::now() + std::time::Duration::from_secs(1),
                );
                let (early, disconnected, timed_out) = match observation {
                    PublicationObservation::Blocked => (None, false, false),
                    PublicationObservation::Early(result) => (Some(result), false, false),
                    PublicationObservation::Disconnected => (None, true, false),
                    PublicationObservation::Timeout => (None, false, true),
                };
                let released = release_tx.send(()).is_ok();
                drop(release_tx);
                let callback_joined = callback.join().is_ok();
                let publisher_joined = publisher.join().is_ok();
                let completed_while_paused = early.is_some();
                let result = early.or_else(|| {
                    publisher_rx
                        .recv_timeout(std::time::Duration::from_secs(1))
                        .ok()
                });
                (
                    owner_observed,
                    drain_observed,
                    completed_while_paused,
                    disconnected,
                    timed_out,
                    released,
                    callback_joined,
                    publisher_joined,
                    result,
                )
            });

            assert!(outcome.0, "{name}: owner publication was not observed");
            assert!(outcome.1, "{name}: drain wait was not observed");
            assert!(
                !outcome.2,
                "{name}: owner publication completed before the callback classified its LUID"
            );
            assert!(!outcome.3, "{name}: publisher result channel disconnected");
            assert!(!outcome.4, "{name}: publisher observation timed out");
            assert!(outcome.5, "{name}: callback release failed");
            assert!(outcome.6, "{name}: callback thread failed");
            assert!(outcome.7, "{name}: publisher thread failed");
            let generation_at_publication = outcome
                .8
                .expect("publisher result missing after callback release");
            assert_eq!(
                generation_at_publication.1, expected_generation,
                "{name}: callback classification was not reflected before publication returned"
            );
            assert_eq!(
                generation_at_publication.0, expected_ok,
                "{name}: publication result"
            );
            assert_eq!(
                context
                    .generation
                    .load(std::sync::atomic::Ordering::Acquire),
                expected_generation,
                "{name}: final notification generation"
            );
        }
    }

    #[test]
    fn notification_publication_observer_bounds_failure_paths() {
        const OWN_LUID: u64 = 0x1020_3040;
        let context = NotificationContext::new(None);

        let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let timeout =
            observe_publication(&context, &publisher_rx, OWN_LUID, std::time::Instant::now());
        assert!(matches!(timeout.2, PublicationObservation::Timeout));
        drop(publisher_tx);
        let disconnected = observe_publication(
            &context,
            &publisher_rx,
            OWN_LUID,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        assert!(matches!(
            disconnected.2,
            PublicationObservation::Disconnected
        ));

        let (publisher_tx, publisher_rx) = std::sync::mpsc::sync_channel::<()>(1);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let publisher = std::thread::spawn(move || {
            let _publisher_tx = publisher_tx;
            let _release_tx = release_tx;
            panic!("synthetic publisher panic");
        });
        let panic_observation = observe_publication(
            &context,
            &publisher_rx,
            OWN_LUID,
            std::time::Instant::now() + std::time::Duration::from_secs(1),
        );
        let release_disconnected = release_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_err();
        let publisher_panicked = publisher.join().is_err();
        assert!(matches!(
            panic_observation.2,
            PublicationObservation::Disconnected
        ));
        assert!(
            release_disconnected,
            "panic did not release callback channel"
        );
        assert!(publisher_panicked, "synthetic publisher did not panic");
    }

    #[test]
    fn notification_publication_deadline_and_cancellation_fail_closed() {
        const OWN_LUID: u64 = 0x1020_3040;

        for (name, cancelled, deadline) in [
            (
                "cancelled",
                true,
                std::time::Instant::now() + std::time::Duration::from_secs(1),
            ),
            ("expired", false, std::time::Instant::now()),
        ] {
            let context = NotificationContext::new(None);
            let entered = std::sync::Barrier::new(2);
            let release = std::sync::Barrier::new(2);
            let cancelled = std::sync::atomic::AtomicBool::new(cancelled);

            let result = std::thread::scope(|scope| {
                let callback = scope.spawn(|| {
                    classify_notification_luid(&context, OWN_LUID, || {
                        entered.wait();
                        release.wait();
                    });
                });
                entered.wait();
                let result = context.publish_owned_luid(OWN_LUID, deadline, &cancelled);
                release.wait();
                callback.join().unwrap();
                result
            });

            assert!(result.is_err(), "{name}: publication did not fail closed");
        }
    }

    #[test]
    fn network_change_notifications_cover_each_callback_and_runtime_owned_events() {
        const OWN_LUID: u64 = 0x1020_3040;
        const FOREIGN_LUID: u64 = 0x5060_7080;

        #[derive(Clone, Copy, Debug)]
        enum Callback {
            Route,
            Interface,
            Address,
        }

        #[derive(Clone, Copy)]
        enum Action {
            Notify(Option<u64>),
            Publish(u64),
            Monitor,
        }

        unsafe fn notify(callback: Callback, context: *const std::ffi::c_void, luid: Option<u64>) {
            match callback {
                Callback::Route => {
                    let mut row = unsafe { std::mem::zeroed::<MIB_IPFORWARD_ROW2>() };
                    row.InterfaceLuid.Value = luid.unwrap_or_default();
                    unsafe {
                        route_changed(
                            context,
                            if luid.is_some() {
                                &raw const row
                            } else {
                                std::ptr::null()
                            },
                            0,
                        )
                    };
                }
                Callback::Interface => {
                    let mut row = unsafe { std::mem::zeroed::<MIB_IPINTERFACE_ROW>() };
                    row.InterfaceLuid.Value = luid.unwrap_or_default();
                    unsafe {
                        interface_changed(
                            context,
                            if luid.is_some() {
                                &raw const row
                            } else {
                                std::ptr::null()
                            },
                            0,
                        )
                    };
                }
                Callback::Address => {
                    let mut row = unsafe { std::mem::zeroed::<MIB_UNICASTIPADDRESS_ROW>() };
                    row.InterfaceLuid.Value = luid.unwrap_or_default();
                    unsafe {
                        address_changed(
                            context,
                            if luid.is_some() {
                                &raw const row
                            } else {
                                std::ptr::null()
                            },
                            0,
                        )
                    };
                }
            }
        }

        fn luid(value: u64) -> NET_LUID_LH {
            let mut luid = unsafe { std::mem::zeroed::<NET_LUID_LH>() };
            luid.Value = value;
            luid
        }

        let cases: &[(&str, &[Action], bool)] = &[
            (
                "repeated own before publication",
                &[
                    Action::Notify(Some(OWN_LUID)),
                    Action::Notify(Some(OWN_LUID)),
                    Action::Publish(OWN_LUID),
                ],
                false,
            ),
            (
                "foreign before publication",
                &[
                    Action::Notify(Some(FOREIGN_LUID)),
                    Action::Publish(OWN_LUID),
                ],
                true,
            ),
            (
                "own then foreign before publication",
                &[
                    Action::Notify(Some(OWN_LUID)),
                    Action::Notify(Some(FOREIGN_LUID)),
                    Action::Publish(OWN_LUID),
                ],
                true,
            ),
            (
                "foreign then own before publication",
                &[
                    Action::Notify(Some(FOREIGN_LUID)),
                    Action::Notify(Some(OWN_LUID)),
                    Action::Publish(OWN_LUID),
                ],
                true,
            ),
            (
                "null row",
                &[Action::Notify(None), Action::Publish(OWN_LUID)],
                true,
            ),
            (
                "zero row LUID",
                &[Action::Notify(Some(0)), Action::Publish(OWN_LUID)],
                true,
            ),
            (
                "own after publication",
                &[Action::Publish(OWN_LUID), Action::Notify(Some(OWN_LUID))],
                false,
            ),
            (
                "foreign after publication",
                &[
                    Action::Publish(OWN_LUID),
                    Action::Notify(Some(FOREIGN_LUID)),
                ],
                true,
            ),
            (
                "same owner republished",
                &[Action::Publish(OWN_LUID), Action::Publish(OWN_LUID)],
                false,
            ),
            (
                "different owner republished",
                &[Action::Publish(OWN_LUID), Action::Publish(FOREIGN_LUID)],
                true,
            ),
            ("zero owner published", &[Action::Publish(0)], true),
            (
                "owned runtime mutation",
                &[
                    Action::Publish(OWN_LUID),
                    Action::Monitor,
                    Action::Notify(Some(OWN_LUID)),
                ],
                true,
            ),
        ];
        for callback in [Callback::Route, Callback::Interface, Callback::Address] {
            for (name, actions, changed) in cases {
                let notifications = NotificationOwners {
                    handles: Vec::new(),
                    context: Some(Box::new(NotificationContext::new(None))),
                };
                let context = (notifications.context.as_deref().unwrap()
                    as *const NotificationContext)
                    .cast();
                for action in *actions {
                    match action {
                        Action::Notify(value) => unsafe { notify(callback, context, *value) },
                        Action::Publish(value) => {
                            let _ = notifications.set_owned_luid(
                                luid(*value),
                                std::time::Instant::now() + std::time::Duration::from_secs(1),
                                &std::sync::atomic::AtomicBool::new(false),
                            );
                        }
                        Action::Monitor => notifications.monitor_runtime(),
                    }
                }
                assert_eq!(
                    notifications.generation() != 0,
                    *changed,
                    "{callback:?}: {name}"
                );
            }
        }
    }

    #[test]
    fn notification_cancel_retains_only_failed_handles_for_safe_retry() {
        struct Context(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Context {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
        for failed in [1_u8, 2, 3] {
            let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut handles = vec![1_u8, 2, 3];
            let mut context = Some(Context(drops.clone()));
            let mut calls = Vec::new();
            assert!(cancel_notification_handles(
                &mut handles,
                &mut context,
                |handle| {
                    calls.push(*handle);
                    *handle != failed
                }
            ));
            assert_eq!(calls, [3, 2, 1]);
            assert_eq!(handles, [failed], "only the live callback owner survives");
            assert!(context.is_some());
            assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 0);

            calls.clear();
            assert!(!cancel_notification_handles(
                &mut handles,
                &mut context,
                |handle| {
                    calls.push(*handle);
                    true
                }
            ));
            assert_eq!(calls, [failed]);
            assert!(handles.is_empty());
            assert!(context.is_none());
            assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        }

        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = vec![4_u8];
        let mut context = Some(Context(drops.clone()));
        assert!(cancel_notification_handles(
            &mut handles,
            &mut context,
            |_| false
        ));
        leak_notification_owners(&mut handles, &mut context);
        assert!(handles.is_empty());
        assert!(context.is_none());
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "persistent callback ownership is intentionally retained"
        );
    }

    #[test]
    fn notification_subscription_failure_cleans_each_completed_ordinal() {
        struct Context(std::sync::Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Context {
            fn drop(&mut self) {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

        for failed in 0..3 {
            let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut subscribed = Vec::new();
            let mut cancelled = Vec::new();
            assert!(
                subscribe_notification_sequence(
                    Context(drops.clone()),
                    |ordinal| {
                        subscribed.push(ordinal);
                        if ordinal == failed {
                            Err(Error)
                        } else {
                            Ok(ordinal)
                        }
                    },
                    |handle| {
                        cancelled.push(*handle);
                        true
                    },
                )
                .is_err()
            );
            assert_eq!(subscribed, (0..=failed).collect::<Vec<_>>());
            assert_eq!(cancelled, (0..failed).rev().collect::<Vec<_>>());
            assert_eq!(drops.load(std::sync::atomic::Ordering::SeqCst), 1);
        }

        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut cancelled = Vec::new();
        assert!(
            subscribe_notification_sequence(
                Context(drops.clone()),
                |ordinal| if ordinal == 2 {
                    Err(Error)
                } else {
                    Ok(ordinal)
                },
                |handle| {
                    cancelled.push(*handle);
                    *handle != 1
                },
            )
            .is_err()
        );
        assert_eq!(cancelled, [1, 0]);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a failed cancellation retains the callback context"
        );
    }

    struct InjectedManagedRoutes {
        occupied: Option<u8>,
        preflight_error: Option<u8>,
        create_conflict: Option<u8>,
        readback_error: Option<u8>,
        readback_mismatch: Option<u8>,
        calls: Vec<(&'static str, u8)>,
        pending: Option<u8>,
        journal: Vec<u8>,
    }

    impl ManagedRouteOperations for InjectedManagedRoutes {
        type Row = u8;

        fn require_absent(&mut self, row: &Self::Row) -> Result<(), Error> {
            self.calls.push(("absent", *row));
            if self.occupied == Some(*row) || self.preflight_error == Some(*row) {
                Err(Error)
            } else {
                Ok(())
            }
        }

        fn create_pending(&mut self, row: Self::Row) -> Result<(), Error> {
            self.calls.push(("create", row));
            if self.create_conflict == Some(row) {
                return Err(Error);
            }
            self.pending = Some(row);
            Ok(())
        }

        fn readback_exact(&mut self, row: &Self::Row) -> Result<bool, Error> {
            self.calls.push(("readback", *row));
            if self.readback_error == Some(*row) {
                return Err(Error);
            }
            Ok(self.readback_mismatch != Some(*row))
        }

        fn commit_pending(&mut self) -> Result<(), Error> {
            self.journal.push(self.pending.take().ok_or(Error)?);
            Ok(())
        }
    }

    #[test]
    fn managed_route_preflights_every_key_before_first_create() {
        let make = || InjectedManagedRoutes {
            occupied: None,
            preflight_error: None,
            create_conflict: None,
            readback_error: None,
            readback_mismatch: None,
            calls: Vec::new(),
            pending: None,
            journal: Vec::new(),
        };
        for (conflict, expected_queries) in [(1, 1), (2, 2), (3, 3)] {
            let mut routes = make();
            routes.occupied = Some(conflict);
            assert!(install_managed_routes(&[1, 2, 3], &mut routes).is_err());
            assert_eq!(
                routes.calls,
                (1..=expected_queries)
                    .map(|row| ("absent", row))
                    .collect::<Vec<_>>()
            );
            assert!(routes.pending.is_none());
            assert!(routes.journal.is_empty());
        }

        let mut query_error = make();
        query_error.preflight_error = Some(2);
        assert!(install_managed_routes(&[1, 2, 3], &mut query_error).is_err());
        assert!(query_error.journal.is_empty());

        let mut late_conflict = make();
        late_conflict.create_conflict = Some(2);
        assert!(install_managed_routes(&[1, 2, 3], &mut late_conflict).is_err());
        assert_eq!(late_conflict.journal, [1]);
        assert!(late_conflict.pending.is_none());

        for readback_error in [true, false] {
            let mut failed = make();
            if readback_error {
                failed.readback_error = Some(2);
            } else {
                failed.readback_mismatch = Some(2);
            }
            assert!(install_managed_routes(&[1, 2, 3], &mut failed).is_err());
            assert_eq!(failed.journal, [1]);
            assert_eq!(failed.pending, Some(2));
            assert_eq!(
                take_last_owned_route(&mut failed.pending, &mut failed.journal),
                Some(2)
            );
            assert_eq!(
                take_last_owned_route(&mut failed.pending, &mut failed.journal),
                Some(1)
            );
        }

        let mut complete = make();
        install_managed_routes(&[1, 2, 3], &mut complete).unwrap();
        assert_eq!(
            std::iter::from_fn(|| {
                take_last_owned_route(&mut complete.pending, &mut complete.journal)
            })
            .collect::<Vec<_>>(),
            [3, 2, 1]
        );
    }

    struct InjectedRouteCleanup {
        reads: std::collections::VecDeque<ManagedRouteRead<u8>>,
        delete_error: bool,
        calls: Vec<&'static str>,
    }

    impl ManagedRouteCleanupOperations for InjectedRouteCleanup {
        type Row = u8;

        fn read(&mut self, _intended: &Self::Row) -> ManagedRouteRead<Self::Row> {
            self.calls.push("get");
            self.reads.pop_front().unwrap_or(ManagedRouteRead::Failed)
        }

        fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
            intended == current
        }

        fn delete(&mut self, _current: &Self::Row) -> Result<(), Error> {
            self.calls.push("delete");
            if self.delete_error {
                Err(Error)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn managed_route_cleanup_preserves_replacements_and_audits_every_delete() {
        let run = |reads, delete_error| {
            let mut cleanup = InjectedRouteCleanup {
                reads: std::collections::VecDeque::from(reads),
                delete_error,
                calls: Vec::new(),
            };
            let failed = delete_managed_route(&mut cleanup, &1);
            (failed, cleanup.calls)
        };
        assert_eq!(
            run(vec![ManagedRouteRead::Absent], false),
            (false, vec!["get"])
        );
        assert_eq!(
            run(
                vec![ManagedRouteRead::Present(1), ManagedRouteRead::Absent],
                false,
            ),
            (false, vec!["get", "delete", "get"])
        );
        assert_eq!(
            run(vec![ManagedRouteRead::Present(2)], false),
            (true, vec!["get"]),
            "a third-party replacement is preserved"
        );
        assert_eq!(
            run(vec![ManagedRouteRead::Failed], false),
            (true, vec!["get"])
        );
        for (delete_error, final_read) in [
            (true, ManagedRouteRead::Absent),
            (false, ManagedRouteRead::Failed),
            (false, ManagedRouteRead::Present(1)),
        ] {
            assert_eq!(
                run(vec![ManagedRouteRead::Present(1), final_read], delete_error,),
                (true, vec!["get", "delete", "get"])
            );
        }
    }

    #[derive(Clone)]
    struct InjectedUnderlay {
        interfaces: Vec<InterfaceIdentity>,
        best_index: u32,
        route: RouteFingerprint,
        default: RouteFingerprint,
        best_calls: usize,
        fail_at: Option<&'static str>,
    }

    #[test]
    fn network_change_revalidates_underlay_and_owned_routes_before_shutdown() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let route = RouteFingerprint {
            interface_luid: physical.luid,
            interface_index: physical.index,
            destination: u32::from_ne_bytes([198, 51, 100, 8]),
            prefix_length: 0,
            next_hop: u32::from_ne_bytes([192, 0, 2, 1]),
            metric: 4,
            source: Some(u32::from_ne_bytes([192, 0, 2, 2])),
        };
        let endpoint = "198.51.100.8:443".parse().unwrap();
        let config = crate::ManagedIpv4Config::new(Vec::new(), vec![endpoint], true, None).unwrap();
        let underlay = InjectedUnderlay {
            interfaces: vec![physical],
            best_index: physical.index,
            route,
            default: route,
            best_calls: 0,
            fail_at: None,
        };
        let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();

        let mut generation = [1, 1].into_iter();
        let mut validated_generation = 0;
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert!(
            revalidate_managed_network(
                &policy,
                wintun,
                &[1],
                &mut validated_generation,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
            )
            .unwrap()
        );
        assert_eq!(validated_generation, 1);
        assert_eq!(owned_routes.calls, ["get"]);

        for (name, changed_underlay, route_readback) in [
            ("underlay", true, ManagedRouteRead::Present(1)),
            ("owned route", false, ManagedRouteRead::Present(2)),
            ("replacement query", false, ManagedRouteRead::Failed),
        ] {
            let mut changed = underlay.clone();
            if changed_underlay {
                changed.route.metric += 1;
            }
            let mut owned_routes = InjectedRouteCleanup {
                reads: [route_readback].into(),
                delete_error: false,
                calls: Vec::new(),
            };
            let mut observed = 1;
            let mut generation = [2, 2].into_iter();
            assert!(
                !revalidate_managed_network(
                    &policy,
                    wintun,
                    &[1],
                    &mut observed,
                    || generation.next().unwrap(),
                    &mut changed,
                    &mut owned_routes,
                )
                .unwrap(),
                "{name}"
            );
            assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
            assert!(policy.bind_fixed(&NeverSocket, endpoint).is_err());
        }

        let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();
        let mut generation = [2, 3, 3].into_iter();
        let mut observed = 1;
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1), ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert!(
            revalidate_managed_network(
                &policy,
                wintun,
                &[1],
                &mut observed,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
            )
            .unwrap(),
            "one repeated/coalesced signal gets one bounded retry"
        );
        assert_eq!(observed, 3);

        let mut generation = [4, 5, 6].into_iter();
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1), ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert!(
            !revalidate_managed_network(
                &policy,
                wintun,
                &[1],
                &mut observed,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
            )
            .unwrap(),
            "repeated changes exhaust the bounded retry"
        );
        assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
        assert!(policy.bind_default(&NeverSocket).is_err());
    }

    struct NeverSocket;

    impl std::os::windows::io::AsRawSocket for NeverSocket {
        fn as_raw_socket(&self) -> std::os::windows::io::RawSocket {
            panic!("revoked policy must reject before reading the socket")
        }
    }

    impl UnderlayOperations for InjectedUnderlay {
        fn eligible_interfaces(
            &mut self,
            excluded: Option<InterfaceIdentity>,
        ) -> Result<Vec<InterfaceIdentity>, Error> {
            if self.fail_at == Some("eligible") {
                return Err(Error);
            }
            Ok(self
                .interfaces
                .iter()
                .copied()
                .filter(|identity| Some(*identity) != excluded)
                .collect())
        }

        fn best_interface(&mut self, _destination: std::net::Ipv4Addr) -> Result<u32, Error> {
            self.best_calls += 1;
            if self.fail_at == Some("best") {
                Err(Error)
            } else {
                Ok(self.best_index)
            }
        }

        fn constrained_route(
            &mut self,
            _destination: std::net::Ipv4Addr,
            _interface_index: u32,
            _require_source: bool,
        ) -> Result<RouteFingerprint, Error> {
            if self.fail_at == Some("route") {
                Err(Error)
            } else {
                Ok(self.route)
            }
        }

        fn unique_default_route(
            &mut self,
            _interfaces: &[InterfaceIdentity],
        ) -> Result<RouteFingerprint, Error> {
            if self.fail_at == Some("default") {
                Err(Error)
            } else {
                Ok(self.default)
            }
        }
    }

    #[test]
    fn managed_generation_and_underlay_post_capture_use_frozen_physical_route() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let route = RouteFingerprint {
            interface_luid: physical.luid,
            interface_index: physical.index,
            destination: u32::from_ne_bytes([198, 51, 100, 8]),
            prefix_length: 0,
            next_hop: u32::from_ne_bytes([192, 0, 2, 1]),
            metric: 4,
            source: Some(u32::from_ne_bytes([192, 0, 2, 2])),
        };
        let endpoint = "198.51.100.8:443".parse().unwrap();
        let config = crate::ManagedIpv4Config::new(Vec::new(), vec![endpoint], true, None).unwrap();
        let mut operations = InjectedUnderlay {
            interfaces: vec![physical],
            best_index: physical.index,
            route,
            default: route,
            best_calls: 0,
            fail_at: None,
        };
        let policy = snapshot_underlay_with(&config, &mut operations).unwrap();
        assert_eq!(
            operations.best_calls, 1,
            "unrestricted lookup is pre-capture"
        );

        operations.interfaces.push(wintun);
        operations.best_index = wintun.index;
        assert!(underlay_matches_with(&policy, wintun, &mut operations).unwrap());
        assert_eq!(
            operations.best_calls, 1,
            "post-capture cannot re-run best-interface"
        );

        for changed in [
            RouteFingerprint {
                interface_luid: physical.luid + 1,
                ..route
            },
            RouteFingerprint {
                interface_index: physical.index + 1,
                ..route
            },
            RouteFingerprint {
                source: Some(u32::from_ne_bytes([192, 0, 2, 3])),
                ..route
            },
            RouteFingerprint {
                next_hop: u32::from_ne_bytes([192, 0, 2, 9]),
                ..route
            },
            RouteFingerprint { metric: 5, ..route },
        ] {
            let mut changed_operations = operations.clone();
            changed_operations.route = changed;
            assert!(!underlay_matches_with(&policy, wintun, &mut changed_operations).unwrap());
        }

        let mut changed_identity = operations.clone();
        changed_identity.interfaces[0].luid += 1;
        assert!(!underlay_matches_with(&policy, wintun, &mut changed_identity).unwrap());

        let mut changed_default = operations.clone();
        changed_default.default.metric += 1;
        assert!(!underlay_matches_with(&policy, wintun, &mut changed_default).unwrap());

        let mut stable = [4_u64, 4].into_iter();
        assert!(
            underlay_snapshot_matches(
                &policy,
                wintun,
                4,
                || stable.next().unwrap(),
                &mut operations.clone(),
            )
            .unwrap()
        );
        let mut changed_before = [5_u64].into_iter();
        assert!(
            !underlay_snapshot_matches(
                &policy,
                wintun,
                4,
                || changed_before.next().unwrap(),
                &mut operations.clone(),
            )
            .unwrap()
        );
        let mut changed_during = [4_u64, 5].into_iter();
        assert!(
            !underlay_snapshot_matches(
                &policy,
                wintun,
                4,
                || changed_during.next().unwrap(),
                &mut operations,
            )
            .unwrap()
        );
    }

    #[test]
    fn underlay_eligibility_and_query_failures_are_closed() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let route = RouteFingerprint {
            interface_luid: physical.luid,
            interface_index: physical.index,
            destination: 0,
            prefix_length: 0,
            next_hop: u32::from_ne_bytes([192, 0, 2, 1]),
            metric: 4,
            source: Some(u32::from_ne_bytes([192, 0, 2, 2])),
        };
        let endpoint = "198.51.100.8:443".parse().unwrap();
        let config = crate::ManagedIpv4Config::new(Vec::new(), vec![endpoint], true, None).unwrap();
        let operations = InjectedUnderlay {
            interfaces: vec![physical],
            best_index: physical.index,
            route,
            default: RouteFingerprint {
                source: None,
                ..route
            },
            best_calls: 0,
            fail_at: None,
        };

        for failure in ["eligible", "best", "route", "default"] {
            let mut failed = operations.clone();
            failed.fail_at = Some(failure);
            assert!(snapshot_underlay_with(&config, &mut failed).is_err());
        }
        let mut none = operations.clone();
        none.interfaces.clear();
        assert!(snapshot_underlay_with(&config, &mut none).is_err());
        let mut missing_best = operations.clone();
        missing_best.best_index += 1;
        assert!(snapshot_underlay_with(&config, &mut missing_best).is_err());

        let mut raw = MIB_IF_ROW2::default();
        raw.InterfaceLuid.Value = physical.luid;
        raw.InterfaceIndex = physical.index;
        raw.Type = 6;
        raw.OperStatus = super::IfOperStatusUp;
        raw.AdminStatus = super::NET_IF_ADMIN_STATUS_UP;
        raw.MediaConnectState = super::MediaConnectStateConnected;
        raw.InterfaceAndOperStatusFlags._bitfield = 1;
        assert!(eligible_interface_identity(&raw, None) == Some(physical));
        assert!(eligible_interface_identity(&raw, Some(physical)).is_none());
        for ineligible in [
            {
                let mut row = raw;
                row.InterfaceIndex = 0;
                row
            },
            {
                let mut row = raw;
                row.Type =
                    windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK;
                row
            },
            {
                let mut row = raw;
                row.OperStatus = 0;
                row
            },
            {
                let mut row = raw;
                row.AdminStatus = 0;
                row
            },
            {
                let mut row = raw;
                row.MediaConnectState = 0;
                row
            },
            {
                let mut row = raw;
                row.InterfaceAndOperStatusFlags._bitfield = 0;
                row
            },
        ] {
            assert!(eligible_interface_identity(&ineligible, None).is_none());
        }

        let mut luid = super::NET_LUID_LH::default();
        luid.Value = physical.luid;
        let mut default = capture_route_row(
            luid,
            physical.index,
            Ipv4Prefix::new("0.0.0.0".parse().unwrap(), 1).unwrap(),
        );
        default.DestinationPrefix.PrefixLength = 0;
        default.Metric = route.metric;
        default.NextHop.Ipv4.sin_addr.S_un.S_addr = route.next_hop;
        let expected = RouteFingerprint {
            source: None,
            ..route
        };
        assert!(select_unique_default_route(&[], &[physical]).is_err());
        assert!(select_unique_default_route(&[default], &[physical]).unwrap() == expected);
        assert!(select_unique_default_route(&[default, default], &[physical]).is_err());
    }

    #[test]
    fn disabled_managed_skips_every_platform_operation() {
        let mut calls = Vec::new();
        assert_eq!(
            prepare_managed_intent(None, |_| {
                calls.extend(["subscribe", "generation", "snapshot", "query", "mutation"]);
                Ok(())
            })
            .unwrap(),
            None
        );
        assert!(calls.is_empty());

        let manual_direct =
            crate::ManagedIpv4Config::new(Vec::new(), Vec::new(), true, None).unwrap();
        assert_eq!(
            prepare_managed_intent(Some(&manual_direct), |config| {
                calls.extend(["subscribe", "generation", "default-snapshot"]);
                assert!(config.needs_default_binder());
                Ok(())
            })
            .unwrap(),
            Some(())
        );
        assert_eq!(calls, ["subscribe", "generation", "default-snapshot"]);
    }

    #[test]
    fn m16_redaction_managed_identity_table_is_aggregate() {
        let adapter_name = "m16-adapter-sentinel";
        let interface_name = "m16-interface-sentinel";
        let endpoint: std::net::SocketAddrV4 = "203.0.113.211:49153".parse().unwrap();
        let dns_address = "198.18.0.1".parse().unwrap();
        let prefix = Ipv4Prefix::new("203.0.113.0".parse().unwrap(), 24).unwrap();
        let managed =
            crate::ManagedIpv4Config::new(vec![prefix], vec![endpoint], true, Some(dns_address))
                .unwrap();
        let config = crate::AdapterConfig::new(
            adapter_name.into(),
            "198.18.0.2".parse().unwrap(),
            30,
            "fd00::2".parse().unwrap(),
            126,
            1420,
            8_388_608,
            std::time::Duration::from_secs(10),
        )
        .unwrap()
        .with_managed_ipv4(managed);
        assert_eq!(config.name.as_ref(), adapter_name);

        let identity = InterfaceIdentity {
            luid: 0x1122_3344_5566_7788,
            index: 0x7f00_1234,
        };
        let mut raw = MIB_IF_ROW2::default();
        raw.InterfaceLuid.Value = identity.luid;
        raw.InterfaceIndex = identity.index;
        raw.InterfaceGuid = windows_sys::core::GUID {
            data1: 0x6fc7_2c11,
            data2: 0x4c9a,
            data3: 0x45c4,
            data4: [0x8f, 0x61, 0x49, 0x55, 0x72, 0x1a, 0x77, 0xe1],
        };
        raw.Type = 6;
        raw.OperStatus = super::IfOperStatusUp;
        raw.AdminStatus = super::NET_IF_ADMIN_STATUS_UP;
        raw.MediaConnectState = super::MediaConnectStateConnected;
        raw.InterfaceAndOperStatusFlags._bitfield = 1;
        for (slot, unit) in raw.Alias.iter_mut().zip(interface_name.encode_utf16()) {
            *slot = unit;
        }
        assert!(eligible_interface_identity(&raw, None) == Some(identity));

        let route = RouteFingerprint {
            interface_luid: identity.luid,
            interface_index: identity.index,
            destination: u32::from_ne_bytes([203, 0, 113, 0]),
            prefix_length: 24,
            next_hop: u32::from_ne_bytes([192, 0, 2, 137]),
            metric: 31337,
            source: Some(u32::from_ne_bytes([192, 0, 2, 138])),
        };
        assert_eq!(route.interface_index, identity.index);

        let rendered = [
            format!("{Error:?}"),
            Error.to_string(),
            format!("{:?}", Err::<(), _>(Error)),
            format!("{:?}", crate::CreateError::operation()),
            crate::CreateError::operation().to_string(),
            format!("{:?}", crate::CreateError::cleanup()),
            crate::CreateError::cleanup().to_string(),
        ];
        let sentinels = [
            adapter_name.to_owned(),
            interface_name.to_owned(),
            endpoint.to_string(),
            dns_address.to_string(),
            "203.0.113.0/24".to_owned(),
            identity.index.to_string(),
            identity.luid.to_string(),
            "6fc72c11-4c9a-45c4-8f61-4955721a77e1".to_owned(),
            std::net::Ipv4Addr::from(route.next_hop.to_ne_bytes()).to_string(),
            std::net::Ipv4Addr::from(route.source.unwrap().to_ne_bytes()).to_string(),
            route.metric.to_string(),
        ];
        let leaks = |values: &[String]| {
            values
                .iter()
                .any(|value| sentinels.iter().any(|sentinel| value.contains(sentinel)))
        };
        assert!(!leaks(&rendered));
        assert!(leaks(&[format!("synthetic leak: {endpoint}")]));
    }

    struct InjectedManagedDns {
        current: u8,
        fail_at: Option<&'static str>,
        replace_on_read: Option<(usize, u8)>,
        readbacks: usize,
        calls: Vec<&'static str>,
    }

    impl ManagedDnsOperations for InjectedManagedDns {
        type Settings = u8;

        fn snapshot(&mut self) -> Result<Self::Settings, Error> {
            self.calls.push("snapshot");
            (self.fail_at != Some("snapshot"))
                .then_some(self.current)
                .ok_or(Error)
        }

        fn apply(&mut self, _address: std::net::Ipv4Addr) -> Result<Self::Settings, Error> {
            self.calls.push("apply");
            if self.fail_at == Some("apply") {
                return Err(Error);
            }
            self.current = 2;
            Ok(2)
        }

        fn readback(&mut self) -> Result<Self::Settings, Error> {
            self.calls.push("readback");
            self.readbacks += 1;
            if self.fail_at == Some("readback") {
                return Err(Error);
            }
            if self
                .replace_on_read
                .is_some_and(|(read, _)| read == self.readbacks)
            {
                self.current = self.replace_on_read.take().unwrap().1;
            }
            Ok(self.current)
        }

        fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
            self.calls.push("restore");
            if self.fail_at == Some("restore") {
                return Err(Error);
            }
            self.current = *settings;
            Ok(())
        }
    }

    #[test]
    fn managed_dns_snapshots_reads_back_and_conditionally_restores() {
        let address = "198.18.0.1".parse().unwrap();
        let make = || InjectedManagedDns {
            current: 1,
            fail_at: None,
            replace_on_read: None,
            readbacks: 0,
            calls: Vec::new(),
        };

        let mut complete = make();
        let mut lease = None;
        install_managed_dns(address, &mut complete, &mut lease).unwrap();
        assert_eq!(complete.calls, ["snapshot", "apply", "readback"]);
        assert!(!restore_managed_dns(&mut complete, lease.as_ref().unwrap()));
        assert_eq!(complete.current, 1);
        assert_eq!(
            complete.calls,
            [
                "snapshot", "apply", "readback", "readback", "restore", "readback"
            ]
        );

        for failure in ["snapshot", "apply", "readback"] {
            let mut injected = make();
            injected.fail_at = Some(failure);
            let mut lease = None;
            assert!(install_managed_dns(address, &mut injected, &mut lease).is_err());
            if failure == "readback" {
                assert!(lease.is_some(), "successful apply must be journaled");
                injected.fail_at = None;
                assert!(!restore_managed_dns(&mut injected, lease.as_ref().unwrap()));
                assert_eq!(injected.current, 1);
            } else {
                assert!(lease.is_none());
                assert_eq!(injected.current, 1);
            }
        }

        let mut replaced = make();
        let mut lease = None;
        install_managed_dns(address, &mut replaced, &mut lease).unwrap();
        replaced.current = 3;
        assert!(restore_managed_dns(&mut replaced, lease.as_ref().unwrap()));
        assert_eq!(replaced.current, 3, "external replacement is preserved");
        assert_eq!(replaced.calls.last(), Some(&"readback"));

        for (failure, replacement) in [(Some("restore"), None), (None, Some((3, 4)))] {
            let mut injected = make();
            let mut lease = None;
            install_managed_dns(address, &mut injected, &mut lease).unwrap();
            injected.fail_at = failure;
            injected.replace_on_read = replacement;
            assert!(restore_managed_dns(&mut injected, lease.as_ref().unwrap()));
        }

        assert_eq!(copy_bounded_wide(std::ptr::null_mut()).unwrap(), None);
        let mut empty = [0_u16];
        assert_eq!(copy_bounded_wide(empty.as_mut_ptr()).unwrap(), None);
        let mut value = [
            b'1' as u16,
            b'.' as u16,
            b'1' as u16,
            b'.' as u16,
            b'1' as u16,
            0,
        ];
        assert_eq!(
            copy_bounded_wide(value.as_mut_ptr()).unwrap().as_deref(),
            Some(&value[..5])
        );
        let mut unterminated = vec![1_u16; 4097];
        assert!(copy_bounded_wide(unterminated.as_mut_ptr()).is_err());
    }

    struct InjectedSetup {
        fail_at: Option<usize>,
        cleanup_fail_at: Option<usize>,
        idle: bool,
        calls: Vec<&'static str>,
        resources: Vec<&'static str>,
        notifications: bool,
        routes: Vec<&'static str>,
        dns: bool,
        cleanup_calls: Vec<&'static str>,
    }

    impl InjectedSetup {
        fn step(
            &mut self,
            name: &'static str,
            resource: Option<&'static str>,
        ) -> Result<(), Error> {
            let position = self.calls.len();
            self.calls.push(name);
            if self.fail_at == Some(position) {
                Err(Error)
            } else {
                if let Some(resource) = resource {
                    self.resources.push(resource);
                }
                Ok(())
            }
        }

        fn cleanup_step(&mut self, resource: &'static str, name: &'static str) -> Option<bool> {
            if self.resources.last() != Some(&resource) {
                return None;
            }
            self.resources.pop();
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push(name);
            Some(self.cleanup_fail_at == Some(position))
        }
    }

    impl SetupOperations for InjectedSetup {
        fn check_cancelled(&mut self) -> Result<(), Error> {
            self.step("cancel", None)
        }

        fn check_deadline(&mut self) -> Result<(), Error> {
            self.step("deadline", None)
        }

        fn create_adapter(&mut self) -> Result<(), Error> {
            self.step("create", Some("adapter"))
        }

        fn check_driver(&mut self) -> Result<(), Error> {
            self.step("driver", None)
        }

        fn set_ipv4_mtu(&mut self) -> Result<(), Error> {
            self.step("ipv4-mtu", Some("ipv4-mtu"))
        }

        fn set_ipv6_mtu(&mut self) -> Result<(), Error> {
            self.step("ipv6-mtu", Some("ipv6-mtu"))
        }

        fn add_ipv4_address(&mut self) -> Result<(), Error> {
            self.step("ipv4-address", Some("ipv4-address"))
        }

        fn add_ipv6_address(&mut self) -> Result<(), Error> {
            self.step("ipv6-address", Some("ipv6-address"))
        }

        fn start_session(&mut self) -> Result<(), Error> {
            self.step("start-session", Some("session"))
        }

        fn wait_for_dad(&mut self) -> Result<(), Error> {
            assert_eq!(self.resources.last(), Some(&"session"));
            self.step("dad", None)
        }
    }

    impl CleanupOperations for InjectedSetup {
        fn session_is_idle(&mut self) -> bool {
            self.idle
        }

        fn cancel_notifications(&mut self) -> Option<bool> {
            if !std::mem::take(&mut self.notifications) {
                return None;
            }
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push("notifications");
            Some(self.cleanup_fail_at == Some(position))
        }

        fn delete_last_route(&mut self) -> Option<bool> {
            let route = self.routes.pop()?;
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push(route);
            Some(self.cleanup_fail_at == Some(position))
        }

        fn restore_dns(&mut self) -> Option<bool> {
            if !std::mem::take(&mut self.dns) {
                return None;
            }
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push("dns");
            Some(self.cleanup_fail_at == Some(position))
        }

        fn end_session(&mut self) -> Option<bool> {
            self.cleanup_step("session", "end-session")
        }

        fn delete_last_address(&mut self) -> Option<bool> {
            for (resource, name) in [
                ("ipv6-address", "ipv6-address"),
                ("ipv4-address", "ipv4-address"),
            ] {
                if let Some(result) = self.cleanup_step(resource, name) {
                    return Some(result);
                }
            }
            None
        }

        fn restore_ipv6_mtu(&mut self) -> Option<bool> {
            self.cleanup_step("ipv6-mtu", "ipv6-mtu")
        }

        fn restore_ipv4_mtu(&mut self) -> Option<bool> {
            self.cleanup_step("ipv4-mtu", "ipv4-mtu")
        }

        fn close_adapter(&mut self) -> Option<bool> {
            self.cleanup_step("adapter", "adapter")
        }
    }

    struct InjectedLoader {
        fail_at: Option<usize>,
        calls: Vec<&'static str>,
    }

    impl InjectedLoader {
        fn step(&mut self, name: &'static str) -> Result<(), Error> {
            let position = self.calls.len();
            self.calls.push(name);
            if self.fail_at == Some(position) {
                Err(Error)
            } else {
                Ok(())
            }
        }
    }

    impl LoaderOperations for InjectedLoader {
        fn discover_executable(&mut self) -> Result<(), Error> {
            self.step("executable")
        }

        fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error> {
            self.step("held-directories")
        }

        fn open_sibling_dll(&mut self) -> Result<(), Error> {
            self.step("sibling-dll")
        }

        fn verify_dll_identity(&mut self) -> Result<(), Error> {
            self.step("file-identity")
        }

        fn verify_artifact(&mut self) -> Result<(), Error> {
            self.step("size/hash")
        }

        fn load_system32_scoped_library(&mut self) -> Result<(), Error> {
            self.step("system32-load")
        }

        fn resolve_exact_abi(&mut self) -> Result<(), Error> {
            self.step("eleven-exports")
        }
    }

    #[test]
    fn loader_and_every_abi_position_fail_closed() {
        let order = [
            "executable",
            "held-directories",
            "sibling-dll",
            "file-identity",
            "size/hash",
            "system32-load",
            "eleven-exports",
        ];
        for failed in 0..order.len() {
            let mut loader = InjectedLoader {
                fail_at: Some(failed),
                calls: Vec::new(),
            };
            assert!(load_transaction(&mut loader).is_err(), "loader {failed}");
            assert_eq!(loader.calls, order[..=failed], "loader {failed}");
        }
        let mut loader = InjectedLoader {
            fail_at: None,
            calls: Vec::new(),
        };
        load_transaction(&mut loader).expect("complete loader");
        assert_eq!(loader.calls, order);

        assert!(validate_artifact(DLL_BYTES, DLL_SHA256).is_ok());
        assert!(validate_artifact(DLL_BYTES - 1, DLL_SHA256).is_err());
        assert!(validate_artifact(DLL_BYTES + 1, DLL_SHA256).is_err());
        let mut wrong_hash = DLL_SHA256;
        wrong_hash[0] ^= 1;
        assert!(validate_artifact(DLL_BYTES, wrong_hash).is_err());

        for missing in 0..ABI_EXPORTS.len() {
            let mut visited = Vec::new();
            let result = require_exports(|name| {
                visited.push(name.to_vec());
                name != ABI_EXPORTS[missing]
            });
            assert!(result.is_err(), "missing export {missing}");
            assert_eq!(
                visited,
                ABI_EXPORTS[..=missing]
                    .iter()
                    .map(|name| name.to_vec())
                    .collect::<Vec<_>>(),
                "missing export {missing}"
            );
        }
        let mut visited = Vec::new();
        require_exports(|name| {
            visited.push(name.to_vec());
            true
        })
        .expect("all exact exports");
        assert_eq!(
            visited,
            ABI_EXPORTS
                .iter()
                .map(|name| name.to_vec())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_setup_position_fails_before_later_work_and_session_precedes_dad() {
        let order = [
            "cancel",
            "deadline",
            "create",
            "driver",
            "ipv4-mtu",
            "ipv6-mtu",
            "ipv4-address",
            "ipv6-address",
            "start-session",
            "dad",
        ];
        let rollback = [
            &[][..],
            &[][..],
            &[][..],
            &["adapter"][..],
            &["adapter"][..],
            &["ipv4-mtu", "adapter"][..],
            &["ipv6-mtu", "ipv4-mtu", "adapter"][..],
            &["ipv4-address", "ipv6-mtu", "ipv4-mtu", "adapter"][..],
            &[
                "ipv6-address",
                "ipv4-address",
                "ipv6-mtu",
                "ipv4-mtu",
                "adapter",
            ][..],
            &[
                "end-session",
                "ipv6-address",
                "ipv4-address",
                "ipv6-mtu",
                "ipv4-mtu",
                "adapter",
            ][..],
        ];
        for (failed, expected_cleanup) in rollback.into_iter().enumerate() {
            let mut setup = InjectedSetup {
                fail_at: Some(failed),
                cleanup_fail_at: None,
                idle: true,
                calls: Vec::new(),
                resources: Vec::new(),
                notifications: false,
                routes: Vec::new(),
                dns: false,
                cleanup_calls: Vec::new(),
            };
            assert!(setup_transaction(&mut setup).is_err(), "step {failed}");
            assert_eq!(setup.calls, order[..=failed], "step {failed}");
            assert!(!cleanup_transaction(&mut setup), "step {failed}");
            assert_eq!(setup.cleanup_calls, expected_cleanup, "step {failed}");
            assert!(setup.resources.is_empty(), "step {failed}");
        }
        let mut setup = InjectedSetup {
            fail_at: None,
            cleanup_fail_at: None,
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            routes: Vec::new(),
            dns: false,
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut setup).expect("complete setup");
        assert_eq!(setup.calls, order);
        assert!(
            setup.calls.iter().position(|step| *step == "start-session")
                < setup.calls.iter().position(|step| *step == "dad")
        );
    }

    #[test]
    fn only_post_session_dual_family_natural_preferred_dad_is_ready() {
        assert!(dad_snapshot(false, [IpDadStatePreferred, IpDadStatePreferred], false).is_err());
        assert_eq!(
            dad_snapshot(true, [IpDadStatePreferred, IpDadStatePreferred], false),
            Ok(DadProgress::Ready)
        );
        for states in [
            [IpDadStateTentative, IpDadStatePreferred],
            [IpDadStatePreferred, IpDadStateTentative],
            [IpDadStateTentative, IpDadStateTentative],
        ] {
            assert_eq!(dad_snapshot(true, states, false), Ok(DadProgress::Waiting));
            assert!(dad_snapshot(true, states, true).is_err());
        }
        for family in 0..2 {
            for state in [IpDadStateDuplicate, IpDadStateInvalid, IpDadStateDeprecated] {
                let mut states = [IpDadStatePreferred, IpDadStatePreferred];
                states[family] = state;
                assert!(dad_snapshot(true, states, false).is_err());
            }
        }
    }

    #[test]
    fn adapter_create_null_causes_are_closed_and_redacted() {
        assert_eq!(
            classify_adapter_create_failure(ERROR_ACCESS_DENIED),
            AdapterCreateFailure::NoAdmin
        );
        assert_eq!(
            classify_adapter_create_failure(ERROR_ALREADY_EXISTS),
            AdapterCreateFailure::NameCollision
        );
        assert_eq!(
            classify_adapter_create_failure(0xdead_beef),
            AdapterCreateFailure::Other
        );
    }

    #[test]
    fn dad_failure_ends_session_first_and_cleanup_conflicts_do_not_short_circuit() {
        let order = [
            "end-session",
            "ipv6-address",
            "ipv4-address",
            "ipv6-mtu",
            "ipv4-mtu",
            "adapter",
        ];
        for failed in 0..order.len() {
            let mut cleanup = InjectedSetup {
                fail_at: None,
                cleanup_fail_at: Some(failed),
                idle: true,
                calls: Vec::new(),
                resources: Vec::new(),
                notifications: false,
                routes: Vec::new(),
                dns: false,
                cleanup_calls: Vec::new(),
            };
            setup_transaction(&mut cleanup).expect("complete setup");
            assert!(cleanup_transaction(&mut cleanup), "cleanup step {failed}");
            assert_eq!(cleanup.cleanup_calls, order, "cleanup step {failed}");
            assert!(cleanup.resources.is_empty(), "cleanup step {failed}");
        }

        let mut cleanup = InjectedSetup {
            fail_at: None,
            cleanup_fail_at: None,
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            routes: Vec::new(),
            dns: false,
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut cleanup).expect("complete setup");
        assert!(!cleanup_transaction(&mut cleanup));
        assert_eq!(cleanup.cleanup_calls, order);

        let journal = SessionJournal::default();
        let wait = journal.begin_wait().expect("first wait");
        assert!(
            journal.begin_wait().is_err(),
            "overlapping waits fail closed"
        );
        let mut overlap = InjectedSetup {
            fail_at: None,
            idle: journal.cleanup_is_safe(),
            calls: Vec::new(),
            cleanup_fail_at: None,
            resources: Vec::new(),
            notifications: false,
            routes: Vec::new(),
            dns: false,
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut overlap).expect("complete setup");
        assert!(cleanup_transaction(&mut overlap));
        assert!(
            overlap.cleanup_calls.is_empty(),
            "EndSession cannot overlap an active wait"
        );
        drop(wait);
        assert!(journal.cleanup_is_safe());
        overlap.idle = true;
        assert!(!cleanup_transaction(&mut overlap));
        assert_eq!(overlap.cleanup_calls, order);

        let clean = finish_setup_transaction(Err(Error), || false).expect_err("DAD failure");
        assert!(!clean.is_cleanup_failure());
        let conflict = finish_setup_transaction(Err(Error), || true).expect_err("cleanup conflict");
        assert!(conflict.is_cleanup_failure());
        let mut cleanup_called = false;
        finish_setup_transaction(Ok(()), || {
            cleanup_called = true;
            false
        })
        .expect("successful setup");
        assert!(!cleanup_called, "successful setup retains the journal");
    }

    #[test]
    fn managed_route_initializer_and_exact_ownership_are_closed() {
        let low = Ipv4Prefix::new("0.0.0.0".parse().unwrap(), 1).unwrap();
        let high = Ipv4Prefix::new("128.0.0.0".parse().unwrap(), 1).unwrap();
        let luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: 7 };
        let low = capture_route_row(luid, 11, low);
        let high = capture_route_row(luid, 11, high);
        assert!(route_matches(&low, &low));
        assert!(route_matches(&high, &high));
        assert_ne!(
            unsafe { low.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr },
            unsafe { high.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr }
        );
        let mut mutations = Vec::new();
        for mutate in [
            |row: &mut MIB_IPFORWARD_ROW2| unsafe { row.InterfaceLuid.Value += 1 },
            |row: &mut MIB_IPFORWARD_ROW2| row.InterfaceIndex += 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.DestinationPrefix.PrefixLength += 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.SitePrefixLength += 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.ValidLifetime -= 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.PreferredLifetime -= 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.Metric += 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.Protocol += 1,
            |row: &mut MIB_IPFORWARD_ROW2| row.Loopback = true,
            |row: &mut MIB_IPFORWARD_ROW2| row.AutoconfigureAddress = true,
            |row: &mut MIB_IPFORWARD_ROW2| row.Publish = true,
            |row: &mut MIB_IPFORWARD_ROW2| row.Immortal = true,
            |row: &mut MIB_IPFORWARD_ROW2| row.Origin += 1,
        ] {
            let mut changed = low;
            mutate(&mut changed);
            mutations.push(changed);
        }
        let mut changed_destination = low;
        unsafe {
            changed_destination
                .DestinationPrefix
                .Prefix
                .Ipv4
                .sin_addr
                .S_un
                .S_addr += 1;
        }
        mutations.push(changed_destination);
        let mut changed_next_hop = low;
        changed_next_hop.NextHop.Ipv4.sin_addr.S_un.S_addr = 1;
        mutations.push(changed_next_hop);
        assert!(
            mutations
                .iter()
                .all(|changed| !route_matches(&low, changed)),
            "every initialized ownership field is mutation-sensitive"
        );

        let mut cleanup = InjectedSetup {
            fail_at: None,
            cleanup_fail_at: Some(1),
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            routes: Vec::new(),
            dns: false,
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut cleanup).expect("complete adapter setup");
        cleanup.notifications = true;
        cleanup.routes.extend(["low-route", "high-route"]);
        cleanup.dns = true;
        assert!(
            cleanup_transaction(&mut cleanup),
            "route conflict is surfaced"
        );
        assert_eq!(
            cleanup.cleanup_calls,
            [
                "notifications",
                "high-route",
                "low-route",
                "dns",
                "end-session",
                "ipv6-address",
                "ipv4-address",
                "ipv6-mtu",
                "ipv4-mtu",
                "adapter",
            ],
            "route conflict cannot short-circuit reverse cleanup"
        );
        assert!(cleanup.resources.is_empty());
        assert_eq!(low.Metric, 1);
        assert_eq!(low.DestinationPrefix.PrefixLength, 1);
        assert_eq!(unsafe { low.NextHop.Ipv4.sin_addr.S_un.S_addr }, 0);
    }

    #[test]
    fn underlay_interface_option_is_exact_network_byte_order() {
        assert_eq!(
            interface_index_option_value(0x0102_0304).to_ne_bytes(),
            [1, 2, 3, 4]
        );
        assert_ne!(interface_index_option_value(0x0102_0304), 0x0102_0304);
    }
}
