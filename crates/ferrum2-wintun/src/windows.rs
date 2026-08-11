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
    CancelMibChangeNotify2, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2,
    CreateUnicastIpAddressEntry, DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeMibTable,
    GetBestInterfaceEx, GetBestRoute2, GetIfTable2, GetIpForwardEntry2, GetIpForwardTable2,
    GetIpInterfaceEntry, GetUnicastIpAddressEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    NotifyIpInterfaceChange, NotifyRouteChange2, NotifyUnicastIpAddressChange, SetIpInterfaceEntry,
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
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects};

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
    interface_index: u32,
    destination: u32,
    prefix_length: u8,
    next_hop: u32,
    metric: u32,
    source: Option<u32>,
}

/// Immutable, redacted IPv4 socket-binding policy frozen before capture.
#[derive(Clone)]
pub struct UnderlayPolicy {
    fixed: Arc<[(std::net::SocketAddrV4, RouteFingerprint)]>,
    default: Option<RouteFingerprint>,
}

impl UnderlayPolicy {
    pub fn bind_fixed<T: AsRawSocket>(
        &self,
        socket: &T,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), Error> {
        let route = self
            .fixed
            .iter()
            .find_map(|(candidate, route)| (*candidate == endpoint).then_some(*route))
            .ok_or(Error)?;
        bind_ipv4_socket(socket, route.interface_index)
    }

    pub fn bind_default<T: AsRawSocket>(&self, socket: &T) -> Result<(), Error> {
        bind_ipv4_socket(socket, self.default.ok_or(Error)?.interface_index)
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
}

struct NotificationOwners {
    handles: Vec<HANDLE>,
    context: Box<NotificationContext>,
}

impl NotificationOwners {
    fn generation(&self) -> u64 {
        self.context.generation.load(Ordering::Acquire)
    }

    fn set_owned_luid(&self, luid: NET_LUID_LH) {
        self.context
            .owned_luid
            .store(unsafe { luid.Value }, Ordering::Release);
    }

    fn cancel_all(&mut self) -> bool {
        let mut failed = false;
        while let Some(handle) = self.handles.pop() {
            failed |= unsafe { CancelMibChangeNotify2(handle) } != ERROR_SUCCESS;
        }
        failed
    }
}

impl Drop for NotificationOwners {
    fn drop(&mut self) {
        let _ = self.cancel_all();
    }
}

unsafe extern "system" fn route_changed(
    context: *const c_void,
    row: *const MIB_IPFORWARD_ROW2,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    let own = context.owned_luid.load(Ordering::Acquire);
    if row.is_null() || own == 0 || unsafe { (*row).InterfaceLuid.Value } != own {
        context.generation.fetch_add(1, Ordering::AcqRel);
    }
}

unsafe extern "system" fn interface_changed(
    context: *const c_void,
    row: *const MIB_IPINTERFACE_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    let own = context.owned_luid.load(Ordering::Acquire);
    if row.is_null() || own == 0 || unsafe { (*row).InterfaceLuid.Value } != own {
        context.generation.fetch_add(1, Ordering::AcqRel);
    }
}

unsafe extern "system" fn address_changed(
    context: *const c_void,
    row: *const MIB_UNICASTIPADDRESS_ROW,
    _: i32,
) {
    let context = unsafe { &*context.cast::<NotificationContext>() };
    let own = context.owned_luid.load(Ordering::Acquire);
    if row.is_null() || own == 0 || unsafe { (*row).InterfaceLuid.Value } != own {
        context.generation.fetch_add(1, Ordering::AcqRel);
    }
}

struct ManagedState {
    notifications: NotificationOwners,
    snapshot_generation: u64,
    policy: UnderlayPolicy,
    capture_routes: Vec<Ipv4Prefix>,
    pending_route: Option<MIB_IPFORWARD_ROW2>,
    routes: Vec<MIB_IPFORWARD_ROW2>,
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
            .and_then(|()| owner.finish_managed());
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
    pub fn wait(&self, timeout: Duration) -> Result<bool, Error> {
        let _wait = self.session_journal.begin_wait()?;
        let read = self.session.as_ref().ok_or(Error)?.read_event;
        let handles = [self.stop.0.0, read];
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        match unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, millis) } {
            WAIT_OBJECT_0 => Ok(false),
            value if value == WAIT_OBJECT_0 + 1 => Ok(true),
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
        let Some(config) = self.config.managed_ipv4().cloned() else {
            return Ok(());
        };
        let notifications = subscribe_network_changes()?;
        let snapshot_generation = notifications.generation();
        let policy = snapshot_underlay(&config)?;
        self.managed = Some(ManagedState {
            notifications,
            snapshot_generation,
            policy,
            capture_routes: config.capture_routes().to_vec(),
            pending_route: None,
            routes: Vec::with_capacity(config.capture_routes().len()),
        });
        Ok(())
    }

    fn finish_managed(&mut self) -> Result<(), Error> {
        let Some(state) = self.managed.as_mut() else {
            return Ok(());
        };
        state.notifications.set_owned_luid(self.luid);
        for prefix in state.capture_routes.clone() {
            let row = capture_route_row(self.luid, self.interface_index, prefix);
            require_route_absent(&row)?;
            if unsafe { CreateIpForwardEntry2(&row) } != ERROR_SUCCESS {
                return Err(Error);
            }
            state.pending_route = Some(row);
            let current = read_owned_route(&row)?;
            if !route_matches(&row, &current) {
                return Err(Error);
            }
            state.routes.push(state.pending_route.take().ok_or(Error)?);
        }
        if state.notifications.generation() != state.snapshot_generation
            || !underlay_matches(&state.policy)?
        {
            return Err(Error);
        }
        Ok(())
    }

    fn cleanup_inner(&mut self) -> bool {
        cleanup_transaction(&mut PlatformCleanup(self))
    }
}

fn subscribe_network_changes() -> Result<NotificationOwners, Error> {
    let context = Box::new(NotificationContext {
        generation: AtomicU64::new(0),
        owned_luid: AtomicU64::new(0),
    });
    let context_pointer = (&raw const *context).cast::<c_void>();
    let mut owners = NotificationOwners {
        handles: Vec::with_capacity(3),
        context,
    };
    let mut handle = null_mut();
    if unsafe {
        NotifyRouteChange2(
            AF_INET,
            Some(route_changed),
            context_pointer,
            false,
            &mut handle,
        )
    } != ERROR_SUCCESS
        || handle.is_null()
    {
        return Err(Error);
    }
    owners.handles.push(handle);
    handle = null_mut();
    if unsafe {
        NotifyIpInterfaceChange(
            AF_INET,
            Some(interface_changed),
            context_pointer,
            false,
            &mut handle,
        )
    } != ERROR_SUCCESS
        || handle.is_null()
    {
        return Err(Error);
    }
    owners.handles.push(handle);
    handle = null_mut();
    if unsafe {
        NotifyUnicastIpAddressChange(
            AF_INET,
            Some(address_changed),
            context_pointer,
            false,
            &mut handle,
        )
    } != ERROR_SUCCESS
        || handle.is_null()
    {
        return Err(Error);
    }
    owners.handles.push(handle);
    Ok(owners)
}

fn snapshot_underlay(config: &crate::ManagedIpv4Config) -> Result<UnderlayPolicy, Error> {
    let interfaces = eligible_interfaces()?;
    let mut fixed = Vec::with_capacity(config.physical_endpoints().len());
    for endpoint in config.physical_endpoints() {
        let destination = ipv4_sockaddr(*endpoint.ip());
        let mut index = 0;
        if unsafe { GetBestInterfaceEx((&raw const destination).cast::<SOCKADDR>(), &mut index) }
            != ERROR_SUCCESS
            || !interfaces
                .iter()
                .any(|candidate| candidate.InterfaceIndex == index)
        {
            return Err(Error);
        }
        fixed.push((*endpoint, constrained_route(*endpoint.ip(), index, true)?));
    }
    let default = if config.needs_default_binder() {
        Some(unique_default_route(&interfaces)?)
    } else {
        None
    };
    Ok(UnderlayPolicy {
        fixed: fixed.into(),
        default,
    })
}

fn underlay_matches(policy: &UnderlayPolicy) -> Result<bool, Error> {
    let interfaces = eligible_interfaces()?;
    for (endpoint, expected) in policy.fixed.iter() {
        let destination = ipv4_sockaddr(*endpoint.ip());
        let mut index = 0;
        if unsafe { GetBestInterfaceEx((&raw const destination).cast::<SOCKADDR>(), &mut index) }
            != ERROR_SUCCESS
            || index != expected.interface_index
            || constrained_route(*endpoint.ip(), index, true)? != *expected
        {
            return Ok(false);
        }
    }
    if let Some(expected) = policy.default
        && unique_default_route(&interfaces)? != expected
    {
        return Ok(false);
    }
    Ok(true)
}

fn eligible_interfaces() -> Result<Vec<MIB_IF_ROW2>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows
        .iter()
        .copied()
        .filter(|row| {
            row.InterfaceIndex != 0
                && row.Type
                    != windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
                && row.OperStatus == IfOperStatusUp
                && row.AdminStatus == NET_IF_ADMIN_STATUS_UP
                && row.MediaConnectState == MediaConnectStateConnected
                && row.InterfaceAndOperStatusFlags._bitfield & 1 == 1
        })
        .collect();
    drop(owner);
    Ok(result)
}

struct MibTable(*mut c_void);

impl Drop for MibTable {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0) };
    }
}

fn unique_default_route(interfaces: &[MIB_IF_ROW2]) -> Result<RouteFingerprint, Error> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut defaults = rows.iter().filter(|row| {
        interfaces
            .iter()
            .any(|candidate| candidate.InterfaceIndex == row.InterfaceIndex)
            && row.DestinationPrefix.PrefixLength == 0
            && unsafe { row.DestinationPrefix.Prefix.si_family } == AF_INET
            && unsafe { row.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr } == 0
    });
    let row = defaults.next().copied().ok_or(Error)?;
    if defaults.next().is_some() {
        return Err(Error);
    }
    let fingerprint = route_fingerprint(&row, None)?;
    drop(owner);
    Ok(fingerprint)
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
        let intended = state.pending_route.take().or_else(|| state.routes.pop())?;
        let mut current = route_key(&intended);
        match unsafe { GetIpForwardEntry2(&mut current) } {
            ERROR_NOT_FOUND => Some(false),
            ERROR_SUCCESS if route_matches(&intended, &current) => {
                let deleted = unsafe { DeleteIpForwardEntry2(&current) };
                let mut absent = route_key(&intended);
                let readback = unsafe { GetIpForwardEntry2(&mut absent) };
                Some(
                    deleted != ERROR_SUCCESS && deleted != ERROR_NOT_FOUND
                        || readback != ERROR_NOT_FOUND,
                )
            }
            _ => Some(true),
        }
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
            state.notifications.set_owned_luid(self.owner.luid);
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
        ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, Error, IpDadStateDeprecated,
        IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative,
        LoaderOperations, SessionJournal, SetupOperations, capture_route_row,
        classify_adapter_create_failure, cleanup_transaction, dad_snapshot,
        finish_setup_transaction, interface_index_option_value, load_transaction, require_exports,
        route_matches, setup_transaction, validate_artifact,
    };
    use crate::Ipv4Prefix;

    struct InjectedSetup {
        fail_at: Option<usize>,
        cleanup_fail_at: Option<usize>,
        idle: bool,
        calls: Vec<&'static str>,
        resources: Vec<&'static str>,
        notifications: bool,
        routes: Vec<&'static str>,
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
        let mut replacement = low;
        replacement.Metric = 2;
        assert!(!route_matches(&low, &replacement));

        let mut cleanup = InjectedSetup {
            fail_at: None,
            cleanup_fail_at: Some(1),
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            routes: Vec::new(),
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut cleanup).expect("complete adapter setup");
        cleanup.notifications = true;
        cleanup.routes.extend(["low-route", "high-route"]);
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
