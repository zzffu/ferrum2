use std::cell::Cell;
use std::ffi::{OsString, c_void};
use std::fmt;
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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ferrum2_runtime::{
    InterfaceBinding, NetworkFamily, NetworkInterfaceCatalog as RuntimeNetworkInterfaceCatalog,
    NetworkInterfaceCatalogError, NetworkInterfaceKind, NetworkInterfaceObservation,
    ResolvedInterface, ResolvedSocketBinder, SystemBestRoute,
};
use socket2::Socket;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW,
    ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND,
    FWP_E_SESSION_ABORTED, FWP_E_SUBLAYER_NOT_FOUND, FreeLibrary, GetLastError, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings, FreeMibTable,
    GetBestInterfaceEx, GetBestRoute2, GetIfTable2, GetInterfaceDnsSettings, GetIpForwardEntry2,
    GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressEntry, GetUnicastIpAddressTable,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, NotifyIpInterfaceChange,
    NotifyRouteChange2, NotifyUnicastIpAddressChange, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, NET_LUID_LH,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT64, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IP_UNICAST_IF,
    IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IpDadStateDeprecated, IpDadStateDuplicate,
    IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative, IpPrefixOriginManual,
    IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, NL_DAD_STATE, NlroManual, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET, bind as winsock_bind, setsockopt,
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
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::GUID;

use crate::{
    ABI_EXPORTS, AdapterConfig, CreateError, DLL_BYTES, DLL_SHA256, Error, IpPrefix,
    ManagedStateDamage, ManagedTunHealth, NetworkChangeOutcome, SendOutcome, WaitOutcome,
};

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
    destination: std::net::IpAddr,
    prefix_length: u8,
    next_hop: std::net::IpAddr,
    metric: u32,
    source: Option<std::net::IpAddr>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InterfaceIdentity {
    luid: u64,
    index: u32,
}

/// Read-only Windows interface catalog used by the shared runtime resolver.
///
/// A catalog created from an [`Adapter`] classifies that exact LUID/index pair as the managed TUN,
/// so automatic underlay selection cannot feed outbound sockets back into Ferrum2's own adapter.
#[derive(Clone, Copy, Default)]
pub struct WindowsNetworkInterfaceCatalog {
    managed_tun: Option<InterfaceIdentity>,
}

impl WindowsNetworkInterfaceCatalog {
    /// Builds a catalog without a managed TUN identity.
    ///
    /// This is suitable for processes that do not own a Wintun adapter. TUN-owning callers should
    /// obtain the catalog from [`Adapter::network_interface_catalog`] instead.
    pub const fn system() -> Self {
        Self { managed_tun: None }
    }

    /// Builds a catalog that classifies one exact managed TUN LUID/index pair.
    pub fn excluding_managed_tun(stable_id: u64, index: u32) -> Result<Self, Error> {
        if stable_id == 0 || index == 0 {
            return Err(Error::invalid_input());
        }
        Ok(Self {
            managed_tun: Some(InterfaceIdentity {
                luid: stable_id,
                index,
            }),
        })
    }
}

impl fmt::Debug for WindowsNetworkInterfaceCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNetworkInterfaceCatalog")
            .field("managed_tun", &self.managed_tun.is_some())
            .finish()
    }
}

impl RuntimeNetworkInterfaceCatalog for WindowsNetworkInterfaceCatalog {
    fn read_interfaces(
        &self,
    ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
        read_network_interface_observations(self.managed_tun)
            .map_err(|_| NetworkInterfaceCatalogError)
    }

    fn system_best_route(
        &self,
        destination: std::net::SocketAddr,
    ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
        system_best_route(destination, self.managed_tun).map_err(|_| NetworkInterfaceCatalogError)
    }
}

/// Immutable, redacted dual-stack socket-binding policy frozen before capture.
#[derive(Clone)]
pub struct UnderlayPolicy {
    fixed: Arc<[(std::net::SocketAddr, RouteFingerprint)]>,
    target_binder: bool,
    valid: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    accepted_generation: Arc<AtomicU64>,
    owned_luid: Arc<AtomicU64>,
    owned_index: Arc<AtomicU32>,
}

impl UnderlayPolicy {
    pub fn bind_fixed<T: AsRawSocket>(
        &self,
        socket: &T,
        endpoint: std::net::SocketAddr,
    ) -> Result<(), Error> {
        bind_fixed_with(self, endpoint, &mut PlatformSocketBinder(socket))
    }

    pub fn bind_target<T: AsRawSocket>(
        &self,
        socket: &T,
        target: std::net::SocketAddr,
    ) -> Result<(), Error> {
        bind_target_with(
            self,
            target,
            &mut PlatformUnderlay,
            &mut PlatformSocketBinder(socket),
        )
    }

    /// Returns whether this snapshot is still the currently accepted network generation.
    pub fn generation_is_current(&self) -> bool {
        let generation = self.generation.load(Ordering::Acquire);
        self.valid.load(Ordering::Acquire)
            && self.accepted_generation.load(Ordering::Acquire) == generation
    }

    fn begin_binding(&self) -> Result<u64, Error> {
        let generation = self.generation.load(Ordering::Acquire);
        self.require_generation(generation)?;
        Ok(generation)
    }

    fn require_generation(&self, generation: u64) -> Result<(), Error> {
        (self.valid.load(Ordering::Acquire)
            && self.accepted_generation.load(Ordering::Acquire) == generation
            && self.generation.load(Ordering::Acquire) == generation)
            .then_some(())
            .ok_or(Error)
    }

    fn accept_generation(&self, generation: u64) {
        self.accepted_generation
            .store(generation, Ordering::Release);
    }

    fn set_owned_identity(&self, owned: InterfaceIdentity) -> Result<(), Error> {
        if owned.luid == 0 || owned.index == 0 {
            return Err(Error);
        }
        match self
            .owned_index
            .compare_exchange(0, owned.index, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {}
            Err(current) if current == owned.index => {}
            Err(_) => return Err(Error),
        }
        match self
            .owned_luid
            .compare_exchange(0, owned.luid, Ordering::Release, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(current) if current == owned.luid => Ok(()),
            Err(_) => Err(Error),
        }
    }

    fn owned_identity(&self) -> Result<InterfaceIdentity, Error> {
        let luid = self.owned_luid.load(Ordering::Acquire);
        let index = self.owned_index.load(Ordering::Acquire);
        if luid == 0 || index == 0 {
            Err(Error)
        } else {
            Ok(InterfaceIdentity { luid, index })
        }
    }

    fn invalidate(&self) {
        self.valid.store(false, Ordering::Release);
    }
}

trait SocketBindingOperations {
    fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error>;
}

fn bind_fixed_with(
    policy: &UnderlayPolicy,
    endpoint: std::net::SocketAddr,
    binder: &mut impl SocketBindingOperations,
) -> Result<(), Error> {
    let generation = policy.begin_binding()?;
    let route = policy
        .fixed
        .iter()
        .find_map(|(candidate, route)| (*candidate == endpoint).then_some(*route))
        .ok_or(Error)?;
    if !same_ip_family(endpoint.ip(), route.destination) {
        return Err(Error);
    }
    policy.require_generation(generation)?;
    binder.bind(endpoint.ip(), route.interface_index)?;
    policy.require_generation(generation)
}

fn bind_target_with(
    policy: &UnderlayPolicy,
    target: std::net::SocketAddr,
    operations: &mut impl UnderlayOperations,
    binder: &mut impl SocketBindingOperations,
) -> Result<(), Error> {
    if !policy.target_binder {
        return Err(Error);
    }
    let generation = policy.begin_binding()?;
    let owned = policy.owned_identity()?;
    let interfaces = operations.eligible_interfaces(Some(owned))?;
    let mut selected = None::<(RouteFingerprint, u64)>;
    for identity in interfaces {
        let Ok(route) = operations.constrained_route(target, identity.index, true) else {
            continue;
        };
        if route.interface_luid != identity.luid
            || route.interface_index != identity.index
            || !same_ip_family(target.ip(), route.destination)
            || route
                .source
                .is_none_or(|source| !same_ip_family(target.ip(), source))
        {
            continue;
        }
        let interface_metric = operations.interface_metric(target.ip(), identity.index)?;
        let effective_metric = u64::from(route.metric) + u64::from(interface_metric);
        let preferred = selected.as_ref().is_none_or(|(current, current_metric)| {
            route.prefix_length > current.prefix_length
                || (route.prefix_length == current.prefix_length
                    && (effective_metric < *current_metric
                        || (effective_metric == *current_metric
                            && route.interface_index < current.interface_index)))
        });
        if preferred {
            selected = Some((route, effective_metric));
        }
    }
    let (route, _) = selected.ok_or(Error)?;
    policy.require_generation(generation)?;
    binder.bind(target.ip(), route.interface_index)?;
    policy.require_generation(generation)
}

fn same_ip_family(left: std::net::IpAddr, right: std::net::IpAddr) -> bool {
    matches!(
        (left, right),
        (std::net::IpAddr::V4(_), std::net::IpAddr::V4(_))
            | (std::net::IpAddr::V6(_), std::net::IpAddr::V6(_))
    )
}

struct PlatformSocketBinder<'a, T>(&'a T);

impl<T: AsRawSocket> SocketBindingOperations for PlatformSocketBinder<'_, T> {
    fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error> {
        bind_socket(self.0, family, interface_index)
    }
}

/// Applies one shared runtime interface decision to an unconnected Windows socket.
///
/// The family-specific `IP_UNICAST_IF`/`IPV6_UNICAST_IF` constraint is installed first. When the
/// decision carries an explicit source address, the socket is then bound to that address and an
/// ephemeral port. Generation validation remains owned by the runtime resolver's prepare/commit
/// boundary; callers must discard the socket when this function or that commit fails.
pub fn bind_resolved_socket<T: AsRawSocket>(
    socket: &T,
    destination: std::net::SocketAddr,
    resolved: &ResolvedInterface,
) -> Result<(), Error> {
    bind_resolved_socket_with(
        destination,
        resolved,
        &mut PlatformResolvedSocketBinder(socket),
    )
}

/// Production adapter from the shared runtime socket service to the reviewed Windows boundary.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsResolvedSocketBinder;

impl ResolvedSocketBinder for WindowsResolvedSocketBinder {
    type Error = Error;

    fn bind_resolved_socket(
        &self,
        socket: &Socket,
        destination: std::net::SocketAddr,
        resolved: &ResolvedInterface,
    ) -> Result<(), Self::Error> {
        bind_resolved_socket(socket, destination, resolved)
    }
}

trait ResolvedSocketBindingOperations {
    fn bind_interface(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<(), Error>;
    fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error>;
}

fn bind_resolved_socket_with(
    destination: std::net::SocketAddr,
    resolved: &ResolvedInterface,
    operations: &mut impl ResolvedSocketBindingOperations,
) -> Result<(), Error> {
    let family = NetworkFamily::of(destination.ip());
    let binding = resolved.binding();
    if !binding.supports(family) {
        return Err(Error::invalid_input());
    }
    let source = resolved.source_address();
    if source.is_some_and(|source| {
        NetworkFamily::of(source) != family || !binding.addresses().contains(&source)
    }) {
        return Err(Error::invalid_input());
    }

    operations.bind_interface(destination.ip(), binding.index())?;
    if let Some(source) = source {
        let scope_id = match source {
            std::net::IpAddr::V6(address) if address.is_unicast_link_local() => binding.index(),
            _ => 0,
        };
        operations.bind_source(std::net::SocketAddr::new(source, 0).with_scope_id(scope_id))?;
    }
    Ok(())
}

trait SocketAddrScopeExt {
    fn with_scope_id(self, scope_id: u32) -> Self;
}

impl SocketAddrScopeExt for std::net::SocketAddr {
    fn with_scope_id(self, scope_id: u32) -> Self {
        match self {
            Self::V4(_) => self,
            Self::V6(address) => Self::V6(std::net::SocketAddrV6::new(
                *address.ip(),
                address.port(),
                address.flowinfo(),
                scope_id,
            )),
        }
    }
}

struct PlatformResolvedSocketBinder<'a, T>(&'a T);

impl<T: AsRawSocket> ResolvedSocketBindingOperations for PlatformResolvedSocketBinder<'_, T> {
    fn bind_interface(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<(), Error> {
        bind_socket(self.0, family, interface_index)
    }

    fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error> {
        bind_source_socket(self.0, source)
    }
}

fn bind_socket<T: AsRawSocket>(
    socket: &T,
    family: std::net::IpAddr,
    interface_index: u32,
) -> Result<(), Error> {
    let (level, option, value) = interface_socket_option(family, interface_index);
    let status = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            level,
            option,
            (&raw const value).cast(),
            i32::try_from(std::mem::size_of_val(&value)).map_err(|_| Error)?,
        )
    };
    if status == 0 { Ok(()) } else { Err(Error) }
}

fn bind_source_socket<T: AsRawSocket>(
    socket: &T,
    source: std::net::SocketAddr,
) -> Result<(), Error> {
    let raw = socket_addr_sockaddr(source);
    let length = match source {
        std::net::SocketAddr::V4(_) => std::mem::size_of::<SOCKADDR_IN>(),
        std::net::SocketAddr::V6(_) => std::mem::size_of::<SOCKADDR_IN6>(),
    };
    let status = unsafe {
        winsock_bind(
            socket.as_raw_socket() as usize,
            (&raw const raw).cast::<SOCKADDR>(),
            i32::try_from(length).map_err(|_| Error)?,
        )
    };
    if status == 0 { Ok(()) } else { Err(Error) }
}

fn interface_socket_option(family: std::net::IpAddr, interface_index: u32) -> (i32, i32, u32) {
    match family {
        std::net::IpAddr::V4(_) => (
            IPPROTO_IP,
            IP_UNICAST_IF,
            ipv4_interface_index_option_value(interface_index),
        ),
        std::net::IpAddr::V6(_) => (
            IPPROTO_IPV6,
            IPV6_UNICAST_IF,
            ipv6_interface_index_option_value(interface_index),
        ),
    }
}

const fn ipv4_interface_index_option_value(interface_index: u32) -> u32 {
    interface_index.to_be()
}

const fn ipv6_interface_index_option_value(interface_index: u32) -> u32 {
    interface_index
}

struct NotificationContext {
    generation: Arc<AtomicU64>,
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
            generation: Arc::new(AtomicU64::new(0)),
            owned_luid: AtomicU64::new(0),
            provisional_luid: AtomicU64::new(0),
            callbacks_in_flight: AtomicU64::new(0),
            monitor_runtime: AtomicBool::new(false),
            wake,
            #[cfg(test)]
            drain_wait_observed: AtomicBool::new(false),
        }
    }

    fn observe_raw(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_owner(&self) {
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

const NOTIFICATION_QUIESCENCE: Duration = Duration::from_millis(350);
const NOTIFICATION_QUIESCENCE_POLL: Duration = Duration::from_millis(25);

impl NotificationOwners {
    fn generation(&self) -> u64 {
        self.context
            .as_ref()
            .expect("live notifications retain their callback context")
            .generation
            .load(Ordering::Acquire)
    }

    fn generation_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(
            &self
                .context
                .as_ref()
                .expect("live notifications retain their callback context")
                .generation,
        )
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

    fn wait_until_quiescent(&self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), Error> {
        let mut observed = self.generation();
        let mut quiet_since = Instant::now();
        loop {
            if cancelled.load(Ordering::Acquire) {
                return Err(Error);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error);
            }
            let current = self.generation();
            if current != observed {
                observed = current;
                quiet_since = now;
            }
            let quiet_remaining =
                NOTIFICATION_QUIESCENCE.saturating_sub(now.saturating_duration_since(quiet_since));
            if quiet_remaining.is_zero() {
                return Ok(());
            }
            std::thread::sleep(
                NOTIFICATION_QUIESCENCE_POLL
                    .min(quiet_remaining)
                    .min(deadline.saturating_duration_since(now)),
            );
        }
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
    context.observe_raw();
    if context.monitor_runtime.load(Ordering::Acquire) {
        context.wake_owner();
        return;
    }
    if luid == 0 {
        context.wake_owner();
        return;
    }
    let owned = context.owned_luid.load(Ordering::SeqCst);
    if owned != 0 {
        if owned != luid {
            context.wake_owner();
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
        context.wake_owner();
    }
}

const STRICT_ROUTE_SESSION_KEY: GUID = GUID::from_u128(0x8ea35b4e_6629_4e26_9776_95c5bf9c6b01);
const STRICT_ROUTE_SUBLAYER_KEY: GUID = GUID::from_u128(0xddbc2fa2_d52f_4a79_8a63_8446c308cf02);
const STRICT_ROUTE_SUBLAYER_WEIGHT: u16 = 0x7fff;
const STRICT_ROUTE_PERMIT_WEIGHT: u8 = 15;
const STRICT_ROUTE_BLOCK_WEIGHT: u8 = 5;
const STRICT_ROUTE_SESSION_NAME: &str = "Ferrum2 strict route dynamic session";
const STRICT_ROUTE_SUBLAYER_NAME: &str = "Ferrum2 strict route";
const MAX_WFP_APP_ID_BYTES: usize = 131_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictRouteLayer {
    V4,
    V6,
}

impl StrictRouteLayer {
    const fn key(self) -> GUID {
        match self {
            Self::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictRouteAction {
    Permit,
    Block,
}

impl StrictRouteAction {
    const fn raw(self) -> u32 {
        match self {
            Self::Permit => FWP_ACTION_PERMIT,
            Self::Block => FWP_ACTION_BLOCK,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StrictRouteRuleKind {
    AppPermitV4,
    AppPermitV6,
    TunPermitV4,
    TunPermitV6,
    FamilyBlockV4,
    FamilyBlockV6,
    DnsTcpBlockV4,
    DnsUdpBlockV4,
    DnsTcpBlockV6,
    DnsUdpBlockV6,
}

impl StrictRouteRuleKind {
    const fn key(self) -> GUID {
        let value = match self {
            Self::AppPermitV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701001,
            Self::AppPermitV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701002,
            Self::TunPermitV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701003,
            Self::TunPermitV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701004,
            Self::FamilyBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701005,
            Self::FamilyBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701006,
            Self::DnsTcpBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701007,
            Self::DnsUdpBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701008,
            Self::DnsTcpBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701009,
            Self::DnsUdpBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e870100a,
        };
        GUID::from_u128(value)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AppPermitV4 => "Ferrum2 app permit IPv4",
            Self::AppPermitV6 => "Ferrum2 app permit IPv6",
            Self::TunPermitV4 => "Ferrum2 TUN permit IPv4",
            Self::TunPermitV6 => "Ferrum2 TUN permit IPv6",
            Self::FamilyBlockV4 => "Ferrum2 family block IPv4",
            Self::FamilyBlockV6 => "Ferrum2 family block IPv6",
            Self::DnsTcpBlockV4 => "Ferrum2 DNS TCP block IPv4",
            Self::DnsUdpBlockV4 => "Ferrum2 DNS UDP block IPv4",
            Self::DnsTcpBlockV6 => "Ferrum2 DNS TCP block IPv6",
            Self::DnsUdpBlockV6 => "Ferrum2 DNS UDP block IPv6",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StrictRouteCondition {
    AppId(Box<[u8]>),
    LocalInterfaceLuid(u64),
    IpProtocol(u8),
    RemotePort(u16),
}

impl StrictRouteCondition {
    const fn field_key(&self) -> GUID {
        match self {
            Self::AppId(_) => FWPM_CONDITION_ALE_APP_ID,
            Self::LocalInterfaceLuid(_) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
            Self::IpProtocol(_) => FWPM_CONDITION_IP_PROTOCOL,
            Self::RemotePort(_) => FWPM_CONDITION_IP_REMOTE_PORT,
        }
    }

    const fn data_type(&self) -> i32 {
        match self {
            Self::AppId(_) => FWP_BYTE_BLOB_TYPE,
            Self::LocalInterfaceLuid(_) => FWP_UINT64,
            Self::IpProtocol(_) => FWP_UINT8,
            Self::RemotePort(_) => FWP_UINT16,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StrictRouteRule {
    kind: StrictRouteRuleKind,
    layer: StrictRouteLayer,
    action: StrictRouteAction,
    weight: u8,
    conditions: Box<[StrictRouteCondition]>,
}

fn strict_route_rules(
    has_ipv4: bool,
    has_ipv6: bool,
    has_managed_dns: bool,
    app_id: &[u8],
    interface_luid: u64,
) -> Result<Vec<StrictRouteRule>, Error> {
    if (!has_ipv4 && !has_ipv6)
        || app_id.is_empty()
        || app_id.len() > MAX_WFP_APP_ID_BYTES
        || interface_luid == 0
    {
        return Err(Error);
    }
    let mut rules = Vec::with_capacity(10);
    let mut push = |kind, layer, action, weight, conditions| {
        rules.push(StrictRouteRule {
            kind,
            layer,
            action,
            weight,
            conditions,
        });
    };
    push(
        StrictRouteRuleKind::AppPermitV4,
        StrictRouteLayer::V4,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::AppId(app_id.into())]),
    );
    push(
        StrictRouteRuleKind::AppPermitV6,
        StrictRouteLayer::V6,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::AppId(app_id.into())]),
    );
    push(
        StrictRouteRuleKind::TunPermitV4,
        StrictRouteLayer::V4,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::LocalInterfaceLuid(interface_luid)]),
    );
    push(
        StrictRouteRuleKind::TunPermitV6,
        StrictRouteLayer::V6,
        StrictRouteAction::Permit,
        STRICT_ROUTE_PERMIT_WEIGHT,
        Box::new([StrictRouteCondition::LocalInterfaceLuid(interface_luid)]),
    );
    if !has_ipv4 {
        push(
            StrictRouteRuleKind::FamilyBlockV4,
            StrictRouteLayer::V4,
            StrictRouteAction::Block,
            STRICT_ROUTE_BLOCK_WEIGHT,
            Box::new([]),
        );
    }
    if !has_ipv6 {
        push(
            StrictRouteRuleKind::FamilyBlockV6,
            StrictRouteLayer::V6,
            StrictRouteAction::Block,
            STRICT_ROUTE_BLOCK_WEIGHT,
            Box::new([]),
        );
    }
    if has_managed_dns {
        for (kind, layer, protocol) in [
            (StrictRouteRuleKind::DnsTcpBlockV4, StrictRouteLayer::V4, 6),
            (StrictRouteRuleKind::DnsUdpBlockV4, StrictRouteLayer::V4, 17),
            (StrictRouteRuleKind::DnsTcpBlockV6, StrictRouteLayer::V6, 6),
            (StrictRouteRuleKind::DnsUdpBlockV6, StrictRouteLayer::V6, 17),
        ] {
            push(
                kind,
                layer,
                StrictRouteAction::Block,
                STRICT_ROUTE_BLOCK_WEIGHT,
                Box::new([
                    StrictRouteCondition::IpProtocol(protocol),
                    StrictRouteCondition::RemotePort(53),
                ]),
            );
        }
    }
    Ok(rules)
}

trait StrictRouteOperations {
    type Session;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error>;
    fn app_id(&mut self) -> Result<Box<[u8]>, Error>;
    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &StrictRouteRule,
    ) -> Result<u64, Error>;
    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error>;
    fn filter_matches(
        &self,
        session: &Self::Session,
        id: u64,
        rule: &StrictRouteRule,
    ) -> Result<bool, Error>;
    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error>;
}

struct StrictRouteSession<O: StrictRouteOperations> {
    operations: O,
    session: Option<O::Session>,
    expected_filters: Vec<(u64, StrictRouteRule)>,
}

impl<O: StrictRouteOperations> StrictRouteSession<O> {
    fn open(mut operations: O) -> Result<Self, Error> {
        let session = operations.open_dynamic_session()?;
        Ok(Self {
            operations,
            session: Some(session),
            expected_filters: Vec::new(),
        })
    }

    fn install(
        &mut self,
        has_ipv4: bool,
        has_ipv6: bool,
        has_managed_dns: bool,
        interface_luid: u64,
    ) -> Result<(), Error> {
        if !self.expected_filters.is_empty() {
            return Err(Error);
        }
        let app_id = self.operations.app_id()?;
        let rules =
            strict_route_rules(has_ipv4, has_ipv6, has_managed_dns, &app_id, interface_luid)?;
        let session = self.session.as_mut().ok_or(Error)?;
        self.operations.begin_transaction(session)?;
        let mut installed = Vec::with_capacity(rules.len());
        let transaction = (|| {
            self.operations.add_sublayer(session)?;
            for rule in rules {
                let id = self.operations.add_filter(session, &rule)?;
                if id == 0 {
                    return Err(Error);
                }
                installed.push((id, rule));
            }
            self.operations.commit_transaction(session)
        })();
        if transaction.is_err() {
            let _ = self.operations.abort_transaction(session);
            return Err(Error);
        }
        self.expected_filters = installed;
        Ok(())
    }

    fn health(&self) -> Result<bool, Error> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if self.expected_filters.is_empty() || !self.operations.sublayer_matches(session)? {
            return Ok(false);
        }
        for (id, rule) in &self.expected_filters {
            if !self.operations.filter_matches(session, *id, rule)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn close(&mut self) -> Result<(), Error> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        self.operations.close_dynamic_session(session)?;
        self.session = None;
        self.expected_filters.clear();
        Ok(())
    }
}

impl<O: StrictRouteOperations> Drop for StrictRouteSession<O> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn strict_route_state_matches<O: StrictRouteOperations>(
    intent: bool,
    session: Option<&StrictRouteSession<O>>,
) -> Result<bool, Error> {
    match (intent, session) {
        (false, None) => Ok(true),
        (true, Some(session)) => session.health(),
        _ => Ok(false),
    }
}

type PlatformStrictRouteSession = StrictRouteSession<PlatformStrictRouteOperations>;

struct PlatformStrictRouteOperations;

struct FwpmOwned<T>(*mut T);

impl<T> FwpmOwned<T> {
    fn get(&self) -> Result<&T, Error> {
        unsafe { self.0.as_ref() }.ok_or(Error)
    }
}

impl<T> Drop for FwpmOwned<T> {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        let mut allocation = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut allocation) };
        self.0 = null_mut();
    }
}

fn guid_matches(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

fn wfp_readback_present(status: u32, not_found: i32) -> Result<bool, Error> {
    match status {
        ERROR_SUCCESS => Ok(true),
        value if value == not_found as u32 || value == FWP_E_SESSION_ABORTED as u32 => Ok(false),
        _ => Err(Error),
    }
}

fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn raw_wide_matches(raw: *const u16, expected: &str) -> bool {
    if raw.is_null() {
        return false;
    }
    let expected = expected.encode_utf16().chain(Some(0));
    expected
        .enumerate()
        .all(|(index, unit)| unsafe { *raw.add(index) } == unit)
}

fn raw_strict_route_condition_matches(
    raw: &FWPM_FILTER_CONDITION0,
    expected: &StrictRouteCondition,
) -> bool {
    if raw.matchType != FWP_MATCH_EQUAL {
        return false;
    }
    match expected {
        StrictRouteCondition::AppId(expected) => {
            if !guid_matches(&raw.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
                || raw.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
            {
                return false;
            }
            let blob = unsafe { raw.conditionValue.Anonymous.byteBlob };
            let Some(blob) = (unsafe { blob.as_ref() }) else {
                return false;
            };
            let Ok(size) = usize::try_from(blob.size) else {
                return false;
            };
            if size != expected.len() || size > MAX_WFP_APP_ID_BYTES || blob.data.is_null() {
                return false;
            }
            (unsafe { std::slice::from_raw_parts(blob.data, size) }) == expected.as_ref()
        }
        StrictRouteCondition::LocalInterfaceLuid(expected) => {
            if !guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_LOCAL_INTERFACE)
                || raw.conditionValue.r#type != FWP_UINT64
            {
                return false;
            }
            let luid = unsafe { raw.conditionValue.Anonymous.uint64 };
            unsafe { luid.as_ref() }.is_some_and(|current| current == expected)
        }
        StrictRouteCondition::IpProtocol(expected) => {
            guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_PROTOCOL)
                && raw.conditionValue.r#type == FWP_UINT8
                && unsafe { raw.conditionValue.Anonymous.uint8 } == *expected
        }
        StrictRouteCondition::RemotePort(expected) => {
            guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
                && raw.conditionValue.r#type == FWP_UINT16
                && unsafe { raw.conditionValue.Anonymous.uint16 } == *expected
        }
    }
}

fn raw_strict_route_filter_matches(
    id: u64,
    raw: &FWPM_FILTER0,
    expected: &StrictRouteRule,
) -> bool {
    let Ok(condition_count) = usize::try_from(raw.numFilterConditions) else {
        return false;
    };
    if raw.filterId != id
        || !guid_matches(&raw.filterKey, &expected.kind.key())
        || !raw_wide_matches(raw.displayData.name, expected.kind.name())
        || raw.flags != 0
        || !raw.providerKey.is_null()
        || raw.providerData.size != 0
        || !raw.providerData.data.is_null()
        || !guid_matches(&raw.layerKey, &expected.layer.key())
        || !guid_matches(&raw.subLayerKey, &STRICT_ROUTE_SUBLAYER_KEY)
        || raw.weight.r#type != FWP_UINT8
        || unsafe { raw.weight.Anonymous.uint8 } != expected.weight
        || raw.action.r#type != expected.action.raw()
        || condition_count != expected.conditions.len()
        || condition_count > 2
        || (condition_count != 0 && raw.filterCondition.is_null())
    {
        return false;
    }
    let raw_conditions = if condition_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(raw.filterCondition, condition_count) }
    };
    expected.conditions.iter().all(|expected| {
        raw_conditions
            .iter()
            .any(|raw| raw_strict_route_condition_matches(raw, expected))
    })
}

impl StrictRouteOperations for PlatformStrictRouteOperations {
    type Session = HANDLE;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
        let mut session_name = wide_string(STRICT_ROUTE_SESSION_NAME);
        let session = FWPM_SESSION0 {
            sessionKey: STRICT_ROUTE_SESSION_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: session_name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..FWPM_SESSION0::default()
        };
        let mut engine = null_mut();
        let status =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) };
        if status != ERROR_SUCCESS {
            if !engine.is_null() {
                let _ = unsafe { FwpmEngineClose0(engine) };
            }
            return Err(Error);
        }
        if engine.is_null() {
            Err(Error)
        } else {
            Ok(engine)
        }
    }

    fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
        let executable = current_executable()?;
        let executable = wide(&executable);
        let mut raw = null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut raw) };
        let allocation = FwpmOwned(raw);
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        let blob = allocation.get()?;
        let size = usize::try_from(blob.size).map_err(|_| Error)?;
        if size == 0 || size > MAX_WFP_APP_ID_BYTES || blob.data.is_null() {
            return Err(Error);
        }
        Ok(unsafe { std::slice::from_raw_parts(blob.data, size) }
            .to_vec()
            .into_boxed_slice())
    }

    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionBegin0(*session, 0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        let mut name = wide_string(STRICT_ROUTE_SUBLAYER_NAME);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: STRICT_ROUTE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            weight: STRICT_ROUTE_SUBLAYER_WEIGHT,
            ..FWPM_SUBLAYER0::default()
        };
        if unsafe { FwpmSubLayerAdd0(*session, &sublayer, null_mut()) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &StrictRouteRule,
    ) -> Result<u64, Error> {
        let mut luid_values = Vec::<Box<u64>>::new();
        let mut app_blobs = Vec::<Box<FWP_BYTE_BLOB>>::new();
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for condition in &rule.conditions {
            let value = match condition {
                StrictRouteCondition::AppId(app_id) => {
                    let size = u32::try_from(app_id.len()).map_err(|_| Error)?;
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size,
                        data: app_id.as_ptr().cast_mut(),
                    });
                    let value = FWP_CONDITION_VALUE0_0 {
                        byteBlob: blob.as_mut(),
                    };
                    app_blobs.push(blob);
                    value
                }
                StrictRouteCondition::LocalInterfaceLuid(luid) => {
                    let mut luid = Box::new(*luid);
                    let value = FWP_CONDITION_VALUE0_0 {
                        uint64: luid.as_mut(),
                    };
                    luid_values.push(luid);
                    value
                }
                StrictRouteCondition::IpProtocol(protocol) => {
                    FWP_CONDITION_VALUE0_0 { uint8: *protocol }
                }
                StrictRouteCondition::RemotePort(port) => FWP_CONDITION_VALUE0_0 { uint16: *port },
            };
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: condition.field_key(),
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: condition.data_type(),
                    Anonymous: value,
                },
            });
        }
        let mut name = wide_string(rule.kind.name());
        let filter = FWPM_FILTER0 {
            filterKey: rule.kind.key(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            layerKey: rule.layer.key(),
            subLayerKey: STRICT_ROUTE_SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: rule.weight },
            },
            numFilterConditions: u32::try_from(conditions.len()).map_err(|_| Error)?,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: rule.action.raw(),
                ..FWPM_ACTION0::default()
            },
            ..FWPM_FILTER0::default()
        };
        let mut id = 0_u64;
        let status = unsafe { FwpmFilterAdd0(*session, &filter, null_mut(), &mut id) };
        drop((luid_values, app_blobs));
        if status == ERROR_SUCCESS && id != 0 {
            Ok(id)
        } else {
            Err(Error)
        }
    }

    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionCommit0(*session) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionAbort0(*session) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status =
            unsafe { FwpmSubLayerGetByKey0(*session, &STRICT_ROUTE_SUBLAYER_KEY, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_SUBLAYER_NOT_FOUND)? {
            return Ok(false);
        }
        let sublayer = allocation.get()?;
        Ok(
            guid_matches(&sublayer.subLayerKey, &STRICT_ROUTE_SUBLAYER_KEY)
                && raw_wide_matches(sublayer.displayData.name, STRICT_ROUTE_SUBLAYER_NAME)
                && sublayer.flags == 0
                && sublayer.providerKey.is_null()
                && sublayer.providerData.size == 0
                && sublayer.providerData.data.is_null()
                && sublayer.weight == STRICT_ROUTE_SUBLAYER_WEIGHT,
        )
    }

    fn filter_matches(
        &self,
        session: &Self::Session,
        id: u64,
        rule: &StrictRouteRule,
    ) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status = unsafe { FwpmFilterGetById0(*session, id, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_FILTER_NOT_FOUND)? {
            return Ok(false);
        }
        Ok(raw_strict_route_filter_matches(id, allocation.get()?, rule))
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if session.is_null() {
            return Err(Error);
        }
        if unsafe { FwpmEngineClose0(*session) } != ERROR_SUCCESS {
            return Err(Error);
        }
        *session = null_mut();
        Ok(())
    }
}

struct ManagedState {
    notifications: NotificationOwners,
    validated_generation: u64,
    policy: UnderlayPolicy,
    capture_routes: Vec<IpPrefix>,
    pending_route: Option<MIB_IPFORWARD_ROW2>,
    routes: Vec<MIB_IPFORWARD_ROW2>,
    ipv4_dns_address: Option<std::net::Ipv4Addr>,
    ipv6_dns_address: Option<std::net::Ipv6Addr>,
    dns_interface: Option<GUID>,
    ipv4_dns: Option<ManagedDnsLease<Ipv4DnsSettings>>,
    ipv6_dns: Option<ManagedDnsLease<Ipv6DnsSettings>>,
    strict_route_intent: bool,
    // The dynamic engine belongs to the long-lived managed plane and closes only in full cleanup.
    strict_route: Option<PlatformStrictRouteSession>,
}

/// Safe RAII owner of the exact Wintun adapter, address, MTU, session and DLL transaction.
pub struct Adapter {
    config: AdapterConfig,
    library: Library,
    adapter: Option<WintunAdapter>,
    luid: NET_LUID_LH,
    interface_index: u32,
    mtus: [Option<MtuState>; 2],
    pending_address: Option<MIB_UNICASTIPADDRESS_ROW>,
    addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
    session: Option<SessionState>,
    session_journal: SessionJournal,
    stop: StopSignal,
    work: WorkSignal,
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
            create_event(true).map_err(|_| CreateError::operation())?,
        )));
        let work = WorkSignal(Arc::new(OwnedHandle(
            create_event(false).map_err(|_| CreateError::operation())?,
        )));
        let network_change = StopSignal(Arc::new(OwnedHandle(
            create_event(true).map_err(|_| CreateError::operation())?,
        )));
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
        WindowsNetworkInterfaceCatalog {
            managed_tun: Some(InterfaceIdentity {
                luid: unsafe { self.luid.Value },
                index: self.interface_index,
            }),
        }
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
        managed_device_health(
            self.adapter.is_some_and(|adapter| !adapter.is_null()),
            self.session
                .as_ref()
                .is_some_and(|session| !session.handle.is_null()),
            self.pending_address.is_none() && self.addresses.len() == expected_addresses,
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
        let handles = [self.stop.0.0, self.work.0.0, self.network_change.0.0, read];
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        let result = {
            let _wait = self.session_journal.begin_wait()?;
            unsafe { WaitForMultipleObjects(4, handles.as_ptr(), 0, millis) }
        };
        let outcome = classify_wait_result(result)?;
        if outcome == WaitOutcome::NetworkChanged
            && unsafe { ResetEvent(self.network_change.0.0) } == 0
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
        let current = read_ip_interface(self.luid, family)?;
        (current.NlMtu == row.NlMtu).then_some(()).ok_or(Error)
    }

    fn ipv4_address_row(&self) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
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

    fn ipv6_address_row(&self) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
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

    fn create_address(&mut self, row: MIB_UNICASTIPADDRESS_ROW) -> Result<(), Error> {
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

    fn wait_for_dad(&self, deadline: Instant, cancelled: &AtomicBool) -> Result<(), Error> {
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
        cleanup_transaction(&mut PlatformCleanup(self))
    }
}

fn classify_receive_null(error: u32) -> Result<(), Error> {
    match error {
        ERROR_NO_MORE_ITEMS => Ok(()),
        ERROR_HANDLE_EOF => Err(Error::recoverable_session()),
        _ => Err(Error),
    }
}

fn classify_wait_result(result: u32) -> Result<WaitOutcome, Error> {
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

fn classify_send_allocation_failure(error: u32) -> Result<SendOutcome, Error> {
    if error == ERROR_BUFFER_OVERFLOW {
        Ok(SendOutcome::DroppedRingFull)
    } else {
        Err(Error)
    }
}

fn prepare_managed_intent<T>(
    config: Option<&crate::ManagedNetworkConfig>,
    prepare: impl FnOnce(&crate::ManagedNetworkConfig) -> Result<T, Error>,
) -> Result<Option<T>, Error> {
    config.map(prepare).transpose()
}

#[derive(Clone, Eq, PartialEq)]
struct Ipv4DnsSettings(Option<Box<[u16]>>);

#[derive(Clone, Eq, PartialEq)]
struct Ipv6DnsSettings(Option<Box<[u16]>>);

struct ManagedDnsLease<S> {
    previous: S,
    applied: S,
}

trait ManagedDnsOperations {
    type Settings: Clone + Eq;
    type Address: Copy;

    fn snapshot(&mut self) -> Result<Self::Settings, Error>;
    fn apply(&mut self, address: Self::Address) -> Result<Self::Settings, Error>;
    fn readback(&mut self) -> Result<Self::Settings, Error>;
    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error>;
}

fn install_managed_dns<O: ManagedDnsOperations>(
    address: O::Address,
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

fn managed_dns_matches<O: ManagedDnsOperations>(
    operations: &mut O,
    lease: &ManagedDnsLease<O::Settings>,
) -> Result<bool, Error> {
    Ok(operations.readback()? == lease.applied)
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

struct PlatformManagedIpv4Dns(GUID);

impl ManagedDnsOperations for PlatformManagedIpv4Dns {
    type Settings = Ipv4DnsSettings;
    type Address = std::net::Ipv4Addr;

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

struct PlatformManagedIpv6Dns(GUID);

impl ManagedDnsOperations for PlatformManagedIpv6Dns {
    type Settings = Ipv6DnsSettings;
    type Address = std::net::Ipv6Addr;

    fn snapshot(&mut self) -> Result<Self::Settings, Error> {
        read_ipv6_dns_settings(self.0)
    }

    fn apply(&mut self, address: std::net::Ipv6Addr) -> Result<Self::Settings, Error> {
        let settings = Ipv6DnsSettings(Some(
            address.to_string().encode_utf16().collect::<Box<[_]>>(),
        ));
        set_ipv6_dns_settings(self.0, &settings)?;
        Ok(settings)
    }

    fn readback(&mut self) -> Result<Self::Settings, Error> {
        read_ipv6_dns_settings(self.0)
    }

    fn restore(&mut self, settings: &Self::Settings) -> Result<(), Error> {
        set_ipv6_dns_settings(self.0, settings)
    }
}

#[derive(Clone, Copy)]
enum DnsFamily {
    Ipv4,
    Ipv6,
}

fn read_dns_settings(interface: GUID, family: DnsFamily) -> Result<Option<Box<[u16]>>, Error> {
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: dns_settings_query_flags(family),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    if unsafe { GetInterfaceDnsSettings(interface, &mut settings) } != ERROR_SUCCESS {
        return Err(Error);
    }
    let result = copy_bounded_wide(settings.NameServer)
        .and_then(|settings| normalize_dns_settings(settings.as_deref(), family));
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    result
}

const fn dns_settings_query_flags(family: DnsFamily) -> u64 {
    match family {
        DnsFamily::Ipv4 => 0,
        DnsFamily::Ipv6 => DNS_SETTING_IPV6 as u64,
    }
}

fn read_ipv4_dns_settings(interface: GUID) -> Result<Ipv4DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv4).map(Ipv4DnsSettings)
}

fn read_ipv6_dns_settings(interface: GUID) -> Result<Ipv6DnsSettings, Error> {
    read_dns_settings(interface, DnsFamily::Ipv6).map(Ipv6DnsSettings)
}

fn normalize_dns_settings(
    settings: Option<&[u16]>,
    family: DnsFamily,
) -> Result<Option<Box<[u16]>>, Error> {
    let Some(settings) = settings else {
        return Ok(None);
    };
    let settings = String::from_utf16(settings).map_err(|_| Error)?;
    let mut addresses = Vec::new();
    for candidate in settings.split(|character: char| character == ',' || character.is_whitespace())
    {
        if candidate.is_empty() {
            continue;
        }
        let address = candidate.parse::<std::net::IpAddr>().map_err(|_| Error)?;
        if matches!(
            (family, address),
            (DnsFamily::Ipv4, std::net::IpAddr::V4(_)) | (DnsFamily::Ipv6, std::net::IpAddr::V6(_))
        ) {
            addresses.push(address.to_string());
        }
    }
    if addresses.is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            addresses.join(",").encode_utf16().collect::<Box<[_]>>(),
        ))
    }
}

fn ipv4_dns_settings_input(settings: &Ipv4DnsSettings) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    dns_settings_input(settings.0.as_deref(), false)
}

fn ipv6_dns_settings_input(settings: &Ipv6DnsSettings) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    dns_settings_input(settings.0.as_deref(), true)
}

fn dns_settings_input(
    settings: Option<&[u16]>,
    ipv6: bool,
) -> (Box<[u16]>, DNS_INTERFACE_SETTINGS) {
    let mut name_server = settings.unwrap_or_default().to_vec();
    name_server.push(0);
    let mut name_server = name_server.into_boxed_slice();
    let raw = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER)
            | if ipv6 { u64::from(DNS_SETTING_IPV6) } else { 0 },
        NameServer: name_server.as_mut_ptr(),
        ..DNS_INTERFACE_SETTINGS::default()
    };
    (name_server, raw)
}

fn set_ipv4_dns_settings(interface: GUID, settings: &Ipv4DnsSettings) -> Result<(), Error> {
    let (_name_server, raw) = ipv4_dns_settings_input(settings);
    if unsafe { SetInterfaceDnsSettings(interface, &raw) } == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error)
    }
}

fn set_ipv6_dns_settings(interface: GUID, settings: &Ipv6DnsSettings) -> Result<(), Error> {
    let (_name_server, raw) = ipv6_dns_settings_input(settings);
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
                        managed_notification_family(),
                        Some(route_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                1 => unsafe {
                    NotifyIpInterfaceChange(
                        managed_notification_family(),
                        Some(interface_changed),
                        context_pointer,
                        false,
                        &mut handle,
                    )
                },
                2 => unsafe {
                    NotifyUnicastIpAddressChange(
                        managed_notification_family(),
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

const fn managed_notification_family() -> u16 {
    AF_UNSPEC
}

fn snapshot_underlay(
    config: &crate::ManagedNetworkConfig,
    generation: Arc<AtomicU64>,
    expected_generation: u64,
) -> Result<UnderlayPolicy, Error> {
    snapshot_underlay_at(
        config,
        generation,
        expected_generation,
        &mut PlatformUnderlay,
    )
}

trait UnderlayOperations {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error>;
    fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error>;
    fn interface_metric(
        &mut self,
        _family: std::net::IpAddr,
        _interface_index: u32,
    ) -> Result<u32, Error> {
        Ok(0)
    }
    fn constrained_route(
        &mut self,
        destination: std::net::SocketAddr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error>;
}

#[cfg(test)]
fn snapshot_underlay_with(
    config: &crate::ManagedNetworkConfig,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    snapshot_underlay_at(config, Arc::new(AtomicU64::new(0)), 0, operations)
}

fn snapshot_underlay_at(
    config: &crate::ManagedNetworkConfig,
    generation: Arc<AtomicU64>,
    expected_generation: u64,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    if generation.load(Ordering::Acquire) != expected_generation {
        return Err(Error);
    }
    let interfaces = operations.eligible_interfaces(None)?;
    if config.needs_target_binder() && interfaces.is_empty() {
        return Err(Error);
    }
    let mut fixed = Vec::with_capacity(config.physical_endpoints().len());
    for endpoint in config.physical_endpoints() {
        let index = operations.best_interface(*endpoint)?;
        let identity = interfaces
            .iter()
            .find(|candidate| candidate.index == index)
            .ok_or(Error)?;
        let route = operations.constrained_route(*endpoint, index, true)?;
        if route.interface_luid != identity.luid
            || route.interface_index != identity.index
            || !same_ip_family(endpoint.ip(), route.destination)
        {
            return Err(Error);
        }
        fixed.push((*endpoint, route));
    }
    if generation.load(Ordering::Acquire) != expected_generation {
        return Err(Error);
    }
    Ok(UnderlayPolicy {
        fixed: fixed.into(),
        target_binder: config.needs_target_binder(),
        valid: Arc::new(AtomicBool::new(true)),
        generation,
        accepted_generation: Arc::new(AtomicU64::new(expected_generation)),
        owned_luid: Arc::new(AtomicU64::new(0)),
        owned_index: Arc::new(AtomicU32::new(0)),
    })
}

fn refresh_underlay_with(
    config: &crate::ManagedNetworkConfig,
    current: &UnderlayPolicy,
    owned: InterfaceIdentity,
    validated_generation: &mut u64,
    generation: Arc<AtomicU64>,
    operations: &mut impl UnderlayOperations,
) -> Result<UnderlayPolicy, Error> {
    for attempt in 0..2 {
        let before = generation.load(Ordering::Acquire);
        let next = match snapshot_underlay_at(config, Arc::clone(&generation), before, operations) {
            Ok(next) => next,
            Err(_) if attempt == 0 && generation.load(Ordering::Acquire) != before => continue,
            Err(error) => return Err(error),
        };
        next.set_owned_identity(owned)?;
        if !underlay_matches_with(&next, owned, operations)? {
            next.invalidate();
            return Err(Error);
        }
        let after = generation.load(Ordering::Acquire);
        if after != before {
            next.invalidate();
            if attempt == 0 {
                continue;
            }
            return Err(Error);
        }
        *validated_generation = after;
        current.invalidate();
        return Ok(next);
    }
    unreachable!("underlay refresh has exactly two attempts")
}

fn classify_underlay_refresh<T>(result: Result<T, Error>) -> Result<T, Error> {
    result.map_err(|_| Error::recoverable_session())
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
        }) || operations.constrained_route(*endpoint, expected.interface_index, true)?
            != *expected
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
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

struct PlatformUnderlay;

impl UnderlayOperations for PlatformUnderlay {
    fn eligible_interfaces(
        &mut self,
        excluded: Option<InterfaceIdentity>,
    ) -> Result<Vec<InterfaceIdentity>, Error> {
        eligible_interfaces(excluded)
    }

    fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error> {
        let destination = socket_addr_sockaddr(destination);
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

    fn interface_metric(
        &mut self,
        family: std::net::IpAddr,
        interface_index: u32,
    ) -> Result<u32, Error> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = match family {
            std::net::IpAddr::V4(_) => AF_INET,
            std::net::IpAddr::V6(_) => AF_INET6,
        };
        row.InterfaceIndex = interface_index;
        if unsafe { GetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS || !row.Connected {
            return Err(Error);
        }
        Ok(row.Metric)
    }

    fn constrained_route(
        &mut self,
        destination: std::net::SocketAddr,
        interface_index: u32,
        require_source: bool,
    ) -> Result<RouteFingerprint, Error> {
        constrained_route(destination, interface_index, require_source)
    }
}

const MAX_CATALOG_INTERFACES: usize = 4_096;
const MAX_CATALOG_ADDRESSES: usize = 16_384;
const MAX_CATALOG_ROUTES: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogInterfaceRow {
    identity: InterfaceIdentity,
    name: Box<str>,
    operational: bool,
    connected: bool,
    kind: NetworkInterfaceKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogAddressGroup {
    identity: InterfaceIdentity,
    family: NetworkFamily,
    addresses: Vec<std::net::IpAddr>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CatalogFamilyRow {
    identity: InterfaceIdentity,
    family: NetworkFamily,
    addresses: Vec<std::net::IpAddr>,
    connected: bool,
    interface_metric: u32,
    default_route_metric: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CatalogDefaultRoute {
    identity: InterfaceIdentity,
    family: NetworkFamily,
    metric: u32,
}

fn read_network_interface_observations(
    managed_tun: Option<InterfaceIdentity>,
) -> Result<Vec<NetworkInterfaceObservation>, Error> {
    require_catalog_managed_identity(managed_tun)?;
    let interfaces = read_catalog_interfaces()?;
    let address_groups = read_catalog_address_groups()?;
    let default_routes = read_catalog_default_routes()?;
    let mut families = Vec::with_capacity(address_groups.len());
    for group in address_groups {
        let (connected, interface_metric) =
            read_catalog_family_state(group.identity, group.family)?;
        let default_route_metric = default_routes
            .iter()
            .filter(|route| route.identity == group.identity && route.family == group.family)
            .map(|route| route.metric)
            .min();
        families.push(CatalogFamilyRow {
            identity: group.identity,
            family: group.family,
            addresses: group.addresses,
            connected,
            interface_metric,
            default_route_metric,
        });
    }
    build_network_interface_observations(&interfaces, &families, managed_tun)
}

fn build_network_interface_observations(
    interfaces: &[CatalogInterfaceRow],
    families: &[CatalogFamilyRow],
    managed_tun: Option<InterfaceIdentity>,
) -> Result<Vec<NetworkInterfaceObservation>, Error> {
    let mut observations = Vec::with_capacity(families.len());
    for family in families {
        let mut matches = interfaces
            .iter()
            .filter(|interface| interface.identity == family.identity);
        let Some(interface) = matches.next() else {
            // The address may have disappeared between the independently allocated MIB tables.
            continue;
        };
        if matches.next().is_some() {
            return Err(Error);
        }
        let kind = if managed_tun == Some(interface.identity) {
            NetworkInterfaceKind::ManagedTun
        } else {
            interface.kind
        };
        let binding = InterfaceBinding::new(
            Arc::<str>::from(interface.name.as_ref()),
            interface.identity.luid,
            interface.identity.index,
            family.addresses.clone(),
        )
        .map_err(|_| Error)?;
        observations.push(
            NetworkInterfaceObservation::new(
                binding,
                family.family,
                interface.operational,
                interface.connected && family.connected,
                kind,
                family.interface_metric,
                family.default_route_metric,
            )
            .map_err(|_| Error)?,
        );
    }
    Ok(observations)
}

fn read_catalog_interfaces() -> Result<Vec<CatalogInterfaceRow>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
    // SAFETY: GetIfTable2 allocated one table with NumEntries contiguous rows. `owner` keeps the
    // allocation live through this copy and releases it exactly once with FreeMibTable.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows.iter().filter_map(catalog_interface_row).collect();
    drop(owner);
    Ok(result)
}

fn catalog_interface_row(row: &MIB_IF_ROW2) -> Option<CatalogInterfaceRow> {
    // SAFETY: InterfaceLuid.Value is the active NET_LUID_LH representation returned by
    // GetIfTable2; reading it does not outlive the copied row.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    if identity.luid == 0 || identity.index == 0 {
        return None;
    }
    let name = decode_interface_name(&row.Alias)?;
    Some(CatalogInterfaceRow {
        identity,
        name,
        operational: row.OperStatus == IfOperStatusUp && row.AdminStatus == NET_IF_ADMIN_STATUS_UP,
        connected: row.MediaConnectState == MediaConnectStateConnected,
        kind: if row.Type
            == windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
        {
            NetworkInterfaceKind::Loopback
        } else {
            NetworkInterfaceKind::Underlay
        },
    })
}

fn decode_interface_name(raw: &[u16]) -> Option<Box<str>> {
    let end = raw.iter().position(|unit| *unit == 0).unwrap_or(raw.len());
    if end == 0 {
        return None;
    }
    String::from_utf16(&raw[..end])
        .ok()
        .map(String::into_boxed_str)
}

fn read_catalog_address_groups() -> Result<Vec<CatalogAddressGroup>, Error> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) } != ERROR_SUCCESS
        || table.is_null()
    {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_ADDRESSES {
        return Err(Error);
    }
    // SAFETY: GetUnicastIpAddressTable allocated NumEntries contiguous rows. `owner` holds the
    // allocation until every address has been copied into owned Rust values.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let mut groups = Vec::<CatalogAddressGroup>::new();
    for row in rows {
        let Some((identity, family, address)) = catalog_unicast_address(row) else {
            continue;
        };
        let group = if let Some(group) = groups
            .iter_mut()
            .find(|group| group.identity == identity && group.family == family)
        {
            group
        } else {
            groups.push(CatalogAddressGroup {
                identity,
                family,
                addresses: Vec::new(),
            });
            groups.last_mut().ok_or(Error)?
        };
        group.addresses.push(address);
    }
    for group in &mut groups {
        group.addresses.sort_unstable();
        group.addresses.dedup();
    }
    drop(owner);
    Ok(groups)
}

fn catalog_unicast_address(
    row: &MIB_UNICASTIPADDRESS_ROW,
) -> Option<(InterfaceIdentity, NetworkFamily, std::net::IpAddr)> {
    if row.DadState != IpDadStatePreferred && row.DadState != IpDadStateDeprecated {
        return None;
    }
    // SAFETY: InterfaceLuid.Value is the active NET_LUID_LH representation in this IP Helper row.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    if identity.luid == 0 || identity.index == 0 {
        return None;
    }
    let address = sockaddr_ip(&row.Address).ok()?;
    if address.is_unspecified() || address.is_multicast() {
        return None;
    }
    Some((identity, NetworkFamily::of(address), address))
}

fn read_catalog_default_routes() -> Result<Vec<CatalogDefaultRoute>, Error> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_ROUTES {
        return Err(Error);
    }
    // SAFETY: GetIpForwardTable2 allocated NumEntries contiguous rows. `owner` keeps the table
    // alive while each default-route identity and metric is copied.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let routes = rows.iter().filter_map(catalog_default_route).collect();
    drop(owner);
    Ok(routes)
}

fn catalog_default_route(row: &MIB_IPFORWARD_ROW2) -> Option<CatalogDefaultRoute> {
    if row.DestinationPrefix.PrefixLength != 0 {
        return None;
    }
    let destination = sockaddr_ip(&row.DestinationPrefix.Prefix).ok()?;
    if !destination.is_unspecified() {
        return None;
    }
    // SAFETY: InterfaceLuid.Value is the active NET_LUID_LH representation in this route row.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    if identity.luid == 0 || identity.index == 0 {
        return None;
    }
    Some(CatalogDefaultRoute {
        identity,
        family: NetworkFamily::of(destination),
        metric: row.Metric,
    })
}

fn read_catalog_family_state(
    identity: InterfaceIdentity,
    family: NetworkFamily,
) -> Result<(bool, u32), Error> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = match family {
        NetworkFamily::Ipv4 => AF_INET,
        NetworkFamily::Ipv6 => AF_INET6,
    };
    row.InterfaceLuid = NET_LUID_LH {
        Value: identity.luid,
    };
    if unsafe { GetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
        return Err(Error);
    }
    // SAFETY: GetIpInterfaceEntry returned a fully initialized NET_LUID_LH row.
    if unsafe { row.InterfaceLuid.Value } != identity.luid || row.InterfaceIndex != identity.index {
        return Err(Error);
    }
    Ok((row.Connected, row.Metric))
}

fn system_best_route(
    destination: std::net::SocketAddr,
    managed_tun: Option<InterfaceIdentity>,
) -> Result<SystemBestRoute, Error> {
    require_catalog_managed_identity(managed_tun)?;
    let primary = unconstrained_route(destination)?;
    let primary_identity = route_identity(primary)?;
    let selected = if managed_tun != Some(primary_identity) {
        primary
    } else {
        let mut selected = None::<(RouteFingerprint, u64)>;
        for identity in catalog_fallback_interfaces(managed_tun)? {
            let Ok(route) = constrained_route(destination, identity.index, true) else {
                continue;
            };
            if route.interface_luid != identity.luid
                || route.interface_index != identity.index
                || !same_ip_family(destination.ip(), route.destination)
                || route
                    .source
                    .is_none_or(|source| !same_ip_family(destination.ip(), source))
            {
                continue;
            }
            let Ok(interface_metric) =
                PlatformUnderlay.interface_metric(destination.ip(), identity.index)
            else {
                continue;
            };
            let effective_metric = u64::from(route.metric) + u64::from(interface_metric);
            if selected.as_ref().is_none_or(|(current, current_metric)| {
                system_route_is_preferred(route, effective_metric, *current, *current_metric)
            }) {
                selected = Some((route, effective_metric));
            }
        }
        selected.map(|(route, _)| route).ok_or(Error)?
    };
    let identity = route_identity(selected)?;
    SystemBestRoute::new(identity.luid, identity.index).map_err(|_| Error)
}

fn require_catalog_managed_identity(managed_tun: Option<InterfaceIdentity>) -> Result<(), Error> {
    let Some(managed_tun) = managed_tun else {
        return Ok(());
    };
    let luid = NET_LUID_LH {
        Value: managed_tun.luid,
    };
    managed_interface_identity_matches(luid, managed_tun.index)
        .then_some(())
        .ok_or(Error)
}

fn unconstrained_route(destination: std::net::SocketAddr) -> Result<RouteFingerprint, Error> {
    let destination_sockaddr = socket_addr_sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    if unsafe {
        GetBestRoute2(
            null(),
            0,
            null(),
            &destination_sockaddr,
            0,
            &mut route,
            &mut source,
        )
    } != ERROR_SUCCESS
    {
        return Err(Error);
    }
    let source = sockaddr_ip(&source)?;
    if source.is_unspecified() || !same_ip_family(destination.ip(), source) {
        return Err(Error);
    }
    route_fingerprint(&route, Some(source))
}

fn route_identity(route: RouteFingerprint) -> Result<InterfaceIdentity, Error> {
    if route.interface_luid == 0 || route.interface_index == 0 {
        return Err(Error);
    }
    Ok(InterfaceIdentity {
        luid: route.interface_luid,
        index: route.interface_index,
    })
}

fn system_route_is_preferred(
    candidate: RouteFingerprint,
    candidate_metric: u64,
    current: RouteFingerprint,
    current_metric: u64,
) -> bool {
    candidate.prefix_length > current.prefix_length
        || (candidate.prefix_length == current.prefix_length
            && (candidate_metric < current_metric
                || (candidate_metric == current_metric
                    && (candidate.interface_luid, candidate.interface_index)
                        < (current.interface_luid, current.interface_index))))
}

fn catalog_fallback_interfaces(
    excluded: Option<InterfaceIdentity>,
) -> Result<Vec<InterfaceIdentity>, Error> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let owner = MibTable(table.cast());
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
    // SAFETY: GetIfTable2 allocated NumEntries contiguous rows and `owner` retains the allocation
    // until every selected LUID/index pair has been copied.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    let result = rows
        .iter()
        .filter_map(|row| catalog_fallback_interface_identity(row, excluded))
        .collect();
    drop(owner);
    Ok(result)
}

fn catalog_fallback_interface_identity(
    row: &MIB_IF_ROW2,
    excluded: Option<InterfaceIdentity>,
) -> Option<InterfaceIdentity> {
    // SAFETY: InterfaceLuid.Value is the active representation returned by GetIfTable2.
    let luid = unsafe { row.InterfaceLuid.Value };
    let identity = InterfaceIdentity {
        luid,
        index: row.InterfaceIndex,
    };
    (identity.luid != 0
        && identity.index != 0
        && row.Type != windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK
        && row.OperStatus == IfOperStatusUp
        && row.AdminStatus == NET_IF_ADMIN_STATUS_UP
        && row.MediaConnectState == MediaConnectStateConnected
        && excluded != Some(identity))
    .then_some(identity)
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
    if count > MAX_CATALOG_INTERFACES {
        return Err(Error);
    }
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

const MANAGED_CAPTURE_ROUTE_METRIC: u32 = 1;

fn constrained_route(
    destination: std::net::SocketAddr,
    interface_index: u32,
    require_source: bool,
) -> Result<RouteFingerprint, Error> {
    let destination_sockaddr = socket_addr_sockaddr(destination);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    if unsafe {
        GetBestRoute2(
            null(),
            interface_index,
            null(),
            &destination_sockaddr,
            0,
            &mut route,
            &mut source,
        )
    } != ERROR_SUCCESS
        || route.InterfaceIndex != interface_index
    {
        return Err(Error);
    }
    let source = sockaddr_ip(&source)?;
    if !same_ip_family(destination.ip(), source) || (require_source && source.is_unspecified()) {
        return Err(Error);
    }
    route_fingerprint(&route, require_source.then_some(source))
}

fn route_fingerprint(
    row: &MIB_IPFORWARD_ROW2,
    source: Option<std::net::IpAddr>,
) -> Result<RouteFingerprint, Error> {
    let destination = sockaddr_ip(&row.DestinationPrefix.Prefix)?;
    let next_hop = sockaddr_ip(&row.NextHop)?;
    if !same_ip_family(destination, next_hop)
        || source.is_some_and(|source| !same_ip_family(destination, source))
    {
        return Err(Error);
    }
    Ok(RouteFingerprint {
        interface_luid: unsafe { row.InterfaceLuid.Value },
        interface_index: row.InterfaceIndex,
        destination,
        prefix_length: row.DestinationPrefix.PrefixLength,
        next_hop,
        metric: row.Metric,
        source,
    })
}

fn sockaddr_ip(address: &SOCKADDR_INET) -> Result<std::net::IpAddr, Error> {
    unsafe {
        match address.si_family {
            AF_INET => Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
            ))),
            AF_INET6 => Ok(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                address.Ipv6.sin6_addr.u.Byte,
            ))),
            _ => Err(Error),
        }
    }
}

fn socket_addr_sockaddr(address: std::net::SocketAddr) -> SOCKADDR_INET {
    match address {
        std::net::SocketAddr::V4(address) => {
            let mut raw = ipv4_sockaddr(*address.ip());
            raw.Ipv4.sin_port = address.port().to_be();
            raw
        }
        std::net::SocketAddr::V6(address) => {
            let mut raw = ipv6_sockaddr(*address.ip());
            raw.Ipv6.sin6_port = address.port().to_be();
            raw.Ipv6.sin6_flowinfo = address.flowinfo().to_be();
            raw.Ipv6.Anonymous.sin6_scope_id = address.scope_id();
            raw
        }
    }
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

fn ipv6_sockaddr(address: std::net::Ipv6Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 {
                    Byte: address.octets(),
                },
            },
            Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
        },
    }
}

fn read_ip_interface(luid: NET_LUID_LH, family: u16) -> Result<MIB_IPINTERFACE_ROW, Error> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = family;
    row.InterfaceLuid = luid;
    if unsafe { GetIpInterfaceEntry(&mut row) } == ERROR_SUCCESS {
        Ok(row)
    } else {
        Err(Error)
    }
}

fn address_key(intended: &MIB_UNICASTIPADDRESS_ROW) -> MIB_UNICASTIPADDRESS_ROW {
    let mut key = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut key) };
    key.Address = intended.Address;
    key.InterfaceLuid = intended.InterfaceLuid;
    key.InterfaceIndex = intended.InterfaceIndex;
    key
}

fn initialize_managed_address(row: &mut MIB_UNICASTIPADDRESS_ROW) {
    unsafe { InitializeUnicastIpAddressEntry(row) };
    // Windows normalizes "unchanged" origins to manual when the row is created. Record the
    // normalized values up front so exact ownership readback and rollback remain comparable.
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
}

fn require_address_absent(intended: &MIB_UNICASTIPADDRESS_ROW) -> Result<(), Error> {
    let mut current = address_key(intended);
    match unsafe { GetUnicastIpAddressEntry(&mut current) } {
        ERROR_NOT_FOUND => Ok(()),
        _ => Err(Error),
    }
}

fn read_owned_address(
    intended: &MIB_UNICASTIPADDRESS_ROW,
) -> Result<MIB_UNICASTIPADDRESS_ROW, Error> {
    let mut current = address_key(intended);
    if unsafe { GetUnicastIpAddressEntry(&mut current) } == ERROR_SUCCESS {
        Ok(current)
    } else {
        Err(Error)
    }
}

fn managed_address_matches(
    expected: &MIB_UNICASTIPADDRESS_ROW,
    actual: &MIB_UNICASTIPADDRESS_ROW,
) -> bool {
    unsafe {
        actual.InterfaceLuid.Value == expected.InterfaceLuid.Value
            && actual.InterfaceIndex == expected.InterfaceIndex
            && sockaddr_matches(&expected.Address, &actual.Address)
            && actual.PrefixOrigin == expected.PrefixOrigin
            && actual.SuffixOrigin == expected.SuffixOrigin
            && actual.ValidLifetime == expected.ValidLifetime
            && actual.PreferredLifetime == expected.PreferredLifetime
            && actual.OnLinkPrefixLength == expected.OnLinkPrefixLength
            && actual.SkipAsSource == expected.SkipAsSource
            && actual.ScopeId.Anonymous.Value == expected.ScopeId.Anonymous.Value
    }
}

enum ManagedAddressRead<R> {
    Absent,
    Present(R),
    Failed,
}

trait ManagedAddressCleanupOperations {
    type Row: Copy;

    fn read(&mut self, intended: &Self::Row) -> ManagedAddressRead<Self::Row>;
    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool;
    fn delete(&mut self, current: &Self::Row) -> Result<(), Error>;
}

fn delete_managed_address<O: ManagedAddressCleanupOperations>(
    operations: &mut O,
    intended: &O::Row,
) -> bool {
    match operations.read(intended) {
        ManagedAddressRead::Absent => false,
        ManagedAddressRead::Present(current) if operations.matches(intended, &current) => {
            let delete_failed = operations.delete(&current).is_err();
            let final_read_failed =
                !matches!(operations.read(intended), ManagedAddressRead::Absent);
            delete_failed | final_read_failed
        }
        ManagedAddressRead::Present(_) | ManagedAddressRead::Failed => true,
    }
}

struct PlatformManagedAddressCleanup;

impl ManagedAddressCleanupOperations for PlatformManagedAddressCleanup {
    type Row = MIB_UNICASTIPADDRESS_ROW;

    fn read(&mut self, intended: &Self::Row) -> ManagedAddressRead<Self::Row> {
        let mut current = address_key(intended);
        match unsafe { GetUnicastIpAddressEntry(&mut current) } {
            ERROR_NOT_FOUND => ManagedAddressRead::Absent,
            ERROR_SUCCESS => ManagedAddressRead::Present(current),
            _ => ManagedAddressRead::Failed,
        }
    }

    fn matches(&self, intended: &Self::Row, current: &Self::Row) -> bool {
        managed_address_matches(intended, current)
    }

    fn delete(&mut self, current: &Self::Row) -> Result<(), Error> {
        match unsafe { DeleteUnicastIpAddressEntry(current) } {
            ERROR_SUCCESS | ERROR_NOT_FOUND => Ok(()),
            _ => Err(Error),
        }
    }
}

fn capture_route_row(
    luid: NET_LUID_LH,
    interface_index: u32,
    prefix: IpPrefix,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.InterfaceIndex = interface_index;
    match prefix {
        IpPrefix::V4(prefix) => {
            row.DestinationPrefix.Prefix = ipv4_sockaddr(prefix.address());
            row.DestinationPrefix.PrefixLength = prefix.length();
            row.NextHop = ipv4_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
        }
        IpPrefix::V6(prefix) => {
            row.DestinationPrefix.Prefix = ipv6_sockaddr(prefix.address());
            row.DestinationPrefix.PrefixLength = prefix.length();
            row.NextHop = ipv6_sockaddr(std::net::Ipv6Addr::UNSPECIFIED);
        }
    }
    row.SitePrefixLength = 0;
    row.ValidLifetime = u32::MAX;
    row.PreferredLifetime = u32::MAX;
    row.Metric = MANAGED_CAPTURE_ROUTE_METRIC;
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
            && sockaddr_matches(
                &expected.DestinationPrefix.Prefix,
                &actual.DestinationPrefix.Prefix,
            )
            && actual.DestinationPrefix.PrefixLength == expected.DestinationPrefix.PrefixLength
            && sockaddr_matches(&expected.NextHop, &actual.NextHop)
            && actual.SitePrefixLength == 0
            && actual.ValidLifetime == u32::MAX
            && actual.PreferredLifetime == u32::MAX
            && actual.Metric == MANAGED_CAPTURE_ROUTE_METRIC
            && actual.Protocol == MIB_IPPROTO_NETMGMT
            && !actual.Loopback
            && !actual.AutoconfigureAddress
            && !actual.Publish
            && !actual.Immortal
            && actual.Origin == NlroManual
    }
}

fn sockaddr_matches(expected: &SOCKADDR_INET, actual: &SOCKADDR_INET) -> bool {
    unsafe {
        match expected.si_family {
            AF_INET => {
                actual.si_family == AF_INET
                    && actual.Ipv4.sin_port == expected.Ipv4.sin_port
                    && actual.Ipv4.sin_addr.S_un.S_addr == expected.Ipv4.sin_addr.S_un.S_addr
            }
            AF_INET6 => {
                actual.si_family == AF_INET6
                    && actual.Ipv6.sin6_port == expected.Ipv6.sin6_port
                    && actual.Ipv6.sin6_flowinfo == expected.Ipv6.sin6_flowinfo
                    && actual.Ipv6.sin6_addr.u.Byte == expected.Ipv6.sin6_addr.u.Byte
                    && actual.Ipv6.Anonymous.sin6_scope_id == expected.Ipv6.Anonymous.sin6_scope_id
            }
            _ => false,
        }
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

fn managed_device_health(
    adapter_present: bool,
    session_present: bool,
    address_ledger_exact: bool,
    mut identity_matches: impl FnMut() -> bool,
    mut addresses_match: impl FnMut() -> bool,
) -> ManagedTunHealth {
    if !adapter_present || !identity_matches() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Adapter);
    }
    if !session_present {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Session);
    }
    if !address_ledger_exact || !addresses_match() {
        return ManagedTunHealth::Damaged(ManagedStateDamage::Address);
    }
    ManagedTunHealth::Healthy
}

fn managed_interface_identity_matches(luid: NET_LUID_LH, expected_index: u32) -> bool {
    if unsafe { luid.Value } == 0 || expected_index == 0 {
        return false;
    }
    let mut current_index = 0_u32;
    (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut current_index) }) == ERROR_SUCCESS
        && current_index == expected_index
}

fn managed_state_health<O: ManagedRouteCleanupOperations>(
    routes: &[O::Row],
    route_operations: &mut O,
    mut dns_matches: impl FnMut() -> Result<bool, Error>,
    mut strict_route_matches: impl FnMut() -> Result<bool, Error>,
) -> Result<ManagedTunHealth, Error> {
    if !managed_routes_match(routes, route_operations) {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Route));
    }
    if !dns_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::Dns));
    }
    if !strict_route_matches()? {
        return Ok(ManagedTunHealth::Damaged(ManagedStateDamage::StrictRoute));
    }
    Ok(ManagedTunHealth::Healthy)
}

struct ManagedNetworkValidation<'a, R> {
    policy: &'a UnderlayPolicy,
    owned: InterfaceIdentity,
    routes: &'a [R],
    validated_generation: &'a mut u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedNetworkValidationOutcome {
    Unchanged,
    UnderlayChanged,
    ManagedStateDamaged(ManagedStateDamage),
}

fn revalidate_managed_network<
    U: UnderlayOperations,
    O: ManagedRouteCleanupOperations,
    F: FnMut() -> Result<bool, Error>,
    S: FnMut() -> Result<bool, Error>,
>(
    validation: ManagedNetworkValidation<'_, O::Row>,
    force: bool,
    mut generation: impl FnMut() -> u64,
    underlay: &mut U,
    route_operations: &mut O,
    mut dns_matches: F,
    mut strict_route_matches: S,
) -> Result<ManagedNetworkValidationOutcome, Error> {
    let ManagedNetworkValidation {
        policy,
        owned,
        routes,
        validated_generation,
    } = validation;
    let mut before = generation();
    if !force && before == *validated_generation {
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    for _ in 0..2 {
        let underlay_matches = match underlay_matches_with(policy, owned, underlay) {
            Ok(matches) => matches,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let health = match managed_state_health(
            routes,
            route_operations,
            &mut dns_matches,
            &mut strict_route_matches,
        ) {
            Ok(health) => health,
            Err(error) => {
                policy.invalidate();
                return Err(error);
            }
        };
        let after = generation();
        if after != before {
            before = after;
            continue;
        }
        if let ManagedTunHealth::Damaged(reason) = health {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::ManagedStateDamaged(reason));
        }
        if !underlay_matches {
            policy.invalidate();
            return Ok(ManagedNetworkValidationOutcome::UnderlayChanged);
        }
        *validated_generation = after;
        policy.accept_generation(after);
        return Ok(ManagedNetworkValidationOutcome::Unchanged);
    }
    policy.invalidate();
    Ok(ManagedNetworkValidationOutcome::UnderlayChanged)
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
    strict_route_install_failed: bool,
    cleanup: impl FnOnce() -> bool,
) -> Result<(), CreateError> {
    match setup {
        Ok(()) => Ok(()),
        Err(_) => {
            let cleanup_failed = cleanup();
            if strict_route_install_failed {
                Err(CreateError::strict_route_install(cleanup_failed))
            } else if cleanup_failed {
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
    fn close_strict_route(&mut self) -> Option<bool> {
        None
    }
    fn delete_last_route(&mut self) -> Option<bool> {
        None
    }
    fn restore_last_dns(&mut self) -> Option<bool> {
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
    failed |= cleanup.close_strict_route().unwrap_or(false);
    while let Some(step_failed) = cleanup.restore_last_dns() {
        failed |= step_failed;
    }
    while let Some(step_failed) = cleanup.delete_last_route() {
        failed |= step_failed;
    }
    while let Some(step_failed) = cleanup.delete_last_address() {
        failed |= step_failed;
    }
    failed |= cleanup.restore_ipv6_mtu().unwrap_or(false);
    failed |= cleanup.restore_ipv4_mtu().unwrap_or(false);
    failed |= cleanup.end_session().unwrap_or(false);
    failed |= cleanup.close_adapter().unwrap_or(false);
    failed
}

struct PlatformCleanup<'a>(&'a mut Adapter);

impl PlatformCleanup<'_> {
    fn restore_mtu(&mut self, slot: usize) -> Option<bool> {
        let state = self.0.mtus[slot].take()?;
        let Ok(mut row) = read_ip_interface(self.0.luid, state.family) else {
            return Some(true);
        };
        if row.NlMtu != state.configured {
            return Some(true);
        }
        if state.family == AF_INET {
            row.SitePrefixLength = 0;
        }
        row.NlMtu = state.previous;
        if unsafe { SetIpInterfaceEntry(&mut row) } != ERROR_SUCCESS {
            return Some(true);
        }
        Some(match read_ip_interface(self.0.luid, state.family) {
            Ok(current) => current.NlMtu != state.previous,
            Err(_) => true,
        })
    }
}

impl CleanupOperations for PlatformCleanup<'_> {
    fn session_is_idle(&mut self) -> bool {
        self.0.session_journal.cleanup_is_safe()
    }

    fn cancel_notifications(&mut self) -> Option<bool> {
        self.0.managed.as_mut().map(|state| {
            state.policy.invalidate();
            state.notifications.cancel_all()
        })
    }

    fn close_strict_route(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let session = state.strict_route.as_mut()?;
        let failed = session.close().is_err();
        if !failed {
            state.strict_route = None;
        }
        Some(failed)
    }

    fn delete_last_route(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        let intended = take_last_owned_route(&mut state.pending_route, &mut state.routes)?;
        Some(delete_managed_route(
            &mut PlatformManagedRouteCleanup,
            &intended,
        ))
    }

    fn restore_last_dns(&mut self) -> Option<bool> {
        let state = self.0.managed.as_mut()?;
        if let Some(lease) = state.ipv6_dns.take() {
            return Some(state.dns_interface.is_none_or(|interface| {
                restore_managed_dns(&mut PlatformManagedIpv6Dns(interface), &lease)
            }));
        }
        if let Some(lease) = state.ipv4_dns.take() {
            return Some(state.dns_interface.is_none_or(|interface| {
                restore_managed_dns(&mut PlatformManagedIpv4Dns(interface), &lease)
            }));
        }
        state.dns_interface.take();
        None
    }

    fn end_session(&mut self) -> Option<bool> {
        let session = self.0.session.take()?;
        unsafe { (self.0.library.exports.end_session)(session.handle) };
        Some(false)
    }

    fn delete_last_address(&mut self) -> Option<bool> {
        let address = self
            .0
            .pending_address
            .take()
            .or_else(|| self.0.addresses.pop())?;
        Some(delete_managed_address(
            &mut PlatformManagedAddressCleanup,
            &address,
        ))
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
    states: &[NL_DAD_STATE],
    deadline_elapsed: bool,
) -> Result<DadProgress, Error> {
    if !session_started || states.is_empty() {
        return Err(Error);
    }
    let mut waiting = false;
    for &state in states {
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
    fn start_session(&mut self) -> Result<(), Error>;
    fn identify_adapter(&mut self) -> Result<(), Error>;
    fn ipv4_enabled(&self) -> bool;
    fn ipv6_enabled(&self) -> bool;
    fn set_ipv4_mtu(&mut self) -> Result<(), Error>;
    fn set_ipv6_mtu(&mut self) -> Result<(), Error>;
    fn add_ipv4_address(&mut self) -> Result<(), Error>;
    fn add_ipv6_address(&mut self) -> Result<(), Error>;
    fn wait_for_dad(&mut self) -> Result<(), Error>;
}

fn setup_transaction(setup: &mut impl SetupOperations) -> Result<(), Error> {
    setup.check_cancelled()?;
    setup.check_deadline()?;
    setup.create_adapter()?;
    setup.check_driver()?;
    setup.start_session()?;
    setup.identify_adapter()?;
    if setup.ipv4_enabled() {
        setup.set_ipv4_mtu()?;
    }
    if setup.ipv6_enabled() {
        setup.set_ipv6_mtu()?;
    }
    if setup.ipv4_enabled() {
        setup.add_ipv4_address()?;
    }
    if setup.ipv6_enabled() {
        setup.add_ipv6_address()?;
    }
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
        Ok(())
    }

    fn identify_adapter(&mut self) -> Result<(), Error> {
        let adapter = self.owner.adapter.ok_or(Error)?;
        unsafe { (self.owner.library.exports.get_adapter_luid)(adapter, &mut self.owner.luid) };
        if unsafe { ConvertInterfaceLuidToIndex(&self.owner.luid, &mut self.owner.interface_index) }
            != ERROR_SUCCESS
            || self.owner.interface_index == 0
        {
            return Err(Error);
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

    fn ipv4_enabled(&self) -> bool {
        self.owner.config.ipv4.is_some()
    }

    fn ipv6_enabled(&self) -> bool {
        self.owner.config.ipv6.is_some()
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

    fn set_ipv4_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET, 0)
    }

    fn set_ipv6_mtu(&mut self) -> Result<(), Error> {
        self.owner.set_mtu(AF_INET6, 1)
    }

    fn add_ipv4_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv4_address_row()?;
        self.owner.create_address(row)
    }

    fn add_ipv6_address(&mut self) -> Result<(), Error> {
        let row = self.owner.ipv6_address_row()?;
        self.owner.create_address(row)
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

/// Cloneable auto-reset signal for waking the owner when adapter-owned work arrives.
pub struct WorkSignal(Arc<OwnedHandle>);

impl Clone for WorkSignal {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl WorkSignal {
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

fn create_event(manual_reset: bool) -> Result<HANDLE, Error> {
    let handle = unsafe { CreateEventW(null(), i32::from(manual_reset), 0, null()) };
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
        ABI_EXPORTS, AF_INET6, AF_UNSPEC, AdapterCreateFailure, CatalogFamilyRow,
        CatalogInterfaceRow, CleanupOperations, DLL_BYTES, DLL_SHA256, DNS_SETTING_IPV6,
        DNS_SETTING_NAMESERVER, DadProgress, DnsFamily, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
        ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, Error, InterfaceIdentity,
        IpDadStateDeprecated, IpDadStateDuplicate, IpDadStateInvalid, IpDadStatePreferred,
        IpDadStateTentative, Ipv4DnsSettings, Ipv6DnsSettings, LoaderOperations, MIB_IF_ROW2,
        MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
        ManagedAddressCleanupOperations, ManagedAddressRead, ManagedDnsLease, ManagedDnsOperations,
        ManagedNetworkValidation, ManagedNetworkValidationOutcome, ManagedRouteCleanupOperations,
        ManagedRouteOperations, ManagedRouteRead, NET_LUID_LH, NotificationContext,
        NotificationOwners, OwnedHandle, ResolvedSocketBindingOperations, RouteFingerprint,
        SessionJournal, SetupOperations, SocketBindingOperations, StopSignal, StrictRouteAction,
        StrictRouteCondition, StrictRouteLayer, StrictRouteOperations, StrictRouteRule,
        StrictRouteRuleKind, StrictRouteSession, UnderlayOperations, WAIT_FAILED, WAIT_OBJECT_0,
        WAIT_TIMEOUT, WaitForMultipleObjects, WindowsNetworkInterfaceCatalog, WorkSignal,
        address_changed, bind_fixed_with, bind_resolved_socket_with, bind_target_with,
        build_network_interface_observations, cancel_notification_handles, capture_route_row,
        catalog_default_route, catalog_fallback_interface_identity,
        classify_adapter_create_failure, classify_notification_luid, classify_receive_null,
        classify_send_allocation_failure, classify_underlay_refresh, classify_wait_result,
        cleanup_transaction, copy_bounded_wide, create_event, dad_snapshot, delete_managed_address,
        delete_managed_route, dns_settings_query_flags, eligible_interface_identity,
        finish_setup_transaction, initialize_managed_address, install_managed_dns,
        install_managed_routes, interface_changed, interface_socket_option,
        ipv4_dns_settings_input, ipv4_interface_index_option_value, ipv4_sockaddr,
        ipv6_dns_settings_input, ipv6_interface_index_option_value, ipv6_sockaddr,
        leak_notification_owners, load_transaction, managed_address_matches, managed_device_health,
        managed_dns_matches, managed_notification_family, managed_state_health,
        normalize_dns_settings, prepare_managed_intent, refresh_underlay_with, require_exports,
        restore_managed_dns, revalidate_managed_network, route_changed, route_matches,
        setup_transaction, snapshot_underlay_at, snapshot_underlay_with, socket_addr_sockaddr,
        strict_route_rules, strict_route_state_matches, subscribe_notification_sequence,
        take_last_owned_route, underlay_matches_with, underlay_snapshot_matches, validate_artifact,
    };
    use crate::{
        ErrorKind, IpPrefix, Ipv4Prefix, Ipv6Prefix, ManagedStateDamage, ManagedTunHealth,
        SendOutcome, WaitOutcome,
    };
    use ferrum2_runtime::{
        DialOptions, InterfaceBinding, NetworkFamily, NetworkInterfaceCatalog,
        NetworkInterfaceCatalogError, NetworkInterfaceKind, NetworkInterfaceObservation,
        NetworkInterfaceResolver, NetworkSnapshot, RouteNetworkOptions, SystemBestRoute,
    };

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
            ("exact own", OWN_LUID, 1, true),
            ("foreign", FOREIGN_LUID, 2, false),
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
                true,
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
                true,
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
        assert_eq!(managed_notification_family(), AF_UNSPEC);

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

    struct InjectedAddressCleanup {
        reads: std::collections::VecDeque<ManagedAddressRead<u8>>,
        delete_error: bool,
        calls: Vec<&'static str>,
    }

    impl ManagedAddressCleanupOperations for InjectedAddressCleanup {
        type Row = u8;

        fn read(&mut self, _intended: &Self::Row) -> ManagedAddressRead<Self::Row> {
            self.calls.push("get");
            self.reads.pop_front().unwrap_or(ManagedAddressRead::Failed)
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
    fn managed_address_readback_and_cleanup_are_exact_and_foreign_safe() {
        let run = |reads, delete_error| {
            let mut cleanup = InjectedAddressCleanup {
                reads: std::collections::VecDeque::from(reads),
                delete_error,
                calls: Vec::new(),
            };
            let failed = delete_managed_address(&mut cleanup, &1);
            (failed, cleanup.calls)
        };
        assert_eq!(
            run(vec![ManagedAddressRead::Absent], false),
            (false, vec!["get"])
        );
        assert_eq!(
            run(
                vec![ManagedAddressRead::Present(1), ManagedAddressRead::Absent,],
                false,
            ),
            (false, vec!["get", "delete", "get"])
        );
        assert_eq!(
            run(vec![ManagedAddressRead::Present(2)], false),
            (true, vec!["get"]),
            "a foreign replacement is preserved"
        );
        for (delete_error, final_read) in [
            (true, ManagedAddressRead::Absent),
            (false, ManagedAddressRead::Failed),
            (false, ManagedAddressRead::Present(1)),
        ] {
            assert_eq!(
                run(
                    vec![ManagedAddressRead::Present(1), final_read],
                    delete_error,
                ),
                (true, vec!["get", "delete", "get"])
            );
        }

        let mut expected = MIB_UNICASTIPADDRESS_ROW::default();
        initialize_managed_address(&mut expected);
        assert_eq!(expected.PrefixOrigin, super::IpPrefixOriginManual);
        assert_eq!(expected.SuffixOrigin, super::IpSuffixOriginManual);
        expected.InterfaceLuid.Value = 7;
        expected.InterfaceIndex = 17;
        expected.Address = ipv4_sockaddr("198.18.0.2".parse().unwrap());
        expected.OnLinkPrefixLength = 30;
        let mut actual = expected;
        actual.DadState = IpDadStatePreferred;
        actual.CreationTimeStamp = 123;
        assert!(managed_address_matches(&expected, &actual));

        let changed = [
            {
                let mut row = actual;
                unsafe { row.InterfaceLuid.Value += 1 };
                row
            },
            {
                let mut row = actual;
                row.InterfaceIndex += 1;
                row
            },
            {
                let mut row = actual;
                row.Address = ipv4_sockaddr("198.18.0.3".parse().unwrap());
                row
            },
            {
                let mut row = actual;
                row.OnLinkPrefixLength += 1;
                row
            },
            {
                let mut row = actual;
                row.SkipAsSource = !row.SkipAsSource;
                row
            },
            {
                let mut row = actual;
                row.ValidLifetime = row.ValidLifetime.saturating_sub(1);
                row
            },
        ];
        assert!(
            changed
                .iter()
                .all(|row| !managed_address_matches(&expected, row))
        );

        let mut ipv6 = expected;
        ipv6.Address = ipv6_sockaddr("fd00::2".parse().unwrap());
        ipv6.OnLinkPrefixLength = 126;
        assert!(managed_address_matches(&ipv6, &ipv6));
    }

    #[derive(Clone)]
    struct InjectedUnderlay {
        interfaces: Vec<InterfaceIdentity>,
        routes: Vec<(std::net::IpAddr, RouteFingerprint)>,
        interface_metrics: Vec<(u32, u32)>,
        best_calls: usize,
        fail_at: Option<&'static str>,
        change_generation: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    }

    #[test]
    fn managed_state_health_reports_owned_route_dns_and_strict_route_damage() {
        for readback in [
            ManagedRouteRead::Absent,
            ManagedRouteRead::Present(2),
            ManagedRouteRead::Failed,
        ] {
            let mut routes = InjectedRouteCleanup {
                reads: [readback].into(),
                delete_error: false,
                calls: Vec::new(),
            };
            assert_eq!(
                managed_state_health(&[1], &mut routes, || Ok(true), || Ok(true)).unwrap(),
                ManagedTunHealth::Damaged(ManagedStateDamage::Route)
            );
        }

        let mut healthy_route = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            managed_state_health(&[1], &mut healthy_route, || Ok(false), || Ok(true)).unwrap(),
            ManagedTunHealth::Damaged(ManagedStateDamage::Dns)
        );

        let mut healthy_route = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            managed_state_health(&[1], &mut healthy_route, || Ok(true), || Ok(false)).unwrap(),
            ManagedTunHealth::Damaged(ManagedStateDamage::StrictRoute)
        );

        let mut healthy_route = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            managed_state_health(&[1], &mut healthy_route, || Ok(true), || Ok(true)).unwrap(),
            ManagedTunHealth::Healthy
        );
    }

    #[derive(Default)]
    struct InjectedStrictRouteState {
        calls: Vec<String>,
        installed: Vec<(u64, StrictRouteRule)>,
        sublayer_present: bool,
        damaged_filter: Option<u64>,
        fail_at: Option<String>,
        close_calls: usize,
    }

    struct InjectedStrictRoute {
        state: std::rc::Rc<std::cell::RefCell<InjectedStrictRouteState>>,
    }

    impl InjectedStrictRoute {
        fn step(&self, name: String) -> Result<(), Error> {
            let mut state = self.state.borrow_mut();
            state.calls.push(name.clone());
            if state.fail_at.as_deref() == Some(name.as_str()) {
                Err(Error)
            } else {
                Ok(())
            }
        }
    }

    impl StrictRouteOperations for InjectedStrictRoute {
        type Session = u64;

        fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
            self.step("open".into())?;
            Ok(7)
        }

        fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
            self.step("app-id".into())?;
            Ok(Box::from(&b"ferrum2-app"[..]))
        }

        fn begin_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
            self.step("begin".into())
        }

        fn add_sublayer(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
            self.step("sublayer".into())?;
            self.state.borrow_mut().sublayer_present = true;
            Ok(())
        }

        fn add_filter(
            &mut self,
            _session: &mut Self::Session,
            rule: &StrictRouteRule,
        ) -> Result<u64, Error> {
            let index = self.state.borrow().installed.len();
            self.step(format!("filter-{index}"))?;
            let id = 100 + u64::try_from(index).unwrap();
            self.state.borrow_mut().installed.push((id, rule.clone()));
            Ok(id)
        }

        fn commit_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
            self.step("commit".into())
        }

        fn abort_transaction(&mut self, _session: &mut Self::Session) -> Result<(), Error> {
            self.step("abort".into())?;
            let mut state = self.state.borrow_mut();
            state.sublayer_present = false;
            state.installed.clear();
            Ok(())
        }

        fn sublayer_matches(&self, _session: &Self::Session) -> Result<bool, Error> {
            self.step("health-sublayer".into())?;
            Ok(self.state.borrow().sublayer_present)
        }

        fn filter_matches(
            &self,
            _session: &Self::Session,
            id: u64,
            rule: &StrictRouteRule,
        ) -> Result<bool, Error> {
            self.step(format!("health-filter-{id}"))?;
            let state = self.state.borrow();
            Ok(state.damaged_filter != Some(id)
                && state
                    .installed
                    .iter()
                    .any(|(current_id, current)| *current_id == id && current == rule))
        }

        fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
            {
                let mut state = self.state.borrow_mut();
                state.close_calls += 1;
            }
            self.step("close".into())?;
            let mut state = self.state.borrow_mut();
            state.sublayer_present = false;
            state.installed.clear();
            *session = 0;
            Ok(())
        }
    }

    fn injected_strict_route(
        fail_at: Option<&str>,
    ) -> (
        InjectedStrictRoute,
        std::rc::Rc<std::cell::RefCell<InjectedStrictRouteState>>,
    ) {
        let state = std::rc::Rc::new(std::cell::RefCell::new(InjectedStrictRouteState {
            fail_at: fail_at.map(str::to_owned),
            ..InjectedStrictRouteState::default()
        }));
        (
            InjectedStrictRoute {
                state: state.clone(),
            },
            state,
        )
    }

    #[test]
    fn strict_route_rule_plan_is_family_and_managed_dns_bounded() {
        let app_id = b"opaque-app-id";
        let luid = 0x1122_3344_5566_7788;
        assert!(super::guid_matches(
            &StrictRouteLayer::V4.key(),
            &super::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        ));
        assert!(super::guid_matches(
            &StrictRouteLayer::V6.key(),
            &super::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ));
        assert_eq!(StrictRouteAction::Permit.raw(), super::FWP_ACTION_PERMIT);
        assert_eq!(StrictRouteAction::Block.raw(), super::FWP_ACTION_BLOCK);
        let dual = strict_route_rules(true, true, false, app_id, luid).unwrap();
        assert_eq!(dual.len(), 4);
        assert!(dual.iter().all(|rule| {
            rule.action == StrictRouteAction::Permit
                && rule.weight > super::STRICT_ROUTE_BLOCK_WEIGHT
        }));
        assert_eq!(
            dual.iter()
                .filter(|rule| rule.layer == StrictRouteLayer::V4)
                .count(),
            2
        );
        assert_eq!(
            dual.iter()
                .filter(|rule| rule.layer == StrictRouteLayer::V6)
                .count(),
            2
        );
        assert!(dual.iter().any(|rule| {
            rule.kind == StrictRouteRuleKind::TunPermitV4
                && rule.conditions.as_ref() == [StrictRouteCondition::LocalInterfaceLuid(luid)]
        }));
        let luid_condition = StrictRouteCondition::LocalInterfaceLuid(luid);
        assert_eq!(luid_condition.data_type(), super::FWP_UINT64);
        assert!(super::guid_matches(
            &luid_condition.field_key(),
            &super::FWPM_CONDITION_IP_LOCAL_INTERFACE,
        ));
        assert!(dual.iter().any(|rule| {
            rule.kind == StrictRouteRuleKind::AppPermitV6
                && rule.conditions.as_ref() == [StrictRouteCondition::AppId(Box::from(&app_id[..]))]
        }));

        let ipv4_only = strict_route_rules(true, false, false, app_id, luid).unwrap();
        assert_eq!(ipv4_only.len(), 5);
        assert!(ipv4_only.iter().any(|rule| {
            rule.kind == StrictRouteRuleKind::FamilyBlockV6
                && rule.layer == StrictRouteLayer::V6
                && rule.action == StrictRouteAction::Block
                && rule.conditions.is_empty()
        }));
        let ipv6_only = strict_route_rules(false, true, false, app_id, luid).unwrap();
        assert_eq!(ipv6_only.len(), 5);
        assert!(ipv6_only.iter().any(|rule| {
            rule.kind == StrictRouteRuleKind::FamilyBlockV4
                && rule.layer == StrictRouteLayer::V4
                && rule.action == StrictRouteAction::Block
                && rule.conditions.is_empty()
        }));

        let dual_with_dns = strict_route_rules(true, true, true, app_id, luid).unwrap();
        assert_eq!(dual_with_dns.len(), 8);
        let dns = dual_with_dns
            .iter()
            .filter(|rule| {
                matches!(
                    rule.kind,
                    StrictRouteRuleKind::DnsTcpBlockV4
                        | StrictRouteRuleKind::DnsUdpBlockV4
                        | StrictRouteRuleKind::DnsTcpBlockV6
                        | StrictRouteRuleKind::DnsUdpBlockV6
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(dns.len(), 4);
        assert!(dns.iter().all(|rule| {
            rule.action == StrictRouteAction::Block
                && rule.weight == super::STRICT_ROUTE_BLOCK_WEIGHT
                && rule
                    .conditions
                    .contains(&StrictRouteCondition::RemotePort(53))
                && rule
                    .conditions
                    .iter()
                    .any(|condition| matches!(condition, StrictRouteCondition::IpProtocol(6 | 17)))
        }));
        for (kind, layer, protocol) in [
            (StrictRouteRuleKind::DnsTcpBlockV4, StrictRouteLayer::V4, 6),
            (StrictRouteRuleKind::DnsUdpBlockV4, StrictRouteLayer::V4, 17),
            (StrictRouteRuleKind::DnsTcpBlockV6, StrictRouteLayer::V6, 6),
            (StrictRouteRuleKind::DnsUdpBlockV6, StrictRouteLayer::V6, 17),
        ] {
            assert!(dns.iter().any(|rule| {
                rule.kind == kind
                    && rule.layer == layer
                    && rule.conditions.as_ref()
                        == [
                            StrictRouteCondition::IpProtocol(protocol),
                            StrictRouteCondition::RemotePort(53),
                        ]
            }));
        }
        assert_eq!(
            strict_route_rules(true, false, true, app_id, luid)
                .unwrap()
                .len(),
            9
        );
        assert!(strict_route_rules(false, false, false, app_id, luid).is_err());
        assert!(strict_route_rules(true, false, false, &[], luid).is_err());
        assert!(strict_route_rules(true, false, false, app_id, 0).is_err());
    }

    #[test]
    fn strict_route_transaction_is_atomic_and_raii_closes_the_dynamic_session() {
        assert!(strict_route_state_matches::<InjectedStrictRoute>(false, None).unwrap());
        assert!(!strict_route_state_matches::<InjectedStrictRoute>(true, None).unwrap());
        let (operations, state) = injected_strict_route(None);
        {
            let mut session = StrictRouteSession::open(operations).unwrap();
            session
                .install(true, false, true, 0x1122_3344_5566_7788)
                .unwrap();
            assert!(session.health().unwrap());
            assert!(strict_route_state_matches(true, Some(&session)).unwrap());
            assert!(!strict_route_state_matches(false, Some(&session)).unwrap());
            assert_eq!(state.borrow().installed.len(), 9);
            assert_eq!(state.borrow().close_calls, 0);
        }
        let state = state.borrow();
        assert_eq!(state.close_calls, 1);
        assert_eq!(state.calls.last().map(String::as_str), Some("close"));
        assert!(
            state
                .calls
                .iter()
                .position(|call| call == "commit")
                .unwrap()
                < state
                    .calls
                    .iter()
                    .position(|call| call == "health-sublayer")
                    .unwrap()
        );
    }

    #[test]
    fn strict_route_install_failure_aborts_then_dynamic_close_removes_partial_state() {
        for failure in ["sublayer", "filter-3", "commit"] {
            let (operations, state) = injected_strict_route(Some(failure));
            {
                let mut session = StrictRouteSession::open(operations).unwrap();
                assert!(session.install(true, false, true, 7).is_err(), "{failure}");
            }
            let state = state.borrow();
            let failure_position = state.calls.iter().position(|call| call == failure).unwrap();
            let abort_position = state.calls.iter().position(|call| call == "abort").unwrap();
            let close_position = state.calls.iter().position(|call| call == "close").unwrap();
            assert!(failure_position < abort_position && abort_position < close_position);
            assert_eq!(state.close_calls, 1);
            assert!(state.installed.is_empty());
        }
    }

    #[test]
    fn strict_route_failed_explicit_close_is_retained_for_raii_retry() {
        let (operations, state) = injected_strict_route(Some("close"));
        let mut session = StrictRouteSession::open(operations).unwrap();
        session.install(true, true, false, 7).unwrap();
        assert!(session.close().is_err());
        state.borrow_mut().fail_at = None;
        drop(session);
        assert_eq!(state.borrow().close_calls, 2);
        assert!(state.borrow().installed.is_empty());
        assert_eq!(
            state
                .borrow()
                .calls
                .iter()
                .filter(|call| call.as_str() == "close")
                .count(),
            2
        );
    }

    #[test]
    fn strict_route_health_reads_every_exact_filter_id_and_rejects_damage() {
        let (operations, state) = injected_strict_route(None);
        let mut session = StrictRouteSession::open(operations).unwrap();
        session.install(true, true, false, 7).unwrap();
        assert!(session.health().unwrap());
        let expected_ids = state
            .borrow()
            .installed
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in &expected_ids {
            assert!(
                state
                    .borrow()
                    .calls
                    .contains(&format!("health-filter-{id}"))
            );
        }
        state.borrow_mut().damaged_filter = expected_ids.get(2).copied();
        assert!(!session.health().unwrap());
        {
            let mut state = state.borrow_mut();
            state.damaged_filter = None;
            state.installed[2].1.weight = super::STRICT_ROUTE_BLOCK_WEIGHT;
        }
        assert!(!session.health().unwrap());
    }

    #[test]
    fn strict_route_readback_classifies_missing_and_aborted_sessions_as_damage() {
        assert!(
            super::wfp_readback_present(super::ERROR_SUCCESS, super::FWP_E_FILTER_NOT_FOUND)
                .unwrap()
        );
        assert!(
            !super::wfp_readback_present(
                super::FWP_E_FILTER_NOT_FOUND as u32,
                super::FWP_E_FILTER_NOT_FOUND,
            )
            .unwrap()
        );
        assert!(
            !super::wfp_readback_present(
                super::FWP_E_SESSION_ABORTED as u32,
                super::FWP_E_FILTER_NOT_FOUND,
            )
            .unwrap()
        );
        assert!(super::wfp_readback_present(0xdead_beef, super::FWP_E_FILTER_NOT_FOUND).is_err());
    }

    #[test]
    fn managed_device_health_is_closed_and_checks_owned_state_in_order() {
        use std::cell::Cell;

        for (name, adapter, session, address_ledger, identity, addresses, expected) in [
            (
                "adapter handle",
                false,
                true,
                true,
                true,
                true,
                ManagedStateDamage::Adapter,
            ),
            (
                "interface identity",
                true,
                true,
                true,
                false,
                true,
                ManagedStateDamage::Adapter,
            ),
            (
                "device session",
                true,
                false,
                true,
                true,
                true,
                ManagedStateDamage::Session,
            ),
            (
                "address ledger",
                true,
                true,
                false,
                true,
                true,
                ManagedStateDamage::Address,
            ),
            (
                "address readback",
                true,
                true,
                true,
                true,
                false,
                ManagedStateDamage::Address,
            ),
        ] {
            assert_eq!(
                managed_device_health(adapter, session, address_ledger, || identity, || addresses,),
                ManagedTunHealth::Damaged(expected),
                "{name}"
            );
        }

        assert_eq!(
            managed_device_health(true, true, true, || true, || true),
            ManagedTunHealth::Healthy
        );

        let identity_calls = Cell::new(0);
        let address_calls = Cell::new(0);
        assert_eq!(
            managed_device_health(
                false,
                true,
                true,
                || {
                    identity_calls.set(identity_calls.get() + 1);
                    true
                },
                || {
                    address_calls.set(address_calls.get() + 1);
                    true
                },
            ),
            ManagedTunHealth::Damaged(ManagedStateDamage::Adapter)
        );
        assert_eq!(identity_calls.get(), 0);
        assert_eq!(address_calls.get(), 0);
    }

    #[test]
    fn network_change_revalidates_underlay_and_owned_routes_before_shutdown() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let route = RouteFingerprint {
            interface_luid: physical.luid,
            interface_index: physical.index,
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 4,
            source: Some("192.0.2.2".parse().unwrap()),
        };
        let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
        let underlay = InjectedUnderlay {
            interfaces: vec![physical],
            routes: vec![(endpoint.ip(), route)],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();

        let mut generation = [1, 1].into_iter();
        let mut validated_generation = 0;
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[1],
                    validated_generation: &mut validated_generation,
                },
                false,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
                || Ok(true),
                || Ok(true),
            )
            .unwrap(),
            ManagedNetworkValidationOutcome::Unchanged
        );
        assert_eq!(validated_generation, 1);
        assert_eq!(owned_routes.calls, ["get"]);

        for (name, changed_underlay, route_readback, expected) in [
            (
                "underlay",
                true,
                ManagedRouteRead::Present(1),
                ManagedNetworkValidationOutcome::UnderlayChanged,
            ),
            (
                "owned route",
                false,
                ManagedRouteRead::Present(2),
                ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Route),
            ),
            (
                "replacement query",
                false,
                ManagedRouteRead::Failed,
                ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Route),
            ),
        ] {
            let mut changed = underlay.clone();
            if changed_underlay {
                changed.routes[0].1.metric += 1;
            }
            let mut owned_routes = InjectedRouteCleanup {
                reads: [route_readback].into(),
                delete_error: false,
                calls: Vec::new(),
            };
            let mut observed = 1;
            let mut generation = [2, 2].into_iter();
            assert_eq!(
                revalidate_managed_network(
                    ManagedNetworkValidation {
                        policy: &policy,
                        owned: wintun,
                        routes: &[1],
                        validated_generation: &mut observed,
                    },
                    false,
                    || generation.next().unwrap(),
                    &mut changed,
                    &mut owned_routes,
                    || Ok(true),
                    || Ok(true),
                )
                .unwrap(),
                expected,
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
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[1],
                    validated_generation: &mut observed,
                },
                false,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
                || Ok(true),
                || Ok(true),
            )
            .unwrap(),
            ManagedNetworkValidationOutcome::Unchanged,
            "one repeated/coalesced signal gets one bounded retry"
        );
        assert_eq!(observed, 3);

        let mut generation = [4, 5, 6].into_iter();
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1), ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[1],
                    validated_generation: &mut observed,
                },
                false,
                || generation.next().unwrap(),
                &mut underlay.clone(),
                &mut owned_routes,
                || Ok(true),
                || Ok(true),
            )
            .unwrap(),
            ManagedNetworkValidationOutcome::UnderlayChanged,
            "repeated changes exhaust the bounded retry"
        );
        assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
        assert!(policy.bind_target(&NeverSocket, endpoint).is_err());

        let policy = snapshot_underlay_with(&config, &mut underlay.clone()).unwrap();
        let mut observed = 0;
        let mut owned_routes = InjectedRouteCleanup {
            reads: [ManagedRouteRead::Present(1)].into(),
            delete_error: false,
            calls: Vec::new(),
        };
        let mut additional_checks = 0;
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[1],
                    validated_generation: &mut observed,
                },
                true,
                || 0,
                &mut underlay.clone(),
                &mut owned_routes,
                || {
                    additional_checks += 1;
                    Ok(false)
                },
                || Ok(true),
            )
            .unwrap(),
            ManagedNetworkValidationOutcome::ManagedStateDamaged(ManagedStateDamage::Dns),
            "a forced runtime audit rejects a mutated DNS lease even without a generation bump"
        );
        assert_eq!(additional_checks, 1);
        assert!(!policy.valid.load(std::sync::atomic::Ordering::Acquire));
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

        fn best_interface(&mut self, destination: std::net::SocketAddr) -> Result<u32, Error> {
            self.best_calls += 1;
            if self.fail_at == Some("best") {
                Err(Error)
            } else {
                self.routes
                    .iter()
                    .find_map(|(candidate, route)| {
                        (*candidate == destination.ip()).then_some(route.interface_index)
                    })
                    .ok_or(Error)
            }
        }

        fn interface_metric(
            &mut self,
            _family: std::net::IpAddr,
            interface_index: u32,
        ) -> Result<u32, Error> {
            Ok(self
                .interface_metrics
                .iter()
                .find_map(|(index, metric)| (*index == interface_index).then_some(*metric))
                .unwrap_or(0))
        }

        fn constrained_route(
            &mut self,
            destination: std::net::SocketAddr,
            interface_index: u32,
            _require_source: bool,
        ) -> Result<RouteFingerprint, Error> {
            if self.fail_at == Some("route") {
                return Err(Error);
            }
            if let Some(generation) = &self.change_generation {
                generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            self.routes
                .iter()
                .find_map(|(candidate, route)| {
                    (*candidate == destination.ip() && route.interface_index == interface_index)
                        .then_some(*route)
                })
                .or_else(|| {
                    self.routes.iter().find_map(|(candidate, route)| {
                        (*candidate == destination.ip()).then_some(*route)
                    })
                })
                .ok_or(Error)
        }
    }

    #[derive(Default)]
    struct InjectedBinder {
        calls: Vec<(std::net::IpAddr, u32)>,
        change_generation: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
        fail: bool,
    }

    impl SocketBindingOperations for InjectedBinder {
        fn bind(&mut self, family: std::net::IpAddr, interface_index: u32) -> Result<(), Error> {
            self.calls.push((family, interface_index));
            if let Some(generation) = &self.change_generation {
                generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            }
            if self.fail { Err(Error) } else { Ok(()) }
        }
    }

    fn injected_fingerprint(
        identity: InterfaceIdentity,
        family: std::net::IpAddr,
    ) -> RouteFingerprint {
        match family {
            std::net::IpAddr::V4(_) => RouteFingerprint {
                interface_luid: identity.luid,
                interface_index: identity.index,
                destination: "0.0.0.0".parse().unwrap(),
                prefix_length: 0,
                next_hop: "192.0.2.1".parse().unwrap(),
                metric: 4,
                source: Some("192.0.2.2".parse().unwrap()),
            },
            std::net::IpAddr::V6(_) => RouteFingerprint {
                interface_luid: identity.luid,
                interface_index: identity.index,
                destination: "::".parse().unwrap(),
                prefix_length: 0,
                next_hop: "2001:db8:ffff::1".parse().unwrap(),
                metric: 4,
                source: Some("2001:db8:ffff::2".parse().unwrap()),
            },
        }
    }

    #[test]
    fn dual_stack_target_binding_selects_actual_target_and_rejects_tun() {
        let physical_v4 = InterfaceIdentity { luid: 7, index: 17 };
        let physical_v6 = InterfaceIdentity { luid: 8, index: 18 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let fixed_v4: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let fixed_v6: std::net::SocketAddr = "[2001:db8::8]:443".parse().unwrap();
        let target_v4_a: std::net::SocketAddr = "203.0.113.8:80".parse().unwrap();
        let target_v4_b: std::net::SocketAddr = "192.0.2.200:80".parse().unwrap();
        let target_v6: std::net::SocketAddr = "[2001:db8:1::8]:80".parse().unwrap();
        let tun_target: std::net::SocketAddr = "203.0.113.19:80".parse().unwrap();
        let routes = vec![
            (
                fixed_v4.ip(),
                injected_fingerprint(physical_v4, fixed_v4.ip()),
            ),
            (
                fixed_v6.ip(),
                injected_fingerprint(physical_v6, fixed_v6.ip()),
            ),
            (
                target_v4_a.ip(),
                injected_fingerprint(physical_v4, target_v4_a.ip()),
            ),
            (
                target_v4_b.ip(),
                injected_fingerprint(physical_v6, target_v4_b.ip()),
            ),
            (
                target_v6.ip(),
                injected_fingerprint(physical_v6, target_v6.ip()),
            ),
            (
                tun_target.ip(),
                injected_fingerprint(wintun, tun_target.ip()),
            ),
        ];
        let mut operations = InjectedUnderlay {
            interfaces: vec![physical_v4, physical_v6, wintun],
            routes,
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(41));
        let config = crate::ManagedNetworkConfig::new(
            Vec::new(),
            vec![fixed_v4, fixed_v6],
            true,
            None,
            None,
        )
        .unwrap();
        let policy = snapshot_underlay_at(&config, generation, 41, &mut operations).unwrap();
        policy.set_owned_identity(wintun).unwrap();

        let mut binder = InjectedBinder::default();
        bind_fixed_with(&policy, fixed_v4, &mut binder).unwrap();
        bind_fixed_with(&policy, fixed_v6, &mut binder).unwrap();
        bind_target_with(&policy, target_v4_a, &mut operations, &mut binder).unwrap();
        bind_target_with(&policy, target_v4_b, &mut operations, &mut binder).unwrap();
        bind_target_with(&policy, target_v6, &mut operations, &mut binder).unwrap();
        assert_eq!(operations.best_calls, 2, "target binds remain constrained");
        assert_eq!(
            binder.calls,
            [
                (fixed_v4.ip(), physical_v4.index),
                (fixed_v6.ip(), physical_v6.index),
                (target_v4_a.ip(), physical_v4.index),
                (target_v4_b.ip(), physical_v6.index),
                (target_v6.ip(), physical_v6.index),
            ],
            "multiple default routes are selected per actual target and family"
        );
        assert!(bind_target_with(&policy, tun_target, &mut operations, &mut binder).is_err());
        assert_eq!(
            operations.best_calls, 2,
            "target binds never use global best route"
        );
        assert_eq!(
            binder.calls.len(),
            5,
            "the managed interface is never bound"
        );

        let fixed_only =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![fixed_v4], false, None, None)
                .unwrap();
        let fixed_only = snapshot_underlay_with(&fixed_only, &mut operations).unwrap();
        fixed_only.set_owned_identity(wintun).unwrap();
        assert!(bind_target_with(&fixed_only, target_v4_a, &mut operations, &mut binder).is_err());
    }

    #[test]
    fn target_binding_excludes_tun_and_orders_prefix_then_effective_metric() {
        let physical_a = InterfaceIdentity { luid: 7, index: 17 };
        let physical_b = InterfaceIdentity { luid: 8, index: 18 };
        let physical_c = InterfaceIdentity { luid: 9, index: 20 };
        let wintun = InterfaceIdentity {
            luid: 10,
            index: 19,
        };
        let target: std::net::SocketAddr = "203.0.113.8:443".parse().unwrap();
        let mut route_a = injected_fingerprint(physical_a, target.ip());
        route_a.prefix_length = 8;
        route_a.metric = 1;
        let mut route_b = injected_fingerprint(physical_b, target.ip());
        route_b.prefix_length = 24;
        route_b.metric = 100;
        let mut route_c = injected_fingerprint(physical_c, target.ip());
        route_c.prefix_length = 24;
        route_c.metric = 50;
        let mut tun_route = injected_fingerprint(wintun, target.ip());
        tun_route.prefix_length = 32;
        tun_route.metric = 0;
        let mut operations = InjectedUnderlay {
            interfaces: vec![physical_a, physical_b, physical_c, wintun],
            routes: vec![
                (target.ip(), route_a),
                (target.ip(), route_b),
                (target.ip(), route_c),
                (target.ip(), tun_route),
            ],
            interface_metrics: vec![(physical_b.index, 100), (physical_c.index, 10)],
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
        let policy = snapshot_underlay_with(&config, &mut operations).unwrap();
        policy.set_owned_identity(wintun).unwrap();
        let mut binder = InjectedBinder::default();

        bind_target_with(&policy, target, &mut operations, &mut binder).unwrap();

        assert_eq!(binder.calls, [(target.ip(), physical_c.index)]);
        assert_eq!(operations.best_calls, 0);
    }

    #[test]
    fn underlay_binding_fails_closed_across_every_generation_race() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let target: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
        let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(7));
        let make_operations = || InjectedUnderlay {
            interfaces: vec![physical, wintun],
            routes: vec![(target.ip(), injected_fingerprint(physical, target.ip()))],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let mut operations = make_operations();
        let policy = snapshot_underlay_at(&config, generation.clone(), 7, &mut operations).unwrap();
        policy.set_owned_identity(wintun).unwrap();

        generation.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let mut binder = InjectedBinder::default();
        assert!(bind_target_with(&policy, target, &mut operations, &mut binder).is_err());
        assert!(
            binder.calls.is_empty(),
            "a stale policy does not touch the socket"
        );

        policy.accept_generation(8);
        let mut changes_during_route = make_operations();
        changes_during_route.change_generation = Some(generation.clone());
        assert!(
            bind_target_with(&policy, target, &mut changes_during_route, &mut binder,).is_err()
        );
        assert!(
            binder.calls.is_empty(),
            "a route-selection race is caught before setsockopt"
        );

        policy.accept_generation(9);
        let mut changes_during_bind = InjectedBinder {
            change_generation: Some(generation.clone()),
            ..InjectedBinder::default()
        };
        assert!(
            bind_target_with(
                &policy,
                target,
                &mut make_operations(),
                &mut changes_during_bind,
            )
            .is_err()
        );
        assert_eq!(changes_during_bind.calls.len(), 1);

        let mut validated_generation = 9;
        let mut no_routes = InjectedRouteCleanup {
            reads: std::collections::VecDeque::new(),
            delete_error: false,
            calls: Vec::new(),
        };
        assert_eq!(
            revalidate_managed_network(
                ManagedNetworkValidation {
                    policy: &policy,
                    owned: wintun,
                    routes: &[],
                    validated_generation: &mut validated_generation,
                },
                false,
                || generation.load(std::sync::atomic::Ordering::Acquire),
                &mut make_operations(),
                &mut no_routes,
                || Ok(true),
                || Ok(true),
            )
            .unwrap(),
            ManagedNetworkValidationOutcome::Unchanged
        );
        assert_eq!(validated_generation, 10);
        bind_target_with(
            &policy,
            target,
            &mut make_operations(),
            &mut InjectedBinder::default(),
        )
        .unwrap();

        let fixed =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![target], false, None, None).unwrap();
        let mut snapshot_race = make_operations();
        snapshot_race.change_generation = Some(generation.clone());
        assert!(snapshot_underlay_at(&fixed, generation, 10, &mut snapshot_race).is_err());
    }

    #[test]
    fn underlay_refresh_is_transactional_and_temporary_capture_failure_is_recoverable() {
        let physical_a = InterfaceIdentity { luid: 7, index: 17 };
        let physical_b = InterfaceIdentity { luid: 8, index: 18 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], false, None, None)
                .unwrap();
        let generation = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1));
        let mut initial_operations = InjectedUnderlay {
            interfaces: vec![physical_a, wintun],
            routes: vec![(
                endpoint.ip(),
                injected_fingerprint(physical_a, endpoint.ip()),
            )],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let current = snapshot_underlay_at(
            &config,
            std::sync::Arc::clone(&generation),
            1,
            &mut initial_operations,
        )
        .unwrap();
        current.set_owned_identity(wintun).unwrap();

        generation.store(2, std::sync::atomic::Ordering::Release);
        let mut refreshed_operations = InjectedUnderlay {
            interfaces: vec![physical_b, wintun],
            routes: vec![(
                endpoint.ip(),
                injected_fingerprint(physical_b, endpoint.ip()),
            )],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let mut validated_generation = 1;
        let refreshed = refresh_underlay_with(
            &config,
            &current,
            wintun,
            &mut validated_generation,
            std::sync::Arc::clone(&generation),
            &mut refreshed_operations,
        )
        .unwrap();

        assert_eq!(validated_generation, 2);
        assert!(!current.valid.load(std::sync::atomic::Ordering::Acquire));
        assert!(refreshed.generation_is_current());
        let mut binder = InjectedBinder::default();
        bind_fixed_with(&refreshed, endpoint, &mut binder).unwrap();
        assert_eq!(binder.calls, [(endpoint.ip(), physical_b.index)]);

        generation.store(3, std::sync::atomic::Ordering::Release);
        let mut failed_operations = InjectedUnderlay {
            fail_at: Some("route"),
            ..refreshed_operations
        };
        let result = classify_underlay_refresh(refresh_underlay_with(
            &config,
            &refreshed,
            wintun,
            &mut validated_generation,
            generation,
            &mut failed_operations,
        ));
        let error = match result {
            Ok(_) => panic!("temporary route capture failure must fail the refresh"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::RecoverableSession);
        assert!(refreshed.valid.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(validated_generation, 2);
    }

    #[test]
    fn managed_generation_and_underlay_post_capture_use_frozen_physical_route() {
        let physical = InterfaceIdentity { luid: 7, index: 17 };
        let wintun = InterfaceIdentity { luid: 9, index: 19 };
        let route = RouteFingerprint {
            interface_luid: physical.luid,
            interface_index: physical.index,
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 4,
            source: Some("192.0.2.2".parse().unwrap()),
        };
        let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
        let mut operations = InjectedUnderlay {
            interfaces: vec![physical],
            routes: vec![(endpoint.ip(), route)],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };
        let policy = snapshot_underlay_with(&config, &mut operations).unwrap();
        assert_eq!(
            operations.best_calls, 1,
            "unrestricted lookup is pre-capture"
        );

        operations.interfaces.push(wintun);
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
                source: Some("192.0.2.3".parse().unwrap()),
                ..route
            },
            RouteFingerprint {
                next_hop: "192.0.2.9".parse().unwrap(),
                ..route
            },
            RouteFingerprint { metric: 5, ..route },
        ] {
            let mut changed_operations = operations.clone();
            changed_operations.routes[0].1 = changed;
            assert!(!underlay_matches_with(&policy, wintun, &mut changed_operations).unwrap());
        }

        let mut changed_identity = operations.clone();
        changed_identity.interfaces[0].luid += 1;
        assert!(!underlay_matches_with(&policy, wintun, &mut changed_identity).unwrap());

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
            destination: "0.0.0.0".parse().unwrap(),
            prefix_length: 0,
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 4,
            source: Some("192.0.2.2".parse().unwrap()),
        };
        let endpoint: std::net::SocketAddr = "198.51.100.8:443".parse().unwrap();
        let config =
            crate::ManagedNetworkConfig::new(Vec::new(), vec![endpoint], true, None, None).unwrap();
        let operations = InjectedUnderlay {
            interfaces: vec![physical],
            routes: vec![(endpoint.ip(), route)],
            interface_metrics: Vec::new(),
            best_calls: 0,
            fail_at: None,
            change_generation: None,
        };

        for failure in ["eligible", "best", "route"] {
            let mut failed = operations.clone();
            failed.fail_at = Some(failure);
            assert!(snapshot_underlay_with(&config, &mut failed).is_err());
        }
        let mut none = operations.clone();
        none.interfaces.clear();
        assert!(snapshot_underlay_with(&config, &mut none).is_err());
        let mut missing_best = operations.clone();
        missing_best.routes[0].1.interface_index += 1;
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
            crate::ManagedNetworkConfig::new(Vec::new(), Vec::new(), true, None, None).unwrap();
        assert_eq!(
            prepare_managed_intent(Some(&manual_direct), |config| {
                calls.extend(["subscribe", "generation", "default-snapshot"]);
                assert!(config.needs_target_binder());
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
        let managed = crate::ManagedNetworkConfig::new(
            vec![IpPrefix::V4(prefix)],
            vec![endpoint.into()],
            true,
            Some(dns_address),
            None,
        )
        .unwrap();
        let config = crate::AdapterConfig::new(
            adapter_name.into(),
            Some(Ipv4Prefix::new("198.18.0.2".parse().unwrap(), 30).unwrap()),
            Some(crate::Ipv6Prefix::new("fd00::2".parse().unwrap(), 126).unwrap()),
            1420,
            8_388_608,
            std::time::Duration::from_secs(10),
        )
        .unwrap()
        .with_managed_network(managed)
        .unwrap();
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
            destination: "203.0.113.0".parse().unwrap(),
            prefix_length: 24,
            next_hop: "192.0.2.137".parse().unwrap(),
            metric: 31337,
            source: Some("192.0.2.138".parse().unwrap()),
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
            route.next_hop.to_string(),
            route.source.unwrap().to_string(),
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
        type Address = std::net::IpAddr;

        fn snapshot(&mut self) -> Result<Self::Settings, Error> {
            self.calls.push("snapshot");
            (self.fail_at != Some("snapshot"))
                .then_some(self.current)
                .ok_or(Error)
        }

        fn apply(&mut self, _address: Self::Address) -> Result<Self::Settings, Error> {
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
    fn managed_dns_runtime_readback_detects_replacement_and_failure() {
        let lease = ManagedDnsLease {
            previous: 1,
            applied: 2,
        };
        let mut matching = InjectedManagedDns {
            current: 2,
            fail_at: None,
            replace_on_read: None,
            readbacks: 0,
            calls: Vec::new(),
        };
        assert!(managed_dns_matches(&mut matching, &lease).unwrap());
        matching.current = 3;
        assert!(!managed_dns_matches(&mut matching, &lease).unwrap());
        matching.fail_at = Some("readback");
        assert!(managed_dns_matches(&mut matching, &lease).is_err());
    }

    #[test]
    fn managed_dns_snapshots_reads_back_and_conditionally_restores() {
        let address = std::net::IpAddr::V4("198.18.0.1".parse().unwrap());
        let ipv6_address = std::net::IpAddr::V6("fd00::1".parse().unwrap());
        let make = || InjectedManagedDns {
            current: 1,
            fail_at: None,
            replace_on_read: None,
            readbacks: 0,
            calls: Vec::new(),
        };

        for family_address in [address, ipv6_address] {
            let mut complete = make();
            let mut lease = None;
            install_managed_dns(family_address, &mut complete, &mut lease).unwrap();
            assert_eq!(complete.calls, ["snapshot", "apply", "readback"]);
            assert!(!restore_managed_dns(&mut complete, lease.as_ref().unwrap()));
            assert_eq!(complete.current, 1);
            assert_eq!(
                complete.calls,
                [
                    "snapshot", "apply", "readback", "readback", "restore", "readback"
                ]
            );
        }

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

        for (settings, expected) in [
            (Ipv4DnsSettings(None), &[0_u16][..]),
            (
                Ipv4DnsSettings(Some(Box::from([b'1' as u16, b'.' as u16, b'1' as u16]))),
                &[b'1' as u16, b'.' as u16, b'1' as u16, 0][..],
            ),
        ] {
            let (name_server, raw) = ipv4_dns_settings_input(&settings);
            assert_eq!(raw.Flags, u64::from(DNS_SETTING_NAMESERVER));
            assert!(!raw.NameServer.is_null());
            assert_eq!(raw.NameServer, name_server.as_ptr().cast_mut());
            assert_eq!(name_server.as_ref(), expected);
        }

        assert_eq!(dns_settings_query_flags(DnsFamily::Ipv4), 0);
        assert_eq!(
            dns_settings_query_flags(DnsFamily::Ipv6),
            u64::from(DNS_SETTING_IPV6)
        );

        let ipv6_settings = Ipv6DnsSettings(Some("fd00::1".encode_utf16().collect::<Box<[u16]>>()));
        let (name_server, raw) = ipv6_dns_settings_input(&ipv6_settings);
        assert_eq!(
            raw.Flags,
            u64::from(DNS_SETTING_NAMESERVER | DNS_SETTING_IPV6)
        );
        assert_eq!(raw.NameServer, name_server.as_ptr().cast_mut());
        assert_eq!(name_server.last(), Some(&0));

        let mixed = "1.1.1.1, 2001:0db8::1 8.8.8.8,2001:db8::2"
            .encode_utf16()
            .collect::<Vec<_>>();
        let ipv4 = normalize_dns_settings(Some(&mixed), DnsFamily::Ipv4)
            .unwrap()
            .unwrap();
        let ipv6 = normalize_dns_settings(Some(&mixed), DnsFamily::Ipv6)
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf16(&ipv4).unwrap(), "1.1.1.1,8.8.8.8");
        assert_eq!(
            String::from_utf16(&ipv6).unwrap(),
            "2001:db8::1,2001:db8::2"
        );
        assert!(normalize_dns_settings(Some(&[b'x' as u16]), DnsFamily::Ipv4).is_err());

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
        ipv4: bool,
        ipv6: bool,
        fail_at: Option<usize>,
        cleanup_fail_at: Option<usize>,
        idle: bool,
        calls: Vec<&'static str>,
        resources: Vec<&'static str>,
        notifications: bool,
        strict_route: bool,
        routes: Vec<&'static str>,
        dns: Vec<&'static str>,
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

        fn identify_adapter(&mut self) -> Result<(), Error> {
            self.step("identity", None)
        }

        fn ipv4_enabled(&self) -> bool {
            self.ipv4
        }

        fn ipv6_enabled(&self) -> bool {
            self.ipv6
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
            assert!(self.resources.contains(&"session"));
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

        fn close_strict_route(&mut self) -> Option<bool> {
            if !std::mem::take(&mut self.strict_route) {
                return None;
            }
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push("strict-route");
            Some(self.cleanup_fail_at == Some(position))
        }

        fn delete_last_route(&mut self) -> Option<bool> {
            let route = self.routes.pop()?;
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push(route);
            Some(self.cleanup_fail_at == Some(position))
        }

        fn restore_last_dns(&mut self) -> Option<bool> {
            let dns = self.dns.pop()?;
            let position = self.cleanup_calls.len();
            self.cleanup_calls.push(dns);
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
    fn every_enabled_family_setup_stage_fails_closed_and_rolls_back() {
        let cases: [(bool, bool, &[&str]); 3] = [
            (
                true,
                false,
                &[
                    "cancel",
                    "deadline",
                    "create",
                    "driver",
                    "start-session",
                    "identity",
                    "ipv4-mtu",
                    "ipv4-address",
                    "dad",
                ],
            ),
            (
                false,
                true,
                &[
                    "cancel",
                    "deadline",
                    "create",
                    "driver",
                    "start-session",
                    "identity",
                    "ipv6-mtu",
                    "ipv6-address",
                    "dad",
                ],
            ),
            (
                true,
                true,
                &[
                    "cancel",
                    "deadline",
                    "create",
                    "driver",
                    "start-session",
                    "identity",
                    "ipv4-mtu",
                    "ipv6-mtu",
                    "ipv4-address",
                    "ipv6-address",
                    "dad",
                ],
            ),
        ];
        for (ipv4, ipv6, order) in cases {
            for failed in 0..order.len() {
                let mut setup = InjectedSetup {
                    ipv4,
                    ipv6,
                    fail_at: Some(failed),
                    cleanup_fail_at: None,
                    idle: true,
                    calls: Vec::new(),
                    resources: Vec::new(),
                    notifications: false,
                    strict_route: false,
                    routes: Vec::new(),
                    dns: Vec::new(),
                    cleanup_calls: Vec::new(),
                };
                assert!(
                    setup_transaction(&mut setup).is_err(),
                    "families {ipv4}/{ipv6}, step {failed}"
                );
                assert_eq!(setup.calls, order[..=failed]);
                let expected_cleanup = [
                    ("ipv6-address", "ipv6-address"),
                    ("ipv4-address", "ipv4-address"),
                    ("ipv6-mtu", "ipv6-mtu"),
                    ("ipv4-mtu", "ipv4-mtu"),
                    ("session", "end-session"),
                    ("adapter", "adapter"),
                ]
                .into_iter()
                .filter_map(|(resource, cleanup)| {
                    setup.resources.contains(&resource).then_some(cleanup)
                })
                .collect::<Vec<_>>();
                assert!(!cleanup_transaction(&mut setup));
                assert_eq!(setup.cleanup_calls, expected_cleanup);
                assert!(setup.resources.is_empty());
            }

            let mut setup = InjectedSetup {
                ipv4,
                ipv6,
                fail_at: None,
                cleanup_fail_at: None,
                idle: true,
                calls: Vec::new(),
                resources: Vec::new(),
                notifications: false,
                strict_route: false,
                routes: Vec::new(),
                dns: Vec::new(),
                cleanup_calls: Vec::new(),
            };
            setup_transaction(&mut setup).expect("complete setup");
            assert_eq!(setup.calls, order);
            assert!(
                setup.calls.iter().position(|step| *step == "start-session")
                    < setup.calls.iter().position(|step| *step == "identity")
            );
            assert!(
                setup
                    .calls
                    .iter()
                    .position(|step| *step == "identity")
                    .unwrap()
                    < setup
                        .calls
                        .iter()
                        .position(|step| matches!(*step, "ipv4-mtu" | "ipv6-mtu"))
                        .unwrap()
            );
        }
    }

    #[test]
    fn only_post_session_enabled_family_natural_preferred_dad_is_ready() {
        assert!(dad_snapshot(true, &[], false).is_err());
        assert_eq!(
            dad_snapshot(true, &[IpDadStatePreferred], false),
            Ok(DadProgress::Ready)
        );
        assert_eq!(
            dad_snapshot(true, &[IpDadStateTentative], false),
            Ok(DadProgress::Waiting)
        );
        assert!(dad_snapshot(true, &[IpDadStateTentative], true).is_err());
        assert!(dad_snapshot(false, &[IpDadStatePreferred, IpDadStatePreferred], false).is_err());
        assert_eq!(
            dad_snapshot(true, &[IpDadStatePreferred, IpDadStatePreferred], false),
            Ok(DadProgress::Ready)
        );
        for states in [
            [IpDadStateTentative, IpDadStatePreferred],
            [IpDadStatePreferred, IpDadStateTentative],
            [IpDadStateTentative, IpDadStateTentative],
        ] {
            assert_eq!(dad_snapshot(true, &states, false), Ok(DadProgress::Waiting));
            assert!(dad_snapshot(true, &states, true).is_err());
        }
        for family in 0..2 {
            for state in [IpDadStateDuplicate, IpDadStateInvalid, IpDadStateDeprecated] {
                let mut states = [IpDadStatePreferred, IpDadStatePreferred];
                states[family] = state;
                assert!(dad_snapshot(true, &states, false).is_err());
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
    fn send_allocation_failure_distinguishes_ring_full_from_fatal_errors() {
        assert_eq!(
            classify_send_allocation_failure(ERROR_BUFFER_OVERFLOW),
            Ok(SendOutcome::DroppedRingFull)
        );
        assert_eq!(
            classify_send_allocation_failure(ERROR_ACCESS_DENIED)
                .expect_err("non-ring failure")
                .kind(),
            ErrorKind::UnrecoverableCorruption
        );
    }

    #[test]
    fn receive_null_distinguishes_empty_recoverable_eof_and_corruption() {
        assert_eq!(classify_receive_null(ERROR_NO_MORE_ITEMS), Ok(()));
        assert_eq!(
            classify_receive_null(ERROR_HANDLE_EOF)
                .expect_err("ended session")
                .kind(),
            ErrorKind::RecoverableSession
        );
        assert_eq!(
            classify_receive_null(ERROR_ACCESS_DENIED)
                .expect_err("unexpected driver failure")
                .kind(),
            ErrorKind::UnrecoverableCorruption
        );
    }

    #[test]
    fn wait_result_distinguishes_each_installed_handle_and_timeout() {
        for (result, expected) in [
            (WAIT_OBJECT_0, WaitOutcome::Stop),
            (WAIT_OBJECT_0 + 1, WaitOutcome::Work),
            (WAIT_OBJECT_0 + 2, WaitOutcome::NetworkChanged),
            (WAIT_OBJECT_0 + 3, WaitOutcome::Readable),
            (WAIT_TIMEOUT, WaitOutcome::Timeout),
        ] {
            assert_eq!(classify_wait_result(result), Ok(expected));
        }
        assert_eq!(
            classify_wait_result(WAIT_FAILED)
                .expect_err("failed wait")
                .kind(),
            ErrorKind::UnrecoverableCorruption
        );
        assert_eq!(
            classify_wait_result(WAIT_OBJECT_0 + 4)
                .expect_err("unexpected wait index")
                .kind(),
            ErrorKind::UnrecoverableCorruption
        );
    }

    #[test]
    fn work_signal_is_distinct_and_auto_resets_while_stop_remains_set() {
        let stop = StopSignal(std::sync::Arc::new(OwnedHandle(
            create_event(true).unwrap(),
        )));
        let work = WorkSignal(std::sync::Arc::new(OwnedHandle(
            create_event(false).unwrap(),
        )));
        let work_clone = work.clone();
        assert_ne!(stop.0.0, work.0.0);
        assert_eq!(work.0.0, work_clone.0.0);

        work_clone.signal().unwrap();
        let handles = [stop.0.0, work.0.0];
        let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 0) };
        assert_eq!(classify_wait_result(result), Ok(WaitOutcome::Work));
        assert_eq!(
            unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 0) },
            WAIT_TIMEOUT,
            "work is a one-wake auto-reset event"
        );

        stop.clone().signal().unwrap();
        for _ in 0..2 {
            let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 0) };
            assert_eq!(classify_wait_result(result), Ok(WaitOutcome::Stop));
        }
        assert_ne!(unsafe { super::ResetEvent(stop.0.0) }, 0);
        assert_eq!(
            unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, 0) },
            WAIT_TIMEOUT
        );
    }

    #[test]
    fn dad_failure_rolls_back_in_reverse_and_cleanup_conflicts_do_not_short_circuit() {
        let order = [
            "ipv6-address",
            "ipv4-address",
            "ipv6-mtu",
            "ipv4-mtu",
            "end-session",
            "adapter",
        ];
        for failed in 0..order.len() {
            let mut cleanup = InjectedSetup {
                ipv4: true,
                ipv6: true,
                fail_at: None,
                cleanup_fail_at: Some(failed),
                idle: true,
                calls: Vec::new(),
                resources: Vec::new(),
                notifications: false,
                strict_route: false,
                routes: Vec::new(),
                dns: Vec::new(),
                cleanup_calls: Vec::new(),
            };
            setup_transaction(&mut cleanup).expect("complete setup");
            assert!(cleanup_transaction(&mut cleanup), "cleanup step {failed}");
            assert_eq!(cleanup.cleanup_calls, order, "cleanup step {failed}");
            assert!(cleanup.resources.is_empty(), "cleanup step {failed}");
        }

        let mut cleanup = InjectedSetup {
            ipv4: true,
            ipv6: true,
            fail_at: None,
            cleanup_fail_at: None,
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            strict_route: false,
            routes: Vec::new(),
            dns: Vec::new(),
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
            ipv4: true,
            ipv6: true,
            fail_at: None,
            idle: journal.cleanup_is_safe(),
            calls: Vec::new(),
            cleanup_fail_at: None,
            resources: Vec::new(),
            notifications: false,
            strict_route: false,
            routes: Vec::new(),
            dns: Vec::new(),
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

        let clean = finish_setup_transaction(Err(Error), false, || false).expect_err("DAD failure");
        assert!(!clean.is_cleanup_failure());
        let conflict =
            finish_setup_transaction(Err(Error), false, || true).expect_err("cleanup conflict");
        assert!(conflict.is_cleanup_failure());
        let mut cleanup_called = false;
        finish_setup_transaction(Ok(()), false, || {
            cleanup_called = true;
            false
        })
        .expect("successful setup");
        assert!(!cleanup_called, "successful setup retains the journal");

        let strict = finish_setup_transaction(Err(Error), true, || false)
            .expect_err("strict-route install failure");
        assert!(strict.is_strict_route_install_failure());
        assert!(!strict.is_cleanup_failure());
        let strict_cleanup = finish_setup_transaction(Err(Error), true, || true)
            .expect_err("strict-route install cleanup conflict");
        assert!(strict_cleanup.is_strict_route_install_failure());
        assert!(strict_cleanup.is_cleanup_failure());
    }

    #[test]
    fn managed_route_initializer_and_exact_ownership_are_closed() {
        let low = Ipv4Prefix::new("0.0.0.0".parse().unwrap(), 1).unwrap();
        let high = Ipv4Prefix::new("128.0.0.0".parse().unwrap(), 1).unwrap();
        let luid = windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH { Value: 7 };
        let low = capture_route_row(luid, 11, IpPrefix::V4(low));
        let high = capture_route_row(luid, 11, IpPrefix::V4(high));
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

        let ipv6 = capture_route_row(
            luid,
            11,
            IpPrefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32).unwrap()),
        );
        assert!(route_matches(&ipv6, &ipv6));
        assert_eq!(unsafe { ipv6.DestinationPrefix.Prefix.si_family }, AF_INET6);
        assert_eq!(unsafe { ipv6.NextHop.Ipv6.sin6_addr.u.Byte }, [0; 16]);
        let mut changed_ipv6_destination = ipv6;
        unsafe {
            changed_ipv6_destination
                .DestinationPrefix
                .Prefix
                .Ipv6
                .sin6_addr
                .u
                .Byte[15] = 1;
        }
        let mut changed_ipv6_next_hop = ipv6;
        unsafe { changed_ipv6_next_hop.NextHop.Ipv6.sin6_addr.u.Byte[15] = 1 };
        assert!(!route_matches(&ipv6, &changed_ipv6_destination));
        assert!(!route_matches(&ipv6, &changed_ipv6_next_hop));

        let mut cleanup = InjectedSetup {
            ipv4: true,
            ipv6: true,
            fail_at: None,
            cleanup_fail_at: Some(3),
            idle: true,
            calls: Vec::new(),
            resources: Vec::new(),
            notifications: false,
            strict_route: false,
            routes: Vec::new(),
            dns: Vec::new(),
            cleanup_calls: Vec::new(),
        };
        setup_transaction(&mut cleanup).expect("complete adapter setup");
        cleanup.notifications = true;
        cleanup.strict_route = true;
        cleanup.routes.extend(["low-route", "high-route"]);
        cleanup.dns.extend(["ipv4-dns", "ipv6-dns"]);
        assert!(
            cleanup_transaction(&mut cleanup),
            "cleanup conflicts are surfaced"
        );
        assert_eq!(
            cleanup.cleanup_calls,
            [
                "notifications",
                "strict-route",
                "ipv6-dns",
                "ipv4-dns",
                "high-route",
                "low-route",
                "ipv6-address",
                "ipv4-address",
                "ipv6-mtu",
                "ipv4-mtu",
                "end-session",
                "adapter",
            ],
            "managed cleanup cannot short-circuit reverse ownership order"
        );
        assert!(cleanup.resources.is_empty());
        assert_eq!(low.Metric, 1);
        assert_eq!(low.DestinationPrefix.PrefixLength, 1);
        assert_eq!(unsafe { low.NextHop.Ipv4.sin_addr.S_un.S_addr }, 0);
    }

    #[test]
    fn underlay_interface_options_use_family_specific_byte_order() {
        let index = 0x0102_0304;
        assert_eq!(
            ipv4_interface_index_option_value(index).to_ne_bytes(),
            [1, 2, 3, 4]
        );
        assert_ne!(ipv4_interface_index_option_value(index), index);
        assert_eq!(ipv6_interface_index_option_value(index), index);
        assert_eq!(
            interface_socket_option("192.0.2.1".parse().unwrap(), index),
            (super::IPPROTO_IP, super::IP_UNICAST_IF, index.to_be())
        );
        assert_eq!(
            interface_socket_option("2001:db8::1".parse().unwrap(), index),
            (super::IPPROTO_IPV6, super::IPV6_UNICAST_IF, index)
        );

        let ipv4 = socket_addr_sockaddr("192.0.2.1:443".parse().unwrap());
        assert_eq!(u16::from_be(unsafe { ipv4.Ipv4.sin_port }), 443);
        let ipv6 = socket_addr_sockaddr("[fe80::1%19]:853".parse().unwrap());
        assert_eq!(u16::from_be(unsafe { ipv6.Ipv6.sin6_port }), 853);
        assert_eq!(unsafe { ipv6.Ipv6.Anonymous.sin6_scope_id }, 19);
    }

    #[test]
    fn windows_catalog_is_family_aware_and_marks_the_exact_managed_tun() {
        let physical_v4 = InterfaceIdentity {
            luid: 10,
            index: 20,
        };
        let physical_v6 = InterfaceIdentity {
            luid: 11,
            index: 21,
        };
        let managed = InterfaceIdentity {
            luid: 12,
            index: 22,
        };
        let unavailable = InterfaceIdentity {
            luid: 13,
            index: 23,
        };
        let interfaces = vec![
            CatalogInterfaceRow {
                identity: physical_v4,
                name: "physical-v4".into(),
                operational: true,
                connected: true,
                kind: NetworkInterfaceKind::Underlay,
            },
            CatalogInterfaceRow {
                identity: physical_v6,
                name: "physical-v6".into(),
                operational: true,
                connected: true,
                kind: NetworkInterfaceKind::Underlay,
            },
            CatalogInterfaceRow {
                identity: managed,
                name: "managed-tun-sentinel".into(),
                operational: true,
                connected: true,
                kind: NetworkInterfaceKind::Underlay,
            },
            CatalogInterfaceRow {
                identity: unavailable,
                name: "down".into(),
                operational: false,
                connected: true,
                kind: NetworkInterfaceKind::Underlay,
            },
        ];
        let families = vec![
            CatalogFamilyRow {
                identity: physical_v4,
                family: NetworkFamily::Ipv4,
                addresses: vec!["192.0.2.10".parse().unwrap()],
                connected: true,
                interface_metric: 20,
                default_route_metric: Some(10),
            },
            CatalogFamilyRow {
                identity: physical_v6,
                family: NetworkFamily::Ipv6,
                addresses: vec!["2001:db8::10".parse().unwrap()],
                connected: true,
                interface_metric: 30,
                default_route_metric: Some(5),
            },
            CatalogFamilyRow {
                identity: managed,
                family: NetworkFamily::Ipv4,
                addresses: vec!["198.18.0.2".parse().unwrap()],
                connected: true,
                interface_metric: 0,
                default_route_metric: Some(0),
            },
            CatalogFamilyRow {
                identity: unavailable,
                family: NetworkFamily::Ipv4,
                addresses: vec!["192.0.2.23".parse().unwrap()],
                connected: true,
                interface_metric: 0,
                default_route_metric: Some(0),
            },
        ];

        let observations =
            build_network_interface_observations(&interfaces, &families, Some(managed)).unwrap();
        assert_eq!(observations.len(), 4);
        assert_eq!(
            observations
                .iter()
                .find(|row| row.binding().stable_id() == managed.luid)
                .unwrap()
                .kind(),
            NetworkInterfaceKind::ManagedTun
        );
        let snapshot = NetworkSnapshot::from_interfaces(41, observations).unwrap();
        assert_eq!(
            snapshot
                .auto_interface("0.0.0.0".parse().unwrap())
                .unwrap()
                .stable_id(),
            physical_v4.luid
        );
        assert_eq!(
            snapshot
                .auto_interface("::".parse().unwrap())
                .unwrap()
                .stable_id(),
            physical_v6.luid
        );

        let catalog =
            WindowsNetworkInterfaceCatalog::excluding_managed_tun(managed.luid, managed.index)
                .unwrap();
        let debug = format!("{catalog:?}");
        assert!(debug.contains("managed_tun: true"));
        assert!(!debug.contains(&managed.luid.to_string()));
        assert!(!debug.contains(&managed.index.to_string()));
        assert!(WindowsNetworkInterfaceCatalog::excluding_managed_tun(0, 1).is_err());

        let virtual_underlay = MIB_IF_ROW2 {
            InterfaceLuid: NET_LUID_LH { Value: 91 },
            InterfaceIndex: 92,
            Type: 53,
            OperStatus: super::IfOperStatusUp,
            AdminStatus: super::NET_IF_ADMIN_STATUS_UP,
            MediaConnectState: super::MediaConnectStateConnected,
            ..MIB_IF_ROW2::default()
        };
        let virtual_identity = InterfaceIdentity {
            luid: 91,
            index: 92,
        };
        assert_eq!(
            catalog_fallback_interface_identity(&virtual_underlay, None),
            Some(virtual_identity),
            "target-aware fallback may use a connected virtual underlay"
        );
        assert_eq!(
            catalog_fallback_interface_identity(&virtual_underlay, Some(virtual_identity)),
            None,
            "the exact managed TUN is never a fallback"
        );
    }

    #[test]
    fn catalog_default_route_requires_an_unspecified_zero_prefix() {
        let identity = InterfaceIdentity {
            luid: 44,
            index: 54,
        };
        let mut row = MIB_IPFORWARD_ROW2 {
            InterfaceLuid: NET_LUID_LH {
                Value: identity.luid,
            },
            InterfaceIndex: identity.index,
            Metric: 17,
            ..MIB_IPFORWARD_ROW2::default()
        };
        row.DestinationPrefix.Prefix = ipv4_sockaddr(std::net::Ipv4Addr::UNSPECIFIED);
        row.DestinationPrefix.PrefixLength = 0;
        let route = catalog_default_route(&row).unwrap();
        assert_eq!(route.identity, identity);
        assert_eq!(route.family, NetworkFamily::Ipv4);
        assert_eq!(route.metric, 17);

        row.DestinationPrefix.PrefixLength = 1;
        assert!(catalog_default_route(&row).is_none());
        row.DestinationPrefix.PrefixLength = 0;
        row.DestinationPrefix.Prefix = ipv4_sockaddr("192.0.2.0".parse().unwrap());
        assert!(catalog_default_route(&row).is_none());
    }

    #[derive(Debug, Eq, PartialEq)]
    enum ResolvedBindCall {
        Interface(std::net::IpAddr, u32),
        Source(std::net::SocketAddr),
    }

    #[derive(Default)]
    struct InjectedResolvedBinder {
        calls: Vec<ResolvedBindCall>,
    }

    impl ResolvedSocketBindingOperations for InjectedResolvedBinder {
        fn bind_interface(
            &mut self,
            family: std::net::IpAddr,
            interface_index: u32,
        ) -> Result<(), Error> {
            self.calls
                .push(ResolvedBindCall::Interface(family, interface_index));
            Ok(())
        }

        fn bind_source(&mut self, source: std::net::SocketAddr) -> Result<(), Error> {
            self.calls.push(ResolvedBindCall::Source(source));
            Ok(())
        }
    }

    #[derive(Default)]
    struct NoRouteCatalog;

    impl NetworkInterfaceCatalog for NoRouteCatalog {
        fn read_interfaces(
            &self,
        ) -> Result<Vec<NetworkInterfaceObservation>, NetworkInterfaceCatalogError> {
            Err(NetworkInterfaceCatalogError)
        }

        fn system_best_route(
            &self,
            _: std::net::SocketAddr,
        ) -> Result<SystemBestRoute, NetworkInterfaceCatalogError> {
            Err(NetworkInterfaceCatalogError)
        }
    }

    #[test]
    fn resolved_socket_binding_applies_interface_then_family_source() {
        let source = "192.0.2.44".parse().unwrap();
        let destination = "203.0.113.9:443".parse().unwrap();
        let binding =
            InterfaceBinding::new("Ethernet", 64, 74, vec![std::net::IpAddr::V4(source)]).unwrap();
        let snapshot = NetworkSnapshot::new(7, Some(binding), None).unwrap();
        let resolved = NetworkInterfaceResolver::new(NoRouteCatalog)
            .resolve(
                &DialOptions::new(None::<&str>, Some(source), None),
                &RouteNetworkOptions::new(true, None::<&str>),
                destination,
                &snapshot,
            )
            .unwrap();
        let mut binder = InjectedResolvedBinder::default();
        bind_resolved_socket_with(destination, &resolved, &mut binder).unwrap();
        assert_eq!(
            binder.calls,
            [
                ResolvedBindCall::Interface(destination.ip(), 74),
                ResolvedBindCall::Source("192.0.2.44:0".parse().unwrap()),
            ]
        );

        let mut wrong_family = InjectedResolvedBinder::default();
        let error = bind_resolved_socket_with(
            "[2001:db8::9]:443".parse().unwrap(),
            &resolved,
            &mut wrong_family,
        )
        .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
        assert!(wrong_family.calls.is_empty());
    }

    #[test]
    fn resolved_link_local_source_carries_the_selected_ipv6_scope() {
        let source = "fe80::44".parse().unwrap();
        let destination = "[2001:db8::9]:443".parse().unwrap();
        let binding =
            InterfaceBinding::new("Ethernet v6", 65, 75, vec![std::net::IpAddr::V6(source)])
                .unwrap();
        let snapshot = NetworkSnapshot::new(8, None, Some(binding)).unwrap();
        let resolved = NetworkInterfaceResolver::new(NoRouteCatalog)
            .resolve(
                &DialOptions::new(None::<&str>, None, Some(source)),
                &RouteNetworkOptions::new(true, None::<&str>),
                destination,
                &snapshot,
            )
            .unwrap();
        let mut binder = InjectedResolvedBinder::default();
        bind_resolved_socket_with(destination, &resolved, &mut binder).unwrap();
        assert_eq!(
            binder.calls,
            [
                ResolvedBindCall::Interface(destination.ip(), 75),
                ResolvedBindCall::Source("[fe80::44%75]:0".parse().unwrap()),
            ]
        );
    }
}
