use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::ops::Deref;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, GetIpInterfaceEntry,
    GetUnicastIpAddressEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred,
    IpDadStateTentative, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
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

use crate::{ABI_EXPORTS, AdapterConfig, CreateError, DLL_BYTES, DLL_SHA256, Error};

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
        let executable = current_executable()?;
        let directory = executable.parent().ok_or(Error)?;
        reject_network_path(directory)?;
        let directories = hold_directories(directory)?;
        let dll = directory.join("wintun.dll");
        let file = open_file(&dll)?;
        verify_regular_non_reparse(file.as_raw_handle() as HANDLE)?;
        let metadata = file.metadata().map_err(|_| Error)?;
        if !metadata.is_file() || metadata.len() != DLL_BYTES {
            return Err(Error);
        }
        if cng_sha256(&file)? != DLL_SHA256 {
            return Err(Error);
        }
        let dll_wide = wide(&dll);
        let module =
            unsafe { LoadLibraryExW(dll_wide.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() {
            return Err(Error);
        }
        let exports = unsafe { resolve_exports(module) };
        match exports {
            Ok(exports) => Ok(Self {
                module,
                exports,
                _file: file,
                _directories: directories,
            }),
            Err(error) => {
                unsafe { FreeLibrary(module) };
                Err(error)
            }
        }
    }
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

/// Safe RAII owner of the exact Wintun adapter, address, MTU, session and DLL transaction.
pub struct Adapter {
    config: AdapterConfig,
    library: Library,
    adapter: Option<WintunAdapter>,
    luid: NET_LUID_LH,
    mtus: [Option<MtuState>; 2],
    addresses: Vec<MIB_UNICASTIPADDRESS_ROW>,
    session: Option<SessionState>,
    stop: StopSignal,
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
        let name = wide(Path::new(config.name.as_ref()));
        let tunnel = wide(Path::new("Ferrum2"));
        let adapter =
            unsafe { (library.exports.create_adapter)(name.as_ptr(), tunnel.as_ptr(), null()) };
        if adapter.is_null() {
            return Err(CreateError::operation());
        }
        let mut owner = Self {
            config,
            library,
            adapter: Some(adapter),
            luid: NET_LUID_LH::default(),
            mtus: [None, None],
            addresses: Vec::with_capacity(2),
            session: None,
            stop,
            _not_send: PhantomData,
        };
        unsafe { (owner.library.exports.get_adapter_luid)(adapter, &mut owner.luid) };
        let setup = (|| {
            if cancelled.load(Ordering::Acquire)
                || Instant::now() >= deadline
                || unsafe { (owner.library.exports.get_running_driver_version)() } == 0
            {
                return Err(Error);
            }
            owner.set_mtu(AF_INET, 0)?;
            owner.set_mtu(AF_INET6, 1)?;
            owner.add_addresses()?;
            let session = unsafe {
                (owner.library.exports.start_session)(adapter, owner.config.ring_capacity)
            };
            if session.is_null() {
                return Err(Error);
            }
            let read_event = unsafe { (owner.library.exports.get_read_wait_event)(session) };
            owner.session = Some(SessionState {
                handle: session,
                read_event,
            });
            if read_event.is_null() || read_event == INVALID_HANDLE_VALUE {
                return Err(Error);
            }
            owner.wait_for_dad(deadline, cancelled)
        })();
        match setup {
            Ok(()) => Ok(owner),
            Err(_) if owner.cleanup_inner() => Err(CreateError::cleanup()),
            Err(_) => Err(CreateError::operation()),
        }
    }

    pub fn stop_signal(&self) -> StopSignal {
        self.stop.clone()
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

    fn add_addresses(&mut self) -> Result<(), Error> {
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
        self.create_address(ipv4)?;

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
        self.create_address(ipv6)
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
            let mut waiting = false;
            for address in &self.addresses {
                let mut row = *address;
                if unsafe { GetUnicastIpAddressEntry(&mut row) } != ERROR_SUCCESS {
                    return Err(Error);
                }
                match row.DadState {
                    value if value == IpDadStatePreferred => {}
                    value if value == IpDadStateTentative => waiting = true,
                    _ => return Err(Error),
                }
            }
            if !waiting {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn cleanup_inner(&mut self) -> bool {
        let mut failed = false;
        if let Some(session) = self.session.take() {
            unsafe { (self.library.exports.end_session)(session.handle) };
        }
        for address in self.addresses.drain(..).rev() {
            let status = unsafe { DeleteUnicastIpAddressEntry(&address) };
            failed |= status != ERROR_SUCCESS;
        }
        for state in self.mtus.iter_mut().rev().filter_map(Option::take) {
            let mut row = MIB_IPINTERFACE_ROW::default();
            unsafe { InitializeIpInterfaceEntry(&mut row) };
            row.Family = state.family;
            row.InterfaceLuid = self.luid;
            let get_status = unsafe { GetIpInterfaceEntry(&mut row) };
            if get_status != ERROR_SUCCESS || row.NlMtu != state.configured {
                failed = true;
            } else {
                if state.family == AF_INET {
                    row.SitePrefixLength = 0;
                }
                row.NlMtu = state.previous;
                let set_status = unsafe { SetIpInterfaceEntry(&mut row) };
                failed |= set_status != ERROR_SUCCESS;
            }
        }
        if let Some(adapter) = self.adapter.take() {
            unsafe { (self.library.exports.close_adapter)(adapter) };
        }
        failed
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
