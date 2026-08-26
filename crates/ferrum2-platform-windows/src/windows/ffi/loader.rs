use std::ffi::{OsString, c_void};
use std::fs::File;
use std::io::Read;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    CloseHandle, FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
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
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleFileNameW,
    GetModuleHandleExW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::Win32::System::Threading::CreateEventW;

use super::super::loader::{
    LoaderOperations, load_transaction, require_exports, validate_artifact,
};
use crate::{ABI_EXPORTS, DLL_BYTES, Error};

pub(super) type WintunAdapter = *mut c_void;
pub(super) type WintunSession = *mut c_void;
pub(super) type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> WintunAdapter;
pub(super) type CloseAdapter = unsafe extern "system" fn(WintunAdapter);
pub(super) type GetAdapterLuid = unsafe extern "system" fn(WintunAdapter, *mut NET_LUID_LH);
pub(super) type GetRunningDriverVersion = unsafe extern "system" fn() -> u32;
pub(super) type StartSession = unsafe extern "system" fn(WintunAdapter, u32) -> WintunSession;
pub(super) type EndSession = unsafe extern "system" fn(WintunSession);
pub(super) type GetReadWaitEvent = unsafe extern "system" fn(WintunSession) -> HANDLE;
pub(super) type ReceivePacket = unsafe extern "system" fn(WintunSession, *mut u32) -> *mut u8;
pub(super) type ReleaseReceivePacket = unsafe extern "system" fn(WintunSession, *const u8);
pub(super) type AllocateSendPacket = unsafe extern "system" fn(WintunSession, u32) -> *mut u8;
pub(super) type SendPacket = unsafe extern "system" fn(WintunSession, *const u8);

#[repr(C)]
pub(super) struct OsVersionInfo {
    pub(super) size: u32,
    pub(super) major: u32,
    pub(super) minor: u32,
    pub(super) build: u32,
    pub(super) platform: u32,
    pub(super) service_pack: [u16; 128],
}

#[link(name = "ntdll")]
unsafe extern "system" {
    pub(super) fn RtlGetVersion(version: *mut OsVersionInfo) -> i32;
}

#[derive(Clone, Copy)]
pub(super) struct Exports {
    pub(super) create_adapter: CreateAdapter,
    pub(super) close_adapter: CloseAdapter,
    pub(super) get_adapter_luid: GetAdapterLuid,
    pub(super) get_running_driver_version: GetRunningDriverVersion,
    pub(super) start_session: StartSession,
    pub(super) end_session: EndSession,
    pub(super) get_read_wait_event: GetReadWaitEvent,
    pub(super) receive_packet: ReceivePacket,
    pub(super) release_receive_packet: ReleaseReceivePacket,
    pub(super) allocate_send_packet: AllocateSendPacket,
    pub(super) send_packet: SendPacket,
}

pub(super) struct DirectoryHandle(HANDLE);

impl Drop for DirectoryHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) struct EventHandle(HANDLE);

// SAFETY: `EventHandle::new` is the only constructor and always owns a Windows event object.
// Events are non-thread-affine kernel objects whose wait, set, and reset operations support
// concurrent callers. Every cross-thread owner stores this value in `Arc<EventHandle>`, so the
// handle is closed only after the final waiter/signaller releases its owner.
unsafe impl Send for EventHandle {}
unsafe impl Sync for EventHandle {}

impl EventHandle {
    pub(super) fn new(manual_reset: bool) -> Result<Self, Error> {
        let handle = unsafe { CreateEventW(null(), i32::from(manual_reset), 0, null()) };
        if handle.is_null() {
            Err(Error)
        } else {
            Ok(Self(handle))
        }
    }

    pub(super) const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for EventHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

pub(super) struct Library {
    pub(super) module: HMODULE,
    pub(super) exports: Exports,
    _file: File,
    _directories: Vec<DirectoryHandle>,
}

impl Library {
    pub(super) fn load() -> Result<Self, Error> {
        let mut loader = PlatformLoader::default();
        load_transaction(&mut loader)?;
        loader.finish()
    }
}

#[derive(Default)]
pub(super) struct PlatformLoader {
    directory: Option<PathBuf>,
    dll: Option<PathBuf>,
    directories: Option<Vec<DirectoryHandle>>,
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

    fn pin_loaded_library(&mut self) -> Result<(), Error> {
        let module = self.module;
        if module.is_null() || self.exports.is_none() {
            return Err(Error);
        }
        let mut pinned_module = null_mut();
        // Wintun 0.14.1's WintunCloseAdapter queues a DLL callback through
        // QueueUserWorkItem, whose Windows contract requires the DLL to remain
        // loaded until its callbacks complete. PIN therefore intentionally lasts
        // for the process lifetime.
        // SAFETY: the preceding artifact and exact-export checks establish `module`
        // as the verified, non-null base returned by LoadLibraryExW. FROM_ADDRESS
        // identifies that already-loaded module from its base, and the output
        // pointer remains valid for the call. On success Windows returns this same
        // module and PIN cannot be undone, so only the API's failure is surfaced.
        let result = unsafe {
            GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
                module as *const u16,
                &raw mut pinned_module,
            )
        };
        if result == 0 { Err(Error) } else { Ok(()) }
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

pub(super) fn current_executable() -> Result<PathBuf, Error> {
    let mut buffer = vec![0_u16; 32_768];
    let len = unsafe { GetModuleFileNameW(null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) };
    if len == 0 || len as usize >= buffer.len() {
        return Err(Error);
    }
    Ok(PathBuf::from(OsString::from_wide(&buffer[..len as usize])))
}

pub(super) fn reject_network_path(path: &Path) -> Result<(), Error> {
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

pub(super) fn hold_directories(directory: &Path) -> Result<Vec<DirectoryHandle>, Error> {
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
            Ok(DirectoryHandle(handle))
        })
        .collect()
}

pub(super) fn open_file(path: &Path) -> Result<File, Error> {
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

pub(super) fn verify_directory_non_reparse(handle: HANDLE) -> Result<(), Error> {
    let attributes = file_attributes(handle)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(Error)
    } else {
        Ok(())
    }
}

pub(super) fn verify_regular_non_reparse(handle: HANDLE) -> Result<(), Error> {
    let attributes = file_attributes(handle)?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
        || attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        Err(Error)
    } else {
        Ok(())
    }
}

pub(super) fn file_attributes(handle: HANDLE) -> Result<FILE_ATTRIBUTE_TAG_INFO, Error> {
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

pub(super) fn cng_sha256(file: &File) -> Result<[u8; 32], Error> {
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

pub(super) unsafe fn resolve_exports(module: HMODULE) -> Result<Exports, Error> {
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

pub(super) unsafe fn symbol<T: Copy>(module: HMODULE, name: &[u8]) -> Result<T, Error> {
    let address = unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or(Error)?;
    if size_of::<T>() != size_of_val(&address) {
        return Err(Error);
    }
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

pub(super) fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}
