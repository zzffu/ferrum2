use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetFileSecurityW,
    GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetTokenInformation, INHERIT_ONLY_ACE, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SetSecurityDescriptorControl, TOKEN_QUERY, TOKEN_USER,
    TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, ReplaceFileW,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn denied() -> io::Error {
    io::Error::from(io::ErrorKind::PermissionDenied)
}

fn wide(path: &Path) -> io::Result<Vec<u16>> {
    let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
    if value.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    value.push(0);
    Ok(value)
}

fn descriptor_buffer(required: u32) -> io::Result<Vec<u64>> {
    if required == 0 || required > 65_536 {
        return Err(denied());
    }
    // u64 storage provides the alignment required by the x86_64 security descriptor.
    Ok(vec![0; (required as usize).div_ceil(8)])
}

fn current_user() -> io::Result<Vec<u64>> {
    let mut handle = std::ptr::null_mut();
    // SAFETY: pseudo process handle is valid; output receives one owned token handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) } == 0 {
        return Err(denied());
    }
    // SAFETY: successful OpenProcessToken transfers unique handle ownership.
    let handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut required = 0;
    // SAFETY: live token handle, null query buffer and valid required-size output.
    unsafe {
        GetTokenInformation(
            handle.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    let mut buffer = descriptor_buffer(required)?;
    // SAFETY: aligned buffer covers the complete requested TOKEN_USER and embedded SID.
    if unsafe {
        GetTokenInformation(
            handle.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(denied());
    }
    Ok(buffer)
}

/// Creates an exclusive new temporary file with the original DACL from its first instant.
/// The caller owns the returned file and must remove the path unless replacement succeeds.
/// Unlike hardening an already-created file, this never exposes a pre-hardening read handle.
pub fn create_config_temporary(original: &Path, temporary: &Path) -> io::Result<File> {
    let original = wide(original)?;
    let temporary = wide(temporary)?;
    let mut required = 0;
    // SAFETY: terminated path, null query buffer, and valid size-output pointer.
    unsafe {
        GetFileSecurityW(
            original.as_ptr(),
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    let mut descriptor = descriptor_buffer(required)?;
    // SAFETY: aligned buffer covers required bytes and remains live through file creation.
    if unsafe {
        GetFileSecurityW(
            original.as_ptr(),
            DACL_SECURITY_INFORMATION,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(denied());
    }
    // SAFETY: modifies only documented control bits in the OS-returned descriptor.
    if unsafe {
        SetSecurityDescriptorControl(
            descriptor.as_mut_ptr().cast(),
            SE_DACL_PROTECTED,
            SE_DACL_PROTECTED,
        )
    } == 0
    {
        return Err(denied());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_mut_ptr().cast(),
        bInheritHandle: 0,
    };
    // SAFETY: all pointers remain valid during the synchronous call. CREATE_NEW never
    // opens an attacker's existing path. The returned handle has one owner below.
    let handle = unsafe {
        CreateFileW(
            temporary.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returned a unique owned file handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// Requires a held credential file's grants to be restricted to its owner, SYSTEM and admins.
/// Rejects null/missing DACLs and unfamiliar granting ACE kinds rather than guessing access.
pub fn validate_private_file(file: &File) -> io::Result<()> {
    let mut required = 0;
    let information = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
    // SAFETY: file remains open throughout; null buffer queries the required size.
    unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            information,
            std::ptr::null_mut(),
            0,
            &mut required,
        );
    }
    let mut descriptor = descriptor_buffer(required)?;
    // SAFETY: buffer is aligned, bounded and held while all pointers into it are used.
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            information,
            descriptor.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(denied());
    }
    let mut owner = std::ptr::null_mut();
    let mut acl = std::ptr::null_mut();
    let (mut present, mut defaulted) = (0, 0);
    // SAFETY: descriptor is OS-produced; outputs point into its live backing buffer.
    if unsafe {
        GetSecurityDescriptorOwner(descriptor.as_mut_ptr().cast(), &mut owner, &mut defaulted)
    } == 0
        || unsafe {
            GetSecurityDescriptorDacl(
                descriptor.as_mut_ptr().cast(),
                &mut present,
                &mut acl,
                &mut defaulted,
            )
        } == 0
        || owner.is_null()
        || present == 0
        || acl.is_null()
    {
        return Err(denied());
    }
    let user = current_user()?;
    // SAFETY: current_user returns the complete aligned TOKEN_USER backing storage.
    let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: owner and current-user SIDs remain valid in their respective backing buffers.
    if unsafe { EqualSid(owner, user_sid) } == 0
        && unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } == 0
        && unsafe { IsWellKnownSid(owner, WinBuiltinAdministratorsSid) } == 0
    {
        return Err(denied());
    }
    // SAFETY: successful DACL extraction above returned a valid live ACL pointer.
    for index in 0..unsafe { (*acl).AceCount } {
        let mut entry = std::ptr::null_mut();
        // SAFETY: index is bounded by OS-returned AceCount; output points into descriptor.
        if unsafe { GetAce(acl, u32::from(index), &mut entry) } == 0 || entry.is_null() {
            return Err(denied());
        }
        // SAFETY: GetAce returns at least an ACE_HEADER for a valid OS descriptor.
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
        {
            continue;
        }
        if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE
            || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            return Err(denied());
        }
        // SAFETY: type/size checked above; SID is variable-length OS-validated ACE payload.
        let sid = unsafe { (&raw mut (*entry.cast::<ACCESS_ALLOWED_ACE>()).SidStart).cast() };
        // SAFETY: all SIDs point into the validated live descriptor or well-known OS constants.
        if unsafe { EqualSid(sid, owner) } == 0
            && unsafe { EqualSid(sid, user_sid) } == 0
            && unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } == 0
            && unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } == 0
        {
            return Err(denied());
        }
    }
    Ok(())
}

/// Atomically replaces an existing configuration while preserving its Windows security metadata.
/// Neither ACL merge errors nor missing originals are ignored.
pub fn replace_config_file(original: &Path, temporary: &Path) -> io::Result<()> {
    let original = wide(original)?;
    let temporary = wide(temporary)?;
    // SAFETY: terminated live paths; optional backup/exclusion/reserved pointers are null.
    let replaced = unsafe {
        ReplaceFileW(
            original.as_ptr(),
            temporary.as_ptr(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if replaced == 0 {
        return Err(io::Error::from(io::ErrorKind::Other));
    }
    Ok(())
}
