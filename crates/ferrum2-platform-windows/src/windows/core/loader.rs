use std::io::{Read, Seek, SeekFrom};

use crate::Error;
use crate::artifact::{ABI_EXPORTS, DLL_BYTES, DLL_SHA256};

pub(in crate::windows) trait LoaderOperations {
    fn discover_executable(&mut self) -> Result<(), Error>;
    fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error>;
    fn open_sibling_dll(&mut self) -> Result<(), Error>;
    fn verify_dll_identity(&mut self) -> Result<(), Error>;
    fn verify_artifact(&mut self) -> Result<(), Error>;
    fn load_system32_scoped_library(&mut self) -> Result<(), Error>;
    fn resolve_exact_abi(&mut self) -> Result<(), Error>;
    fn pin_loaded_library(&mut self) -> Result<(), Error>;
}

pub(in crate::windows) fn load_transaction(
    loader: &mut impl LoaderOperations,
) -> Result<(), Error> {
    loader.discover_executable()?;
    loader.reject_network_and_reparse_directories()?;
    loader.open_sibling_dll()?;
    loader.verify_dll_identity()?;
    loader.verify_artifact()?;
    loader.load_system32_scoped_library()?;
    loader.resolve_exact_abi()?;
    loader.pin_loaded_library()
}

pub(in crate::windows) fn validate_artifact(bytes: u64, sha256: [u8; 32]) -> Result<(), Error> {
    if bytes == DLL_BYTES && sha256 == DLL_SHA256 {
        Ok(())
    } else {
        Err(Error)
    }
}

/// Reads the pinned artifact from the already identity-checked file. Rejects
/// metadata size before allocating or touching the reader, then verifies exact
/// length independently of metadata without reading more than one excess byte.
pub(in crate::windows) fn read_pinned_artifact(
    reader: &mut (impl Read + Seek),
    metadata_bytes: u64,
) -> Result<Vec<u8>, Error> {
    if metadata_bytes != DLL_BYTES {
        return Err(Error);
    }
    reader.seek(SeekFrom::Start(0)).map_err(|_| Error)?;
    let mut bytes = vec![0_u8; DLL_BYTES as usize];
    reader.read_exact(&mut bytes).map_err(|_| Error)?;
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(|_| Error)? != 0 {
        return Err(Error);
    }
    Ok(bytes)
}

pub(in crate::windows) fn require_exports(
    mut present: impl FnMut(&[u8]) -> bool,
) -> Result<(), Error> {
    for name in ABI_EXPORTS {
        if !present(name) {
            return Err(Error);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_identity_requires_exact_size_and_digest() {
        assert!(validate_artifact(DLL_BYTES, DLL_SHA256).is_ok());
        assert!(validate_artifact(DLL_BYTES + 1, DLL_SHA256).is_err());
        assert!(validate_artifact(DLL_BYTES, [0; 32]).is_err());
    }
}

#[cfg(test)]
mod reader_tests;
