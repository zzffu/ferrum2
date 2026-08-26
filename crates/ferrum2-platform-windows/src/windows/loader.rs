use crate::{ABI_EXPORTS, DLL_BYTES, DLL_SHA256, Error};

pub(super) trait LoaderOperations {
    fn discover_executable(&mut self) -> Result<(), Error>;
    fn reject_network_and_reparse_directories(&mut self) -> Result<(), Error>;
    fn open_sibling_dll(&mut self) -> Result<(), Error>;
    fn verify_dll_identity(&mut self) -> Result<(), Error>;
    fn verify_artifact(&mut self) -> Result<(), Error>;
    fn load_system32_scoped_library(&mut self) -> Result<(), Error>;
    fn resolve_exact_abi(&mut self) -> Result<(), Error>;
    fn pin_loaded_library(&mut self) -> Result<(), Error>;
}

pub(super) fn load_transaction(loader: &mut impl LoaderOperations) -> Result<(), Error> {
    loader.discover_executable()?;
    loader.reject_network_and_reparse_directories()?;
    loader.open_sibling_dll()?;
    loader.verify_dll_identity()?;
    loader.verify_artifact()?;
    loader.load_system32_scoped_library()?;
    loader.resolve_exact_abi()?;
    loader.pin_loaded_library()
}

pub(super) fn validate_artifact(bytes: u64, sha256: [u8; 32]) -> Result<(), Error> {
    if bytes == DLL_BYTES && sha256 == DLL_SHA256 {
        Ok(())
    } else {
        Err(Error)
    }
}

pub(super) fn require_exports(mut present: impl FnMut(&[u8]) -> bool) -> Result<(), Error> {
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
