use windows_sys::Win32::Foundation::{
    ERROR_BUFFER_OVERFLOW, ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};

use crate::{Error, SendOutcome, WaitOutcome};

pub(in crate::windows) fn classify_receive_null(error: u32) -> Result<(), Error> {
    match error {
        ERROR_NO_MORE_ITEMS => Ok(()),
        ERROR_HANDLE_EOF => Err(Error::recoverable_session()),
        _ => Err(Error),
    }
}

pub(in crate::windows) fn classify_wait_result(result: u32) -> Result<WaitOutcome, Error> {
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

pub(in crate::windows) fn classify_send_allocation_failure(
    error: u32,
) -> Result<SendOutcome, Error> {
    if error == ERROR_BUFFER_OVERFLOW {
        Ok(SendOutcome::DroppedRingFull)
    } else {
        Err(Error)
    }
}
