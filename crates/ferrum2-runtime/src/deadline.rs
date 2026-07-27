use std::fmt;
use std::future::Future;
use std::time::Duration;

/// A closed operation result with a monotonic deadline.
pub enum DeadlineError<E> {
    /// The monotonic deadline elapsed.
    Timeout,
    /// The operation failed before its deadline.
    Inner(E),
}

impl<E> fmt::Debug for DeadlineError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("DeadlineError::Timeout"),
            Self::Inner(_) => formatter.write_str("DeadlineError::Inner([closed])"),
        }
    }
}

impl<E> fmt::Display for DeadlineError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("operation timed out"),
            Self::Inner(_) => formatter.write_str("operation failed"),
        }
    }
}

impl<E> std::error::Error for DeadlineError<E> {}

/// Runs an operation under a Tokio monotonic deadline.
pub async fn with_deadline<F, T, E>(timeout: Duration, operation: F) -> Result<T, DeadlineError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result.map_err(DeadlineError::Inner),
        Err(_) => Err(DeadlineError::Timeout),
    }
}
