use bytes::BytesMut;

use super::error::FlowTerminal;

/// Fixed scratch allocation roles observable without exposing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BufferRole {
    /// The one per-flow encrypt scratch.
    Encrypt,
    /// The one receive-direction decrypt scratch.
    Decrypt,
}

/// Safe fixed-buffer observation seam.
pub trait BufferObserver: Send + Sync {
    /// Records one fixed usable-limit request and opaque storage identity.
    fn allocated(&self, role: BufferRole, usable_limit: usize, storage_identity: usize);

    /// Records the current identity at a public flow poll boundary.
    fn inspected(&self, _role: BufferRole, _storage_identity: usize) {}
}

/// Closed terminal observation seam.
pub trait FlowObserver: Send + Sync {
    /// Records installation of the sole terminal latch.
    fn terminal_installed(&self, terminal: FlowTerminal);

    /// Records destruction of one opaque client flow owner.
    fn owner_dropped(&self) {}
}

pub(super) struct NoopObserver;

impl BufferObserver for NoopObserver {
    fn allocated(&self, _role: BufferRole, _usable_limit: usize, _storage_identity: usize) {}
}

impl FlowObserver for NoopObserver {
    fn terminal_installed(&self, _terminal: FlowTerminal) {}
}

pub(super) static NOOP_OBSERVER: NoopObserver = NoopObserver;

#[derive(Clone, Copy)]
pub(super) struct Observers<'a> {
    pub(super) buffer: &'a dyn BufferObserver,
    pub(super) flow: &'a dyn FlowObserver,
}

impl Observers<'static> {
    pub(super) const fn noop() -> Self {
        Self {
            buffer: &NOOP_OBSERVER,
            flow: &NOOP_OBSERVER,
        }
    }
}

pub(super) fn fixed_scratch(
    role: BufferRole,
    limit: usize,
    observer: &dyn BufferObserver,
) -> BytesMut {
    let scratch = BytesMut::with_capacity(limit);
    observer.allocated(role, limit, scratch.as_ptr() as usize);
    scratch
}

pub(super) fn inspect_scratch(role: BufferRole, scratch: &BytesMut, observer: &dyn BufferObserver) {
    observer.inspected(role, scratch.as_ptr() as usize);
}
