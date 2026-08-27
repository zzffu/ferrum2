/// Hosted-safe underlay handle used when the real Windows backend is absent.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnderlayPublisher;

impl UnderlayPublisher {
    pub const fn new() -> Self {
        Self
    }
}
