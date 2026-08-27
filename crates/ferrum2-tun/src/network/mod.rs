#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
#[path = "live.rs"]
mod implementation;
#[cfg(not(all(windows, target_arch = "x86_64", feature = "live-backend", not(test))))]
#[path = "hosted.rs"]
mod implementation;

pub use implementation::UnderlayPublisher;
