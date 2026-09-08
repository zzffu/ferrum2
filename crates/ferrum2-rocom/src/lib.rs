//! Opt-in sensitive TCP evidence recording and replayable TSF4G interpretation.
//! This module never dials a socket, alters application bytes, or emits secrets to tracing.

#[cfg(feature = "decode")]
mod crypto;
#[cfg(feature = "decode")]
pub mod decode;
mod io;
mod keys;
mod record;
mod recorder;
mod wire;

pub use io::ObservedIo;
pub use keys::{KeySnapshot, KeyTracker};
pub use record::{Direction, Record, RecordEvent};
pub use recorder::{Capture, EndReason, Recorder, Recording, RecordingReport};
