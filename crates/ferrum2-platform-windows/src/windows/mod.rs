mod core;

#[cfg(not(test))]
#[path = "live/mod.rs"]
pub(crate) mod backend;

#[cfg(test)]
mod tests;
