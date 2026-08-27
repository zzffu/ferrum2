mod reducer;
mod reset;

#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
mod live;
#[cfg(all(windows, target_arch = "x86_64", feature = "live-backend", not(test)))]
pub(crate) use live::owner_main;

#[cfg(test)]
pub(crate) use reset::{
    NetworkChangeErrorDisposition, NetworkChangeTransition, NetworkResetHealthDisposition,
    bounded_network_wait, classify_network_change, classify_network_change_error,
    classify_network_reset_health, classify_network_reset_refresh_error, map_managed_state_damage,
    owner_wait_after_budget,
};
