use std::ptr::null_mut;

use ferrum2_net::NetworkRouteObservation;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetIpForwardTable2, MIB_IPFORWARD_TABLE2};
use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

use super::{MAX_CATALOG_ROUTES, MibTable, route_fingerprint};
use crate::Error;

pub(super) fn capture_routes() -> Result<Vec<NetworkRouteObservation>, Error> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
    // SAFETY: Windows supplies the table allocation; the pointer is checked before
    // access and the MibTable owner releases it on every subsequent exit path.
    if unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) } != ERROR_SUCCESS || table.is_null() {
        return Err(Error);
    }
    let _owner = MibTable(table.cast());
    // SAFETY: a successful GetIpForwardTable2 returns its initialized row count.
    let count = unsafe { (*table).NumEntries as usize };
    if count > MAX_CATALOG_ROUTES {
        return Err(Error);
    }
    // SAFETY: the allocation contains count contiguous rows and remains owned
    // until every route's value fields have been copied into the result.
    let rows = unsafe { std::slice::from_raw_parts((*table).Table.as_ptr(), count) };
    rows.iter()
        .map(|row| {
            let route = route_fingerprint(row, None)?;
            Ok(NetworkRouteObservation::new(
                route.interface_luid,
                route.interface_index,
                route.destination,
                route.prefix_length,
                route.next_hop,
                route.metric,
            ))
        })
        .collect()
}
