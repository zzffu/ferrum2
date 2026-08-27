use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT64,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_PORT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
};
use windows_sys::core::GUID;

use crate::Error;
use crate::strict_route::{StrictRouteAction, StrictRouteCondition, StrictRouteLayer};

impl StrictRouteLayer {
    pub(in crate::windows) const fn key(self) -> GUID {
        match self {
            Self::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }
}

impl StrictRouteAction {
    pub(in crate::windows) const fn raw(self) -> u32 {
        match self {
            Self::Permit => FWP_ACTION_PERMIT,
            Self::Block => FWP_ACTION_BLOCK,
        }
    }
}

impl StrictRouteCondition {
    pub(in crate::windows) const fn field_key(&self) -> GUID {
        match self {
            Self::AppId(_) => FWPM_CONDITION_ALE_APP_ID,
            Self::LocalInterfaceLuid(_) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
            Self::IpProtocol(_) => FWPM_CONDITION_IP_PROTOCOL,
            Self::RemotePort(_) => FWPM_CONDITION_IP_REMOTE_PORT,
        }
    }

    pub(in crate::windows) const fn data_type(&self) -> i32 {
        match self {
            Self::AppId(_) => FWP_BYTE_BLOB_TYPE,
            Self::LocalInterfaceLuid(_) => FWP_UINT64,
            Self::IpProtocol(_) => FWP_UINT8,
            Self::RemotePort(_) => FWP_UINT16,
        }
    }
}

pub(in crate::windows) fn guid_matches(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

pub(in crate::windows) fn wfp_readback_present(status: u32, not_found: i32) -> Result<bool, Error> {
    match status {
        0 => Ok(true),
        value if value == not_found as u32 => Ok(false),
        value if value == windows_sys::Win32::Foundation::FWP_E_SESSION_ABORTED as u32 => Ok(false),
        _ => Err(Error),
    }
}
