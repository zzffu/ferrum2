use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, FWP_E_SESSION_ABORTED, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT64, FWP_VALUE0,
    FWP_VALUE0_0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0,
    FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0, FwpmFreeMemory0,
    FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerGetByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use super::super::strict_route::{StrictRouteOperations, StrictRouteSession};
use super::loader::{current_executable, wide};
use crate::Error;
use crate::strict_route::{
    MAX_WFP_APP_ID_BYTES, StrictRouteAction, StrictRouteCondition, StrictRouteLayer,
    StrictRouteRule, StrictRouteRuleKind,
};

pub(super) const STRICT_ROUTE_SESSION_KEY: GUID =
    GUID::from_u128(0x8ea35b4e_6629_4e26_9776_95c5bf9c6b01);
pub(super) const STRICT_ROUTE_SUBLAYER_KEY: GUID =
    GUID::from_u128(0xddbc2fa2_d52f_4a79_8a63_8446c308cf02);
pub(super) const STRICT_ROUTE_SUBLAYER_WEIGHT: u16 = 0x7fff;
pub(super) const STRICT_ROUTE_SESSION_NAME: &str = "Ferrum2 strict route dynamic session";
pub(super) const STRICT_ROUTE_SUBLAYER_NAME: &str = "Ferrum2 strict route";

impl StrictRouteLayer {
    pub(super) const fn key(self) -> GUID {
        match self {
            Self::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Self::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        }
    }
}

impl StrictRouteAction {
    pub(super) const fn raw(self) -> u32 {
        match self {
            Self::Permit => FWP_ACTION_PERMIT,
            Self::Block => FWP_ACTION_BLOCK,
        }
    }
}

impl StrictRouteRuleKind {
    const fn key(self) -> GUID {
        let value = match self {
            Self::AppPermitV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701001,
            Self::AppPermitV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701002,
            Self::TunPermitV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701003,
            Self::TunPermitV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701004,
            Self::FamilyBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701005,
            Self::FamilyBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701006,
            Self::DnsTcpBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701007,
            Self::DnsUdpBlockV4 => 0xa158b31d_7a59_40bc_9339_38b5e8701008,
            Self::DnsTcpBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e8701009,
            Self::DnsUdpBlockV6 => 0xa158b31d_7a59_40bc_9339_38b5e870100a,
        };
        GUID::from_u128(value)
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AppPermitV4 => "Ferrum2 app permit IPv4",
            Self::AppPermitV6 => "Ferrum2 app permit IPv6",
            Self::TunPermitV4 => "Ferrum2 TUN permit IPv4",
            Self::TunPermitV6 => "Ferrum2 TUN permit IPv6",
            Self::FamilyBlockV4 => "Ferrum2 family block IPv4",
            Self::FamilyBlockV6 => "Ferrum2 family block IPv6",
            Self::DnsTcpBlockV4 => "Ferrum2 DNS TCP block IPv4",
            Self::DnsUdpBlockV4 => "Ferrum2 DNS UDP block IPv4",
            Self::DnsTcpBlockV6 => "Ferrum2 DNS TCP block IPv6",
            Self::DnsUdpBlockV6 => "Ferrum2 DNS UDP block IPv6",
        }
    }
}

impl StrictRouteCondition {
    pub(super) const fn field_key(&self) -> GUID {
        match self {
            Self::AppId(_) => FWPM_CONDITION_ALE_APP_ID,
            Self::LocalInterfaceLuid(_) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
            Self::IpProtocol(_) => FWPM_CONDITION_IP_PROTOCOL,
            Self::RemotePort(_) => FWPM_CONDITION_IP_REMOTE_PORT,
        }
    }

    pub(super) const fn data_type(&self) -> i32 {
        match self {
            Self::AppId(_) => FWP_BYTE_BLOB_TYPE,
            Self::LocalInterfaceLuid(_) => FWP_UINT64,
            Self::IpProtocol(_) => FWP_UINT8,
            Self::RemotePort(_) => FWP_UINT16,
        }
    }
}

pub(super) type PlatformStrictRouteSession = StrictRouteSession<PlatformStrictRouteOperations>;

pub(super) struct PlatformStrictRouteOperations;

pub(super) struct WfpSession(HANDLE);

pub(super) struct FwpmOwned<T>(*mut T);

impl<T> FwpmOwned<T> {
    fn get(&self) -> Result<&T, Error> {
        unsafe { self.0.as_ref() }.ok_or(Error)
    }
}

impl<T> Drop for FwpmOwned<T> {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        let mut allocation = self.0.cast::<c_void>();
        unsafe { FwpmFreeMemory0(&mut allocation) };
        self.0 = null_mut();
    }
}

pub(super) fn guid_matches(left: &GUID, right: &GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

pub(super) fn wfp_readback_present(status: u32, not_found: i32) -> Result<bool, Error> {
    match status {
        ERROR_SUCCESS => Ok(true),
        value if value == not_found as u32 || value == FWP_E_SESSION_ABORTED as u32 => Ok(false),
        _ => Err(Error),
    }
}

pub(super) fn wide_string(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub(super) fn raw_wide_matches(raw: *const u16, expected: &str) -> bool {
    if raw.is_null() {
        return false;
    }
    let expected = expected.encode_utf16().chain(Some(0));
    expected
        .enumerate()
        .all(|(index, unit)| unsafe { *raw.add(index) } == unit)
}

pub(super) fn raw_strict_route_condition_matches(
    raw: &FWPM_FILTER_CONDITION0,
    expected: &StrictRouteCondition,
) -> bool {
    if raw.matchType != FWP_MATCH_EQUAL {
        return false;
    }
    match expected {
        StrictRouteCondition::AppId(expected) => {
            if !guid_matches(&raw.fieldKey, &FWPM_CONDITION_ALE_APP_ID)
                || raw.conditionValue.r#type != FWP_BYTE_BLOB_TYPE
            {
                return false;
            }
            let blob = unsafe { raw.conditionValue.Anonymous.byteBlob };
            let Some(blob) = (unsafe { blob.as_ref() }) else {
                return false;
            };
            let Ok(size) = usize::try_from(blob.size) else {
                return false;
            };
            if size != expected.len() || size > MAX_WFP_APP_ID_BYTES || blob.data.is_null() {
                return false;
            }
            (unsafe { std::slice::from_raw_parts(blob.data, size) }) == expected.as_ref()
        }
        StrictRouteCondition::LocalInterfaceLuid(expected) => {
            if !guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_LOCAL_INTERFACE)
                || raw.conditionValue.r#type != FWP_UINT64
            {
                return false;
            }
            let luid = unsafe { raw.conditionValue.Anonymous.uint64 };
            unsafe { luid.as_ref() }.is_some_and(|current| current == expected)
        }
        StrictRouteCondition::IpProtocol(expected) => {
            guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_PROTOCOL)
                && raw.conditionValue.r#type == FWP_UINT8
                && unsafe { raw.conditionValue.Anonymous.uint8 } == *expected
        }
        StrictRouteCondition::RemotePort(expected) => {
            guid_matches(&raw.fieldKey, &FWPM_CONDITION_IP_REMOTE_PORT)
                && raw.conditionValue.r#type == FWP_UINT16
                && unsafe { raw.conditionValue.Anonymous.uint16 } == *expected
        }
    }
}

pub(super) fn raw_strict_route_filter_matches(
    id: u64,
    raw: &FWPM_FILTER0,
    expected: &StrictRouteRule,
) -> bool {
    let Ok(condition_count) = usize::try_from(raw.numFilterConditions) else {
        return false;
    };
    if raw.filterId != id
        || !guid_matches(&raw.filterKey, &expected.kind.key())
        || !raw_wide_matches(raw.displayData.name, expected.kind.name())
        || raw.flags != 0
        || !raw.providerKey.is_null()
        || raw.providerData.size != 0
        || !raw.providerData.data.is_null()
        || !guid_matches(&raw.layerKey, &expected.layer.key())
        || !guid_matches(&raw.subLayerKey, &STRICT_ROUTE_SUBLAYER_KEY)
        || raw.weight.r#type != FWP_UINT8
        || unsafe { raw.weight.Anonymous.uint8 } != expected.weight
        || raw.action.r#type != expected.action.raw()
        || condition_count != expected.conditions.len()
        || condition_count > 2
        || (condition_count != 0 && raw.filterCondition.is_null())
    {
        return false;
    }
    let raw_conditions = if condition_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(raw.filterCondition, condition_count) }
    };
    expected.conditions.iter().all(|expected| {
        raw_conditions
            .iter()
            .any(|raw| raw_strict_route_condition_matches(raw, expected))
    })
}

impl StrictRouteOperations for PlatformStrictRouteOperations {
    type Session = WfpSession;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
        let mut session_name = wide_string(STRICT_ROUTE_SESSION_NAME);
        let session = FWPM_SESSION0 {
            sessionKey: STRICT_ROUTE_SESSION_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: session_name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..FWPM_SESSION0::default()
        };
        let mut engine = null_mut();
        let status =
            unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut engine) };
        if status != ERROR_SUCCESS {
            if !engine.is_null() {
                let _ = unsafe { FwpmEngineClose0(engine) };
            }
            return Err(Error);
        }
        if engine.is_null() {
            Err(Error)
        } else {
            Ok(WfpSession(engine))
        }
    }

    fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
        let executable = current_executable()?;
        let executable = wide(&executable);
        let mut raw = null_mut();
        let status = unsafe { FwpmGetAppIdFromFileName0(executable.as_ptr(), &mut raw) };
        let allocation = FwpmOwned(raw);
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        let blob = allocation.get()?;
        let size = usize::try_from(blob.size).map_err(|_| Error)?;
        if size == 0 || size > MAX_WFP_APP_ID_BYTES || blob.data.is_null() {
            return Err(Error);
        }
        Ok(unsafe { std::slice::from_raw_parts(blob.data, size) }
            .to_vec()
            .into_boxed_slice())
    }

    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionBegin0(session.0, 0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        let mut name = wide_string(STRICT_ROUTE_SUBLAYER_NAME);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: STRICT_ROUTE_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            weight: STRICT_ROUTE_SUBLAYER_WEIGHT,
            ..FWPM_SUBLAYER0::default()
        };
        if unsafe { FwpmSubLayerAdd0(session.0, &sublayer, null_mut()) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &StrictRouteRule,
    ) -> Result<u64, Error> {
        let mut luid_values = Vec::<Box<u64>>::new();
        let mut app_blobs = Vec::<Box<FWP_BYTE_BLOB>>::new();
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for condition in &rule.conditions {
            let value = match condition {
                StrictRouteCondition::AppId(app_id) => {
                    let size = u32::try_from(app_id.len()).map_err(|_| Error)?;
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size,
                        data: app_id.as_ptr().cast_mut(),
                    });
                    let value = FWP_CONDITION_VALUE0_0 {
                        byteBlob: blob.as_mut(),
                    };
                    app_blobs.push(blob);
                    value
                }
                StrictRouteCondition::LocalInterfaceLuid(luid) => {
                    let mut luid = Box::new(*luid);
                    let value = FWP_CONDITION_VALUE0_0 {
                        uint64: luid.as_mut(),
                    };
                    luid_values.push(luid);
                    value
                }
                StrictRouteCondition::IpProtocol(protocol) => {
                    FWP_CONDITION_VALUE0_0 { uint8: *protocol }
                }
                StrictRouteCondition::RemotePort(port) => FWP_CONDITION_VALUE0_0 { uint16: *port },
            };
            conditions.push(FWPM_FILTER_CONDITION0 {
                fieldKey: condition.field_key(),
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: condition.data_type(),
                    Anonymous: value,
                },
            });
        }
        let mut name = wide_string(rule.kind.name());
        let filter = FWPM_FILTER0 {
            filterKey: rule.kind.key(),
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            layerKey: rule.layer.key(),
            subLayerKey: STRICT_ROUTE_SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: rule.weight },
            },
            numFilterConditions: u32::try_from(conditions.len()).map_err(|_| Error)?,
            filterCondition: if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            },
            action: FWPM_ACTION0 {
                r#type: rule.action.raw(),
                ..FWPM_ACTION0::default()
            },
            ..FWPM_FILTER0::default()
        };
        let mut id = 0_u64;
        let status = unsafe { FwpmFilterAdd0(session.0, &filter, null_mut(), &mut id) };
        drop((luid_values, app_blobs));
        if status == ERROR_SUCCESS && id != 0 {
            Ok(id)
        } else {
            Err(Error)
        }
    }

    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionCommit0(session.0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionAbort0(session.0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status =
            unsafe { FwpmSubLayerGetByKey0(session.0, &STRICT_ROUTE_SUBLAYER_KEY, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_SUBLAYER_NOT_FOUND)? {
            return Ok(false);
        }
        let sublayer = allocation.get()?;
        Ok(
            guid_matches(&sublayer.subLayerKey, &STRICT_ROUTE_SUBLAYER_KEY)
                && raw_wide_matches(sublayer.displayData.name, STRICT_ROUTE_SUBLAYER_NAME)
                && sublayer.flags == 0
                && sublayer.providerKey.is_null()
                && sublayer.providerData.size == 0
                && sublayer.providerData.data.is_null()
                && sublayer.weight == STRICT_ROUTE_SUBLAYER_WEIGHT,
        )
    }

    fn filter_matches(
        &self,
        session: &Self::Session,
        id: u64,
        rule: &StrictRouteRule,
    ) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status = unsafe { FwpmFilterGetById0(session.0, id, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_FILTER_NOT_FOUND)? {
            return Ok(false);
        }
        Ok(raw_strict_route_filter_matches(id, allocation.get()?, rule))
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if session.0.is_null() {
            return Err(Error);
        }
        if unsafe { FwpmEngineClose0(session.0) } != ERROR_SUCCESS {
            return Err(Error);
        }
        session.0 = null_mut();
        Ok(())
    }
}
