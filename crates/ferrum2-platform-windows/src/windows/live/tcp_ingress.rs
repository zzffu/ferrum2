use std::ffi::c_void;
use std::net::IpAddr;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
    FWPM_FILTER_FLAG_INDEXED, FWPM_FILTER0, FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0,
    FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0, FwpmSubLayerGetByKey0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

use super::super::core::strict_route::{guid_matches, wfp_readback_present};
use super::super::core::tcp_ingress::{TcpIngressOperations, TcpIngressSession};
use super::loader::{current_executable, wide};
use super::strict_route::{raw_wide_matches, wide_string};
use crate::Error;
use crate::tcp_ingress::{
    MAX_WFP_APP_ID_BYTES, TcpIngressCondition, TcpIngressLayer, TcpIngressRule,
};

pub(super) const TCP_INGRESS_SESSION_KEY: GUID =
    GUID::from_u128(0x41b9d0c7_65ac_49a7_8d97_bf8ad5abbe01);
pub(super) const TCP_INGRESS_SUBLAYER_KEY: GUID =
    GUID::from_u128(0x5e741969_f578_43bd_a1e2_a420c49a7f01);
// A fixed key intentionally makes a second Ferrum2 instance fail closed instead of sharing or
// deleting another process's dynamic objects. BFE may assign the closest available weight.
pub(super) const TCP_INGRESS_SUBLAYER_WEIGHT: u16 = 0x7ffe;
pub(super) const TCP_INGRESS_SESSION_NAME: &str = "Ferrum2 TCP ingress dynamic session";
pub(super) const TCP_INGRESS_SUBLAYER_NAME: &str = "Ferrum2 TCP ingress";
impl TcpIngressLayer {
    pub(crate) const fn display_name(self) -> &'static str {
        match self {
            Self::V4 => "Ferrum2 TCP ingress IPv4",
            Self::V6 => "Ferrum2 TCP ingress IPv6",
        }
    }
}

pub(super) type PlatformTcpIngressSession = TcpIngressSession<PlatformTcpIngressOperations>;

pub(super) struct PlatformTcpIngressOperations;

pub(super) struct WfpSession {
    handle: HANDLE,
    sublayer_weight: Option<u16>,
}

pub(super) struct FilterIdentity {
    effective_weight: u64,
    id: u64,
    key: GUID,
}

struct FwpmOwned<T>(*mut T);

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

fn guid_is_zero(value: &GUID) -> bool {
    value.data1 == 0
        && value.data2 == 0
        && value.data3 == 0
        && value.data4.iter().all(|byte| *byte == 0)
}

/// # Safety
///
/// Every pointer selected by `raw.conditionValue` must belong to the live WFP readback allocation
/// and match its declared data type.
unsafe fn raw_condition_matches(
    raw: &FWPM_FILTER_CONDITION0,
    expected: &TcpIngressCondition,
) -> bool {
    if raw.matchType != FWP_MATCH_EQUAL
        || !guid_matches(&raw.fieldKey, &expected.field_key())
        || raw.conditionValue.r#type != expected.data_type()
    {
        return false;
    }
    match expected {
        TcpIngressCondition::AppId(expected) => {
            let Some(blob) = (unsafe { raw.conditionValue.Anonymous.byteBlob.as_ref() }) else {
                return false;
            };
            let Ok(size) = usize::try_from(blob.size) else {
                return false;
            };
            size == expected.len()
                && size <= MAX_WFP_APP_ID_BYTES
                && !blob.data.is_null()
                && (unsafe { std::slice::from_raw_parts(blob.data, size) }) == expected.as_ref()
        }
        TcpIngressCondition::LocalInterfaceLuid(expected) => {
            (unsafe { raw.conditionValue.Anonymous.uint64.as_ref() })
                .is_some_and(|current| current == expected)
        }
        TcpIngressCondition::IpProtocol(expected) => {
            (unsafe { raw.conditionValue.Anonymous.uint8 }) == *expected
        }
        TcpIngressCondition::LocalPort(expected) => {
            (unsafe { raw.conditionValue.Anonymous.uint16 }) == *expected
        }
        TcpIngressCondition::LocalAddress(expected)
        | TcpIngressCondition::RemoteAddress(expected) => match expected {
            IpAddr::V4(expected) => {
                (unsafe { raw.conditionValue.Anonymous.uint32 }) == u32::from(*expected)
            }
            IpAddr::V6(expected) => unsafe { raw.conditionValue.Anonymous.byteArray16.as_ref() }
                .is_some_and(|current| current.byteArray16 == expected.octets()),
        },
    }
}

/// # Safety
///
/// `raw` and every pointer-bearing nested field must remain owned by the live WFP allocation for
/// this call.
unsafe fn raw_filter_matches(
    raw: &FWPM_FILTER0,
    identity: &FilterIdentity,
    expected: &TcpIngressRule,
) -> bool {
    let Ok(condition_count) = usize::try_from(raw.numFilterConditions) else {
        return false;
    };
    if raw.filterId != identity.id
        || !guid_matches(&raw.filterKey, &identity.key)
        || unsafe { !raw_wide_matches(raw.displayData.name, expected.layer.display_name()) }
        || !raw.displayData.description.is_null()
        || raw.flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT == 0
        || raw.flags & !(FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_INDEXED) != 0
        || !raw.providerKey.is_null()
        || raw.providerData.size != 0
        || !raw.providerData.data.is_null()
        || !guid_matches(&raw.layerKey, &expected.layer.key())
        || !guid_matches(&raw.subLayerKey, &TCP_INGRESS_SUBLAYER_KEY)
        || raw.weight.r#type != FWP_UINT8
        || unsafe { raw.weight.Anonymous.uint8 } != expected.weight
        || raw.action.r#type != FWP_ACTION_PERMIT
        || condition_count != expected.conditions.len()
        || condition_count != 6
        || raw.filterCondition.is_null()
        || !raw.reserved.is_null()
        || raw.effectiveWeight.r#type != FWP_UINT64
        || unsafe { raw.effectiveWeight.Anonymous.uint64.as_ref() }
            .is_none_or(|current| *current != identity.effective_weight)
        || unsafe { raw.Anonymous.rawContext } != 0
    {
        return false;
    }
    let conditions = unsafe { std::slice::from_raw_parts(raw.filterCondition, condition_count) };
    expected.conditions.iter().all(|expected| {
        conditions
            .iter()
            .any(|raw| unsafe { raw_condition_matches(raw, expected) })
    })
}

impl TcpIngressOperations for PlatformTcpIngressOperations {
    type Session = WfpSession;
    type FilterIdentity = FilterIdentity;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error> {
        let mut session_name = wide_string(TCP_INGRESS_SESSION_NAME);
        let session = FWPM_SESSION0 {
            sessionKey: TCP_INGRESS_SESSION_KEY,
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
            Ok(WfpSession {
                handle: engine,
                sublayer_weight: None,
            })
        }
    }

    fn app_id(&mut self) -> Result<Box<[u8]>, Error> {
        let executable = wide(&current_executable()?);
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
        if unsafe { FwpmTransactionBegin0(session.handle, 0) } == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        let mut name = wide_string(TCP_INGRESS_SUBLAYER_NAME);
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: TCP_INGRESS_SUBLAYER_KEY,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            weight: TCP_INGRESS_SUBLAYER_WEIGHT,
            ..FWPM_SUBLAYER0::default()
        };
        if unsafe { FwpmSubLayerAdd0(session.handle, &sublayer, null_mut()) } != ERROR_SUCCESS {
            return Err(Error);
        }
        let mut raw = null_mut();
        let status =
            unsafe { FwpmSubLayerGetByKey0(session.handle, &TCP_INGRESS_SUBLAYER_KEY, &mut raw) };
        let allocation = FwpmOwned(raw);
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        session.sublayer_weight = Some(allocation.get()?.weight);
        Ok(())
    }

    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &TcpIngressRule,
    ) -> Result<Self::FilterIdentity, Error> {
        let mut app_blobs = Vec::<Box<FWP_BYTE_BLOB>>::new();
        let mut luid_values = Vec::<Box<u64>>::new();
        let mut ipv6_values = Vec::<Box<FWP_BYTE_ARRAY16>>::new();
        let mut conditions = Vec::with_capacity(rule.conditions.len());
        for condition in &rule.conditions {
            let value = match condition {
                TcpIngressCondition::AppId(app_id) => {
                    let mut blob = Box::new(FWP_BYTE_BLOB {
                        size: u32::try_from(app_id.len()).map_err(|_| Error)?,
                        data: app_id.as_ptr().cast_mut(),
                    });
                    let value = FWP_CONDITION_VALUE0_0 {
                        byteBlob: blob.as_mut(),
                    };
                    app_blobs.push(blob);
                    value
                }
                TcpIngressCondition::LocalInterfaceLuid(luid) => {
                    let mut luid = Box::new(*luid);
                    let value = FWP_CONDITION_VALUE0_0 {
                        uint64: luid.as_mut(),
                    };
                    luid_values.push(luid);
                    value
                }
                TcpIngressCondition::IpProtocol(protocol) => {
                    FWP_CONDITION_VALUE0_0 { uint8: *protocol }
                }
                TcpIngressCondition::LocalPort(port) => FWP_CONDITION_VALUE0_0 { uint16: *port },
                TcpIngressCondition::LocalAddress(address)
                | TcpIngressCondition::RemoteAddress(address) => match address {
                    IpAddr::V4(address) => FWP_CONDITION_VALUE0_0 {
                        uint32: u32::from(*address),
                    },
                    IpAddr::V6(address) => {
                        let mut address = Box::new(FWP_BYTE_ARRAY16 {
                            byteArray16: address.octets(),
                        });
                        let value = FWP_CONDITION_VALUE0_0 {
                            byteArray16: address.as_mut(),
                        };
                        ipv6_values.push(address);
                        value
                    }
                },
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
        let mut name = wide_string(rule.layer.display_name());
        let filter = FWPM_FILTER0 {
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            layerKey: rule.layer.key(),
            subLayerKey: TCP_INGRESS_SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_VALUE0_0 { uint8: rule.weight },
            },
            numFilterConditions: u32::try_from(conditions.len()).map_err(|_| Error)?,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..FWPM_ACTION0::default()
            },
            ..FWPM_FILTER0::default()
        };
        let mut id = 0_u64;
        let status = unsafe { FwpmFilterAdd0(session.handle, &filter, null_mut(), &mut id) };
        drop((app_blobs, luid_values, ipv6_values));
        if status != ERROR_SUCCESS || id == 0 {
            return Err(Error);
        }
        let mut raw = null_mut();
        let status = unsafe { FwpmFilterGetById0(session.handle, id, &mut raw) };
        let allocation = FwpmOwned(raw);
        if status != ERROR_SUCCESS {
            return Err(Error);
        }
        let readback = allocation.get()?;
        let key = readback.filterKey;
        let effective_weight = if readback.effectiveWeight.r#type == FWP_UINT64 {
            unsafe { readback.effectiveWeight.Anonymous.uint64.as_ref() }
                .copied()
                .ok_or(Error)?
        } else {
            return Err(Error);
        };
        if guid_is_zero(&key) || effective_weight == 0 {
            Err(Error)
        } else {
            Ok(FilterIdentity {
                id,
                key,
                effective_weight,
            })
        }
    }

    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if session.sublayer_weight.is_some()
            && unsafe { FwpmTransactionCommit0(session.handle) } == ERROR_SUCCESS
        {
            Ok(())
        } else {
            Err(Error)
        }
    }

    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if unsafe { FwpmTransactionAbort0(session.handle) } != ERROR_SUCCESS {
            return Err(Error);
        }
        session.sublayer_weight = None;
        Ok(())
    }

    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status =
            unsafe { FwpmSubLayerGetByKey0(session.handle, &TCP_INGRESS_SUBLAYER_KEY, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_SUBLAYER_NOT_FOUND)? {
            return Ok(false);
        }
        let sublayer = allocation.get()?;
        Ok(
            guid_matches(&sublayer.subLayerKey, &TCP_INGRESS_SUBLAYER_KEY)
                && unsafe {
                    raw_wide_matches(sublayer.displayData.name, TCP_INGRESS_SUBLAYER_NAME)
                }
                && sublayer.displayData.description.is_null()
                && sublayer.flags == 0
                && sublayer.providerKey.is_null()
                && sublayer.providerData.size == 0
                && sublayer.providerData.data.is_null()
                && session
                    .sublayer_weight
                    .is_some_and(|expected| sublayer.weight == expected),
        )
    }

    fn filter_matches(
        &self,
        session: &Self::Session,
        identity: &Self::FilterIdentity,
        rule: &TcpIngressRule,
    ) -> Result<bool, Error> {
        let mut raw = null_mut();
        let status = unsafe { FwpmFilterGetById0(session.handle, identity.id, &mut raw) };
        let allocation = FwpmOwned(raw);
        if !wfp_readback_present(status, FWP_E_FILTER_NOT_FOUND)? {
            return Ok(false);
        }
        Ok(unsafe { raw_filter_matches(allocation.get()?, identity, rule) })
    }

    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error> {
        if session.handle.is_null() {
            return Err(Error);
        }
        if unsafe { FwpmEngineClose0(session.handle) } != ERROR_SUCCESS {
            return Err(Error);
        }
        session.handle = null_mut();
        session.sublayer_weight = None;
        Ok(())
    }
}
