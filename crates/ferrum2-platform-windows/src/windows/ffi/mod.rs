#![allow(unsafe_code)]
#![cfg_attr(test, allow(unused_imports))]

#[cfg(test)]
use std::ffi::{OsString, c_void};
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::io::Read;
#[cfg(test)]
use std::marker::PhantomData;
#[cfg(test)]
use std::ops::Deref;
#[cfg(test)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[cfg(test)]
use std::os::windows::io::{AsRawHandle, AsRawSocket, FromRawHandle};
#[cfg(test)]
use std::path::{Path, PathBuf, Prefix};
#[cfg(test)]
use std::ptr::{null, null_mut};
#[cfg(test)]
use std::rc::Rc;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(test)]
use std::time::{Duration, Instant};

#[cfg(test)]
use ferrum2_net::{
    InterfaceBinding, NetworkFamily, NetworkInterfaceKind, NetworkInterfaceObservation,
    ResolvedInterface, ResolvedSocketBinder, SystemBestRoute,
};
#[cfg(test)]
use socket2::Socket;
#[cfg(test)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW,
    ERROR_HANDLE_EOF, ERROR_NO_MORE_ITEMS, ERROR_NOT_FOUND, ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND,
    FWP_E_SESSION_ABORTED, FWP_E_SUBLAYER_NOT_FOUND, FreeLibrary, GetLastError, HANDLE, HMODULE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
#[cfg(test)]
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CancelMibChangeNotify2, ConvertInterfaceLuidToGuid, ConvertInterfaceLuidToIndex,
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_IPV6, DNS_SETTING_NAMESERVER,
    DeleteIpForwardEntry2, DeleteUnicastIpAddressEntry, FreeInterfaceDnsSettings, FreeMibTable,
    GetBestInterfaceEx, GetBestRoute2, GetIfTable2, GetInterfaceDnsSettings, GetIpForwardEntry2,
    GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressEntry, GetUnicastIpAddressTable,
    InitializeIpForwardEntry, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, NotifyIpInterfaceChange,
    NotifyRouteChange2, NotifyUnicastIpAddressChange, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
#[cfg(test)]
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusUp, MediaConnectStateConnected, NET_IF_ADMIN_STATUS_UP, NET_LUID_LH,
};
#[cfg(test)]
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
#[cfg(test)]
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IP_UNICAST_IF,
    IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IpDadStateDeprecated, IpDadStateDuplicate,
    IpDadStateInvalid, IpDadStatePreferred, IpDadStateTentative, IpPrefixOriginManual,
    IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, NL_DAD_STATE, NlroManual, SOCKADDR, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET, bind as winsock_bind, setsockopt,
};
#[cfg(test)]
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_ALG_HANDLE, BCRYPT_SHA256_ALGORITHM, BCryptCloseAlgorithmProvider, BCryptHash,
    BCryptOpenAlgorithmProvider,
};
#[cfg(test)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    FILE_SHARE_READ, FILE_SHARE_WRITE, FileAttributeTagInfo, GetFileInformationByHandleEx,
    OPEN_EXISTING,
};
#[cfg(test)]
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN, GetModuleFileNameW,
    GetModuleHandleExW, GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
#[cfg(test)]
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
#[cfg(test)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, ResetEvent, SetEvent, WaitForMultipleObjects,
};
#[cfg(test)]
use windows_sys::core::GUID;

#[cfg(test)]
use super::loader::{LoaderOperations, load_transaction, require_exports, validate_artifact};
#[cfg(test)]
use super::managed::*;
#[cfg(test)]
use super::network::{
    InterfaceIdentity, RouteFingerprint, SocketBindingOperations, UnderlayOperations,
    UnderlayPolicy, WindowsNetworkInterfaceCatalog, bind_fixed_with, bind_target_with,
    classify_underlay_refresh, refresh_underlay_with, same_ip_family, snapshot_underlay_at,
    underlay_matches_with,
};
#[cfg(test)]
use super::network::{snapshot_underlay_with, underlay_snapshot_matches};
#[cfg(test)]
use super::notification::leak_notification_owners;
#[cfg(test)]
use super::notification::{
    NetworkChangeWaitOperations, cancel_notification_handles, close_notification_handles,
    subscribe_notification_sequence, wait_for_network_change,
};
#[cfg(test)]
use super::strict_route::{StrictRouteOperations, StrictRouteSession, strict_route_state_matches};
#[cfg(test)]
use super::wintun::SessionJournal;
#[cfg(test)]
use crate::DLL_SHA256;
#[cfg(test)]
use crate::strict_route::STRICT_ROUTE_BLOCK_WEIGHT;
#[cfg(test)]
use crate::strict_route::strict_route_rules;
#[cfg(test)]
use crate::strict_route::{
    MAX_WFP_APP_ID_BYTES, StrictRouteAction, StrictRouteCondition, StrictRouteLayer,
    StrictRouteRule, StrictRouteRuleKind,
};
#[cfg(test)]
use crate::{
    ABI_EXPORTS, AdapterConfig, CreateError, DLL_BYTES, Error, IpPrefix, ManagedStateDamage,
    ManagedTunHealth, NetworkChangeOutcome, NetworkChangeWaitOutcome, SendOutcome, WaitOutcome,
};

mod loader;
mod managed;
pub(super) mod network;
mod notification;
mod strict_route;
mod wintun;

#[cfg(test)]
use loader::*;
#[cfg(test)]
use managed::*;
#[cfg(test)]
use network::*;
#[cfg(test)]
use notification::*;
#[cfg(test)]
use strict_route::*;
#[cfg(test)]
use wintun::*;

pub use network::{WindowsResolvedSocketBinder, bind_resolved_socket};
pub use notification::WindowsNetworkChangeMonitor;
pub use wintun::{Adapter, ReceivedPacket, StopSignal, WorkSignal};

#[cfg(test)]
mod tests;
