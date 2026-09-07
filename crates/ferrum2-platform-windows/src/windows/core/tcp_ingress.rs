use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB_TYPE, FWP_UINT8, FWP_UINT16, FWP_UINT32, FWP_UINT64,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_LOCAL_INTERFACE,
    FWPM_CONDITION_IP_LOCAL_PORT, FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
};
use windows_sys::core::GUID;

use crate::tcp_ingress::{TcpIngressCondition, TcpIngressLayer, TcpIngressRule, tcp_ingress_rules};
use crate::{Error, TcpIngressEndpoint};

impl TcpIngressLayer {
    pub(in crate::windows) const fn key(self) -> GUID {
        match self {
            Self::V4 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            Self::V6 => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
        }
    }
}

impl TcpIngressCondition {
    pub(in crate::windows) const fn field_key(&self) -> GUID {
        match self {
            Self::AppId(_) => FWPM_CONDITION_ALE_APP_ID,
            Self::LocalInterfaceLuid(_) => FWPM_CONDITION_IP_LOCAL_INTERFACE,
            Self::IpProtocol(_) => FWPM_CONDITION_IP_PROTOCOL,
            Self::LocalAddress(_) => FWPM_CONDITION_IP_LOCAL_ADDRESS,
            Self::LocalPort(_) => FWPM_CONDITION_IP_LOCAL_PORT,
            Self::RemoteAddress(_) => FWPM_CONDITION_IP_REMOTE_ADDRESS,
        }
    }

    pub(in crate::windows) const fn data_type(&self) -> i32 {
        match self {
            Self::AppId(_) => FWP_BYTE_BLOB_TYPE,
            Self::LocalInterfaceLuid(_) => FWP_UINT64,
            Self::IpProtocol(_) => FWP_UINT8,
            Self::LocalPort(_) => FWP_UINT16,
            Self::LocalAddress(std::net::IpAddr::V4(_))
            | Self::RemoteAddress(std::net::IpAddr::V4(_)) => FWP_UINT32,
            Self::LocalAddress(std::net::IpAddr::V6(_))
            | Self::RemoteAddress(std::net::IpAddr::V6(_)) => FWP_BYTE_ARRAY16_TYPE,
        }
    }
}

/// Owns one dynamic WFP ingress transaction. Implementations must retain every BFE-assigned
/// identity needed to prove exact readback; failed explicit close keeps the owner for Drop retry.
pub(in crate::windows) trait TcpIngressOperations {
    type Session;
    type FilterIdentity;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error>;
    fn app_id(&mut self) -> Result<Box<[u8]>, Error>;
    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &TcpIngressRule,
    ) -> Result<Self::FilterIdentity, Error>;
    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error>;
    fn filter_matches(
        &self,
        session: &Self::Session,
        identity: &Self::FilterIdentity,
        rule: &TcpIngressRule,
    ) -> Result<bool, Error>;
    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error>;
}

pub(in crate::windows) struct TcpIngressSession<O: TcpIngressOperations> {
    operations: O,
    session: Option<O::Session>,
    expected_filters: Vec<(O::FilterIdentity, TcpIngressRule)>,
}

impl<O: TcpIngressOperations> TcpIngressSession<O> {
    pub(in crate::windows) fn open(mut operations: O) -> Result<Self, Error> {
        let session = operations.open_dynamic_session()?;
        Ok(Self {
            operations,
            session: Some(session),
            expected_filters: Vec::new(),
        })
    }

    pub(in crate::windows) fn install(
        &mut self,
        endpoints: &[TcpIngressEndpoint],
        interface_luid: u64,
    ) -> Result<(), Error> {
        if !self.expected_filters.is_empty() {
            return Err(Error);
        }
        let app_id = self.operations.app_id()?;
        let rules = tcp_ingress_rules(endpoints, &app_id, interface_luid)?;
        let session = self.session.as_mut().ok_or(Error)?;
        self.operations.begin_transaction(session)?;
        let mut installed = Vec::with_capacity(rules.len());
        let transaction = (|| {
            self.operations.add_sublayer(session)?;
            for rule in rules {
                let identity = self.operations.add_filter(session, &rule)?;
                installed.push((identity, rule));
            }
            self.operations.commit_transaction(session)
        })();
        if let Err(error) = transaction {
            if self.operations.abort_transaction(session).is_err() {
                return Err(Error::cleanup());
            }
            return Err(error);
        }
        self.expected_filters = installed;
        if self.health()? { Ok(()) } else { Err(Error) }
    }

    pub(in crate::windows) fn health(&self) -> Result<bool, Error> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if self.expected_filters.is_empty() || !self.operations.sublayer_matches(session)? {
            return Ok(false);
        }
        for (identity, rule) in &self.expected_filters {
            if !self.operations.filter_matches(session, identity, rule)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(in crate::windows) fn close(&mut self) -> Result<(), Error> {
        let Some(session) = self.session.as_mut() else {
            return Ok(());
        };
        self.operations.close_dynamic_session(session)?;
        self.session = None;
        self.expected_filters.clear();
        Ok(())
    }
}

impl<O: TcpIngressOperations> Drop for TcpIngressSession<O> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
