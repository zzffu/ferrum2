use crate::Error;
use crate::strict_route::{StrictRouteRule, strict_route_rules};

mod readback;

pub(in crate::windows) use readback::{guid_matches, wfp_readback_present};

pub(in crate::windows) trait StrictRouteOperations {
    type Session;

    fn open_dynamic_session(&mut self) -> Result<Self::Session, Error>;
    fn app_id(&mut self) -> Result<Box<[u8]>, Error>;
    fn begin_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_sublayer(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn add_filter(
        &mut self,
        session: &mut Self::Session,
        rule: &StrictRouteRule,
    ) -> Result<u64, Error>;
    fn commit_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn abort_transaction(&mut self, session: &mut Self::Session) -> Result<(), Error>;
    fn sublayer_matches(&self, session: &Self::Session) -> Result<bool, Error>;
    fn filter_matches(
        &self,
        session: &Self::Session,
        id: u64,
        rule: &StrictRouteRule,
    ) -> Result<bool, Error>;
    fn close_dynamic_session(&mut self, session: &mut Self::Session) -> Result<(), Error>;
}

pub(in crate::windows) struct StrictRouteSession<O: StrictRouteOperations> {
    operations: O,
    session: Option<O::Session>,
    expected_filters: Vec<(u64, StrictRouteRule)>,
}

impl<O: StrictRouteOperations> StrictRouteSession<O> {
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
        has_ipv4: bool,
        has_ipv6: bool,
        has_managed_dns: bool,
        interface_luid: u64,
    ) -> Result<(), Error> {
        if !self.expected_filters.is_empty() {
            return Err(Error);
        }
        let app_id = self.operations.app_id()?;
        let rules =
            strict_route_rules(has_ipv4, has_ipv6, has_managed_dns, &app_id, interface_luid)?;
        let session = self.session.as_mut().ok_or(Error)?;
        self.operations.begin_transaction(session)?;
        let mut installed = Vec::with_capacity(rules.len());
        let transaction = (|| {
            self.operations.add_sublayer(session)?;
            for rule in rules {
                let id = self.operations.add_filter(session, &rule)?;
                if id == 0 {
                    return Err(Error);
                }
                installed.push((id, rule));
            }
            self.operations.commit_transaction(session)
        })();
        if transaction.is_err() {
            let _ = self.operations.abort_transaction(session);
            return Err(Error);
        }
        self.expected_filters = installed;
        Ok(())
    }

    pub(in crate::windows) fn health(&self) -> Result<bool, Error> {
        let Some(session) = self.session.as_ref() else {
            return Ok(false);
        };
        if self.expected_filters.is_empty() || !self.operations.sublayer_matches(session)? {
            return Ok(false);
        }
        for (id, rule) in &self.expected_filters {
            if !self.operations.filter_matches(session, *id, rule)? {
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

impl<O: StrictRouteOperations> Drop for StrictRouteSession<O> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

pub(in crate::windows) fn strict_route_state_matches<O: StrictRouteOperations>(
    intent: bool,
    session: Option<&StrictRouteSession<O>>,
) -> Result<bool, Error> {
    match (intent, session) {
        (false, None) => Ok(true),
        (true, Some(session)) => session.health(),
        _ => Ok(false),
    }
}
