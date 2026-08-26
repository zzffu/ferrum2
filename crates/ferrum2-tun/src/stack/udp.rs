use super::Stack;

impl Stack {
    pub(crate) fn live_udp_associations(&self) -> usize {
        self.udp.active_associations()
    }

    pub(crate) fn ingress_available(&self) -> usize {
        self.device.ingress_available()
    }

    pub(crate) fn has_output(&self) -> bool {
        self.device.has_output()
    }

    pub(crate) fn process_one_udp_control(&mut self, now_millis: i64, admitting: bool) -> bool {
        self.udp
            .process_one_control(now_millis, admitting)
            .is_some()
    }

    pub(crate) fn process_owner_control_stage(
        &mut self,
        now_millis: i64,
        admitting: bool,
        forwarding_work: bool,
    ) -> bool {
        let udp_control = self.process_one_udp_control(now_millis, admitting);
        forwarding_work || udp_control
    }

    pub(crate) fn process_one_udp_response(
        &mut self,
        now_millis: i64,
    ) -> crate::udp::ResponseProcessOutcome {
        let device = &mut self.device;
        self.udp.process_one_response(now_millis, |tuple, payload| {
            device.inject_udp_response(tuple, payload)
        })
    }

    #[cfg(test)]
    pub(crate) fn poll_udp_events(
        &mut self,
        now_millis: i64,
        admitting: bool,
    ) -> crate::udp::EventOutcome {
        let device = &mut self.device;
        self.udp
            .process_events(now_millis, admitting, |tuple, payload| {
                device.inject_udp_response(tuple, payload)
            })
    }
}
