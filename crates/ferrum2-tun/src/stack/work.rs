use super::Stack;
use crate::TunEvent;
use crate::scheduler::{StepOutcome, WorkStage};
use crate::udp::ResponseProcessOutcome;

impl Stack {
    /// Runs one production owner stage that does not cross adapter or handler I/O.
    /// Callers must serialize stages on the owner and supply its monotonic clock.
    /// Receive/flush and handler forwarding remain external, statically dispatched seams.
    pub(crate) fn owner_internal_step(
        &mut self,
        stage: WorkStage,
        now: i64,
        admitting: bool,
    ) -> Option<StepOutcome> {
        Some(match stage {
            WorkStage::Control => {
                StepOutcome::from_work(self.process_owner_control_stage(now, admitting, false))
            }
            WorkStage::Stack => StepOutcome::from_work(self.process_one_tcp_packet()),
            WorkStage::UdpResponse => match self.process_one_udp_response(now) {
                ResponseProcessOutcome::Idle => StepOutcome::Idle,
                ResponseProcessOutcome::Deferred => {
                    self.events.emit(TunEvent::InternalEgressBackpressured);
                    StepOutcome::Worked
                }
                ResponseProcessOutcome::Injected | ResponseProcessOutcome::Dropped(_) => {
                    StepOutcome::Worked
                }
            },
            WorkStage::Expire => StepOutcome::from_work(self.expire_deadlines(now)),
            WorkStage::Receive | WorkStage::FlushOutput => return None,
        })
    }
}
