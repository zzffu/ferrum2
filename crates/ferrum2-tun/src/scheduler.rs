/// Fixed owner-loop stages. Each call advances by one stage so no source of
/// work can monopolize an iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkStage {
    Control,
    FlushOutput,
    Stack,
    Receive,
    UdpResponse,
    Expire,
}

impl WorkStage {
    const ALL: [Self; 6] = [
        Self::Control,
        Self::FlushOutput,
        Self::Stack,
        Self::Receive,
        Self::UdpResponse,
        Self::Expire,
    ];
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FairScheduler {
    next: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepOutcome {
    Idle,
    Worked,
    Fatal,
}

impl StepOutcome {
    pub(crate) const fn from_work(worked: bool) -> Self {
        if worked { Self::Worked } else { Self::Idle }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BudgetOutcome {
    pub(crate) work_units: usize,
    pub(crate) fatal: bool,
    /// The stage budget ended before the scheduler observed one complete idle
    /// rotation. The caller must poll again without blocking because work may
    /// remain behind a coalesced wake signal.
    pub(crate) budget_exhausted: bool,
}

impl FairScheduler {
    pub(crate) const STAGE_COUNT: usize = WorkStage::ALL.len();

    pub(crate) fn next_stage(&mut self) -> WorkStage {
        let stage = WorkStage::ALL[self.next];
        self.next = (self.next + 1) % Self::STAGE_COUNT;
        stage
    }

    /// Runs a bounded number of fair stages, stopping after one complete idle
    /// rotation or immediately on a fatal boundary.
    pub(crate) fn run_budget(
        &mut self,
        budget: usize,
        mut step: impl FnMut(WorkStage) -> StepOutcome,
    ) -> BudgetOutcome {
        let mut outcome = BudgetOutcome::default();
        let mut idle_stages = 0;
        for _ in 0..budget {
            match step(self.next_stage()) {
                StepOutcome::Idle => {
                    idle_stages += 1;
                    if idle_stages >= Self::STAGE_COUNT {
                        return outcome;
                    }
                }
                StepOutcome::Worked => {
                    outcome.work_units += 1;
                    idle_stages = 0;
                }
                StepOutcome::Fatal => {
                    outcome.fatal = true;
                    return outcome;
                }
            }
        }
        outcome.budget_exhausted = budget != 0;
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::{FairScheduler, StepOutcome, WorkStage};

    #[test]
    fn rotation_is_stable_across_arbitrary_work_budget_boundaries() {
        let mut scheduler = FairScheduler::default();
        let observed = (0..14).map(|_| scheduler.next_stage()).collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                WorkStage::Control,
                WorkStage::FlushOutput,
                WorkStage::Stack,
                WorkStage::Receive,
                WorkStage::UdpResponse,
                WorkStage::Expire,
                WorkStage::Control,
                WorkStage::FlushOutput,
                WorkStage::Stack,
                WorkStage::Receive,
                WorkStage::UdpResponse,
                WorkStage::Expire,
                WorkStage::Control,
                WorkStage::FlushOutput,
            ]
        );
    }

    #[test]
    fn fatal_step_stops_before_any_later_state_mutation() {
        let mut scheduler = FairScheduler::default();
        let mut observed = Vec::new();
        let outcome = scheduler.run_budget(64, |stage| {
            observed.push(stage);
            if stage == WorkStage::Receive {
                StepOutcome::Fatal
            } else {
                StepOutcome::Worked
            }
        });

        assert!(outcome.fatal);
        assert!(!outcome.budget_exhausted);
        assert_eq!(outcome.work_units, 3);
        assert_eq!(
            observed,
            [
                WorkStage::Control,
                WorkStage::FlushOutput,
                WorkStage::Stack,
                WorkStage::Receive,
            ]
        );
    }

    #[test]
    fn one_idle_rotation_stops_without_spinning() {
        let mut scheduler = FairScheduler::default();
        let mut calls = 0;
        let outcome = scheduler.run_budget(64, |_| {
            calls += 1;
            StepOutcome::Idle
        });
        assert_eq!(calls, FairScheduler::STAGE_COUNT);
        assert_eq!(outcome.work_units, 0);
        assert!(!outcome.fatal);
        assert!(!outcome.budget_exhausted);
    }

    #[test]
    fn reaching_the_stage_limit_reports_budget_exhaustion() {
        let mut scheduler = FairScheduler::default();
        let outcome = scheduler.run_budget(FairScheduler::STAGE_COUNT, |stage| {
            if stage == WorkStage::Control {
                StepOutcome::Worked
            } else {
                StepOutcome::Idle
            }
        });

        assert_eq!(outcome.work_units, 1);
        assert!(outcome.budget_exhausted);
    }
}
