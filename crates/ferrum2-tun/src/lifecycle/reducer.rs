use std::time::Duration;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum LifecycleState<R> {
    Ready(R),
    Transitioning,
    Active,
    BackingOff { resume: R, delay: Duration },
    Stopping,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InvalidLifecycleTransition;

pub(crate) struct LifecycleReducer<R> {
    state: LifecycleState<R>,
}

impl<R> LifecycleReducer<R> {
    pub(crate) const fn starting(resume: R) -> Self {
        Self {
            state: LifecycleState::Ready(resume),
        }
    }

    #[cfg(test)]
    pub(crate) const fn state(&self) -> &LifecycleState<R> {
        &self.state
    }

    pub(crate) fn begin_transition(&mut self) -> Result<R, InvalidLifecycleTransition> {
        let state = std::mem::replace(&mut self.state, LifecycleState::Transitioning);
        match state {
            LifecycleState::Ready(resume) => Ok(resume),
            state => {
                self.state = state;
                Err(InvalidLifecycleTransition)
            }
        }
    }

    pub(crate) fn stage(&mut self, resume: R) -> Result<(), InvalidLifecycleTransition> {
        if !matches!(
            self.state,
            LifecycleState::Transitioning | LifecycleState::Active
        ) {
            return Err(InvalidLifecycleTransition);
        }
        self.state = LifecycleState::Ready(resume);
        Ok(())
    }

    pub(crate) fn activate(&mut self) -> Result<(), InvalidLifecycleTransition> {
        if !matches!(self.state, LifecycleState::Transitioning) {
            return Err(InvalidLifecycleTransition);
        }
        self.state = LifecycleState::Active;
        Ok(())
    }

    pub(crate) fn back_off(
        &mut self,
        resume: R,
        delay: Duration,
    ) -> Result<(), InvalidLifecycleTransition> {
        if !matches!(self.state, LifecycleState::Transitioning) {
            return Err(InvalidLifecycleTransition);
        }
        self.state = LifecycleState::BackingOff { resume, delay };
        Ok(())
    }

    pub(crate) const fn backoff_delay(&self) -> Option<Duration> {
        match self.state {
            LifecycleState::BackingOff { delay, .. } => Some(delay),
            _ => None,
        }
    }

    pub(crate) fn resume(&mut self) -> Result<R, InvalidLifecycleTransition> {
        let state = std::mem::replace(&mut self.state, LifecycleState::Transitioning);
        match state {
            LifecycleState::BackingOff { resume, .. } => Ok(resume),
            state => {
                self.state = state;
                Err(InvalidLifecycleTransition)
            }
        }
    }

    pub(crate) fn stop(&mut self) -> Option<R> {
        let state = std::mem::replace(&mut self.state, LifecycleState::Stopping);
        match state {
            LifecycleState::Ready(resume) | LifecycleState::BackingOff { resume, .. } => {
                Some(resume)
            }
            LifecycleState::Transitioning | LifecycleState::Active | LifecycleState::Stopping => {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_interface_owns_resume_state_end_to_end() {
        let mut lifecycle = LifecycleReducer::starting(1_u8);
        assert_eq!(lifecycle.state(), &LifecycleState::Ready(1));
        assert_eq!(lifecycle.begin_transition(), Ok(1));
        assert_eq!(lifecycle.state(), &LifecycleState::Transitioning);
        assert_eq!(lifecycle.back_off(2, Duration::from_millis(250)), Ok(()));
        assert_eq!(lifecycle.backoff_delay(), Some(Duration::from_millis(250)));
        assert_eq!(lifecycle.resume(), Ok(2));
        assert_eq!(lifecycle.activate(), Ok(()));
        assert_eq!(lifecycle.state(), &LifecycleState::Active);
        assert_eq!(lifecycle.stage(3), Ok(()));
        assert_eq!(lifecycle.stop(), Some(3));
        assert_eq!(lifecycle.state(), &LifecycleState::Stopping);
    }

    #[test]
    fn invalid_transitions_cannot_replace_or_duplicate_owned_resume_state() {
        let mut lifecycle = LifecycleReducer::starting(7_u8);
        assert_eq!(lifecycle.activate(), Err(InvalidLifecycleTransition));
        assert_eq!(lifecycle.resume(), Err(InvalidLifecycleTransition));
        assert_eq!(
            lifecycle.back_off(9, Duration::ZERO),
            Err(InvalidLifecycleTransition)
        );
        assert_eq!(lifecycle.state(), &LifecycleState::Ready(7));

        assert_eq!(lifecycle.begin_transition(), Ok(7));
        assert_eq!(
            lifecycle.begin_transition(),
            Err(InvalidLifecycleTransition)
        );
        assert_eq!(lifecycle.stage(8), Ok(()));
        assert_eq!(lifecycle.stage(9), Err(InvalidLifecycleTransition));
        assert_eq!(lifecycle.stop(), Some(8));
        assert_eq!(
            lifecycle.begin_transition(),
            Err(InvalidLifecycleTransition)
        );
    }
}
