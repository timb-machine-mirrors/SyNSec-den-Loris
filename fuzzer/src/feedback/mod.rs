use core::marker::PhantomData;
use libafl::{
    events::EventFirer,
    Error,
    executors::ExitKind,
    feedbacks::Feedback,
    inputs::UsesInput,
    observers::{Observer, ObserversTuple, UsesObserver},
    state::{HasMetadata, State},
};
use libafl::corpus::Testcase;
use libafl_bolts::Named;
use libafl_bolts::shmem::UnixShMemProvider;
use crate::input::state::{StateDescList, StateValueDiffList};

use crate::input::transition::TransitionInput;
use crate::observer::variable::VariableObserver;

pub const MISMATCH_FEEDBACK_PREFIX: &str = "mismatch_feedback_";

#[derive(Debug)]
pub struct MismatchFeedback<O> {
    /// Name identifier of this instance
    name: String,
    /// Name identifier of the observer
    observer_name: String,
    /// Mismatches between an expected value and the observed one
    mismatches: StateValueDiffList,
    phantom: PhantomData<O>,
}

impl<O> MismatchFeedback<O>
where
    O: Named,
{
    #[must_use]
    pub fn new(observer: &O) -> Self {
        Self {
            name: MISMATCH_FEEDBACK_PREFIX.to_string() + observer.name(),
            observer_name: observer.name().to_string(),
            mismatches: StateValueDiffList::new(),
            phantom: PhantomData,
        }
    }
}

impl<O, S> Feedback<S> for MismatchFeedback<O>
where
    O: Observer<S>,
    S: State + UsesInput<Input=TransitionInput>,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        input: &S::Input,
        observers: &OT,
        _exit_kind: &ExitKind
    ) -> Result<bool, Error>
    where
        EM: EventFirer<State=S>,
        OT: ObserversTuple<S>,
    {
        fn err(name: &str) -> Error {
            Error::illegal_argument(format!("DiffFeedback: observer {name} not found"))
        }
        let o = observers
            .match_name::<VariableObserver<UnixShMemProvider, StateDescList>>(self.observer_name.as_str())
            .ok_or_else(|| err(self.observer_name.as_str()))
            .unwrap();
        let observed_vars = o.variables().unwrap();
        self.mismatches = input.variables.diff(observed_vars);
        if self.mismatches.any() {
            return Ok(true)
        }
        Ok(false)
    }

    fn append_metadata<OT>(
        &mut self,
        _state: &mut S,
        _observers: &OT,
        testcase: &mut Testcase<S::Input>
    ) -> Result<(), Error>
    where
        OT: ObserversTuple<S>
    {
        let meta = self.mismatches.clone();
        testcase.add_metadata(meta);
        Ok(())
    }
}

impl<O> Named for MismatchFeedback<O>
where
    O: Named,
{
    fn name(&self) -> &str {
        self.name.as_str()
    }
}
