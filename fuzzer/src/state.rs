use core::marker::PhantomData;
use libafl::{
	inputs::{Input, UsesInput},
	state::HasRand,
};
use libafl_bolts::rands::StdRand;

pub struct NopState<I> {
    rand: StdRand,
    phantom: PhantomData<I>,
}

impl<I> NopState<I> {
    /// Create a new State that does nothing (for tests)
    #[must_use]
    pub fn new() -> Self {
        NopState {
            rand: StdRand::default(),
            phantom: PhantomData,
        }
    }
}

impl<I> UsesInput for NopState<I>
where
    I: Input,
{
    type Input = I;
}

impl<I> HasRand for NopState<I> {
    type Rand = StdRand;

    fn rand(&self) -> &Self::Rand {
        &self.rand
    }

    fn rand_mut(&mut self) -> &mut Self::Rand {
        &mut self.rand
    }
}