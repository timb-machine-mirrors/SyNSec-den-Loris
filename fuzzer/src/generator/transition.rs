use libafl::{
    state::HasRand,
};

use crate::generator::{
    grammar::LorisGrammarGenerator,
    LorisGenerator,
};
use crate::grammar::LorisGrammar;
use crate::input::{
    grammar::FastGrammarInput,
    transition::TransitionInput,
};

pub struct TransitionGenerator<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S>,
    G: LorisGrammar,
    S: HasRand,
{
    base: &'a LorisGenerator<'a, GG, G, S>,
}

impl<'a, GG, G, S> TransitionGenerator<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    #[must_use]
    pub fn new(base: &'a LorisGenerator<'a, GG, G, S>) -> Self {
        Self {
            base,
        }
    }

    pub fn regenerate_grammar_fields(&self, state: &mut S, input: &mut TransitionInput) {
        self.base.regenerate_grammar_fields(state, &mut input.loris_input);
    }

    pub fn generate_continue(&self, input: &mut TransitionInput, state: &mut S) {
        self.base.generate_continue(&mut input.loris_input, state);
    }
}
