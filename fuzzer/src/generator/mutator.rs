use libafl::{
    corpus::Corpus,
    inputs::{BytesInput, HasBytesVec, HasTargetBytes},
    mutators::{ByteFlipMutator, MutationResult, Mutator, scheduled::havoc_mutations_no_crossover, StdScheduledMutator},
    state::{HasCorpus, HasMaxSize, HasRand},
    Error,
    random_corpus_id,
};
use libafl_bolts::{AsSlice, HasLen, Named, rands::Rand, tuples::tuple_list};
use std::marker::PhantomData;

use crate::generator::{
    grammar::LorisGrammarGenerator,
    LorisGenerator,
    utils,
};
use crate::grammar::LorisGrammar;
use crate::input::{
    grammar::{BaseGrammarInput, FastGrammarInput, HasGrammarInput},
    LorisInput,
    transition::TransitionInput,
    vendor::{
        shannon::{
            qitem::{QItem, QItemField},
            smpf::SmpfEventPaylod,
            ShannonInput,
        },
        VendorInput,
    },
};

pub struct GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S>,
    G: LorisGrammar,
    S: HasRand,
{
    generator: &'a LorisGenerator<'a, GG, G, S>,
}

impl<'a, GG, G, S> Mutator<BaseGrammarInput, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut BaseGrammarInput,
        _stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let indices = input.find_all_mutable_fields();
        let len = indices.len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let index= indices[choice];
        if input.fields[index].mutable == false {
            unreachable!("no mutable input at specified index!");
        }
        let symbol = input.fields[index].path.get_symbol();
        let new_string = self.generator.gg.generate_from_symbol(state, &symbol)
            .target_bytes()
            .as_slice()
            .to_vec();
        input.replace_by_index(new_string, index);
        Ok(MutationResult::Mutated)
    }
}

impl<'a, GG, G, S> Mutator<FastGrammarInput, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut GG::GrammarInput, stage_idx: i32) -> Result<MutationResult, Error> {
        let len = input.fields().len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let orig_field = input.fields()[choice].clone();
        let index = orig_field.state();
        self.generator.gg.generate_index(index, input, state);
        if input.fields()[choice] == orig_field {
            Ok(MutationResult::Skipped)
        } else {
            Ok(MutationResult::Mutated)
        }
    }
}

impl<'a, GG, G, S> Mutator<LorisInput, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut LorisInput,
        stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let res = match &mut input.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        match sael3_input.iter_mut().last() {
                            Some(qitem) =>
                                <Self as Mutator<QItem, S>>::mutate(self, state, qitem, stage_idx),
                            None => Ok(MutationResult::Skipped)
                        }
                    }
                    ShannonInput::NasotInput(nasot_input) => {
                        match nasot_input.iter_mut().last() {
                            Some(event) => 
                                <Self as Mutator<SmpfEventPaylod, S>>::mutate(self, state, event.payload_mut(), stage_idx),
                            None => Ok(MutationResult::Skipped)
                        }
                    }
                }
            }
        };
        res
    }
}

impl<'a, GG, G, S> Mutator<QItem, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(
        &mut self,
        state: &mut S,
        input: &mut QItem,
        stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let indices = input.find_all_grammar_inputs();
        let len = indices.len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let index = indices[choice];
        match input.grammar_input_at_mut(index) {
            Some(i) =>
                <Self as Mutator<GG::GrammarInput, S>>::mutate(self, state, i, stage_idx),
            None => unreachable!("no grammar input at specified index!"),
        }
    }
}

impl<'a, GG, G, S> Mutator<SmpfEventPaylod, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(
            &mut self,
            state: &mut S,
            input: &mut SmpfEventPaylod,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
        match input {
            SmpfEventPaylod::GrammarInput(grammar_input) => 
                <Self as Mutator<GG::GrammarInput, S>>::mutate(self, state, grammar_input, stage_idx),
            _ => unreachable!("no grammar input at specified index!")
        }
    }
}

impl<'a, GG, G, S> Mutator<TransitionInput, S> for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut TransitionInput, stage_idx: i32) -> Result<MutationResult, Error> {
        <Self as Mutator<LorisInput, S>>::mutate(self, state, &mut input.loris_input, stage_idx)
    }
}

impl<'a, GG, G, S> Named for GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S>,
    G: LorisGrammar,
    S: HasRand,
{
    fn name(&self) -> &str {
        "GrammarRandomMutatorLast"
    }
}

impl<'a, GG, G, S> GrammarRandomMutatorLast<'a, GG, G, S>
where
    GG: LorisGrammarGenerator<'a, G, S, GrammarInput=FastGrammarInput>,
    G: LorisGrammar,
    S: HasRand,
{
    #[must_use]
    pub fn new(generator: &'a LorisGenerator<'a, GG, G, S>) -> Self {
        Self { generator }
    }

    pub fn try_mutate(
        &mut self,
        state: &mut S,
        input: &mut LorisInput,
    ) -> MutationResult {
        self.mutate(state, input, 0).unwrap()
    }
}

pub struct LorisSpliceMutator;

/*
impl<S> Mutator<QItem, S> for LorisSpliceMutator
where
    S: HasRand + HasCorpus<Input=TransitionInput> + HasMaxSize,
{
    fn mutate(
            &mut self,
            state: &mut S,
            input: &mut QItem,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
            let len = input.payload.len() as u64;
            if len == 0 {
                return Ok(MutationResult::Skipped);
            }
            let choice = state.rand_mut().below(len) as usize;
            let pdu = input.payload.get_mut(choice).unwrap();
            match pdu.field_mut() {
                QItemField::BytesInput(bytes_input) => {
                    match utils::mutator_crossover_insert(state, bytes_input, other) {
                        ture => Ok(MutationResult::Mutated),
                        false => Ok(MutationResult::Skipped)
                    }
                }
                _ => Ok(MutationResult::Skipped)
            }
    }
}

impl<S> Mutator<LorisInput, S> for LorisSpliceMutator
where
    S: HasRand + HasCorpus<Input=TransitionInput>,
{
    fn mutate(
            &mut self,
            state: &mut S,
            input: &mut LorisInput,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
        match &mut input.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        let len = sael3_input.len() as u64;
                        if len == 0 {
                            return Ok(MutationResult::Skipped);
                        }
                        let choice = state.rand_mut().below(len) as usize;
                        let qitem = sael3_input.get_mut(choice).unwrap();
                        <Self as Mutator<QItem, S>>::mutate(self, state, qitem, stage_idx)
                    },
                    ShannonInput::NasotInput(nasot_input) => {
                        unimplemented!("LorisSpliceMutator for {:?}", nasot_input)
                    },
                }
            }
        }
    }
}
*/

impl<S> Mutator<TransitionInput, S> for LorisSpliceMutator
where
    S: HasRand + HasCorpus<Input=TransitionInput>,
{
    fn mutate(&mut self, state: &mut S, input: &mut TransitionInput, stage_idx: i32) -> Result<MutationResult, Error> {
        let grammar_input = input.last_grammar_mut(state);
        let idx = random_corpus_id!(state.corpus(), state.rand_mut());
        let mut other = state.corpus().cloned_input_for_id(idx)?;
        let other_grammar_input = other.last_grammar(state);
        match (grammar_input, other_grammar_input) {
            (Some(g), Some(other_g)) => {
                let len = g.fields().len();
                if len == 0 || other_g.len() == 0 {
                    return Ok(MutationResult::Skipped);
                }
                let insert_at = state.rand_mut().below(len as u64) as usize;
                let idx = g.fields()[insert_at].state();
                let other_idx = other_g.fields()
                    .iter()
                    .enumerate()
                    .find_map(|(i, f)| (f.state() == idx).then_some(i));
                if let Some(other_idx) = other_idx {
                    g.fields_mut().truncate(insert_at);
                    g.fields_mut().extend_from_slice(&other_g.fields()[other_idx..]);
                    return Ok(MutationResult::Mutated);
                }
                Ok(MutationResult::Skipped)
            },
            // _ => <Self as Mutator<LorisInput, S>>::mutate(self, state, &mut input.loris_input, stage_idx),
            _ => Ok(MutationResult::Skipped),
        }
    }
}

impl Named for LorisSpliceMutator {
    fn name(&self) -> &str {
        "LorisSpliceMutator"
    }
}

impl LorisSpliceMutator {
    #[must_use]
    pub fn new() -> Self {
        Self {}
    }
}

pub struct LorisHavocMutator<S> {
    phantom: PhantomData<S>
}

impl<S> Mutator<BytesInput, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
        &mut self, state: &mut S, input: &mut BytesInput, stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let mut mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations_no_crossover(), 6);
        mutator.mutate(state, input, stage_idx)
    }
}

impl<S> Mutator<BaseGrammarInput, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
        &mut self, state: &mut S, input: &mut BaseGrammarInput, stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let len = input.fields.len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let field = input.fields.get_mut(choice).unwrap();
        let mut mutator = StdScheduledMutator::with_max_stack_pow(havoc_mutations_no_crossover(), 1);
        let mut bytes = BytesInput::from(field.string.clone());
        match mutator.mutate(state, &mut bytes, stage_idx)? {
            MutationResult::Mutated => {
                let bytes = bytes.bytes().to_vec();
                input.replace_by_index(bytes, choice);
                input.fields[choice].dirty = true;
                Ok(MutationResult::Mutated)
            }
            MutationResult::Skipped => Ok(MutationResult::Skipped)
        }
    }
}

impl<S> Mutator<FastGrammarInput, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(&mut self, state: &mut S, input: &mut FastGrammarInput, stage_idx: i32) -> Result<MutationResult, Error> {
        let len = input.fields().len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let mut bytes = BytesInput::from(input.fields()[choice].string().clone());
        let mut mutator = StdScheduledMutator::with_max_stack_pow(tuple_list!(ByteFlipMutator::new()), 1);
        match mutator.mutate(state, &mut bytes, stage_idx)? {
            MutationResult::Mutated => {
                *input.fields_mut()[choice].string_mut() = bytes.bytes().to_vec();
                Ok(MutationResult::Mutated)
            }
            MutationResult::Skipped => Ok(MutationResult::Skipped),
        }
    }
}

impl<S> Mutator<QItem, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
        &mut self, state: &mut S, input: &mut QItem, stage_idx: i32
    ) -> Result<MutationResult, Error> {
        let len = input.payload.len() as u64;
        if len == 0 {
            return Ok(MutationResult::Skipped);
        }
        let choice = state.rand_mut().below(len) as usize;
        let pdu = input.payload.get_mut(choice).unwrap();
        match pdu.field_mut() {
            QItemField::BytesInput(bytes_input) => {
                <Self as Mutator<BytesInput, S>>::mutate(self, state, bytes_input, stage_idx)
            }
            QItemField::GrammarInput(grammar_input) => {
                <Self as Mutator<FastGrammarInput, S>>::mutate(self, state, grammar_input, stage_idx)
            }
        }
    }
}

impl<S> Mutator<SmpfEventPaylod, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
            &mut self,
            state: &mut S,
            input: &mut SmpfEventPaylod,
            stage_idx: i32,
        ) -> Result<MutationResult, Error> {
        match input {
            SmpfEventPaylod::BytesInput(bytes_input) => {
                <Self as Mutator<BytesInput, S>>::mutate(self, state, bytes_input, stage_idx)
            }
            SmpfEventPaylod::GrammarInput(grammar_input) => {
                <Self as Mutator<FastGrammarInput, S>>::mutate(self, state, grammar_input, stage_idx)
            }
        }
    }
}

impl<S> Mutator<LorisInput, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
        &mut self, state: &mut S, input: &mut LorisInput, stage_idx: i32
    ) -> Result<MutationResult, Error> {
        match &mut input.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        let len = sael3_input.len() as u64;
                        if len == 0 {
                            return Ok(MutationResult::Skipped);
                        }
                        let choice = state.rand_mut().below(len) as usize;
                        let qitem = sael3_input.get_mut(choice).unwrap();
                        <Self as Mutator<QItem, S>>::mutate(self, state, qitem, stage_idx)
                    },
                    ShannonInput::NasotInput(nasot_input) => {
                        let len = nasot_input.len() as u64;
                        if len == 0 {
                            return Ok(MutationResult::Skipped);
                        }
                        let choice = state.rand_mut().below(len) as usize;
                        let event = nasot_input.get_mut(choice).unwrap();
                        <Self as Mutator<SmpfEventPaylod, S>>::mutate(self, state, event.payload_mut(), stage_idx)
                    },
                }
            }
        }
    }
}

impl<S> Mutator<TransitionInput, S> for LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    fn mutate(
        &mut self, state: &mut S, input: &mut TransitionInput, stage_idx: i32
    ) -> Result<MutationResult, Error> {
        <Self as Mutator<LorisInput, S>>::mutate(self, state, &mut input.loris_input, stage_idx)
    }
}

impl<S> Named for LorisHavocMutator<S> {
    fn name(&self) -> &str {
        "LorisRandomMutator"
    }
}
impl<S> LorisHavocMutator<S>
where
    S: HasCorpus + HasRand + HasMaxSize,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    pub fn try_mutate(
        &mut self,
        state: &mut S,
        input: &mut LorisInput,
    ) -> MutationResult {
        self.mutate(state, input, 0).unwrap()
    }
}
