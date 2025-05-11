use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use libafl::{
    state::HasRand,
    inputs::{HasTargetBytes, Input, UsesInput},
};
use libafl_bolts::{
    Error,
    ownedref::OwnedSlice
};
use serde::{Deserialize, Serialize};

use crate::input::{
    grammar::{FastGrammarInput, HasGrammarInput},
    LorisInput,
    state::StateDescList,
};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransitionInput {
    #[serde(skip)]
    pub name: String,
    #[serde(rename = "pre_cond")]
    pub pre_cond_vars: StateDescList,
    #[serde(rename = "input")]
    pub loris_input: LorisInput,
    #[serde(rename = "post_mem")]
    pub variables: StateDescList,
}

impl HasTargetBytes for TransitionInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        self.loris_input.target_bytes()
    }
}

impl Input for TransitionInput {
    fn to_file<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        if serde_json::to_writer(writer, &self).is_err() {
            let name = &self.name;
            return Err(Error::serialize(format!("{name}")));
        }
        Ok(())
    }

    fn from_file<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>
    {
        let filename = path.as_ref().file_stem().unwrap().to_str().unwrap().to_string();
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut t: TransitionInput = serde_json::from_reader(reader)?;
        t.name = filename;

        Ok(t)
    }

    fn generate_name(&self, _idx: usize) -> String {
        self.name.clone()
    }
}

impl<S> HasGrammarInput<FastGrammarInput, S> for TransitionInput
where
    S: HasRand,
{
    fn last_grammar(&self, state: &mut S) -> Option<&FastGrammarInput> {
        self.loris_input.last_grammar(state)
    }
    fn last_grammar_mut(&mut self, state: &mut S) -> Option<&mut FastGrammarInput> {
        self.loris_input.last_grammar_mut(state)
    }
}