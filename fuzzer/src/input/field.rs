use serde_derive::{Deserialize, Serialize};
use std::fmt::{self, Formatter};

use crate::input::rule::RulePath;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct GrammarField {
    pub path: RulePath,
    pub string: GrammarString,
    pub index_in_seq: usize,
    pub mutable: bool,
    /// if true, the field has been randomly mutated (regardless of the grammar)
    pub dirty: bool,
}

pub type GrammarString = Vec<u8>;

impl fmt::Display for GrammarField {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl GrammarField {
    #[must_use]
    pub fn new(path: RulePath, string: Vec<u8>, index_in_seq: usize, mutable: bool) -> Self {
        Self { path, string, index_in_seq, mutable, dirty: false }
    }

    pub fn append(&mut self, field: &mut Self) {
        self.string.append(&mut field.string);
    }

    pub fn get_string(&self) -> GrammarString {
        self.string.clone()
    }

    pub fn set_string(&mut self, string: GrammarString) {
        self.string = string;
    }
}

/// [`FastGrammarField`] is the grammar field generated following an automaton state rule
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct FastGrammarField {
    /// The automaton state index
    state: usize,
    /// The generated string from the automaton state rule
    string: GrammarString,
    /// If a mutator can mutate this field
    mutable: bool,
}

impl FastGrammarField {
    /// Creates a [`FastGrammarField`]
    #[must_use]
    pub fn new(state: usize, string: GrammarString, mutable: bool) -> Self {
        Self { state, string, mutable }
    }

    /// The ref to the grammar field string
    pub fn string(&self) -> &GrammarString {
        &self.string
    }

    /// The ref to the grammar field string (mutable)
    pub fn string_mut(&mut self) -> &mut GrammarString {
        &mut self.string
    }

    /// The grammar field state
    pub fn state(&self) -> usize {
        self.state
    }

    /// The ref to the grammar field mutability (mutable)
    pub fn mutable_mut(&mut self) -> &mut bool {
        &mut self.mutable
    }
}
