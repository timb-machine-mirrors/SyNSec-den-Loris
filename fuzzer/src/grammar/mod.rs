pub mod automaton;
pub mod attribute;
pub mod base;
pub mod expression;
pub mod fast;
pub mod fast2;
pub mod parser;
pub mod rule;
mod utils;
mod validator;
pub mod worklist;

use std::{
    fmt::Debug,
    path::Path,
};

pub trait LorisGrammar: Clone + Debug {
    type Rule;

    /// Create this grammar from a file
    fn from_file(path: &Path, start: String) -> Result<Self, String>;
    /// Get start symbol
    fn start(&self) -> &Self::Rule;
    /// Get start symbol (mutable)
    fn start_mut(&mut self) -> &mut Self::Rule;
    /// Get a rule by `name`
    fn get(&self, name: &str) -> Option<&Self::Rule>;
    /// Get a rule by `name` (mutable)
    fn get_mut(&mut self, name: &str) -> Option<&mut Self::Rule>;
}
