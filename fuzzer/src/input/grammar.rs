use serde_derive::{Deserialize, Serialize};
use std::{
    ascii::escape_default,
    collections::VecDeque
};
use libafl::{
    inputs::HasTargetBytes,
    state::HasRand,
};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::input::{
    field::{FastGrammarField, GrammarField, GrammarString},
    rule::RulePath,
};

pub trait HasGrammarInput<GI, S>
where
    S: HasRand,
{
    fn last_grammar(&self, state: &mut S) -> Option<&GI>;
    fn last_grammar_mut(&mut self, state: &mut S) -> Option<&mut GI>;
}

pub static SERIALIZE_GRAMMAR_FIELDS: AtomicBool = AtomicBool::new(true);

fn dont_serialize_fields<T>(_: &T) -> bool {
    !SERIALIZE_GRAMMAR_FIELDS.load(Ordering::Acquire)
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct BaseGrammarInput {
    #[serde(skip_serializing_if = "dont_serialize_fields")]
    pub fields: VecDeque<GrammarField>,
    pub string: Vec<u8>,
}

impl HasLen for BaseGrammarInput {
    fn len(&self) -> usize {
        self.string.len()
    }
}

impl HasTargetBytes for BaseGrammarInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(&self.string)
    }
}

impl BaseGrammarInput {
    #[must_use]
    pub fn new() -> Self {
        Self {
            fields: VecDeque::new(),
            string: Vec::new(),
        }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.string.clone()
    }

    pub fn append(&mut self, value: &mut BaseGrammarInput) -> Self {
        self.fields.append(&mut value.fields);
        self.string.append(&mut value.string);
        self.to_owned()
    }

    pub fn push_back(&mut self, field: &mut GrammarField) {
        self.string.extend(field.string.iter());
        if self.fields.len() > 0 && self.fields.back().unwrap().path == field.path {
            let back_field = self.fields.back_mut().unwrap();
            back_field.string.append(&mut field.string);
            back_field.mutable |= field.mutable;
        } else {
            self.fields.push_back(field.to_owned());
        }
    }

    pub fn try_reduce_fields(&mut self, path: &RulePath) {
        self.reduce_fields(path, false);
    }

    pub fn reduce_fields_forced(&mut self, path: &RulePath) {
        self.reduce_fields(path, true);
    }

    fn reduce_fields(&mut self, path: &RulePath, force: bool) {
        if !force && !self.any_mutable_string() && self.any_mutable() {
            return;
        }
        let mut new_fields = VecDeque::new();
        while let Some(mut field) = self.fields.pop_front() {
            if !field.path.starts_with(path) {
                new_fields.push_back(field);
                continue;
            }
            let mut reduced_field = GrammarField::new(path.clone(), vec![], field.index_in_seq, false);
            reduced_field.append(&mut field);
            reduced_field.mutable |= field.mutable;
            while let Some(field) = self.fields.front() {
                if !field.path.starts_with(path) {
                    break;
                }
                let mut field = self.fields.pop_front().unwrap();
                reduced_field.append(&mut field);
                reduced_field.mutable |= field.mutable;
            }
            reduced_field.mutable |= force;
            new_fields.push_back(reduced_field);
        }
        self.fields.append(&mut new_fields);
    }

    pub fn print_fields(&self) {
        println!("[");
        for f in &self.fields {
            println!("    {f}");
        }
        println!("]");
    }

    pub fn any_mutable_string(&self) -> bool {
        for field in self.fields.iter() {
            if field.path.get_symbol() == "string" && field.mutable {
                return true;
            }
        }
        return false;
    }

    pub fn any_mutable(&self) -> bool {
        for field in self.fields.iter() {
            if field.mutable {
                return true;
            }
        }
        return false;
    }

    pub fn find_all_mutable_fields(&self) -> Vec<usize> {
        self.fields.iter()
            .enumerate()
            .filter(|(_, f)| f.mutable && !f.dirty)
            .map(|(i, _)| i)
            .collect()
    }

    pub fn replace_by_index(&mut self, string: GrammarString, index: usize) -> Option<GrammarString> {
        if index >= self.fields.len() {
            return None;
        }
        let old_string = self.fields[index].get_string();
        self.fields[index].set_string(string);
        self.update_string();
        Some(old_string)
    }

    pub fn update_string(&mut self) {
        self.string.clear();
        for f in &self.fields {
            self.string.extend(f.string.iter());
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FastGrammarInput {
    fields: Vec<FastGrammarField>,
    string: GrammarString,
}

impl Default for FastGrammarInput {
    fn default() -> Self {
        Self {
            fields: Vec::new(),
            string: GrammarString::default(),
        }
    }
}

impl HasLen for FastGrammarInput {
    fn len(&self) -> usize {
        self.to_vec().len()
    }
}

impl HasTargetBytes for FastGrammarInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.to_vec())
    }
}

impl FastGrammarInput {
    /// Creates a [`FastGrammarInput`]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The ref to the slice of the input fields
    pub fn fields(&self) -> &[FastGrammarField] {
        self.fields.as_slice()
    }

    /// The ref to the vector of the input fields (mutable)
    pub fn fields_mut(&mut self) -> &mut Vec<FastGrammarField> {
        &mut self.fields
    }

    /// The ref to the string of input
    pub fn string(&self) -> &GrammarString {
        self.string.as_ref()
    }

    /// Adds the `field` at end of input fields vector
    pub fn push_back(&mut self, field: FastGrammarField) {
        self.fields.push(field);
    }

    /// Converts the [`FastGrammarInput`] to a vector of bytes
    pub fn to_vec(&self) -> GrammarString {
        self.fields.iter()
            .map(|f| f.string().to_owned())
            .flatten()
            .collect()
    }
}

pub fn show_buf<B>(buf: B) -> String
    where
        B: AsRef<[u8]>,
{
    String::from_utf8(
        buf.as_ref()
            .iter()
            .map(|b| escape_default(*b))
            .flatten()
            .collect(),
    ).unwrap()
}
