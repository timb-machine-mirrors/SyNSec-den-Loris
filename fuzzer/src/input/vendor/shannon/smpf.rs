use libafl::{
    inputs::BytesInput,
    state::HasRand,
};
use serde_derive::{Deserialize, Serialize};

use crate::input::grammar::{FastGrammarInput, HasGrammarInput};

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum SmpfEventPaylod {
    BytesInput(BytesInput),
    GrammarInput(FastGrammarInput),
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SmpfEventHeader {
    pub msg_id: u32,
    pub obj_id: u32,
    pub domain_s: u8,
    pub domain_d: u8,
    pub routing: u32,
}

impl SmpfEventHeader {
    #[must_use]
    pub fn new(msg_id: u32, obj_id: u32) -> Self {
        Self {
            msg_id,
            obj_id,
            domain_s: 0x40,
            domain_d: 0,
            routing: 0x80,
        }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct SmpfEvent {
    pub header: SmpfEventHeader,
    payload: SmpfEventPaylod,
}

impl<S> HasGrammarInput<FastGrammarInput, S> for SmpfEvent
where
    S: HasRand,
{
    fn last_grammar(&self, _: &mut S) -> Option<&FastGrammarInput> {
        self.grammar_input()
    }

    fn last_grammar_mut(&mut self, _: &mut S) -> Option<&mut FastGrammarInput> {
        self.grammar_input_mut()
    }
}

impl SmpfEvent {
    pub fn new(msg_id: u32, obj_id: u32, payload: SmpfEventPaylod) -> Self {
        Self {
            header: SmpfEventHeader::new(msg_id, obj_id),
            payload,
        }
    }
    pub fn payload_mut(&mut self) -> &mut SmpfEventPaylod {
        &mut self.payload
    }

    pub fn grammar_input(&self) -> Option<&FastGrammarInput> {
        match &self.payload {
            SmpfEventPaylod::BytesInput(_) => None,
            SmpfEventPaylod::GrammarInput(i) => Some(i),
        }
    }

    pub fn grammar_input_mut(&mut self) -> Option<&mut FastGrammarInput> {
        match &mut self.payload {
            SmpfEventPaylod::BytesInput(_) => None,
            SmpfEventPaylod::GrammarInput(i) => Some(i),
        }
    }
}
