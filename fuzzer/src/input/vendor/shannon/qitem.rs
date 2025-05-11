use libafl::{
    inputs::{BytesInput, Input},
    state::HasRand,
};
use libafl_bolts::{
    HasLen,
    rands::Rand,
};
use serde_derive::{Deserialize, Serialize};

use crate::input::grammar::{FastGrammarInput, HasGrammarInput};

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum QItemOperand {
    Op(u32),
    MBox {
        src_qid: u16,
        dst_qid: u16,
    },
    MBoxName {
        op1: String,
        op2: String,
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum QItemField {
    BytesInput(BytesInput),
    GrammarInput(FastGrammarInput),
}

impl QItemField {
    fn len(&self) -> usize {
        match self {
            QItemField::BytesInput(input) => input.len(),
            QItemField::GrammarInput(input) => input.len(),
        }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum QItemPDU {
    Array(QItemField),
    IndirU32(QItemField),
}

impl QItemPDU {
    //! the list of `*_from_*` functions are defined to avoid long names of nesting QItemPDU and
    //! QItemField to create each instance. May be removed later.
    pub fn array_from_vec(input: Vec<u8>) -> Self {
        Self::Array(QItemField::BytesInput(BytesInput::from(input)))
    }

    pub fn array_from_file(path: &str) -> Self {
        let input = BytesInput::from_file(path).expect("");
        Self::Array(QItemField::BytesInput(input))
    }

    pub fn array_from_grammar(input: FastGrammarInput) -> Self {
        Self::Array(QItemField::GrammarInput(input))
    }

    pub fn indir_u32_from(input: Vec<u8>) -> Self {
        Self::IndirU32(QItemField::BytesInput(BytesInput::from(input)))
    }

    pub fn indir_u32_from_file(path: &str) -> Self {
        let input = BytesInput::from_file(path).expect("");
        Self::IndirU32(QItemField::BytesInput(input))
    }

    pub fn indir_u32_from_grammar(input: FastGrammarInput) -> Self {
        Self::IndirU32(QItemField::GrammarInput(input))
    }

    pub fn field(&self) -> &QItemField {
        match self {
            Self::Array(a) => a,
            Self::IndirU32(i) => i,
        }
    }

    pub fn field_mut(&mut self) -> &mut QItemField {
        match self {
            Self::Array(a) => a,
            Self::IndirU32(i) => i,
        }
    }

    fn len(&self) -> u16 {
        // TODO: check for len overflow
        match *self {
            Self::Array(ref array) => array.len() as u16,
            Self::IndirU32(_) => 4 + 4,  // 32-bit size and 32-bit address size
        }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QItemHeader {
    pub op: QItemOperand,
    pub size: u16,
    pub message_group: u16,
}

impl QItemHeader {
    pub fn new(op: QItemOperand, size: u16, message_group: u16) -> Self {
        return Self { op, size, message_group }
    }
}

type QItemPayload = Vec<QItemPDU>;

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct QItem {
    pub header: QItemHeader,
    pub payload: QItemPayload,
}

impl<S> HasGrammarInput<FastGrammarInput, S> for QItem
where
    S: HasRand,
{
    fn last_grammar(&self, state: &mut S) -> Option<&FastGrammarInput> {
        let indices = self.find_all_grammar_inputs();
        let len = indices.len();
        if len == 0 {
            return None;
        }
        let choice = state.rand_mut().below(len as u64) as usize;
        let index = indices[choice];
        self.grammar_input_at(index)
    }

    fn last_grammar_mut(&mut self, state: &mut S) -> Option<&mut FastGrammarInput> {
        let indices = self.find_all_grammar_inputs();
        let len = indices.len();
        if len == 0 {
            return None;
        }
        let choice = state.rand_mut().below(len as u64) as usize;
        let index = indices[choice];
        self.grammar_input_at_mut(index)
    }
}

impl QItem {
    pub fn from_qid(src_qid: u16, dst_qid: u16, message_group: u16) -> Self {
        use QItemOperand::*;
        Self {
            header: QItemHeader::new(MBox { src_qid, dst_qid }, 0, message_group),
            payload: vec![],
        }
    }

    pub fn grammar_inputs_mut(&mut self) -> Vec<&mut FastGrammarInput> {
        self.payload.iter_mut().filter_map(|pdu| {
            match pdu.field_mut() {
                QItemField::GrammarInput(f) => Some(f),
                _ => None,
            }
        }).collect()
    }

    pub fn grammar_input_at(&self, index: usize) -> Option<&FastGrammarInput> {
        match self.payload[index].field() {
            QItemField::BytesInput(_) => None,
            QItemField::GrammarInput(i) => Some(i),
        }
    }

    pub fn grammar_input_at_mut(&mut self, index: usize) -> Option<&mut FastGrammarInput> {
        match self.payload[index].field_mut() {
            QItemField::BytesInput(_) => None,
            QItemField::GrammarInput(i) => Some(i),
        }
    }

    pub fn find_all_grammar_inputs(&self) -> Vec<usize> {
        self.payload.iter()
            .enumerate()
            .filter(|(_, p)| matches!(p.field(), QItemField::GrammarInput(_)))
            .map(|(i, _)| i)
            .collect()
    }

    pub fn push_payload_field(&mut self, field: QItemPDU) {
        self.header.size += field.len();
        self.payload.push(field);
    }
}


