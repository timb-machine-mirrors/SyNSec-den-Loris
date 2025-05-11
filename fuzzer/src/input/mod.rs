pub mod field;
pub mod grammar;
pub mod rule;
pub mod state;
pub mod transition;
pub mod vendor;

use bincode::Options;
use libafl::{
    state::HasRand,
    inputs::{BytesInput, HasTargetBytes, Input},
};
use libafl_bolts::ownedref::OwnedSlice;
use serde_derive::{Deserialize, Serialize};
use libafl_bolts::AsSlice;

use crate::input::{
    grammar::HasGrammarInput,
    vendor::{
        shannon::{
            qitem::{QItemField, QItemPDU},
            smpf::SmpfEventPaylod,
            ShannonInput,
        },
        VendorInput,
    },
};
use crate::input::grammar::FastGrammarInput;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LorisInput {
    pub vendor_input: VendorInput,
}

impl HasTargetBytes for LorisInput {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.to_vec())
    }
}

impl Input for LorisInput {
    fn generate_name(&self, idx: usize) -> String {
        self.vendor_input.generate_name(idx)
    }
}

impl<S> HasGrammarInput<FastGrammarInput, S> for LorisInput
where
    S: HasRand,
{
    fn last_grammar(&self, state: &mut S) -> Option<&FastGrammarInput> {
        match &self.vendor_input {
            VendorInput::ShannonInput(shannon_input) => match shannon_input {
                ShannonInput::Sael3Input(sael3_input) => sael3_input
                    .iter()
                    .last()
                    .map_or(None, |input| input.last_grammar(state)),
                ShannonInput::NasotInput(nasot_input) => nasot_input
                    .iter()
                    .last()
                    .map_or(None, |input| input.last_grammar(state)),
            }
        }
    }

    fn last_grammar_mut(&mut self, state: &mut S) -> Option<&mut FastGrammarInput> {
        match &mut self.vendor_input {
            VendorInput::ShannonInput(shannon_input) => match shannon_input {
                ShannonInput::Sael3Input(sael3_input) => sael3_input
                    .iter_mut()
                    .last()
                    .map_or(None, |input| input.last_grammar_mut(state)),
                ShannonInput::NasotInput(nasot_input) => nasot_input
                    .iter_mut()
                    .last()
                    .map_or(None, |input| input.last_grammar_mut(state)),
            }
        }
    }
}

impl LorisInput {
    pub fn to_vec(&self) -> Vec<u8> {
        let converted = self.convert_grammar();
        let ser_ops = bincode::DefaultOptions::new();
        let input = ser_ops.with_fixint_encoding().serialize(&converted.vendor_input).unwrap();
        let len = input.len() as u32;
        let len = len.to_le_bytes().to_vec();
        [len, input].concat()
    }

    /// Calls `target_bytes` on all grammar fields of a [`LorisInput`]
    pub fn convert_grammar(&self) -> Self {
        let mut copy = self.clone();
        match &mut copy.vendor_input {
            VendorInput::ShannonInput(shannon_input) => {
                match shannon_input {
                    ShannonInput::Sael3Input(sael3_input) => {
                        for qitem in sael3_input.iter_mut() {
                            for pdu  in qitem.payload.iter_mut() {
                                match pdu {
                                    QItemPDU::Array(field) | QItemPDU::IndirU32(field) => {
                                        match field {
                                            QItemField::GrammarInput(grammar_input) => {
                                                let bytes = grammar_input.target_bytes().clone().as_slice().to_vec();
                                                let _ = std::mem::replace(
                                                    field,
                                                    QItemField::BytesInput(BytesInput::from(bytes)));
                                            },
                                            _ => {}
                                        }
                                    }
                                }
                            }
                        }
                    },
                    ShannonInput::NasotInput(nasot_input) => {
                        for event in nasot_input.iter_mut() {
                            match event.payload_mut() {
                                SmpfEventPaylod::GrammarInput(grammar_input) => {
                                    let bytes = grammar_input.target_bytes().clone().as_slice().to_vec();
                                    let _ = std::mem::replace(
                                        event.payload_mut(),
                                        SmpfEventPaylod::BytesInput(BytesInput::from(bytes)));
                                },
                                _ => {},
                            }
                        }
                    },
                }
            }
        };
        copy
    }
}
