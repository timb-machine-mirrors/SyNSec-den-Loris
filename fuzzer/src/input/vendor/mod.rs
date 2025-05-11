pub mod shannon;

use libafl::inputs::Input;
use serde_derive::{Deserialize, Serialize};

use crate::input::vendor::shannon::ShannonInput;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum VendorInput {
    ShannonInput(ShannonInput),
}

impl Input for VendorInput {
    fn generate_name(&self, idx: usize) -> String {
        match self {
            VendorInput::ShannonInput(input) => input.generate_name(idx),
        }
    }
}
