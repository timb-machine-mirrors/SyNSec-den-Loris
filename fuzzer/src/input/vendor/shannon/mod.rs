pub mod qitem;
pub mod smpf;

use libafl::inputs::Input;
use serde_derive::{Deserialize, Serialize};

use crate::input::vendor::shannon::{
    qitem::QItem,
    smpf::SmpfEvent,
};

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum ShannonInput {
    Sael3Input(Vec<QItem>),
    NasotInput(Vec<SmpfEvent>),
}

impl Input for ShannonInput {
    fn generate_name(&self, idx: usize) -> String {
        idx.to_string().to_owned()
    }
}
