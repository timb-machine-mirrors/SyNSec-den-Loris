use bincode::Options;
use libafl::inputs::HasTargetBytes;
use libafl_bolts::ownedref::OwnedSlice;
use serde_derive::{Deserialize, Serialize};

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct StateVarDesc {
    addr: u32,
    size: u32,
}

impl StateVarDesc {
    #[must_use]
    pub fn new(addr: u32, size: u32) -> Self {
        Self { addr, size }
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct StateValueDesc {
    addr: u32,
    size: u32,
    value: u32,
}

impl StateValueDesc {
    #[must_use]
    pub fn new(addr: u32, size: u32, value: u32) -> Self {
        Self { addr, size, value }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateValueDiff {
    expected: StateValueDesc,
    observed: StateValueDesc,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StateValueDiffList {
    diffs: Vec<StateValueDiff>
}

libafl_bolts::impl_serdeany!(StateValueDiffList);

impl StateValueDiffList {
    pub fn new() -> Self {
        Self {
            diffs: vec![],
        }
    }

    pub fn set(&mut self, diffs: Vec<StateValueDiff>) {
        self.diffs = diffs;
    }

    pub fn any(&self) -> bool {
        self.diffs.len() > 0
    }
}

#[repr(C)]
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum StateDescList {
    Observe(Vec<StateValueDesc>),
    Ensure(Vec<StateValueDesc>),
}

impl HasTargetBytes for StateDescList {
    fn target_bytes(&self) -> OwnedSlice<u8> {
        OwnedSlice::from(self.to_vec())
    }
}

impl StateDescList {
    pub fn to_vec(&self) -> Vec<u8> {
        let ser_ops = bincode::DefaultOptions::new();
        let input = ser_ops.with_fixint_encoding().serialize(self).unwrap();
        input
    }

    pub fn from_vec(value: Vec<u8>) -> Self {
        // TODO: validate length
        let ser_ops = bincode::DefaultOptions::new();
        ser_ops.with_fixint_encoding().deserialize(&value[..]).unwrap()
    }

    pub fn diff(&self, other: &Self) -> StateValueDiffList {
        let diffs = match (self, other) {
            (StateDescList::Observe(a), StateDescList::Observe(b)) => {
                a.iter().zip(b)
                    .filter(|&(e, o)| e != o)
                    .map(|(e, o)| StateValueDiff{expected: e.clone(), observed: o.clone()})
                    .collect()
            }
            (a, b) => unimplemented!("diffing {:?} and {:?}", a, b)
        };
        let mut l = StateValueDiffList::new();
        l.set(diffs);
        l
    }
}

impl From<Vec<u8>> for StateDescList {
    fn from(value: Vec<u8>) -> Self {
        StateDescList::from_vec(value)
    }
}
