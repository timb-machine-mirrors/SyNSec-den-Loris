pub mod utils;
pub mod shmem;
pub mod variable;

use libafl::{
    Error,
    executors::ExitKind,
    inputs::UsesInput,
    observers::{
        map::MapObserver,
        Observer,
        StdMapObserver,
    },
};
use libafl_bolts::{
    AsIter,
    AsIterMut,
    AsMutSlice,
    HasLen,
    Named,
};
use serde::{Deserialize, Serialize};

use crate::{
    input::state::StateDescList,
    observer::shmem::ShMemInfo,
};

/// Map observer with state ?
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(bound = "M: serde::de::DeserializeOwned")]
pub struct MemoryObserver<M>
where
    M: Serialize,
{
    base: M,
}

impl<S, M> Observer<S> for MemoryObserver<M>
where
    M: MapObserver<Entry = u8> + Observer<S> + AsMutSlice<Entry = u8>,
    S: UsesInput,
{
    #[inline]
    fn pre_exec(&mut self, state: &mut S, input: &S::Input) -> Result<(), Error> {
        self.base.pre_exec(state, input)
    }

    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    fn post_exec(&mut self, state: &mut S, input: &S::Input, exit_kind: &ExitKind) -> Result<(), Error> {
        self.base.post_exec(state, input, exit_kind)
    }
}

impl<M> Named for MemoryObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned,
{
    #[inline]
    fn name(&self) -> &str {
        self.base.name()
    }
}

impl<M> MapObserver for MemoryObserver<M>
where
    M: MapObserver<Entry = u8>,
{
    type Entry = u8;

    #[inline]
    fn get(&self, idx: usize) -> &u8 {
        self.base.get(idx)
    }

    #[inline]
    fn get_mut(&mut self, idx: usize) -> &mut u8 {
        self.base.get_mut(idx)
    }

    #[inline]
    fn usable_count(&self) -> usize {
        self.base.usable_count()
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        self.base.count_bytes()
    }

    fn hash(&self) -> u64 {
        self.base.hash()
    }

    #[inline]
    fn initial(&self) -> Self::Entry {
        self.base.initial()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        self.base.reset_map()
    }
    fn to_vec(&self) -> Vec<u8> {
        self.base.to_vec()
    }

    fn how_many_set(&self, indexes: &[usize]) -> usize {
        self.base.how_many_set(indexes)
    }
}

impl<M> HasLen for MemoryObserver<M>
where
    M: MapObserver,
{
    #[inline]
    fn len(&self) -> usize {
        self.base.len()
    }
}

impl<'a> MemoryObserver<StdMapObserver<'a, u8, false>>
{
    pub unsafe fn new(map: &'a mut [u8], shmem_info: ShMemInfo, observe_list: &StateDescList) -> Result<Self, String> {
        utils::write_to_shmem::<StateDescList>(map, shmem_info, observe_list)?;
        let base = StdMapObserver::new("shared_states", map);
        Ok(Self { base })
    }
}

impl<'it, M> AsIter<'it> for MemoryObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIter<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIter<'it>>::IntoIter;

    fn as_iter(&'it self) -> Self::IntoIter {
        self.base.as_iter()
    }
}

impl<'it, M> AsIterMut<'it> for MemoryObserver<M>
where
    M: Named + Serialize + serde::de::DeserializeOwned + AsIterMut<'it, Item = u8>,
{
    type Item = u8;
    type IntoIter = <M as AsIterMut<'it>>::IntoIter;

    fn as_iter_mut(&'it mut self) -> Self::IntoIter {
        self.base.as_iter_mut()
    }
}