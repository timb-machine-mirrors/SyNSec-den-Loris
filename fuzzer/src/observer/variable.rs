use byteorder::{LittleEndian, ReadBytesExt};
use core::fmt::Debug;
use std::usize;
use libafl::{
    Error,
    executors::ExitKind,
    inputs::{HasTargetBytes, UsesInput},
    observers::Observer
};
use libafl_bolts::{
    AsMutSlice,
    shmem::{ShMem, ShMemProvider, UnixShMemProvider},
    Named,
};
use serde::{Deserialize, Serialize};

use crate::input::transition::TransitionInput;
use crate::observer::{shmem::ShMemInfo, utils};

const SHMEM_FUZZ_HDR_SIZE: usize = 8;
const VAR_MAP_SIZE: usize = 10 * 1024;

/// An observer collecting variables from target memory
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(bound = "V: serde::de::DeserializeOwned")]
pub struct VariableObserver<SP, V>
where
    SP: ShMemProvider,
    V: Debug + Serialize,
{
    /// The name of this observer
    name: String,
    /// The shared memory to store pre-condition variables
    #[serde(skip)]
    pre_cond_shmem: Option<SP::ShMem>,
    /// The description of `pre_cond_shmem`
    pre_cond_shmem_info: ShMemInfo,
    /// The variables to observe after execution
    variables: Option<V>,
    /// The shared memory used to observe `variables`
    #[serde(skip)]
    shmem: Option<SP::ShMem>,
    /// The description of `shmem`
    shmem_info: ShMemInfo,
}

impl<SP, V> VariableObserver<SP, V>
where
    SP: ShMemProvider,
    V: Debug + HasTargetBytes + Serialize + serde::de::DeserializeOwned,
{
    pub fn variables(&self) -> Option<&V> {
        self.variables.as_ref()
    }

    pub fn set_variables(&mut self, vars: V) {
        self.variables = Some(vars);
    }
}

impl<V> VariableObserver<UnixShMemProvider, V>
where
    V: Debug + Serialize,
{
    #[must_use]
    pub fn builder() -> VariableObserverBuilder<'static, UnixShMemProvider> {
        VariableObserverBuilder::new()
    }
}

impl<'a, S, V> Observer<S> for VariableObserver<UnixShMemProvider, V>
where
    S: UsesInput<Input = TransitionInput>,
    V: Debug + HasTargetBytes + Serialize + serde::de::DeserializeOwned + From<Vec<u8>>,
{
    fn pre_exec(&mut self, _state: &mut S, input: &S::Input) -> Result<(), Error> {
        let map = unsafe { self.pre_cond_shmem.as_mut().unwrap_unchecked() };
        utils::init_map(map.as_mut_slice(), &self.pre_cond_shmem_info, &input.pre_cond_vars)?;

        let map = unsafe { self.shmem.as_mut().unwrap_unchecked() };
        utils::init_map(map.as_mut_slice(), &self.shmem_info, &input.variables)?;

        Ok(())
    }

    fn post_exec(&mut self, _state: &mut S, _input: &S::Input, _exit_kind: &ExitKind) -> Result<(), Error> {
        let map = unsafe { self.shmem.as_mut().unwrap_unchecked() };
        let map = map.as_mut_slice();
        let header_size = self.shmem_info.header_size;
        let size = (&map[header_size/2..header_size]).read_u32::<LittleEndian>().unwrap() as usize;
        let vars = V::from(map[header_size..(header_size + size)].to_vec());
        self.set_variables(vars);
        Ok(())
    }
}

impl<'a, SP, V> Named for VariableObserver<SP, V>
where
    SP: ShMemProvider,
    V: Debug + HasTargetBytes + Serialize + serde::de::DeserializeOwned + From<Vec<u8>>,
{
    fn name(&self) -> &str {
        &self.name
    }
}

/// The builder for `VariableObserver`
#[derive(Debug)]
pub struct VariableObserverBuilder<'a, SP> {
    shmem_provider: Option<&'a mut SP>
}

impl<'a> VariableObserverBuilder<'a, UnixShMemProvider> {
    #[must_use]
    pub fn new() -> VariableObserverBuilder<'a, UnixShMemProvider> {
        Self {
            shmem_provider: None,
        }
    }

    pub fn build<V>(&mut self, name: &'static str) -> Result<VariableObserver<UnixShMemProvider, V>, String>
    where
        V: Debug + HasTargetBytes + Serialize,
    {
        let (mut pre_cond_shmem, pre_cond_shmem_info, mut shmem, shmem_info) = self.build_helper()?;

        Ok(VariableObserver {
            name: name.to_string(),
            pre_cond_shmem,
            pre_cond_shmem_info,
            variables: None,
            shmem,
            shmem_info,
        })
    }
}

impl<'a, SP> VariableObserverBuilder<'a, SP> {
    fn build_helper(&mut self) -> Result<(Option<SP::ShMem>, ShMemInfo, Option<SP::ShMem>, ShMemInfo), String>
    where
        SP: ShMemProvider,
    {
        match &mut self.shmem_provider {
            None => {
                return Err(format!(""));
            },
            Some(provider) => {
                let pre_cond_shmem_info = ShMemInfo::new("__LORIS_SHM_PRE_ID", VAR_MAP_SIZE + SHMEM_FUZZ_HDR_SIZE);
                let mut pre_cond_shmem = provider.new_shmem(pre_cond_shmem_info.size).unwrap();
                pre_cond_shmem.write_to_env(pre_cond_shmem_info.env_name.as_str()).unwrap();

                let post_mem_shmem_info = ShMemInfo::new("__LORIS_SHM_VARS_ID", VAR_MAP_SIZE + SHMEM_FUZZ_HDR_SIZE);
                let mut post_mem_shmem = provider.new_shmem(post_mem_shmem_info.size).unwrap();
                post_mem_shmem.write_to_env(post_mem_shmem_info.env_name.as_str()).unwrap();

                Ok((Some(pre_cond_shmem), pre_cond_shmem_info, Some(post_mem_shmem), post_mem_shmem_info))
            }
        }
    }

    pub fn shmem_provider(self, shmem_provider: &'a mut SP) -> Self
    where
        SP: ShMemProvider,
    {
        Self {
            shmem_provider: Some(shmem_provider),
        }
    }
}
