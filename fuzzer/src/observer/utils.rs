use libafl::{
    Error,
    inputs::HasTargetBytes
};
use libafl_bolts::AsSlice;

use crate::observer::shmem::ShMemInfo;

pub fn write_to_shmem<T>(map: &mut [u8], info: ShMemInfo, object: &T) -> Result<(), String>
where
    T: HasTargetBytes
{
    let target_bytes = object.target_bytes();
    let mut size = target_bytes.as_slice().len();
    let map_size = info.data_size();
    if size > map_size {
        return Err(format!("the object size ({size}) > map size {map_size}"));
    }
    let size_in_bytes = size.to_ne_bytes();
    // The first four bytes tells the size of the shmem
    map[..info.header_size].copy_from_slice(&size_in_bytes[..info.header_size]);
    map[info.header_size..(info.header_size + size)].copy_from_slice(target_bytes.as_slice());
    Ok(())
}

pub fn init_map<V>(map: &mut [u8], shmem_info: &ShMemInfo, vars: &V) -> Result<(), Error>
where
    V: HasTargetBytes,
{
    let target_bytes = vars.target_bytes();
    let mut data_size = target_bytes.as_slice().len();
    let map_size = shmem_info.data_size();
    if data_size > map_size {
        return Err(Error::unknown("the object size ({size}) > map size {map_size}".to_string()));
    }
    let data_size_in_bytes = data_size.to_ne_bytes();
    let max_size_in_bytes = map_size.to_ne_bytes();
    // The header bytes are used to store the size of the shmem data
    let header_size = shmem_info.header_size;
    map[..header_size/2]
        .copy_from_slice(&max_size_in_bytes[..header_size/2]);
    map[header_size/2..header_size]
        .copy_from_slice(&data_size_in_bytes[..header_size/2]);
    map[header_size..(header_size + data_size)]
        .copy_from_slice(target_bytes.as_slice());
    Ok(())
}
