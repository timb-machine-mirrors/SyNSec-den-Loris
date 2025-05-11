use serde::{Deserialize, Serialize};

/// The length of header bytes which tells shmem size
const SHMEM_FUZZ_HDR_SIZE: usize = 4;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShMemInfo {
    /// Size of the map used for metadata
    pub header_size: usize,
    /// Size of this map to store data
    pub size: usize,
    /// Environment variable to store shmem id
    pub env_name: String,
}

impl ShMemInfo {
    #[must_use]
    pub fn new(env_name: &'static str, size: usize) -> Self {
        Self {
            header_size: SHMEM_FUZZ_HDR_SIZE,
            size: size.saturating_sub(SHMEM_FUZZ_HDR_SIZE),
            env_name: env_name.to_string(),
        }
    }

    pub fn data_size(&self) -> usize {
        self.size - self.header_size
    }
}
