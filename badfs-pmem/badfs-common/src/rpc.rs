use crate::metadata::metadata::Metadata;
use ibverbs::{QueuePairEndpoint, RemoteKey, RemoteMemoryBlockAddress};
use serde::{Deserialize, Serialize};

pub enum RPCError {
    Internal,
}

pub type Result<U> = std::result::Result<U, RPCError>;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Blob {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

impl Blob {
    pub fn new(vec: Vec<u8>) -> Self {
        Blob { data: vec }
    }

    pub fn compare(self: &Self, other: &Self) -> bool {
        self.data.iter().zip(other.data.iter()).all(|(l, r)| l == r)
    }

    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.data.len() == 0
    }
}

impl Into<Vec<u8>> for Blob {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

impl From<Vec<u8>> for Blob {
    fn from(data: Vec<u8>) -> Self {
        Blob { data }
    }
}

#[tarpc::service]
pub trait BadfsService {
    async fn create_metadata(path: String, metadata: Metadata) -> ();
    async fn read_metadata(path: String) -> Option<Metadata>;
    async fn update_file_metadata_size(path: String, new_file_size: usize) -> ();
    async fn remove_metadata(path: String) -> ();
    // rdma handshake
    async fn handshake(endpoint: QueuePairEndpoint) -> (usize, QueuePairEndpoint);
    // actual size that we can write
    async fn read_file_block(
        path: String,
        offset: usize,
        length: usize,
    ) -> (usize, Vec<(RemoteKey, RemoteMemoryBlockAddress)>);
    async fn write_file_block(
        path: String,
        offset: usize,
        length: usize,
    ) -> Vec<(RemoteKey, RemoteMemoryBlockAddress)>;
    async fn remove_file_block(path: String) -> ();
    async fn read_dirents(father_path: String) -> Blob;
}
