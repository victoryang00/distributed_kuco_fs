use badfs_common::metadata::metadata_storage::{DashMapMetadataStorage, MetadataStorage};
use badfs_common::metadata::metadata_wrapper::RWLockMetadataWrapper;
use std::collections::BTreeMap;

use badfs_common::data::data_storage::{DashMapDataStorage, DataStorage};
use badfs_common::metadata::metadata::Metadata;
use badfs_common::rpc::*;

use ibverbs::{CompletionQueue, Context as RDMAContext, ProtectionDomain, QueuePairEndpoint};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use tarpc::context::Context;

use crate::rdma::ServerSideConnection;
use log::trace;

static CLIENT_ID: AtomicUsize = AtomicUsize::new(0);

struct BadfsServerInner<'server> {
    ctx: &'static RDMAContext,
    pd: &'static ProtectionDomain<'static>,
    cq: &'static CompletionQueue<'static>,
    connection: RwLock<BTreeMap<usize, ServerSideConnection<'server>>>,
    metadata_storage: DashMapMetadataStorage<RWLockMetadataWrapper>,
    data_storage: DashMapDataStorage,
}

impl<'server> BadfsServerInner<'server> {
    pub fn new(
        ctx: &'static RDMAContext,
        pd: &'static ProtectionDomain,
        cq: &'static CompletionQueue,
    ) -> Self {
        BadfsServerInner {
            ctx,
            pd,
            cq,
            connection: Default::default(),
            metadata_storage: DashMapMetadataStorage::new(),
            data_storage: DashMapDataStorage::new(pd),
        }
    }

    pub fn rdma_handshake(&self, endpoint: QueuePairEndpoint) -> (usize, QueuePairEndpoint) {
        let (connection, local_endpoint) =
            ServerSideConnection::new_connection(self.ctx, self.pd, self.cq, endpoint);
        let client_id = CLIENT_ID.fetch_add(1, Ordering::Relaxed);
        let mut guard = self.connection.write().unwrap();
        guard.insert(client_id, connection);
        (client_id, local_endpoint)
    }
}

#[derive(Clone)]
pub struct BadfsServer {
    data: Arc<BadfsServerInner<'static>>,
}

impl BadfsServer {
    pub fn new(
        ctx: &'static RDMAContext,
        pd: &'static ProtectionDomain,
        cq: &'static CompletionQueue,
    ) -> Self {
        BadfsServer {
            data: Arc::new(BadfsServerInner::new(ctx, pd, cq)),
        }
    }
}

#[tarpc::server]
impl BadfsService for BadfsServer {
    async fn create_metadata(self, _: Context, path: String, metadata: Metadata) -> () {
        trace!("create_metadata");
        self.data.metadata_storage.create(&path, metadata)
    }

    async fn read_metadata(self, _: Context, path: String) -> Option<Metadata> {
        trace!("read_metadata");
        self.data.metadata_storage.read(&path)
    }

    async fn update_file_metadata_size(self, _: Context, path: String, new_file_size: usize) -> () {
        trace!("update_file_metadata_size");
        self.data.metadata_storage.update_size(&path, new_file_size)
    }

    async fn remove_metadata(self, _: Context, path: String) -> () {
        trace!("remove_metadata");
        self.data.metadata_storage.remove(&path)
    }

    async fn handshake(
        self,
        _: Context,
        endpoint: QueuePairEndpoint,
    ) -> (usize, QueuePairEndpoint) {
        self.data.rdma_handshake(endpoint)
    }

    async fn read_file_block(
        self,
        _: Context,
        path: String,
        offset: usize,
        length: usize,
    ) -> (
        usize,
        Vec<(ibverbs::RemoteKey, ibverbs::RemoteMemoryBlockAddress)>,
    ) {
        trace!("read_file_block");
        self.data.data_storage.read_access(&path, offset, length)
    }

    async fn write_file_block(
        self,
        _: Context,
        path: String,
        offset: usize,
        length: usize,
    ) -> Vec<(ibverbs::RemoteKey, ibverbs::RemoteMemoryBlockAddress)> {
        trace!("write_file_block");
        self.data.data_storage.write_access(&path, offset, length)
    }

    async fn remove_file_block(self, _: Context, path: String) -> () {
        trace!("remove_file_block");
        self.data.data_storage.remove(&path)
    }

    async fn read_dirents(self, _: Context, father_path: String) -> Blob {
        trace!("read_dirents");
        Blob::new(self.data.metadata_storage.read_dirents(&father_path))
    }
}
