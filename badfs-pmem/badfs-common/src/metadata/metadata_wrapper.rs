use super::metadata::Metadata;
use crate::file::FileType;

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

pub trait MetadataWrapper {
    fn new(metadata: Metadata) -> Self;
    fn access_ref<T>(&self, f: impl Fn(&Metadata) -> T) -> T;
    fn access_mut<T>(&self, f: impl Fn(&mut Metadata) -> T) -> T;
    fn access_dirent_ref<T>(&self, f: impl Fn(&BTreeMap<String, FileType>) -> T) -> T;
    fn access_dirent_mut<T>(&self, f: impl Fn(&mut BTreeMap<String, FileType>) -> T) -> T;
    fn clone(&self) -> Self;
}

pub trait CanSerializeFromU8 {
    fn from_mut_vec_u8(bytes: Vec<u8>) -> Self;
}

/// RWLockMetadataWrapper is a wrapper for Metadata struct that
/// has a RWLock to avoid race conditions
///
/// mainly used in metadata storage that do not provide an atomic update (eg, tire tree)
#[derive(Debug)]
pub struct RWLockMetadataWrapper {
    data: Arc<RwLock<Metadata>>,
    dirent: Arc<RwLock<BTreeMap<String, FileType>>>,
}

impl MetadataWrapper for RWLockMetadataWrapper {
    fn new(metadata: Metadata) -> Self {
        RWLockMetadataWrapper {
            data: Arc::new(RwLock::new(metadata)),
            dirent: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    fn access_ref<T>(&self, f: impl Fn(&Metadata) -> T) -> T {
        let metadata_guard = self.data.read().unwrap();
        f(&*metadata_guard)
    }

    fn access_mut<T>(&self, f: impl Fn(&mut Metadata) -> T) -> T {
        let mut metadata_guard = self.data.write().unwrap();
        f(&mut *metadata_guard)
    }

    fn access_dirent_ref<T>(&self, f: impl Fn(&BTreeMap<String, FileType>) -> T) -> T {
        let dirent_guard = self.dirent.read().unwrap();
        f(&*dirent_guard)
    }

    fn access_dirent_mut<T>(&self, f: impl Fn(&mut BTreeMap<String, FileType>) -> T) -> T {
        let mut dirent_guard = self.dirent.write().unwrap();
        f(&mut *dirent_guard)
    }

    fn clone(&self) -> Self {
        return RWLockMetadataWrapper {
            data: self.data.clone(),
            dirent: self.dirent.clone(),
        };
    }
}
