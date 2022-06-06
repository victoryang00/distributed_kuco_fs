use super::metadata::Metadata;
use super::metadata_wrapper::MetadataWrapper as MetadataWrapperTrait;
use crate::file::FileType;
use crate::metadata::metadata_wrapper::RWLockMetadataWrapper;

use bytes::BufMut;

pub trait MetadataStorage
where
    Self: Debug,
{
    type MetadataWrapper: MetadataWrapperTrait;
    fn new() -> Self;
    fn get_parent_path(self_path: &str) -> Option<(&str, &str)> {
        match self_path.rfind('/') {
            Some(value) => Some(self_path.split_at(value)),
            None => None,
        }
    }

    fn inner_create(&self, key: &str, value: Metadata) -> ();
    fn inner_read(&self, key: &str) -> Option<Self::MetadataWrapper>;
    fn inner_remove(&self, key: &str) -> ();
    fn inner_dirent_create(&self, parent_path: &str, dirent_filename: &str, filetype: FileType);
    fn inner_dirent_read(&self, parent_path: &str) -> Vec<(String, FileType)>;
    fn inner_dirent_remove(&self, parent_path: &str, dirent_filename: &str);

    fn update_size(&self, key: &str, new_size: usize);

    fn create(&self, path: &str, metadata: Metadata) -> () {
        let file_type = metadata.get_file_type();
        self.inner_create(path, metadata);
        let parent_path = Self::get_parent_path(path);
        if let Some((parent_path, dirent_filename)) = parent_path {
            self.inner_dirent_create(parent_path, dirent_filename, file_type)
        }
    }

    fn read(&self, path: &str) -> Option<Metadata> {
        let data = self.inner_read(path)?;
        Some(data.access_ref(|metadata| metadata.clone()))
    }

    fn fetch_file_type(&self, path: &str) -> Option<FileType> {
        let data = self.inner_read(path)?;
        Some(data.access_ref(|metadata| metadata.get_file_type()))
    }

    fn remove(&self, path: &str) {
        if let Some((parent_path, dirent_filename)) = Self::get_parent_path(path) {
            self.inner_dirent_remove(parent_path, dirent_filename)
        }
        self.inner_remove(path);
    }

    fn read_dirents(&self, path: &str) -> Vec<u8> {
        let result = self.inner_dirent_read(path);
        let mut bytes_result: Vec<u8> = Vec::with_capacity(result.len() * 16);

        for (name, file_type) in result {
            debug_assert!(name.len() <= 255);
            bytes_result.put_u8(file_type as u8);
            bytes_result.put_u8(name.len() as u8);
            bytes_result.put_slice(name.as_bytes());
        }
        bytes_result
    }
}

use dashmap::DashMap;
/// ### PERFORMANCE ISSUE
/// + We should use raw string instead of rust string to avoid the long char size in rust
/// + We should try to use tire tree instead of hashmap
/// + We should use concurrent HashMap or trie tree
use std::fmt::Debug;
use std::time::SystemTime;

#[derive(Debug)]
pub struct DashMapMetadataStorage<MetadataWrapper> {
    metadata_storage: DashMap<String, MetadataWrapper>,
}

impl MetadataStorage for DashMapMetadataStorage<RWLockMetadataWrapper> {
    type MetadataWrapper = RWLockMetadataWrapper;

    fn new() -> Self {
        let result: Self = DashMapMetadataStorage {
            metadata_storage: DashMap::new(),
        };
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("failed to get time")
            .as_secs() as i64;
        result.create(
            "/",
            Metadata {
                mode: libc::DT_DIR as u32,
                size: 0,
                time: time,
            },
        );
        result
    }

    fn inner_create(&self, key: &str, value: Metadata) -> () {
        self.metadata_storage
            .insert(key.into(), RWLockMetadataWrapper::new(value));
    }

    fn inner_read(&self, key: &str) -> Option<Self::MetadataWrapper> {
        let result = self.metadata_storage.get(key);
        match result {
            None => None,
            Some(wrapper) => Some(wrapper.value().clone()),
        }
    }

    fn inner_remove(&self, key: &str) -> () {
        self.metadata_storage.remove(key.into());
    }

    fn inner_dirent_create(&self, parent_path: &str, dirent_filename: &str, filetype: FileType) {
        let result = self.metadata_storage.get(parent_path);
        if let Some(result) = result {
            let result = result.value();
            result.access_dirent_mut(|set| {
                set.insert(dirent_filename.into(), filetype);
            })
        }
    }

    fn inner_dirent_read(&self, parent_path: &str) -> Vec<(String, FileType)> {
        let result = self.metadata_storage.get(parent_path);
        if let Some(result) = result {
            let result = result.value();
            return result.access_dirent_ref(|map| {
                map.iter()
                    .map(|(k, v)| (k.to_owned(), v.clone()))
                    .collect::<Vec<_>>()
            });
        }
        return Vec::new();
    }

    fn inner_dirent_remove(&self, parent_path: &str, dirent_filename: &str) {
        let result = self.metadata_storage.get(parent_path);
        if let Some(result) = result {
            let result = result.value();
            result.access_dirent_mut(|set| {
                set.remove(dirent_filename.into());
            })
        }
    }

    fn update_size(&self, key: &str, new_size: usize) {
        let result = self.metadata_storage.get(key);
        if let Some(result) = result {
            result.access_mut(|metadata| {
                if metadata.size < new_size {
                    metadata.size = new_size
                }
            })
        }
    }
}
