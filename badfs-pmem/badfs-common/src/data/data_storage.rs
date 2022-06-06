use super::data::Data;
use super::data::BLOCK_SIZE;
use std::cmp::{max, min};

use dashmap::DashMap;
use ibverbs::{ProtectionDomain, RemoteKey, RemoteMemoryBlockAddress};

pub trait DataStorage {
    fn new(pd: &'static ProtectionDomain) -> Self;
    fn read_access(
        &self,
        filename: &str,
        offset: usize,
        length: usize,
    ) -> (usize, Vec<(RemoteKey, RemoteMemoryBlockAddress)>);
    fn write_access(
        &self,
        filename: &str,
        offset: usize,
        length: usize,
    ) -> Vec<(ibverbs::RemoteKey, ibverbs::RemoteMemoryBlockAddress)>;
    fn remove(&self, filename: &str);
}

pub struct DashMapDataStorage {
    data: DashMap<String, Data>,
    pd: &'static ProtectionDomain<'static>,
}

impl DataStorage for DashMapDataStorage {
    fn new(pd: &'static ProtectionDomain) -> Self {
        DashMapDataStorage {
            data: DashMap::new(),
            pd,
        }
    }

    fn read_access(
        &self,
        filename: &str,
        offset: usize,
        length: usize,
    ) -> (usize, Vec<(RemoteKey, RemoteMemoryBlockAddress)>) {
        let value = self.data.get(&filename.to_owned());
        let value = match value {
            None => return (0, vec![]),
            Some(value) => value,
        };
        let data_vec = value.value().read().unwrap();
        let start_block_id = (offset) / BLOCK_SIZE;
        if start_block_id >= data_vec.len() {
            return (0, vec![]);
        }
        let stop_block_id = max(
            Data::cast_data_length_to_total_block_count(offset + length) - 1,
            data_vec.len() - 1,
        );
        if stop_block_id == start_block_id {
            let current_block_size = data_vec[start_block_id].access_container(|c| c.len());
            if current_block_size < offset % BLOCK_SIZE {
                return (0, vec![]);
            }
            let len = min(length, current_block_size - offset % BLOCK_SIZE);
            return (len, vec![data_vec[start_block_id].rkey_and_addr()]);
        }
        let mut bytes_able_to_read = 0;
        let rkey_and_addr = data_vec[start_block_id..=stop_block_id]
            .iter()
            .zip(start_block_id..=stop_block_id)
            .map(|(data, block_index)| {
                bytes_able_to_read += data.access_container(|c| c.len());
                data.rkey_and_addr()
            })
            .collect();
        bytes_able_to_read = min(bytes_able_to_read, length);
        (bytes_able_to_read, rkey_and_addr)
    }

    fn write_access(
        &self,
        filename: &str,
        offset: usize,
        length: usize,
    ) -> Vec<(RemoteKey, RemoteMemoryBlockAddress)> {
        let value = self.data.get(&filename.to_owned());
        let value = match value {
            None => self
                .data
                .entry(filename.to_owned())
                .or_insert_with(|| Data::with_capacity(offset + length, self.pd))
                .downgrade(),
            Some(value) => {
                value.value().resize(offset + length, &self.pd);
                value
            }
        };
        let data_vec = value.value().read().unwrap();
        let start_block_id = offset / BLOCK_SIZE;
        let stop_block_id = Data::cast_data_length_to_total_block_count(offset + length) - 1;
        data_vec[start_block_id..=stop_block_id]
            .iter()
            .map(|data| data.rkey_and_addr())
            .collect()
    }

    fn remove(&self, filename: &str) {
        self.data.remove(filename);
    }
}
