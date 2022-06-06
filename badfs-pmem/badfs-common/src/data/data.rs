use ibverbs::memory_container::MemoryContainer;
use ibverbs::{MemoryRegion, ProtectionDomain};
use std::ops::Deref;
use std::sync::RwLock;

pub const BLOCK_SIZE: usize = 1 * 1024 * 1024;

#[derive(Debug)]
pub struct Array<T, const CAPACITY: usize> {
    data: Box<[T; CAPACITY]>,
    length: usize,
}

impl<T, const CAPACITY: usize> Array<T, CAPACITY> {
    pub fn new() -> Self {
        Self {
            data: unsafe { Box::new_uninit().assume_init() },
            length: 0,
        }
    }

    pub fn set_len(&mut self, length: usize) {
        self.length = length;
    }

    pub fn len(&self) -> usize {
        self.length
    }
}

impl<T, const CAPACITY: usize> MemoryContainer for Array<T, CAPACITY> {
    type Element = T;

    fn access_memory<U>(&mut self, accessor: impl FnOnce(&mut [Self::Element]) -> U) -> U {
        accessor(&mut self.data[..self.length])
    }

    unsafe fn access_maybe_uninit_memory<U>(
        &mut self,
        accessor: impl FnOnce(&mut [Self::Element]) -> U,
    ) -> U {
        accessor(&mut self.data[..])
    }
}

pub struct Data(RwLock<Vec<MemoryRegion<Array<u8, BLOCK_SIZE>>>>);

impl Data {
    pub fn cast_data_length_to_total_block_count(data_full_size: usize) -> usize {
        ((data_full_size as isize - 1) / BLOCK_SIZE as isize + 1) as usize
    }

    pub fn with_capacity(data_size: usize, pd: &'static ProtectionDomain) -> Self {
        let block_count = Self::cast_data_length_to_total_block_count(data_size);
        // let mut block_count = Self::cast_data_length_to_total_block_count(data_size);
        // if block_count == 0{
        //     block_count = 1;
        // }
        let data = Data {
            0: RwLock::new(Vec::with_capacity(block_count)),
        };
        data.resize(data_size, pd);
        data
    }

    pub fn resize(&self, mut new_size: usize, pd: &'static ProtectionDomain) {
        {
            let guard = self.read().unwrap();
            if guard.len() > 0 {
                if (guard.len() - 1) * BLOCK_SIZE
                    + guard.last().unwrap().access_container(|c| c.length)
                    >= new_size
                {
                    return;
                }
            }
        }
        let mut guard = self.write().unwrap();
        if guard.len() * BLOCK_SIZE < new_size {
            let mut append_size = new_size - guard.len() * BLOCK_SIZE;
            guard.resize_with(
                Self::cast_data_length_to_total_block_count(new_size),
                || {
                    let mut array = Array::new();
                    if append_size > BLOCK_SIZE {
                        array.set_len(BLOCK_SIZE);
                        append_size -= BLOCK_SIZE;
                    } else {
                        assert_ne!(append_size, 0);
                        array.set_len(append_size);
                        append_size = 0;
                    }
                    MemoryRegion::new(array, pd).unwrap()
                },
            )
        } else {
            let vec_len = guard.len();
            let mut last_option = guard.last_mut();
            let mut last = last_option.as_mut().unwrap();
            let actual_size = (vec_len - 1) * BLOCK_SIZE + last.access_container(|c| c.length);
            if actual_size < new_size {
                last.access_container_mut(|c| {
                    c.length += new_size - actual_size;
                });
            }
        }
    }

    pub fn len(&self) -> usize {
        self.0.read().unwrap().len()
    }
}

impl Deref for Data {
    type Target = RwLock<Vec<MemoryRegion<Array<u8, BLOCK_SIZE>>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
