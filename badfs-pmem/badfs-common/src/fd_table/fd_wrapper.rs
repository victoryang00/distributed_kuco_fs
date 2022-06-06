use std::ops::Deref;
use std::sync::{Arc, RwLock};

use crate::file::SomethingOpen;
use libc::c_long;
use sharded_slab::Slab;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;

pub trait FileDescriptorWrapper {
    fn new(file: SomethingOpen) -> Self;
    fn clone(&self) -> Self;
    fn access_ref<T>(&self, access: impl FnMut(&SomethingOpen) -> T) -> T;
    fn access_mut<T>(&self, access: impl FnMut(&mut SomethingOpen) -> T) -> T;
}

pub struct RwLockRefCellFileDescriptorWrapper {
    data: Arc<RwLock<SomethingOpen>>,
}

impl FileDescriptorWrapper for RwLockRefCellFileDescriptorWrapper {
    fn new(file: SomethingOpen) -> Self {
        return RwLockRefCellFileDescriptorWrapper {
            data: Arc::new(RwLock::new(file)),
        };
    }

    fn clone(&self) -> Self {
        RwLockRefCellFileDescriptorWrapper {
            data: self.data.clone(),
        }
    }

    fn access_ref<T>(&self, mut access: impl FnMut(&SomethingOpen) -> T) -> T {
        let data = self.data.read().unwrap();
        access(&*data)
    }

    fn access_mut<T>(&self, mut access: impl FnMut(&mut SomethingOpen) -> T) -> T {
        let mut data = self.data.write().unwrap();
        access(&mut *data)
    }
}

pub trait FileDescriptorManager {
    type FileDescriptor: FileDescriptorWrapper;
    fn new() -> Self;
    fn add(&self, file: SomethingOpen) -> c_long;
    fn get(&self, fd: c_long) -> Option<Self::FileDescriptor>;
    fn contains(&self, fd: c_long) -> bool;
    fn remove(&self, fd: c_long);
    fn dup(&self, fd: c_long) -> c_long;
    // fn dup2(&self, old_fd: c_long, new_fd: c_long);
}

pub struct HashMapFileDescriptorManager<FileDescriptorWrapper> {
    next_fd: std::sync::atomic::AtomicI64,
    map: RwLock<HashMap<c_long, FileDescriptorWrapper>>,
}

impl<T> HashMapFileDescriptorManager<T>
where
    T: FileDescriptorWrapper,
{
    pub fn dup2(&self, old_fd: c_long, new_fd: c_long) {
        let file = self.get(old_fd).unwrap().clone();
        self.map.write().unwrap().insert(new_fd, file);
    }

    fn allocate_fd(&self) -> c_long {
        self.next_fd.fetch_add(1, Ordering::Relaxed)
    }
}

impl<T> FileDescriptorManager for HashMapFileDescriptorManager<T>
where
    T: FileDescriptorWrapper,
{
    type FileDescriptor = T;

    fn new() -> Self {
        return HashMapFileDescriptorManager {
            next_fd: std::sync::atomic::AtomicI64::new(100000),
            map: RwLock::new(HashMap::new()),
        };
    }

    fn add(&self, file: SomethingOpen) -> c_long {
        let fd = self.allocate_fd();
        self.map.write().unwrap().insert(fd, T::new(file));
        fd
    }

    fn get(&self, fd: c_long) -> Option<Self::FileDescriptor> {
        match self.map.read().unwrap().get(&fd) {
            None => None,
            Some(fd) => Some(fd.clone()),
        }
    }

    fn contains(&self, fd: c_long) -> bool {
        self.map.read().unwrap().contains_key(&fd)
    }

    fn remove(&self, fd: c_long) {
        self.map.write().unwrap().remove(&fd);
    }

    fn dup(&self, fd: c_long) -> c_long {
        let new_fd = self.allocate_fd();
        self.dup2(fd, new_fd);
        new_fd
    }
    // fn dup2(&self, oldfd: i64, newfd: i64) {
    //     let file = self.map.read().unwrap().get(&oldfd).unwrap().clone();
    //     self.map.write().unwrap().insert(newfd,file);
    //  }
}

pub struct BTreeMapFileDescriptorManager<FileDescriptorWrapper> {
    next_fd: std::sync::atomic::AtomicI64,
    map: RwLock<BTreeMap<c_long, FileDescriptorWrapper>>,
}

impl<T> BTreeMapFileDescriptorManager<T>
where
    T: FileDescriptorWrapper,
{
    fn dup2(&self, old_fd: c_long, new_fd: c_long) {
        let file = self.get(old_fd).unwrap().clone();
        self.map.write().unwrap().insert(new_fd, file);
    }

    fn allocate_fd(&self) -> c_long {
        self.next_fd.fetch_add(1, Ordering::Relaxed)
    }
}

impl<T> FileDescriptorManager for BTreeMapFileDescriptorManager<T>
where
    T: FileDescriptorWrapper,
{
    type FileDescriptor = T;

    fn new() -> Self {
        return BTreeMapFileDescriptorManager {
            next_fd: std::sync::atomic::AtomicI64::new(100000),
            map: RwLock::new(BTreeMap::new()),
        };
    }

    fn add(&self, file: SomethingOpen) -> c_long {
        let fd = self.allocate_fd();
        self.map.write().unwrap().insert(fd, T::new(file));
        fd
    }

    fn get(&self, fd: c_long) -> Option<Self::FileDescriptor> {
        match self.map.read().unwrap().get(&fd) {
            None => None,
            Some(fd) => Some(fd.clone()),
        }
    }

    fn contains(&self, fd: c_long) -> bool {
        self.map.read().unwrap().contains_key(&fd)
    }

    fn remove(&self, fd: c_long) {
        self.map.write().unwrap().remove(&fd);
    }

    fn dup(&self, fd: c_long) -> c_long {
        let new_fd = self.allocate_fd();
        self.dup2(fd, new_fd);
        new_fd
    }
}

pub struct ShardedSlabFileDescriptorManager<FileDescriptorWrapper> {
    slab: Slab<FileDescriptorWrapper>,
}

impl<T> FileDescriptorManager for ShardedSlabFileDescriptorManager<T>
where
    T: FileDescriptorWrapper,
{
    type FileDescriptor = T;

    fn new() -> Self {
        return ShardedSlabFileDescriptorManager { slab: Slab::new() };
    }

    fn add(&self, file: SomethingOpen) -> c_long {
        self.slab.insert(T::new(file)).unwrap() as c_long
    }

    fn get(&self, fd: c_long) -> Option<Self::FileDescriptor> {
        let entry = self.slab.get(fd as _);
        match entry {
            None => None,
            Some(fd) => Some(fd.deref().clone()),
        }
    }

    fn contains(&self, fd: c_long) -> bool {
        self.slab.contains(fd as _)
    }

    fn remove(&self, fd: c_long) {
        self.slab.remove(fd as _);
    }

    fn dup(&self, fd: c_long) -> c_long {
        let data = self.slab.take(fd as _);
        self.slab.insert(data.unwrap().clone()).unwrap() as c_long
    }
}
