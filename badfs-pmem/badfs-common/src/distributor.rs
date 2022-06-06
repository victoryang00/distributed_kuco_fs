use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub trait Distributor: Send + Sync {
    fn locate_data(&self, path: &str) -> HostID;
}

pub type HostID = usize;

pub struct SimpleHashDistributor {
    pub host_num: usize,
}

impl SimpleHashDistributor {
    pub fn new(host_num: usize) -> Self {
        SimpleHashDistributor { host_num }
    }
}

impl Distributor for SimpleHashDistributor {
    fn locate_data(&self, path: &str) -> HostID {
        let mut hasher = DefaultHasher::new();
        path.hash(&mut hasher);
        hasher.finish() as usize % self.host_num
    }
}
