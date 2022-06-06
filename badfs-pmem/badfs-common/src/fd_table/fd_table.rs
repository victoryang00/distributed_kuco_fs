use super::fd_wrapper::*;

pub type HashmapFDTable = HashMapFileDescriptorManager<RwLockRefCellFileDescriptorWrapper>;
