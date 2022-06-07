#![feature(async_stream)]
#![feature(trivial_bounds)]
#![feature(in_band_lifetimes)]
#![feature(new_uninit)]

use CorundumAllocator::*;
#[global_allocator]
static GLOBAL_CORUNDUM: CorundumAlloc = CorundumAlloc;

pub mod data;
pub mod distributor;
pub mod error;
pub mod fd_table;
pub mod file;
pub mod metadata;
pub mod rpc;
