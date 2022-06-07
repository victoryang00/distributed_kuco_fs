/*
 * SPDX-License-Identifier: GPL-2.0 OR MIT
 *
 * Copyright (C) 2020 Samantha Miller, Kaiyuan Zhang, Danyang Zhuo, Tom
      Anderson, Ang Chen, University of Washington
 */

#[cfg(not(feature="user"))]
use crate::bento_utils;
#[cfg(not(feature="user"))]
use crate::fuse;
#[cfg(not(feature="user"))]
use crate::libc;
#[cfg(not(feature="user"))]
use crate::std;
#[cfg(not(feature="user"))]
use crate::time;
//#[cfg(not(feature="user"))]
//use crate::println;

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use bento_utils::*;

use core::sync::atomic;
use core::str;

use fuse::*;

use serde::{Serialize, Deserialize};

use std::ffi::OsStr;
use std::sync::RwLock;

use time::Timespec;

pub const PAGE_SIZE: usize = 4096;

static LEN: atomic::AtomicUsize = atomic::AtomicUsize::new(13);
static HELLO_NAME: &str = "hello";

#[derive(Serialize, Deserialize)]
pub struct HelloState {
    pub len: usize,
    pub diskname: String, 
}

pub struct HelloFS {
    pub disk: Option<RwLock<Disk>>,
    pub diskname: Option<String>,
}

impl HelloFS {
    const NAME: &'static str = "hello_ll\0";

    fn hello_stat(ino: u64) -> Result<FileAttr, i32> {
        if ino != 1 && ino != 2 {
            return Err(-1);
        }
        let nlink = match ino {
            1 => 2,
            2 => 1,
            _ => 0,
        };
        let file_type = match ino {
            1 => FileType::Directory,
            2 => FileType::RegularFile,
            _ => FileType::RegularFile,
        };
        let size = match ino {
            1 => 0,
            2 => LEN.load(atomic::Ordering::SeqCst) as u64,
            _ => 0,
        };
        Ok(FileAttr {
            ino: ino,
            size: size,
            blocks: 0,
            atime: Timespec::new(0, 0),
            mtime: Timespec::new(0, 0),
            ctime: Timespec::new(0, 0),
            crtime: Timespec::new(0, 0),
            kind: file_type,
            perm: 0o077,
            nlink: nlink,
            uid: 0,
            gid: 0,
            rdev: 0,
            flags: 0,
        })
    }
}

impl BentoFilesystem<'_,i32,HelloState> for HelloFS {
    fn get_name(&self) -> &'static str {
        Self::NAME
    }

    fn bento_init(
        &mut self,
        _req: &Request,
        devname: &OsStr,
        outarg: &mut FuseConnInfo,
    ) -> Result<(), i32> {
        outarg.proto_major = BENTO_KERNEL_VERSION;
        outarg.proto_minor = BENTO_KERNEL_MINOR_VERSION;

        LOGGER_INITED.get_or_init(|| {
            env_logger::init();
            info!(
                "env_logger has initialized.(thread_id: {:?})",
                std::thread::current().id()
            );
        });
    
        //create a new client in a really thread-safe way
        let mut guard = CLIENT.write().unwrap();
        if let None = *guard {
            *guard = Some({
                TOKIO_RUNTIME.with(|tokio| {
                    tokio.block_on(async {
                        let client = BadfsClient::new().await.expect("failed to create client");
                        info!(
                            "Badfs Client has initialized.(thread_id: {:?})",
                            std::thread::current().id()
                        );
                        client
                    })
                })
            });
        }
    
        unsafe {
            intercept_hook_point = Some(intercept_hook);
            info!(
                "intercept_hook_point has been set to our hook.(thread_id: {:?})",
                std::thread::current().id()
            );
        }
        ENABLE_INTERCEPT.with(|f| {
            info!(
                "enabled intercept hook for current thread.(thread_id: {:?})",
                std::thread::current().id()
            );
            f.set(true);
        });

        return Ok(());
    }

    fn bento_statfs(&self, _req: &Request, _ino: u64, reply: ReplyStatfs) {
        reply.statfs(0, 0, 0, 0, 0, 512, 255, 0);
    }

    fn bento_open(
        &self,
        _req: &Request,
        nodeid: u64,
        _flags: u32,
        reply: ReplyOpen,
    ) {
        if nodeid != 2 {
            reply.error(libc::EISDIR);
        } else {
            reply.opened(0, 0);
        }
    }

    fn bento_opendir(
        &self,
        _req: &Request,
        nodeid: u64,
        _flags: u32,
        reply: ReplyOpen,
    ) {
        if nodeid != 1 {
            reply.error(libc::EISDIR);
        } else {
            reply.opened(0, 0);
        }
    }

    fn bento_getattr(&self, _req: &Request, nodeid: u64, reply: ReplyAttr) {
        let attr_valid = Timespec::new(1, 999999999);
        match HelloFS::hello_stat(nodeid) {
            Ok(attr) => reply.attr(&attr_valid, &attr),
            Err(_) => reply.error(libc::ENOENT),
        }
    }

    fn bento_lookup(
        &self,
        _req: &Request,
        nodeid: u64,
        name: &OsStr,
        reply: ReplyEntry,
    ) {
        let name_str = name.to_str().unwrap();
        if nodeid != 1 || name_str != HELLO_NAME {
            reply.error(libc::ENOENT);
        } else {
            let out_nodeid = 2;
            let generation = 0;
            let entry_valid = Timespec::new(1, 999999999);
            match HelloFS::hello_stat(out_nodeid) {
                Ok(attr) => reply.entry(&entry_valid, &attr, generation),
                Err(_) => reply.error(libc::ENOENT),
            }
        }
    }

    fn bento_read(
        &self,
        _req: &Request,
        nodeid: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        reply: ReplyData,
    ) {
        if nodeid != 2 {
            reply.error(libc::ENOENT);
            return;
        }
        let copy_len = LEN.load(atomic::Ordering::SeqCst) - offset as usize;

        let disk = self.disk.as_ref().unwrap().read().unwrap();
        let mut bh = match disk.bread(0) {
            Ok(x) => x,
            Err(x)=> {
                reply.error(x);
                return;
            }
        };

        let mut buf_vec: Vec<u8> = vec![0; copy_len];
        let buf_slice = buf_vec.as_mut_slice();

        let b_slice = bh.data_mut();
        let offset = offset as usize;
        let data_region = &b_slice[offset..offset + copy_len];
        buf_slice.copy_from_slice(data_region);
        reply.data(&buf_slice);
    }

    fn bento_write(
        &self,
        _req: &Request,
        nodeid: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _flags: u32,
        reply: ReplyWrite,
    ) {
        
       Ok(())
    }

    #[allow(unused_mut)]
    fn bento_readdir(
        &self,
        _req: &Request,
        nodeid: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if nodeid != 1 {
            reply.error(libc::ENOTDIR);
            return;
        }
        let mut buf_off = 1;
        let mut inarg_offset = offset;
        if inarg_offset < 1 {
            if reply.add(1 as u64, buf_off, FileType::Directory, ".") {
                reply.ok();
                return;
            };
        }
        inarg_offset -= 1;
        buf_off += 1;
        if inarg_offset < 1 {
            if reply.add(2 as u64, buf_off, FileType::RegularFile, HELLO_NAME) {
                reply.ok();
                return;
            };
        }
        inarg_offset -= 1;
        buf_off += 1;
        if inarg_offset < 1 {
            if reply.add(1 as u64, buf_off, FileType::Directory, "..") {
                reply.ok();
                return;
            };
        }
        reply.ok();
    }

    fn bento_fsync(
        &self,
        _req: &Request,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let disk = self.disk.as_ref().unwrap().read().unwrap();
        if let Err(x) = disk.sync_all() {
            reply.error(x);
        } else {
            reply.ok();
        }
    }

    fn bento_update_prepare(&mut self) -> Option<HelloState> {
        let state = HelloState {
            len: LEN.load(atomic::Ordering::SeqCst),
            diskname: self.diskname.as_ref().unwrap().clone(),
        };
        return Some(state);
    }
}
