mod rdma;
mod rpc;

use badfs_common::rpc::*;
use libc::c_long;
use std::borrow::BorrowMut;
use std::cell::RefCell;
use tarpc::tokio_serde::formats::Bincode;

use badfs_common::distributor::{Distributor, SimpleHashDistributor};

use crate::rdma::ClientSideConnection;
use badfs_common::data::data::BLOCK_SIZE;
use badfs_common::error::Error;
use badfs_common::error::Error::ForwardToKernel;
use badfs_common::fd_table::fd_table::HashmapFDTable;
use badfs_common::fd_table::fd_wrapper::{FileDescriptorManager, FileDescriptorWrapper};
use badfs_common::file::{FileType, OpenDir, OpenFile, SomethingOpen};
use badfs_common::metadata::metadata::Metadata;
use ibverbs::{RemoteKey, RemoteMemoryBlockAddress};
use libc::{c_char, c_int, mode_t};
use std::ffi::CStr;
use std::io::Write;
use std::rc::Rc;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};
use futures::StreamExt;

type Result<U> = std::result::Result<U, badfs_common::error::Error>;

pub struct BadfsConfig {
    pub server_address: Vec<String>,
    pub base_path: String,
}

impl BadfsConfig {
    fn new() -> Self {
        BadfsConfig {
            server_address: vec!["192.168.10.4:3344".into(),"0.0.0.0:3345".into()],
            // server_address: vec!["192.168.10.4:3344".into()],
            // server_address: vec!["localhost:3344".into(), "localhost:3345".into(),"localhost:3346".into()],
            base_path: "/storage/io500-test".to_string(),
        }
    }
}

pub struct BadfsClient {
    clients: Vec<BadfsServiceClient>,
    rdma_connections: Vec<RwLock<ClientSideConnection<'static>>>,
    base_path: String,
    fd_table: HashmapFDTable,
    distributor: SimpleHashDistributor,
}

impl BadfsClient {
    pub async fn new() -> Result<Self> {
        let config = BadfsConfig::new();
        let future_tcp_stream: Vec<_> = config
            .server_address
            .iter()
            .map(|server_address| tokio::net::TcpStream::connect(server_address))
            .collect();

        let mut result = Vec::new();
        for i in future_tcp_stream {
            let stream = i.await.unwrap();
            let transport = tarpc::serde_transport::Transport::from((stream, Bincode::default()));
            result
                .push(BadfsServiceClient::new(tarpc::client::Config::default(), transport).spawn());
        }

        let result_ref = &result as *const Vec<BadfsServiceClient>;
        // this is safe because we move result_ref into closure, then execute the closure before function returns
        let result_ref: &'static Vec<BadfsServiceClient> = unsafe { result_ref.as_ref().unwrap() };

        let rdma_connections = futures::future::join_all(result_ref.iter().map(|client| {
            ClientSideConnection::new_connection(&rdma::CONTEXT, &rdma::PD, &rdma::CQ, client)
        }))
        .await
        .into_iter()
        .map(|client| RwLock::new(client))
        .collect();

        Ok(BadfsClient {
            clients: result,
            rdma_connections,
            base_path: config.base_path.to_owned(),
            fd_table: HashmapFDTable::new(),
            distributor: SimpleHashDistributor::new(config.server_address.len()),
        })
    }

    fn context(&self) -> tarpc::context::Context {
        let mut cx = tarpc::context::current();
        cx.deadline = SystemTime::now() + Duration::from_secs(3600);
        cx
    }

    fn get_inner_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        if path.len() >= self.base_path.len() {
            if path
                .chars()
                .take(self.base_path.len())
                .zip(self.base_path.chars())
                .fold(true, |b, (c1, c2)| b && c1 == c2)
            {
                return Some(path.split_at(self.base_path.len()).1);
            }
        }
        None
    }

    pub async fn syscall(
        &self,
        num: c_long,
        a0: c_long,
        a1: c_long,
        a2: c_long,
        a3: c_long,
        a4: c_long,
        a5: c_long,
    ) -> Result<c_long> {
        match num as i64 {
            libc::SYS_open => {
                self.open_at(self.convert_cstr_to_path(a0 as _)?, a1 as _, a2 as _)
                    .await
            }
            libc::SYS_openat => {
                self.open_at(self.convert_cstr_to_path(a1 as _)?, a2 as _, a3 as _)
                    .await
            }
            libc::SYS_close => self.close(a0 as _).await,
            libc::SYS_read => self.read_by_fd(a0 as _, a1 as _, a2 as _).await,
            libc::SYS_write => self.write_by_fd(a0 as _, a1 as _, a2 as _).await,
            libc::SYS_creat => {
                self.open_at(
                    self.convert_cstr_to_path(a0 as _)?,
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    a1 as _,
                )
                .await
            }
            // TODO: Remove files belong to the dir
            libc::SYS_unlink => self.unlink_at(self.convert_cstr_to_path(a0 as _)?).await,
            libc::SYS_rmdir => self.unlink_at(self.convert_cstr_to_path(a0 as _)?).await,
            libc::SYS_mkdir => {
                self.mkdir(self.convert_cstr_to_path(a0 as _)?, a1 as _)
                    .await
            }
            libc::SYS_lseek => self.lseek(a0 as _, a1 as _, a2 as _).await,
            libc::SYS_stat => {
                self.stat(self.convert_cstr_to_path(a0 as _)?, a1 as _)
                    .await
            }
            libc::SYS_lstat => {
                self.fstatat(self.convert_cstr_to_path(a0 as _)?, a1 as _)
                    .await
            }
            libc::SYS_access => {
                self.faccessat(self.convert_cstr_to_path(a0 as _)?, a1 as _)
                    .await
            }
            // libc::SYS_dup2 => self.dup3(a0 as _, a1 as _),
            libc::SYS_getdents => self.getdents(a0 as _, a1 as _, a2 as _),
            libc::SYS_readlink => {
                self.readlinkat(self.convert_cstr_to_path(a0 as _)?, a1 as _, a2 as _)
                    .await
            }
            _ => Err(Error::ForwardToKernel),
        }
    }

    async fn mkdir(&self, path: &str, mode: mode_t) -> Result<c_long> {
        self.mknod(path, mode | libc::S_IFDIR).await?;
        Ok(0)
    }
    async fn lseek(&self, fd: c_long, offset: i64, whence: u64) -> Result<c_long> {
        let fd = self.fd_table.get(fd).ok_or(ForwardToKernel)?;
        let (metadata_host_id, file_path) = fd.access_ref(|file| {
            (
                self.distributor.locate_data(file.path()),
                file.path().to_owned(),
            )
        });
        let metadata = self.clients[metadata_host_id]
            .read_metadata(self.context(), file_path.clone())
            .await
            .unwrap()
            .unwrap();

        fd.access_mut(|file| match whence as _ {
            libc::SEEK_SET => file.set_offset(offset as usize),
            libc::SEEK_CUR => file.add_offset(offset as isize),
            libc::SEEK_END => {
                file.set_offset(metadata.size);
            }
            _ => todo!(),
        });
        Ok(0)
    }

    async fn stat(&self, path: &str, buf: *mut libc::stat) -> Result<c_long> {
        let client = &self.clients[self.distributor.locate_data(path)];
        match client
            .read_metadata(self.context(), path.to_owned())
            .await
            .unwrap()
        {
            Some(metadata) => {
                metadata.set_stat(unsafe { &mut *buf });
                Ok(0)
            }
            None => {
                return Ok(0);
            }
        }
    }

    async fn close(&self, fd: c_long) -> Result<c_long> {
        let fd = self.fd_table.get(fd).ok_or(ForwardToKernel)?;
        let (is_file, file_size, metadata_host_id, file_path) = fd.access_ref(|file| {
            (
                {
                    match file {
                        SomethingOpen::OpenFile(_) => true,
                        SomethingOpen::OpenDir(_) => false,
                    }
                },
                file.offset(),
                self.distributor.locate_data(file.path()),
                file.path().to_owned(),
            )
        });
        if is_file {
            self.clients[metadata_host_id]
                .update_file_metadata_size(self.context(), file_path, file_size)
                .await;
        }
        Ok(0)
    }

    async fn open_at(&self, path: &str, flags: c_int, mode: mode_t) -> Result<c_long> {
        let client = &self.clients[self.distributor.locate_data(path)];
        let result: Option<Metadata> = client
            .read_metadata(self.context(), path.to_owned())
            .await
            .unwrap();
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("failed to get time")
            .as_secs() as i64;
        return match result {
            None => {
                let metadata = Metadata {
                    mode: mode | libc::S_IFREG,
                    size: 0,
                    time: time,
                };
                if flags & libc::O_CREAT == 0 {
                    return Err(Error::NotFound);
                }
                self.mknod(path, metadata.mode).await;
                let fd = self
                    .fd_table
                    .add(SomethingOpen::OpenFile(OpenFile::new(path, flags)));
                Ok(fd)
            }
            Some(metadata) => {
                let open = match metadata.get_file_type() {
                    FileType::Regular => SomethingOpen::OpenFile(OpenFile::new(path, flags)),
                    FileType::Directory => {
                        let dirents: Blob = client
                            .read_dirents(self.context(), path.to_owned())
                            .await
                            .unwrap();
                        let tmp: Vec<u8> = dirents.into();
                        SomethingOpen::OpenDir(OpenDir::new(path, flags, tmp.into()))
                    }
                };
                Ok(self.fd_table.add(open))
            }
        };
    }

    async fn mknod(&self, path: &str, mode: mode_t) -> Result<()> {
        let host = self.distributor.locate_data(path);
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("failed to get time")
            .as_secs() as i64;
        self.clients[host]
            .create_metadata(
                self.context(),
                path.into(),
                Metadata {
                    mode,
                    size: 0,
                    time: time,
                },
            )
            .await
            .unwrap();
        Ok(())
    }

    async fn fstatat(&self, path: &str, buf: *mut libc::stat) -> Result<c_long> {
        let client = &self.clients[self.distributor.locate_data(path)];
        let metadata: Metadata = client
            .read_metadata(self.context(), path.to_owned())
            .await
            .unwrap()
            .unwrap();
        metadata.set_stat(unsafe { &mut *buf });
        Ok(0)
    }

    async fn faccessat(&self, path: &str, mode: libc::mode_t) -> Result<c_long> {
        // let client = &self.clients[self.distributor.locate_data(path)];
        // let metadata: Metadata = client
        //     .read_metadata(self.context(), path.to_owned())
        //     .await
        //     .unwrap()
        //     .unwrap();
        Ok(0)
    }

    pub fn dup3(&self, oldfd: i32, newfd: i32) -> Result<c_long> {
        self.fd_table.dup2(oldfd.into(), newfd.into());
        Ok(newfd as i64)
    }

    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_ptr_alignment)]
    pub fn getdents(&self, fd: i32, dirp: *mut libc::dirent64, count: u32) -> Result<c_long> {
        use std::hash::Hasher;
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let file = self.fd_table.get(fd.into()).ok_or(Error::ForwardToKernel)?;
        file.access_mut(|mut file| {
            let dir = file.as_dir();
            let mut written_len = 0;
            while let Some((type_, name)) = dir.peek_entry() {
                let len = (8 + 8 + 2 + 2 + name.len() + 1 + 7) / 8 * 8;
                if written_len + len > count as usize {
                    break;
                }
                let e =
                    unsafe { &mut *((dirp as *mut u8).add(written_len) as *mut libc::dirent64) };
                hasher.write(name.as_bytes());
                e.d_ino = hasher.finish();
                e.d_reclen = len as u16;
                e.d_name[..name.len()].copy_from_slice(unsafe {
                    std::slice::from_raw_parts_mut(name.as_bytes().as_ptr() as *mut i8, name.len())
                });
                e.d_name[name.len()] = 0;
                e.d_name[name.len() + 2] = type_ as i8; // d_type

                written_len += len;
                dir.move_next();

                e.d_off = dir.offset() as i64;
            }
            Ok(written_len as i64)
        })
    }
    async fn readlinkat(&self, path: &str, buf: *mut u8, bufsize: usize) -> Result<c_long> {
        let client = &self.clients[self.distributor.locate_data(path)];
        let metadata: Metadata = client
            .read_metadata(self.context(), path.to_owned())
            .await
            .unwrap()
            .unwrap();
        Err(Error::NotSupported.into())
    }

    async fn read_by_fd(&self, fd: c_long, buf: *mut u8, count: usize) -> Result<c_long> {
        let file = self.fd_table.get(fd).ok_or(Error::ForwardToKernel)?;
        let (path, offset) = file.access_ref(|file| (file.path().to_owned(), file.offset()));
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, count) };
        let len = self.read_at(&path, offset, buf).await?;
        file.access_mut(|file| file.add_offset(len as isize));
        Ok(len)
    }

    async fn write_by_fd(&self, fd: c_long, buf: *const u8, count: usize) -> Result<c_long> {
        let file = self.fd_table.get(fd).ok_or(Error::ForwardToKernel)?;
        let (path, offset) = file.access_ref(|file| (file.path().to_owned(), file.offset()));
        let buf = unsafe {
            // this is safe because we do not change buf
            let buf = buf as *mut u8;
            std::slice::from_raw_parts_mut(buf, count)
        };
        let len = self.write_at(&path, offset, buf).await?;
        file.access_mut(|file| file.add_offset(len as isize));
        Ok(len)
    }

    pub async fn read_at(&self, path: &str, offset: usize, buf: &mut [u8]) -> Result<c_long> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut completions = [ibverbs::ibv_wc::default(); rdma::CLIENT_CQ_ENTRIES as _];
        let buf_len = buf.len();
        let mut buf = ibverbs::MemoryRegion::new(buf, &rdma::PD).unwrap();
        let client_count = self.clients.len();
        let client_start = self.distributor.locate_data(path);
        let client_index_iter = (0..client_count)
            .cycle()
            .skip(client_start + offset / BLOCK_SIZE)
            .take(client_count);
        let result = self.prepare_access_at(buf_len, offset);
        log::warn!("Here is schedule for\nbuffer length: {}\noffset: {}\nclient count: {}\nblock size: {}\n{:?}",buf_len,offset,client_count,BLOCK_SIZE,result);
        let promises: Vec<(usize, Vec<(RemoteKey, RemoteMemoryBlockAddress)>)> =
            futures::future::join_all(result.iter().zip(client_index_iter.clone()).map(
                |(param, client_id)| {
                    if param.length > 0 {
                        Some(self.clients[client_id].read_file_block(
                            self.context(),
                            path.into(),
                            param.server_offset,
                            param.length,
                        ))
                    }else{
                        None
                    }
                },
            ).filter(|option|option.is_some()).map(|option| option.unwrap()))
            .await
            .into_iter()
            .map(|x| x.unwrap())
            .collect();

        let mut work_count = 0;
        let mut bytes_read = 0;
        let mut first_block_local_end = 0;
        promises
            .into_iter()
            .zip(result.into_iter())
            .zip(client_index_iter)
            .for_each(
                |(((bytes_able_to_read_length, requests), param), client_id)| {
                    bytes_read += bytes_able_to_read_length;
                    let mut param = param;
                    param.length = bytes_able_to_read_length;
                    let first_block_local_start = if first_block_local_end == 0 {
                        first_block_local_end = BLOCK_SIZE - param.server_offset % BLOCK_SIZE;
                        0
                    } else {
                        first_block_local_end += BLOCK_SIZE;
                        first_block_local_end - BLOCK_SIZE
                    };
                    let mut current_block_local_start = first_block_local_start;
                    let mut current_block_local_end = first_block_local_end;
                    requests
                        .into_iter()
                        .enumerate()
                        .for_each(|(index, (rkey, remote_addr))| {
                            while param.length > 0 {
                                let server_offset = param.server_offset % BLOCK_SIZE;
                                param.server_offset = 0;
                                let read_length = if param.length + server_offset > BLOCK_SIZE {
                                    BLOCK_SIZE - server_offset
                                } else {
                                    param.length
                                };
                                param.length -= read_length;
                                if current_block_local_end - current_block_local_start != read_length{
                                    current_block_local_end = current_block_local_start + read_length;
                                }
                                log::warn!("Reading...\nclient id: {}\nlength: {}\nserver read start: {}\nmemory offset: {}\nlocal read length: {}\nremaining param length: {}\ncurrent block local start: {}\ncurrent block local end: {}",client_id,read_length,client_start,server_offset,read_length,param.length,current_block_local_start,current_block_local_end);
                                self.rdma_connections[client_id]
                                    .write()
                                    .unwrap()
                                    .with_qp_mut(|qp| unsafe {
                                        qp.post_send_read(
                                            &mut buf,
                                            current_block_local_start..current_block_local_end,
                                            work_count,
                                            rkey,
                                            remote_addr.offset(server_offset as _),
                                        )
                                        .unwrap();
                                    });
                                current_block_local_start = current_block_local_end + (client_count - 1) * BLOCK_SIZE;
                                current_block_local_end = current_block_local_start + BLOCK_SIZE;
                                work_count += 1;
                                let now_read_free = rdma::WR_READ_FREE.fetch_sub(1, Relaxed) - 1;
                                if now_read_free == 0 {
                                    rdma::must_pop_cq(&mut completions, &mut work_count,&rdma::WR_READ_FREE);
                                }
                            }
                        })
                },
            );

        while work_count > 0 {
            rdma::must_pop_cq(&mut completions, &mut work_count,&rdma::WR_READ_FREE);
        }

        return Ok(bytes_read as _);
    }

    pub async fn write_at(&self, path: &str, mut offset: usize, buf: &mut [u8]) -> Result<c_long> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut completions = [ibverbs::ibv_wc::default(); rdma::CLIENT_CQ_ENTRIES as _];
        let buf_len = buf.len();
        let mut buf = ibverbs::MemoryRegion::new(buf, &rdma::PD).unwrap();
        let client_count = self.clients.len();
        let client_start = self.distributor.locate_data(path);
        let client_index_iter = (0..client_count)
            .cycle()
            .skip(client_start + offset / BLOCK_SIZE)
            .take(client_count);
        let result = self.prepare_access_at(buf_len, offset);
        log::warn!("Here is schedule for\nbuffer length: {}\noffset: {}\nclient count: {}\nblock size: {}\n{:?}",buf_len,offset,client_count,BLOCK_SIZE,result);
        let promises: Vec<Vec<(RemoteKey, RemoteMemoryBlockAddress)>> =
            futures::future::join_all(result.iter().zip(client_index_iter.clone()).map(
                |(param, client_id)| {
                    if param.length > 0{
                        Some(self.clients[client_id].write_file_block(
                            self.context(),
                            path.into(),
                            param.server_offset,
                            param.length,
                        ))
                    }else{
                        None
                    }
                },
            ).filter(|option|option.is_some()).map(|option| option.unwrap()))
            .await
            .into_iter()
            .map(|x| x.unwrap())
            .collect();

        let mut work_count = 0;
        let mut first_block_local_end = 0;
        promises
            .into_iter()
            .zip(result.into_iter())
            .zip(client_index_iter)
            .for_each(|((requests, param), client_id)| {
                let mut param = param;
                let first_block_local_start = if first_block_local_end == 0 {
                    first_block_local_end = BLOCK_SIZE - param.server_offset % BLOCK_SIZE;
                    0
                } else {
                    first_block_local_end += BLOCK_SIZE;
                    first_block_local_end - BLOCK_SIZE
                };
                let mut current_block_local_start = first_block_local_start;
                let mut current_block_local_end = first_block_local_end;
                requests
                    .into_iter()
                    .enumerate()
                    .for_each(|(index, (rkey, remote_addr))| {
                        while param.length > 0 {
                            let server_offset = param.server_offset % BLOCK_SIZE;
                            param.server_offset = 0;
                            let write_length = if param.length + server_offset > BLOCK_SIZE {
                                BLOCK_SIZE - server_offset
                            } else {
                                param.length
                            };
                            debug_assert_ne!(write_length, 0);
                            param.length -= write_length;
                            if current_block_local_end - current_block_local_start != write_length {
                                current_block_local_end = current_block_local_start + write_length;
                            }
                            log::warn!("Writing...\nclient id: {}\nlength: {}\nserver write start: {}\nmemory offset: {}\nlocal write length: {}\nremaining param length: {}\ncurrent block local start: {}\ncurrent block local end: {}",client_id,write_length,client_start,server_offset,write_length,param.length,current_block_local_start,current_block_local_end);
                            self.rdma_connections[client_id]
                                .write()
                                .unwrap()
                                .with_qp_mut(|qp| unsafe {
                                    qp.post_send_write(
                                        &mut buf,
                                        current_block_local_start..current_block_local_end,
                                        work_count,
                                        rkey,
                                        remote_addr.offset(server_offset as _),
                                    )
                                        .unwrap();
                                });
                            current_block_local_start = current_block_local_end + (client_count - 1) * BLOCK_SIZE;
                            current_block_local_end = current_block_local_start + BLOCK_SIZE;
                            work_count += 1;
                            let now_write_free = rdma::WR_WRITE_FREE.fetch_sub(1, Relaxed) - 1;
                            if now_write_free == 0 {
                                rdma::must_pop_cq(&mut completions, &mut work_count, &rdma::WR_WRITE_FREE);
                            }
                        }
                    })
            });

        while work_count > 0 {
            rdma::must_pop_cq(&mut completions, &mut work_count,&rdma::WR_WRITE_FREE);
        }

        return Ok(buf_len as _);
    }

    fn prepare_access_at(&self, data_length: usize, mut offset: usize) -> Vec<ReadWriteParam> {
        let client_count = self.clients.len();
        let block_size = BLOCK_SIZE;
        let base_block_offset_count = (offset / (client_count * block_size)) * block_size;
        offset = offset % block_size;
        let length_padding_start = offset % block_size + data_length;
        let length_padding_start_end =
            (length_padding_start + block_size - 1) / block_size * block_size;

        let result = (0..client_count)
            .map(|client_id| {
                let mut length_at_least =
                    length_padding_start_end / (client_count * block_size) * block_size;
                if (length_at_least + block_size) * client_id
                    + length_at_least * (client_count - client_id)
                    < length_padding_start_end
                {
                    length_at_least += block_size;
                }
                let mut length_without_header = length_at_least;
                if client_id == 0 {
                    length_without_header -= offset;
                    log::warn!("offset: {} length_without_header: {}",offset,length_without_header);
                }
                let mut length_without_tail = length_without_header;
                if client_id == (length_padding_start_end / block_size - 1) % client_count {
                    length_without_tail -=
                        (BLOCK_SIZE - length_padding_start % BLOCK_SIZE) % BLOCK_SIZE;
                }
                let length = length_without_tail;
                let server_offset = if offset != 0 {
                    let server_offset = base_block_offset_count + offset;
                    offset = 0;
                    log::warn!("offset: {}",offset);
                    server_offset
                } else {
                    log::warn!("base_block_offset_count: {}",base_block_offset_count + block_size);
                    base_block_offset_count
                };
                ReadWriteParam {
                    server_offset,
                    length,
                }
            })
            .collect();
        log::warn!("{:?}",result);

        result
    }

    pub async fn unlink_at(&self, path: &str) -> Result<c_long> {
        futures::join!(
            futures::future::join_all(
                self.clients
                    .iter()
                    .map(|client| { client.remove_file_block(self.context(), path.into()) })
            ),
            self.clients[self.distributor.locate_data(path)]
                .remove_metadata(self.context(), path.into())
        );
        Ok(0)
    }

    fn convert_cstr_to_path(&self, path: *const c_char) -> Result<&str> {
        let path = unsafe { CStr::from_ptr(path).to_str().map_err(|_| ForwardToKernel)? };
        let inner_path = self.get_inner_path(path);
        if let None = inner_path {
            return Err(Error::ForwardToKernel);
        }
        Ok(inner_path.unwrap())
    }
}

#[derive(Copy, Clone, Debug)]
struct ReadWriteParam {
    pub server_offset: usize,
    pub length: usize,
}

#[cfg(test)]
mod test {
    use super::*;

    async fn read(client: &BadfsClient, filename: &str, length: usize, offset: usize) {
        let mut vec: Vec<u8> = Vec::with_capacity(length);
        client.read_at(filename, offset, &mut *vec).await.unwrap();
    }

    async fn write(client: &BadfsClient, filename: &str, length: usize, offset: usize) {
        let mut vec: Vec<u8> = (0..1).cycle().take(length).collect();
        client.write_at(filename, offset, &mut *vec).await.unwrap();
    }

    #[tokio::test]
    async fn test_read() {
        let client = BadfsClient::new().await.unwrap();
        write(&client, "/filename", 1000, 0);
        write(&client, "/", 5, 36237);
        read(&client, "/", 10000, 36237);
        write(&client, "/", 5, 36237);
        read(&client, "/", 10000, 36237);
        write(&client, "/", 11, 0);
        read(&client, "/", 10000, 0);
        write(&client, "/", 11, 0);
        read(&client, "/", 10000, 0);
        write(&client, "/", 6, 5155);
        read(&client, "/", 10000, 5155);
        write(&client, "/", 6, 5155);
        read(&client, "/", 10000, 5155);
        read(&client, "/", 10000, 13107);
    }

    #[tokio::test]
    async fn test_write() {
        let client = BadfsClient::new().await.unwrap();
        const LEN: usize = 47008;
        let mut vector: Vec<u8> = (0..233).cycle().take(LEN * 5).collect();
        client
            .write_at("/QFR", 0, &mut vector[0..LEN])
            .await
            .unwrap();
        client
            .write_at("/QFR", LEN, &mut vector[LEN..2 * LEN])
            .await
            .unwrap();
        client
            .write_at("/QFR", LEN * 2, &mut vector[2 * LEN..3 * LEN])
            .await
            .unwrap();
        client
            .write_at("/QFR", LEN * 3, &mut vector[3 * LEN..4 * LEN])
            .await
            .unwrap();
        client
            .write_at("/QFR", LEN * 4, &mut vector[4 * LEN..5 * LEN])
            .await
            .unwrap();
        let mut buf = [0; 20];
        client.read_at("/QFR", 0, &mut buf).await.unwrap();
        // assert_eq!(&vector, &buf);
    }

    #[tokio::test]
    async fn test_access() {
        let mut client = BadfsClient {
            clients: vec![],
            rdma_connections: vec![],
            base_path: "".to_string(),
            fd_table: HashmapFDTable::new(),
            distributor: SimpleHashDistributor { host_num: 3 },
        };
        unsafe { client.clients.set_len(3) };
        let del = 47008;
        for i in 0..1000 {
            let ac = client.prepare_access_at(47008, i * del);
            for (id, d) in ac.iter().enumerate() {
                print!("{}->length:{}, server_offset:{}\t", id, d.length, d.server_offset)
            }
            println!()
        }
        unsafe { client.clients.set_len(0) };
    }
}
