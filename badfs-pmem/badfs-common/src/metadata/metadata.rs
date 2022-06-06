use crate::file::FileType;

/// this struct is File Metadata, as known as inode
/// https://zh.wikipedia.org/wiki/Inode
/// POSIX标准强制规范了文件系统的行为。每个“文件系统对象”必须具有：
///     以字节为单位表示的文件大小。
///     设备ID，标识容纳该文件的设备。
///     文件所有者的User ID。
///     文件的Group ID
///     文件的模式（mode），确定了文件的类型，以及它的所有者、它的group、其它用户访问此文件的权限。
///     额外的系统与用户标志（flag），用来保护该文件。
///     3个时间戳，记录了inode自身被修改（ctime, inode change time）、文件内容被修改（mtime, modification time）、最后一次访问（atime, access time）的时间。
///     1个链接数，表示有多少个硬链接指向此inode。
///     到文件系统存储位置的指针。通常是1K字节或者2K字节的存储容量为基本单位。
/// 使用stat系统调用可以查询一个文件的inode号码及一些元信息。
///
///
///
/// From https://www.cs.columbia.edu/~smb/classes/s06-4118/l21.pdf
///
/// In linux, the metadata is like the following struct
///
/// struct stat{
///     dev_t st_dev; /* device */
///     ino_t st_ino; /* inode */
///     mode_t st_mode; /* protection */
///     nlink_t st_nlink; /* number of hard links*/
///     uid_t st_uid; /* user ID of owner */
///     gid_t st_gid; /* group ID of owner */
///     dev_t st_rdev; /* device type (if inode*/
///     off_t st_size; /* total size, in bytes*/
///     blksize_t st_blksize; /* blocksize for filesystem*/
///     blkcnt_t st_blocks; /* number of blocks allocated*/
///     time_t st_atime; /* time of last access*/
///     time_t st_mtime; /* time of last modification*/
///     time_t st_ctime; /* time of last status*/
/// };
///
// MAY BE A PERFORMANCE ISSUE
// inappropriate memory alignment
// #[repr(packed)]
// #[derive(Debug, zerocopy::AsBytes, zerocopy::FromBytes, Clone)]
use serde::{Deserialize, Serialize};
pub const CHUNK_SIZE: usize = 0x80000;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Metadata {
    pub mode: u32,
    pub size: usize,
    pub time: i64,
}

impl Metadata {
    pub fn get_file_type(&self) -> FileType {
        if self.mode & libc::S_IFREG != 0 {
            return FileType::Regular;
        }
        FileType::Directory
    }
    pub fn set_stat(&self, stat: &mut libc::stat) {
        stat.st_dev = 0;
        stat.st_ino = 1;
        stat.st_nlink = 0;
        stat.st_mode = self.mode as _;
        stat.st_uid = 0;
        stat.st_gid = 0;
        stat.st_rdev = 0;
        stat.st_size = self.size as _;
        stat.st_blksize = CHUNK_SIZE as _;
        stat.st_blocks = 0;
        stat.st_atime = self.time as _;
        stat.st_atime_nsec = 0;
        stat.st_mtime = self.time as _;
        stat.st_mtime_nsec = 0;
        stat.st_ctime = self.time as _;
        stat.st_ctime_nsec = 0;
    }
}
