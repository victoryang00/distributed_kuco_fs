use bytes::BufMut;
use serde::{Deserialize, Serialize};

#[repr(u8)]
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq)]
pub enum FileType {
    Regular = libc::DT_REG,
    Directory = libc::DT_DIR,
}

pub enum SomethingOpen {
    OpenFile(OpenFile),
    OpenDir(OpenDir),
}

impl SomethingOpen {
    pub fn is_readable(&self) -> bool {
        match self {
            SomethingOpen::OpenFile(f) => f.is_readable(),
            SomethingOpen::OpenDir(d) => d.is_readable(),
        }
    }
    pub fn is_writable(&self) -> bool {
        match self {
            SomethingOpen::OpenFile(f) => f.is_writable(),
            SomethingOpen::OpenDir(d) => d.is_writable(),
        }
    }
    pub fn offset(&self) -> usize {
        match self {
            SomethingOpen::OpenFile(f) => f.offset(),
            SomethingOpen::OpenDir(d) => d.offset(),
        }
    }
    pub fn path(&self) -> &str {
        match self {
            SomethingOpen::OpenFile(f) => f.path(),
            SomethingOpen::OpenDir(d) => d.path(),
        }
    }
    pub fn set_offset(&mut self, offset: usize) {
        match self {
            SomethingOpen::OpenFile(f) => f.offset = offset,
            SomethingOpen::OpenDir(_) => todo!(),
        }
    }
    pub fn add_offset(&mut self, delta: isize) {
        match self {
            SomethingOpen::OpenFile(f) => f.add_offset(delta),
            SomethingOpen::OpenDir(d) => d.add_offset(delta),
        }
    }
    pub fn as_dir<'x>(&mut self) -> &mut OpenDir {
        match self {
            SomethingOpen::OpenFile(_) => todo!(),
            SomethingOpen::OpenDir(d) => return d,
        }
    }
}

/// OpenFile
/// path: the identifier of the file (which will used in rpc parameters)
/// flags: the flags parameter of open()
/// mode: read only mode / write only mode / read and write mode
/// offset: the offset of file pointer, updated after read and write or updated directly by lseek
pub struct OpenFile {
    path: String,
    flags: i32,
    offset: usize,
}

/// OpenDir
/// path: the identifier of the directory (which will used in rpc parameters)
/// flags: the flags parameter of open()
/// entries: the files and directories that in the current directory
pub struct OpenDir {
    path: String,
    flags: i32,
    entries: DirEntries,
}

impl OpenFile {
    pub fn new(path: &str, flags: i32) -> Self {
        OpenFile {
            path: path.to_owned(),
            flags,
            offset: 0,
        }
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn flags(&self) -> i32 {
        self.flags
    }
    pub fn set_flags(&mut self, flags: i32) {
        self.flags |= flags;
    }
    pub fn is_readable(&self) -> bool {
        self.flags & 0b11 == libc::O_RDONLY | libc::O_RDWR
    }
    pub fn is_writable(&self) -> bool {
        self.flags & 0b11 == libc::O_WRONLY | libc::O_RDWR
    }
    pub fn offset(&self) -> usize {
        self.offset
    }
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset
    }
    pub fn add_offset(&mut self, delta: isize) {
        self.offset = (self.offset as isize + delta) as usize
    }
}

impl OpenDir {
    /// new: create a open directory instance
    /// entries: the entries in the directory
    pub fn new(path: &str, flags: i32, entries: DirEntries) -> Self {
        OpenDir {
            path: path.to_owned(),
            flags,
            entries,
        }
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn is_readable(&self) -> bool {
        self.flags & 0b11 == libc::O_RDONLY | libc::O_RDWR
    }
    pub fn is_writable(&self) -> bool {
        self.flags & 0b11 == libc::O_WRONLY | libc::O_RDWR
    }
    pub fn offset(&self) -> usize {
        self.entries.offset
    }
    pub fn add_offset(&mut self, delta: isize) {
        self.entries.offset = (self.entries.offset as isize + delta) as usize
    }

    pub fn peek_entry(&mut self) -> Option<(FileType, &str)> {
        let mut iter = unsafe { self.entries.iter_at(self.entries.offset) };
        iter.next()
    }

    pub fn move_next(&mut self) {
        let mut iter = unsafe { self.entries.iter_at(self.entries.offset) };
        iter.next();
        self.entries.offset = *iter.offset;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntries {
    #[serde(with = "serde_bytes")]
    buf: Vec<u8>,
    offset: usize,
}

impl DirEntries {
    pub fn new() -> DirEntries {
        DirEntries {
            buf: Vec::new(),
            offset: 0,
        }
    }
    pub fn iter(&mut self) -> DirEntriesIterator {
        DirEntriesIterator {
            buf: &*self.buf,
            offset: &mut self.offset,
        }
    }
    pub unsafe fn iter_at(&mut self, offset: usize) -> DirEntriesIterator {
        self.offset = offset;
        DirEntriesIterator {
            buf: &self.buf[offset..],
            offset: &mut self.offset,
        }
    }
    /// Push a directory entry.
    pub fn push(&mut self, name: &str, file_type: FileType) {
        debug_assert!(name.len() <= 255);
        self.buf.put_u8(file_type as u8);
        self.buf.put_u8(name.len() as u8);
        self.buf.put_slice(name.as_bytes());
    }
}

impl From<Vec<u8>> for DirEntries {
    fn from(vec: Vec<u8>) -> Self {
        DirEntries {
            buf: vec,
            offset: 0,
        }
    }
}

pub struct DirEntriesIterator<'a> {
    buf: &'a [u8],
    offset: &'a mut usize,
}

impl<'a> Iterator for DirEntriesIterator<'a> {
    type Item = (FileType, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if *self.offset >= self.buf.len() {
            return None;
        }
        let file_type = unsafe { std::mem::transmute::<u8, FileType>(self.buf[*self.offset]) };
        *self.offset += 1;
        let file_name_length = self.buf[*self.offset] as usize;
        *self.offset += 1;
        let name = unsafe {
            std::str::from_utf8_unchecked(&self.buf[*self.offset..*self.offset + file_name_length])
        };
        Some((file_type, name))
    }
}
