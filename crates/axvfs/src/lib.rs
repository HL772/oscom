#![no_std]

// Early VFS trait scaffold: use lightweight inode handles to avoid allocator use.

pub type InodeId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsError {
    NotFound,
    NotDir,
    AlreadyExists,
    Invalid,
    NoMem,
    NotSupported,
    Io,
    Permission,
    Busy,
    Unknown,
}

pub type VfsResult<T> = core::result::Result<T, VfsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileType {
    File,
    Dir,
    Char,
    Block,
    Fifo,
    Socket,
    Symlink,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub file_type: FileType,
    pub size: u64,
    pub mode: u16,
}

impl Metadata {
    pub const fn new(file_type: FileType, size: u64, mode: u16) -> Self {
        Self { file_type, size, mode }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeekWhence {
    Set,
    Cur,
    End,
}

pub trait VfsOps {
    fn root(&self) -> VfsResult<InodeId>;
    fn lookup(&self, parent: InodeId, name: &str) -> VfsResult<Option<InodeId>>;
    fn create(&self, parent: InodeId, name: &str, kind: FileType, mode: u16) -> VfsResult<InodeId>;
    fn remove(&self, parent: InodeId, name: &str) -> VfsResult<()>;
    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata>;
    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;
    fn write_at(&self, inode: InodeId, offset: u64, buf: &[u8]) -> VfsResult<usize>;
}

pub trait FileOps {
    fn read(&mut self, buf: &mut [u8]) -> VfsResult<usize>;
    fn write(&mut self, buf: &[u8]) -> VfsResult<usize>;
    fn seek(&mut self, offset: i64, whence: SeekWhence) -> VfsResult<u64>;
    fn metadata(&self) -> VfsResult<Metadata>;
}
