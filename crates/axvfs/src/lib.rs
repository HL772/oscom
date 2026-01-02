#![no_std]
//! Minimal VFS traits and shared filesystem types.

// Early VFS trait scaffold: use lightweight inode handles to avoid allocator use.

/// Inode identifier used by VFS implementations.
pub type InodeId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Errors returned by VFS operations.
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

/// Result type for VFS operations.
pub type VfsResult<T> = core::result::Result<T, VfsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// File type identifiers used by VFS metadata.
pub enum FileType {
    File,
    Dir,
    Char,
    Block,
    Fifo,
    Socket,
    Symlink,
}

/// Maximum directory entry name length.
pub const MAX_NAME_LEN: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Directory entry returned by read_dir.
pub struct DirEntry {
    /// Inode identifier for this entry.
    pub ino: InodeId,
    /// File type for this entry.
    pub file_type: FileType,
    /// Length of the name in bytes.
    pub name_len: u8,
    /// Name bytes (unused bytes are zero).
    pub name: [u8; MAX_NAME_LEN],
}

impl DirEntry {
    /// Construct an empty directory entry.
    pub const fn empty() -> Self {
        Self {
            ino: 0,
            file_type: FileType::File,
            name_len: 0,
            name: [0; MAX_NAME_LEN],
        }
    }

    /// Set the directory entry name from a byte slice.
    pub fn set_name(&mut self, name: &[u8]) -> VfsResult<()> {
        if name.len() > MAX_NAME_LEN {
            return Err(VfsError::Invalid);
        }
        let len = name.len();
        self.name[..len].copy_from_slice(name);
        self.name_len = len as u8;
        Ok(())
    }

    /// Return the entry name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Basic file metadata returned by VFS backends.
pub struct Metadata {
    /// File type.
    pub file_type: FileType,
    /// File size in bytes.
    pub size: u64,
    /// Mode bits (permission + type).
    pub mode: u16,
}

impl Metadata {
    /// Construct metadata with the provided fields.
    pub const fn new(file_type: FileType, size: u64, mode: u16) -> Self {
        Self { file_type, size, mode }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Seek origin used by file operations.
pub enum SeekWhence {
    Set,
    Cur,
    End,
}

/// Filesystem operations exposed to the kernel VFS layer.
pub trait VfsOps {
    /// Return the root inode identifier.
    fn root(&self) -> VfsResult<InodeId>;
    /// Lookup a child name under the given parent inode.
    fn lookup(&self, parent: InodeId, name: &str) -> VfsResult<Option<InodeId>>;
    /// Create a new inode under the parent.
    fn create(&self, parent: InodeId, name: &str, kind: FileType, mode: u16) -> VfsResult<InodeId>;
    /// Remove a child entry under the parent.
    fn remove(&self, parent: InodeId, name: &str) -> VfsResult<()>;
    /// Return metadata for an inode.
    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata>;
    /// Read data from an inode at the given offset.
    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize>;
    /// Write data to an inode at the given offset.
    fn write_at(&self, inode: InodeId, offset: u64, buf: &[u8]) -> VfsResult<usize>;
    /// Enumerate directory entries for an inode.
    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize>;
    /// Flush pending data to stable storage.
    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
    /// Truncate a file to the given size.
    fn truncate(&self, _inode: InodeId, _size: u64) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }
}

/// Optional file-oriented operations for file-like handles.
pub trait FileOps {
    /// Read from the file into the provided buffer.
    fn read(&mut self, buf: &mut [u8]) -> VfsResult<usize>;
    /// Write data from the provided buffer.
    fn write(&mut self, buf: &[u8]) -> VfsResult<usize>;
    /// Seek to a new offset using the provided origin.
    fn seek(&mut self, offset: i64, whence: SeekWhence) -> VfsResult<u64>;
    /// Return metadata for this file handle.
    fn metadata(&self) -> VfsResult<Metadata>;
}
