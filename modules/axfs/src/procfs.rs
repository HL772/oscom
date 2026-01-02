//! Minimal procfs placeholder.

use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

/// Root inode identifier for procfs.
pub const ROOT_ID: InodeId = 1;

const ROOT_FILE_TYPE: FileType = FileType::Dir;
const ROOT_MODE: u16 = 0o755;

#[derive(Clone, Copy)]
struct DirEntrySpec {
    ino: InodeId,
    name: &'static [u8],
    file_type: FileType,
}

const PROC_ENTRIES: [DirEntrySpec; 2] = [
    DirEntrySpec {
        ino: ROOT_ID,
        name: b".",
        file_type: FileType::Dir,
    },
    DirEntrySpec {
        ino: ROOT_ID,
        name: b"..",
        file_type: FileType::Dir,
    },
];

/// Minimal procfs implementation with only the root directory.
pub struct ProcFs;

impl ProcFs {
    /// Create a new procfs instance.
    pub const fn new() -> Self {
        Self
    }

}

impl VfsOps for ProcFs {
    fn root(&self) -> VfsResult<InodeId> {
        Ok(ROOT_ID)
    }

    fn lookup(&self, _parent: InodeId, _name: &str) -> VfsResult<Option<InodeId>> {
        Ok(None)
    }

    fn create(&self, _parent: InodeId, _name: &str, _kind: FileType, _mode: u16) -> VfsResult<InodeId> {
        Err(VfsError::NotSupported)
    }

    fn remove(&self, _parent: InodeId, _name: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata> {
        if inode == ROOT_ID {
            Ok(Metadata::new(ROOT_FILE_TYPE, 0, ROOT_MODE))
        } else {
            Err(VfsError::NotFound)
        }
    }

    fn read_at(&self, _inode: InodeId, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn write_at(&self, _inode: InodeId, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
        if inode != ROOT_ID {
            return Err(VfsError::NotDir);
        }
        fill_dir_entries(&PROC_ENTRIES, offset, entries)
    }
}

fn fill_dir_entries(list: &[DirEntrySpec], offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
    if offset >= list.len() {
        return Ok(0);
    }
    let mut written = 0usize;
    for spec in list.iter().skip(offset).take(entries.len()) {
        let mut entry = DirEntry::empty();
        entry.ino = spec.ino;
        entry.file_type = spec.file_type;
        entry.set_name(spec.name)?;
        entries[written] = entry;
        written += 1;
    }
    Ok(written)
}
