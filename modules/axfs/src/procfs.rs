use axvfs::{FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

use crate::memfs::{DirEntry, DT_DIR};

pub const ROOT_ID: InodeId = 1;

const ROOT_FILE_TYPE: FileType = FileType::Dir;
const ROOT_MODE: u16 = 0o755;

const PROC_ENTRIES: [DirEntry; 2] = [
    DirEntry {
        ino: ROOT_ID,
        name: b".",
        dtype: DT_DIR,
    },
    DirEntry {
        ino: ROOT_ID,
        name: b"..",
        dtype: DT_DIR,
    },
];

pub struct ProcFs;

impl ProcFs {
    pub const fn new() -> Self {
        Self
    }

    pub fn dir_entries(&self, inode: InodeId) -> Option<&'static [DirEntry]> {
        match inode {
            ROOT_ID => Some(&PROC_ENTRIES),
            _ => None,
        }
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
}
