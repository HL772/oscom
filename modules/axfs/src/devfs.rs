use axvfs::{FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

use crate::memfs::{DirEntry, DT_CHR, DT_DIR};

pub const ROOT_ID: InodeId = 1;
pub const DEV_NULL_ID: InodeId = 2;
pub const DEV_ZERO_ID: InodeId = 3;

#[derive(Clone, Copy)]
struct Node {
    id: InodeId,
    parent: InodeId,
    name: &'static str,
    file_type: FileType,
    mode: u16,
}

const NODES: [Node; 3] = [
    Node {
        id: ROOT_ID,
        parent: ROOT_ID,
        name: "",
        file_type: FileType::Dir,
        mode: 0o755,
    },
    Node {
        id: DEV_NULL_ID,
        parent: ROOT_ID,
        name: "null",
        file_type: FileType::Char,
        mode: 0o666,
    },
    Node {
        id: DEV_ZERO_ID,
        parent: ROOT_ID,
        name: "zero",
        file_type: FileType::Char,
        mode: 0o666,
    },
];

const DEV_ENTRIES: [DirEntry; 4] = [
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
    DirEntry {
        ino: DEV_NULL_ID,
        name: b"null",
        dtype: DT_CHR,
    },
    DirEntry {
        ino: DEV_ZERO_ID,
        name: b"zero",
        dtype: DT_CHR,
    },
];

pub struct DevFs;

impl DevFs {
    pub const fn new() -> Self {
        Self
    }

    fn node(&self, inode: InodeId) -> Option<&'static Node> {
        NODES.iter().find(|node| node.id == inode)
    }

    pub fn dir_entries(&self, inode: InodeId) -> Option<&'static [DirEntry]> {
        match inode {
            ROOT_ID => Some(&DEV_ENTRIES),
            _ => None,
        }
    }
}

impl VfsOps for DevFs {
    fn root(&self) -> VfsResult<InodeId> {
        Ok(ROOT_ID)
    }

    fn lookup(&self, parent: InodeId, name: &str) -> VfsResult<Option<InodeId>> {
        if let Some(node) = NODES.iter().find(|node| node.parent == parent && node.name == name) {
            Ok(Some(node.id))
        } else {
            Ok(None)
        }
    }

    fn create(&self, _parent: InodeId, _name: &str, _kind: FileType, _mode: u16) -> VfsResult<InodeId> {
        Err(VfsError::NotSupported)
    }

    fn remove(&self, _parent: InodeId, _name: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata> {
        let node = self.node(inode).ok_or(VfsError::NotFound)?;
        Ok(Metadata::new(node.file_type, 0, node.mode))
    }

    fn read_at(&self, inode: InodeId, _offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        match inode {
            DEV_ZERO_ID => {
                buf.fill(0);
                Ok(buf.len())
            }
            DEV_NULL_ID => Ok(0),
            _ => Err(VfsError::NotSupported),
        }
    }

    fn write_at(&self, inode: InodeId, _offset: u64, buf: &[u8]) -> VfsResult<usize> {
        match inode {
            DEV_NULL_ID | DEV_ZERO_ID => Ok(buf.len()),
            _ => Err(VfsError::NotSupported),
        }
    }
}
