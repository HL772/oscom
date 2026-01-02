//! Device filesystem with basic /dev/null and /dev/zero.

use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

/// Root inode identifier for devfs.
pub const ROOT_ID: InodeId = 1;
/// Inode identifier for /dev/null.
pub const DEV_NULL_ID: InodeId = 2;
/// Inode identifier for /dev/zero.
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

#[derive(Clone, Copy)]
struct DirEntrySpec {
    ino: InodeId,
    name: &'static [u8],
    file_type: FileType,
}

const DEV_ENTRIES: [DirEntrySpec; 4] = [
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
    DirEntrySpec {
        ino: DEV_NULL_ID,
        name: b"null",
        file_type: FileType::Char,
    },
    DirEntrySpec {
        ino: DEV_ZERO_ID,
        name: b"zero",
        file_type: FileType::Char,
    },
];

/// Simple devfs implementation with fixed nodes.
pub struct DevFs;

impl DevFs {
    /// Create a new devfs instance.
    pub const fn new() -> Self {
        Self
    }

    fn node(&self, inode: InodeId) -> Option<&'static Node> {
        NODES.iter().find(|node| node.id == inode)
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

    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
        if inode != ROOT_ID {
            return Err(VfsError::NotDir);
        }
        fill_dir_entries(&DEV_ENTRIES, offset, entries)
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
