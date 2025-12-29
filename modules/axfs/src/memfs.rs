use axvfs::{FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;

pub const ROOT_ID: InodeId = 1;
pub const DEV_ID: InodeId = 2;
pub const DEV_NULL_ID: InodeId = 3;
pub const DEV_ZERO_ID: InodeId = 4;
pub const INIT_ID: InodeId = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    NotFound,
    NotDir,
    Invalid,
}

#[derive(Clone, Copy)]
struct Node {
    id: InodeId,
    parent: InodeId,
    name: &'static str,
    file_type: FileType,
    mode: u16,
}

const NODES: [Node; 5] = [
    Node {
        id: ROOT_ID,
        parent: ROOT_ID,
        name: "",
        file_type: FileType::Dir,
        mode: 0o755,
    },
    Node {
        id: DEV_ID,
        parent: ROOT_ID,
        name: "dev",
        file_type: FileType::Dir,
        mode: 0o755,
    },
    Node {
        id: DEV_NULL_ID,
        parent: DEV_ID,
        name: "null",
        file_type: FileType::Char,
        mode: 0o666,
    },
    Node {
        id: DEV_ZERO_ID,
        parent: DEV_ID,
        name: "zero",
        file_type: FileType::Char,
        mode: 0o666,
    },
    Node {
        id: INIT_ID,
        parent: ROOT_ID,
        name: "init",
        file_type: FileType::File,
        mode: 0o444,
    },
];

#[derive(Clone, Copy)]
pub struct DirEntry {
    pub ino: InodeId,
    pub name: &'static [u8],
    pub dtype: u8,
}

const ROOT_ENTRIES: [DirEntry; 4] = [
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
        ino: DEV_ID,
        name: b"dev",
        dtype: DT_DIR,
    },
    DirEntry {
        ino: INIT_ID,
        name: b"init",
        dtype: DT_REG,
    },
];

const DEV_ENTRIES: [DirEntry; 4] = [
    DirEntry {
        ino: DEV_ID,
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

pub struct MemFs;

impl MemFs {
    pub const fn new() -> Self {
        Self
    }

    fn node(&self, inode: InodeId) -> Option<&'static Node> {
        NODES.iter().find(|node| node.id == inode)
    }

    pub fn dir_entries(&self, inode: InodeId) -> Option<&'static [DirEntry]> {
        match inode {
            ROOT_ID => Some(&ROOT_ENTRIES),
            DEV_ID => Some(&DEV_ENTRIES),
            _ => None,
        }
    }

    pub fn resolve_path(&self, path: &str) -> Result<InodeId, ResolveError> {
        if !path.starts_with('/') {
            return Err(ResolveError::Invalid);
        }
        if path == "/" {
            return Ok(ROOT_ID);
        }
        let mut current = ROOT_ID;
        for segment in path.split('/') {
            if segment.is_empty() {
                continue;
            }
            if segment == "." {
                continue;
            }
            if segment == ".." {
                let node = self.node(current).ok_or(ResolveError::NotFound)?;
                current = node.parent;
                continue;
            }
            let node = self.node(current).ok_or(ResolveError::NotFound)?;
            if node.file_type != FileType::Dir {
                return Err(ResolveError::NotDir);
            }
            match self.lookup(current, segment) {
                Ok(Some(next)) => current = next,
                Ok(None) => return Err(ResolveError::NotFound),
                Err(_) => return Err(ResolveError::NotFound),
            }
        }
        Ok(current)
    }

    pub fn metadata_for(&self, inode: InodeId) -> Option<Metadata> {
        let node = self.node(inode)?;
        Some(Metadata::new(node.file_type, 0, node.mode))
    }
}

impl VfsOps for MemFs {
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
        self.metadata_for(inode).ok_or(VfsError::NotFound)
    }

    fn read_at(&self, _inode: InodeId, _offset: u64, _buf: &mut [u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn write_at(&self, _inode: InodeId, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }
}
