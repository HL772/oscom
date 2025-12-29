use core::cmp::min;

use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

pub const ROOT_ID: InodeId = 1;
pub const DEV_ID: InodeId = 2;
pub const DEV_NULL_ID: InodeId = 3;
pub const DEV_ZERO_ID: InodeId = 4;
pub const INIT_ID: InodeId = 5;
pub const PROC_ID: InodeId = 6;

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

const NODES: [Node; 6] = [
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
    Node {
        id: PROC_ID,
        parent: ROOT_ID,
        name: "proc",
        file_type: FileType::Dir,
        mode: 0o755,
    },
];

#[derive(Clone, Copy)]
struct DirEntrySpec {
    ino: InodeId,
    name: &'static [u8],
    file_type: FileType,
}

const ROOT_ENTRIES: [DirEntrySpec; 5] = [
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
        ino: DEV_ID,
        name: b"dev",
        file_type: FileType::Dir,
    },
    DirEntrySpec {
        ino: INIT_ID,
        name: b"init",
        file_type: FileType::File,
    },
    DirEntrySpec {
        ino: PROC_ID,
        name: b"proc",
        file_type: FileType::Dir,
    },
];

const DEV_ENTRIES: [DirEntrySpec; 4] = [
    DirEntrySpec {
        ino: DEV_ID,
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

const PROC_ENTRIES: [DirEntrySpec; 2] = [
    DirEntrySpec {
        ino: PROC_ID,
        name: b".",
        file_type: FileType::Dir,
    },
    DirEntrySpec {
        ino: ROOT_ID,
        name: b"..",
        file_type: FileType::Dir,
    },
];

pub struct MemFs<'a> {
    init_image: Option<&'a [u8]>,
}

impl<'a> MemFs<'a> {
    pub const fn new() -> Self {
        Self { init_image: None }
    }

    pub fn with_init_image(image: &'a [u8]) -> Self {
        Self {
            init_image: Some(image),
        }
    }

    fn node(&self, inode: InodeId) -> Option<&'static Node> {
        NODES.iter().find(|node| node.id == inode)
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
        let size = if inode == INIT_ID {
            self.init_image.map(|image| image.len() as u64).unwrap_or(0)
        } else {
            0
        };
        Some(Metadata::new(node.file_type, size, node.mode))
    }

    pub fn readlink(&self, inode: InodeId) -> VfsResult<&'static [u8]> {
        let node = self.node(inode).ok_or(VfsError::NotFound)?;
        if node.file_type != FileType::Symlink {
            return Err(VfsError::NotSupported);
        }
        Err(VfsError::NotSupported)
    }

    pub fn resolve_parent<'b>(&self, path: &'b str) -> Result<(InodeId, &'b str), ResolveError> {
        if !path.starts_with('/') {
            return Err(ResolveError::Invalid);
        }
        let trimmed = path.trim_end_matches('/');
        if trimmed == "/" {
            return Err(ResolveError::Invalid);
        }
        let mut current = ROOT_ID;
        let mut iter = trimmed.split('/').filter(|seg| !seg.is_empty()).peekable();
        let mut leaf = None;
        while let Some(segment) = iter.next() {
            if iter.peek().is_none() {
                let node = self.node(current).ok_or(ResolveError::NotFound)?;
                if node.file_type != FileType::Dir {
                    return Err(ResolveError::NotDir);
                }
                leaf = Some(segment);
                break;
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
        let name = leaf.ok_or(ResolveError::Invalid)?;
        if name == "." || name == ".." {
            return Err(ResolveError::Invalid);
        }
        Ok((current, name))
    }
}

impl<'a> VfsOps for MemFs<'a> {
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

    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        match inode {
            INIT_ID => {
                let image = match self.init_image {
                    Some(image) => image,
                    None => return Err(VfsError::NotSupported),
                };
                let offset = offset as usize;
                if offset >= image.len() {
                    return Ok(0);
                }
                let to_read = min(buf.len(), image.len() - offset);
                buf[..to_read].copy_from_slice(&image[offset..offset + to_read]);
                Ok(to_read)
            }
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
        let list = match inode {
            ROOT_ID => &ROOT_ENTRIES[..],
            DEV_ID => &DEV_ENTRIES[..],
            PROC_ID => &PROC_ENTRIES[..],
            _ => return Err(VfsError::NotDir),
        };
        fill_dir_entries(list, offset, entries)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_paths() {
        let fs = MemFs::new();
        assert_eq!(fs.resolve_path("/").unwrap(), ROOT_ID);
        assert_eq!(fs.resolve_path("/dev/null").unwrap(), DEV_NULL_ID);
        assert_eq!(fs.resolve_path("/dev/zero").unwrap(), DEV_ZERO_ID);
        assert_eq!(fs.resolve_path("/init").unwrap(), INIT_ID);
        assert_eq!(fs.resolve_path("/proc").unwrap(), PROC_ID);
        assert_eq!(fs.resolve_path("dev").unwrap_err(), ResolveError::Invalid);
        assert_eq!(fs.resolve_path("/init/child").unwrap_err(), ResolveError::NotDir);
    }

    #[test]
    fn metadata_basics() {
        let fs = MemFs::new();
        let root_meta = fs.metadata_for(ROOT_ID).unwrap();
        assert_eq!(root_meta.file_type, FileType::Dir);
        assert_eq!(root_meta.mode, 0o755);
        let init_meta = fs.metadata_for(INIT_ID).unwrap();
        assert_eq!(init_meta.file_type, FileType::File);
        assert_eq!(init_meta.size, 0);
        let proc_meta = fs.metadata_for(PROC_ID).unwrap();
        assert_eq!(proc_meta.file_type, FileType::Dir);
    }

    #[test]
    fn init_read_uses_image() {
        let image = b"init";
        let fs = MemFs::with_init_image(image);
        let mut buf = [0u8; 8];
        let read = fs.read_at(INIT_ID, 0, &mut buf).unwrap();
        assert_eq!(read, 4);
        assert_eq!(&buf[..4], image);
        let meta = fs.metadata_for(INIT_ID).unwrap();
        assert_eq!(meta.size, 4);
    }

    #[test]
    fn dev_nodes_read() {
        let fs = MemFs::new();
        let mut buf = [0x5a_u8; 4];
        let read = fs.read_at(DEV_NULL_ID, 0, &mut buf).unwrap();
        assert_eq!(read, 0);
        let read = fs.read_at(DEV_ZERO_ID, 0, &mut buf).unwrap();
        assert_eq!(read, 4);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn dev_nodes_write() {
        let fs = MemFs::new();
        let buf = [0x5a_u8; 4];
        let written = fs.write_at(DEV_NULL_ID, 0, &buf).unwrap();
        assert_eq!(written, 4);
        let written = fs.write_at(DEV_ZERO_ID, 0, &buf).unwrap();
        assert_eq!(written, 4);
    }

    #[test]
    fn resolve_parent_paths() {
        let fs = MemFs::new();
        let (parent, name) = fs.resolve_parent("/dev/null").unwrap();
        assert_eq!(parent, DEV_ID);
        assert_eq!(name, "null");
        let (parent, name) = fs.resolve_parent("/missing").unwrap();
        assert_eq!(parent, ROOT_ID);
        assert_eq!(name, "missing");
        let (parent, name) = fs.resolve_parent("/dev/").unwrap();
        assert_eq!(parent, ROOT_ID);
        assert_eq!(name, "dev");
        let (parent, name) = fs.resolve_parent("/dev/../init").unwrap();
        assert_eq!(parent, ROOT_ID);
        assert_eq!(name, "init");
        assert_eq!(fs.resolve_parent("/").unwrap_err(), ResolveError::Invalid);
        assert_eq!(fs.resolve_parent("/dev/..").unwrap_err(), ResolveError::Invalid);
        assert_eq!(
            fs.resolve_parent("/dev/null/child").unwrap_err(),
            ResolveError::NotDir
        );
    }
}
