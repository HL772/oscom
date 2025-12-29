use axvfs::{FileType, InodeId, VfsError, VfsOps, VfsResult};

pub const MAX_PATH_DEPTH: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountId {
    Root,
    Dev,
    Proc,
}

pub struct MountPoint<'a> {
    pub id: MountId,
    pub path: &'a str,
    pub fs: &'a dyn VfsOps,
}

impl<'a> MountPoint<'a> {
    pub fn new(id: MountId, path: &'a str, fs: &'a dyn VfsOps) -> Self {
        Self { id, path, fs }
    }
}

pub struct MountTable<'a, const N: usize> {
    mounts: [MountPoint<'a>; N],
}

impl<'a, const N: usize> MountTable<'a, N> {
    pub fn new(mounts: [MountPoint<'a>; N]) -> Self {
        Self { mounts }
    }

    pub fn resolve_path(&self, path: &str) -> VfsResult<(MountId, InodeId)> {
        let (mount, rel) = self.find_mount(path)?;
        let inode = resolve_path_fs(mount.fs, rel)?;
        Ok((mount.id, inode))
    }

    pub fn resolve_parent<'p>(&self, path: &'p str) -> VfsResult<(MountId, InodeId, &'p str)> {
        if !path.starts_with('/') {
            return Err(VfsError::Invalid);
        }
        let trimmed = path.trim_end_matches('/');
        if trimmed == "/" {
            return Err(VfsError::Invalid);
        }
        let split = trimmed.rfind('/').ok_or(VfsError::Invalid)?;
        let (parent, name) = trimmed.split_at(split);
        let name = &name[1..];
        if name.is_empty() || name == "." || name == ".." {
            return Err(VfsError::Invalid);
        }
        let parent_path = if parent.is_empty() { "/" } else { parent };
        let (mount, rel) = self.find_mount(parent_path)?;
        let inode = resolve_path_fs(mount.fs, rel)?;
        Ok((mount.id, inode, name))
    }

    pub fn fs_for(&self, id: MountId) -> Option<&'a dyn VfsOps> {
        self.mounts.iter().find(|mount| mount.id == id).map(|mount| mount.fs)
    }

    fn find_mount<'p>(&self, path: &'p str) -> VfsResult<(&MountPoint<'a>, &'p str)> {
        if !path.starts_with('/') {
            return Err(VfsError::Invalid);
        }
        let mut best: Option<(&MountPoint<'a>, &str)> = None;
        for mount in &self.mounts {
            if let Some(rel) = match_mount_path(mount.path, path) {
                let replace = match best {
                    None => true,
                    Some((best_mount, _)) => mount.path.len() > best_mount.path.len(),
                };
                if replace {
                    best = Some((mount, rel));
                }
            }
        }
        best.ok_or(VfsError::NotFound)
    }
}

fn match_mount_path<'a>(mount_path: &str, path: &'a str) -> Option<&'a str> {
    if mount_path == "/" {
        return Some(path);
    }
    if path == mount_path {
        return Some("/");
    }
    if path.starts_with(mount_path) {
        let rest = &path[mount_path.len()..];
        if rest.starts_with('/') {
            return Some(rest);
        }
    }
    None
}

fn resolve_path_fs(fs: &dyn VfsOps, path: &str) -> VfsResult<InodeId> {
    let root = fs.root()?;
    if path.is_empty() || path == "/" {
        return Ok(root);
    }
    let mut current = root;
    let mut stack = [root; MAX_PATH_DEPTH];
    let mut depth = 1usize;
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            if depth > 1 {
                depth -= 1;
                current = stack[depth - 1];
            }
            continue;
        }
        let meta = fs.metadata(current)?;
        if meta.file_type != FileType::Dir {
            return Err(VfsError::NotDir);
        }
        let next = fs.lookup(current, segment)?.ok_or(VfsError::NotFound)?;
        current = next;
        if depth >= MAX_PATH_DEPTH {
            return Err(VfsError::Invalid);
        }
        stack[depth] = current;
        depth += 1;
    }
    if path.len() > 1 && path.ends_with('/') {
        let meta = fs.metadata(current)?;
        if meta.file_type != FileType::Dir {
            return Err(VfsError::NotDir);
        }
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{devfs, memfs, procfs};

    #[test]
    fn resolve_mount_paths() {
        let rootfs = memfs::MemFs::new();
        let devfs = devfs::DevFs::new();
        let procfs = procfs::ProcFs::new();
        let mounts = MountTable::new([
            MountPoint::new(MountId::Root, "/", &rootfs),
            MountPoint::new(MountId::Dev, "/dev", &devfs),
            MountPoint::new(MountId::Proc, "/proc", &procfs),
        ]);
        let (mount, inode) = mounts.resolve_path("/").unwrap();
        assert_eq!(mount, MountId::Root);
        assert_eq!(inode, memfs::ROOT_ID);
        let (mount, inode) = mounts.resolve_path("/init").unwrap();
        assert_eq!(mount, MountId::Root);
        assert_eq!(inode, memfs::INIT_ID);
        let (mount, inode) = mounts.resolve_path("/dev").unwrap();
        assert_eq!(mount, MountId::Dev);
        assert_eq!(inode, devfs::ROOT_ID);
        let (mount, inode) = mounts.resolve_path("/dev/null").unwrap();
        assert_eq!(mount, MountId::Dev);
        assert_eq!(inode, devfs::DEV_NULL_ID);
        let (mount, inode) = mounts.resolve_path("/proc").unwrap();
        assert_eq!(mount, MountId::Proc);
        assert_eq!(inode, procfs::ROOT_ID);
    }

    #[test]
    fn resolve_parent_paths() {
        let rootfs = memfs::MemFs::new();
        let devfs = devfs::DevFs::new();
        let procfs = procfs::ProcFs::new();
        let mounts = MountTable::new([
            MountPoint::new(MountId::Root, "/", &rootfs),
            MountPoint::new(MountId::Dev, "/dev", &devfs),
            MountPoint::new(MountId::Proc, "/proc", &procfs),
        ]);
        let (mount, parent, name) = mounts.resolve_parent("/dev/null").unwrap();
        assert_eq!(mount, MountId::Dev);
        assert_eq!(parent, devfs::ROOT_ID);
        assert_eq!(name, "null");
        let (mount, parent, name) = mounts.resolve_parent("/proc").unwrap();
        assert_eq!(mount, MountId::Root);
        assert_eq!(parent, memfs::ROOT_ID);
        assert_eq!(name, "proc");
    }
}
