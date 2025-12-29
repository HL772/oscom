#![no_std]

pub mod block;
pub mod devfs;
pub mod fat32;
pub mod ext4;
pub mod memfs;
pub mod mount;
pub mod procfs;

pub use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult, MAX_NAME_LEN};

#[cfg(test)]
extern crate std;
