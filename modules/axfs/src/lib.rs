#![no_std]

pub mod devfs;
pub mod memfs;
pub mod mount;
pub mod procfs;

pub use axvfs::{FileType, InodeId, Metadata, VfsError, VfsOps};

#[cfg(test)]
extern crate std;
