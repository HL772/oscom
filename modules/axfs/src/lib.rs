#![no_std]

pub mod memfs;

pub use axvfs::{FileType, InodeId, Metadata};

#[cfg(test)]
extern crate std;
