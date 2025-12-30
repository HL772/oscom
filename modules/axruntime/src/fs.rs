use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axfs::block::{BlockDevice, BlockId};
use axfs::{fat32, VfsError, VfsResult};

use crate::mm::MemoryRegion;
use crate::virtio_blk;

const ROOTFS_BLOCK_SIZE: usize = 512;
const ROOTFS_IMAGE_MAX: usize = 16 * 1024;

static ROOTFS_READY: AtomicBool = AtomicBool::new(false);
static ROOTFS_SIZE: AtomicUsize = AtomicUsize::new(0);
// SAFETY: 单核早期阶段初始化一次，后续只读。
static mut ROOTFS_IMAGE: [u8; ROOTFS_IMAGE_MAX] = [0; ROOTFS_IMAGE_MAX];

#[derive(Clone, Copy)]
pub struct RootFsDevice {
    image: &'static [u8],
}

impl RootFsDevice {
    pub fn new() -> Self {
        Self {
            image: rootfs_image(),
        }
    }
}

impl BlockDevice for RootFsDevice {
    fn block_size(&self) -> usize {
        ROOTFS_BLOCK_SIZE
    }

    fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        let offset = block_id as usize * ROOTFS_BLOCK_SIZE;
        if offset + ROOTFS_BLOCK_SIZE > self.image.len() || buf.len() < ROOTFS_BLOCK_SIZE {
            return Err(VfsError::NotFound);
        }
        buf[..ROOTFS_BLOCK_SIZE]
            .copy_from_slice(&self.image[offset..offset + ROOTFS_BLOCK_SIZE]);
        Ok(())
    }

    fn write_block(&self, _block_id: BlockId, _buf: &[u8]) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
}

pub enum RootBlockDevice {
    Virtio(&'static virtio_blk::VirtioBlkDevice),
    Ramdisk(RootFsDevice),
}

impl RootBlockDevice {
    pub fn as_block_device(&self) -> &dyn BlockDevice {
        match self {
            Self::Virtio(dev) => *dev,
            Self::Ramdisk(dev) => dev,
        }
    }
}

pub fn init(virtio_mmio: &[MemoryRegion]) {
    virtio_blk::init(virtio_mmio);
}

pub fn root_device() -> RootBlockDevice {
    if let Some(dev) = virtio_blk::device() {
        RootBlockDevice::Virtio(dev)
    } else {
        RootBlockDevice::Ramdisk(RootFsDevice::new())
    }
}

fn rootfs_image() -> &'static [u8] {
    if !ROOTFS_READY.load(Ordering::Acquire) {
        // SAFETY: 单核启动阶段初始化 rootfs 镜像。
        unsafe {
            let size = fat32::build_minimal_image(
                &mut ROOTFS_IMAGE,
                "init",
                crate::user::init_exec_elf_image(),
            )
            .unwrap_or(0);
            ROOTFS_SIZE.store(size, Ordering::Release);
            ROOTFS_READY.store(true, Ordering::Release);
        }
    }
    let size = ROOTFS_SIZE.load(Ordering::Acquire);
    // SAFETY: ROOTFS_IMAGE 在上方初始化后只读。
    unsafe { &ROOTFS_IMAGE[..size] }
}
