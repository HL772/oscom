//! 根文件系统设备选择与内存盘辅助。

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use axfs::block::{BlockDevice, BlockId};
use axfs::{fat32, VfsError, VfsResult};

use crate::dtb::VirtioMmioDevice;
use crate::virtio_blk;

const ROOTFS_BLOCK_SIZE: usize = 512;
const ROOTFS_IMAGE_MAX: usize = 16 * 1024;

static ROOTFS_READY: AtomicBool = AtomicBool::new(false);
static ROOTFS_SIZE: AtomicUsize = AtomicUsize::new(0);
// 安全性： 单核早期阶段初始化一次，后续只读。
static mut ROOTFS_IMAGE: [u8; ROOTFS_IMAGE_MAX] = [0; ROOTFS_IMAGE_MAX];
static ROOT_DEVICE_READY: AtomicBool = AtomicBool::new(false);
// 安全性： 单核早期阶段初始化一次，后续只读。
static mut ROOT_DEVICE: MaybeUninit<RootBlockDevice> = MaybeUninit::uninit();

#[derive(Clone, Copy)]
/// 初始 rootfs 的内存盘块设备。
pub struct RootFsDevice {
    size: usize,
}

impl RootFsDevice {
    /// 基于内嵌镜像构造内存盘设备。
    pub fn new() -> Self {
        let image = rootfs_image();
        Self { size: image.len() }
    }
}

impl BlockDevice for RootFsDevice {
    fn block_size(&self) -> usize {
        ROOTFS_BLOCK_SIZE
    }

    fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        let offset = block_id as usize * ROOTFS_BLOCK_SIZE;
        if offset + ROOTFS_BLOCK_SIZE > self.size || buf.len() < ROOTFS_BLOCK_SIZE {
            return Err(VfsError::NotFound);
        }
        // 安全性： rootfs 镜像在启动时初始化一次，且位于静态内存中。
        unsafe {
            buf[..ROOTFS_BLOCK_SIZE]
                .copy_from_slice(&ROOTFS_IMAGE[offset..offset + ROOTFS_BLOCK_SIZE]);
        }
        Ok(())
    }

    fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
        let offset = block_id as usize * ROOTFS_BLOCK_SIZE;
        if offset + ROOTFS_BLOCK_SIZE > self.size || buf.len() < ROOTFS_BLOCK_SIZE {
            return Err(VfsError::NotFound);
        }
        // 安全性： rootfs 镜像在早期单核阶段可变。
        unsafe {
            ROOTFS_IMAGE[offset..offset + ROOTFS_BLOCK_SIZE]
                .copy_from_slice(&buf[..ROOTFS_BLOCK_SIZE]);
        }
        Ok(())
    }

    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
}

/// 选定的根块设备后端。
pub enum RootBlockDevice {
    Virtio(&'static virtio_blk::VirtioBlkDevice),
    Ramdisk(RootFsDevice),
}

impl RootBlockDevice {
    /// 返回块设备 trait 对象。
    pub fn as_block_device(&self) -> &dyn BlockDevice {
        match self {
            Self::Virtio(dev) => *dev,
            Self::Ramdisk(dev) => dev,
        }
    }
}

/// 初始化 rootfs 的块设备后端。
pub fn init(virtio_mmio: &[VirtioMmioDevice]) {
    virtio_blk::init(virtio_mmio);
}

/// 返回选定的根块设备。
pub fn root_device() -> &'static RootBlockDevice {
    if !ROOT_DEVICE_READY.load(Ordering::Acquire) {
        let dev = if let Some(dev) = virtio_blk::device() {
            RootBlockDevice::Virtio(dev)
        } else {
            RootBlockDevice::Ramdisk(RootFsDevice::new())
        };
        // 安全性： 单核初始化时写入静态设备句柄。
        unsafe {
            ROOT_DEVICE.write(dev);
        }
        ROOT_DEVICE_READY.store(true, Ordering::Release);
    }
    // 安全性： ROOT_DEVICE 在上方初始化后只读。
    unsafe { &*ROOT_DEVICE.as_ptr() }
}

fn rootfs_image() -> &'static [u8] {
    if !ROOTFS_READY.load(Ordering::Acquire) {
        // 安全性： 单核启动阶段初始化 rootfs 镜像。
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
    // 安全性： ROOTFS_IMAGE 在上方初始化后只读。
    unsafe { &ROOTFS_IMAGE[..size] }
}
