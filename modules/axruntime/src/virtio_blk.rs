//! VirtIO 块设备（MMIO）驱动。

use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};

use axfs::block::{BlockDevice, BlockId};
use axfs::{VfsError, VfsResult};

use crate::dtb::VirtioMmioDevice;
use crate::mm;
use crate::plic;
use crate::wait::WaitResult;
use crate::wait_queue::WaitQueue;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_MMIO_VERSION: u32 = 2;
const VIRTIO_DEVICE_BLOCK: u32 = 2;
const VIRTIO_F_VERSION_1: u32 = 1 << 0;

const MMIO_MAGIC: usize = 0x000;
const MMIO_VERSION: usize = 0x004;
const MMIO_DEVICE_ID: usize = 0x008;
const MMIO_DEVICE_FEATURES: usize = 0x010;
const MMIO_DEVICE_FEATURES_SEL: usize = 0x014;
const MMIO_DRIVER_FEATURES: usize = 0x020;
const MMIO_DRIVER_FEATURES_SEL: usize = 0x024;
const MMIO_QUEUE_SEL: usize = 0x030;
const MMIO_QUEUE_NUM_MAX: usize = 0x034;
const MMIO_QUEUE_NUM: usize = 0x038;
const MMIO_QUEUE_READY: usize = 0x044;
const MMIO_QUEUE_NOTIFY: usize = 0x050;
const MMIO_STATUS: usize = 0x070;
const MMIO_INTERRUPT_STATUS: usize = 0x060;
const MMIO_INTERRUPT_ACK: usize = 0x064;
const MMIO_QUEUE_DESC_LOW: usize = 0x080;
const MMIO_QUEUE_DESC_HIGH: usize = 0x084;
const MMIO_QUEUE_AVAIL_LOW: usize = 0x090;
const MMIO_QUEUE_AVAIL_HIGH: usize = 0x094;
const MMIO_QUEUE_USED_LOW: usize = 0x0a0;
const MMIO_QUEUE_USED_HIGH: usize = 0x0a4;

const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_FAILED: u32 = 128;

const QUEUE_SIZE: usize = 8;
const SECTOR_SIZE: usize = 512;
const VIRTIO_BLK_WAIT_TIMEOUT_MS: u64 = 20;

const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

static VIRTIO_BLK_READY: AtomicBool = AtomicBool::new(false);
static VIRTIO_BLK_BASE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_BLK_QUEUE_SIZE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_BLK_USED_IDX: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_BLK_IRQ: AtomicUsize = AtomicUsize::new(0);
// 单队列同步 I/O：inflight 保障互斥，waiters 用于 IRQ 唤醒阻塞等待者。
static VIRTIO_BLK_INFLIGHT: AtomicBool = AtomicBool::new(false);
static VIRTIO_BLK_WAITERS: WaitQueue = WaitQueue::new();
static VIRTIO_QUEUE_LOCK: SpinLock = SpinLock::new();
static VIRTIO_BLK_DEVICE: VirtioBlkDevice = VirtioBlkDevice;
static VIRTIO_QUEUE: QueueCell = QueueCell::new();

#[repr(align(512))]
struct BounceBuf([u8; SECTOR_SIZE]);

// 安全性： 单队列同步 I/O；通过锁保证同一时刻只有一个请求使用缓冲区。
static mut VIRTIO_BLK_BOUNCE: BounceBuf = BounceBuf([0; SECTOR_SIZE]);

/// 实现 BlockDevice 的 VirtIO 块设备封装。
pub struct VirtioBlkDevice;

impl BlockDevice for VirtioBlkDevice {
    fn block_size(&self) -> usize {
        SECTOR_SIZE
    }

    fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        if buf.len() < SECTOR_SIZE {
            return Err(VfsError::Invalid);
        }
        submit_request(VIRTIO_BLK_T_IN, block_id, &mut buf[..SECTOR_SIZE])
    }

    fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
        if buf.len() < SECTOR_SIZE {
            return Err(VfsError::Invalid);
        }
        let mut scratch = [0u8; SECTOR_SIZE];
        scratch.copy_from_slice(&buf[..SECTOR_SIZE]);
        submit_request(VIRTIO_BLK_T_OUT, block_id, &mut scratch)
    }

    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
}

/// 根据 DTB 条目初始化 virtio-blk 设备。
pub fn init(virtio_mmio: &[VirtioMmioDevice]) {
    if VIRTIO_BLK_READY.load(Ordering::Acquire) {
        return;
    }
    for dev in virtio_mmio {
        if dev.region.size == 0 {
            continue;
        }
        if try_init_device(dev.region.base as usize, dev.irq) {
            VIRTIO_BLK_READY.store(true, Ordering::Release);
            break;
        }
    }
}

/// 返回已初始化的 virtio-blk 设备（若存在）。
pub fn device() -> Option<&'static VirtioBlkDevice> {
    if VIRTIO_BLK_READY.load(Ordering::Acquire) {
        Some(&VIRTIO_BLK_DEVICE)
    } else {
        None
    }
}

fn try_init_device(base: usize, irq: u32) -> bool {
    if mmio_read32(base, MMIO_MAGIC) != VIRTIO_MMIO_MAGIC {
        return false;
    }
    let version = mmio_read32(base, MMIO_VERSION);
    if version != VIRTIO_MMIO_VERSION {
        return false;
    }
    if mmio_read32(base, MMIO_DEVICE_ID) != VIRTIO_DEVICE_BLOCK {
        return false;
    }

    mmio_write32(base, MMIO_STATUS, 0);
    mmio_write32(base, MMIO_STATUS, STATUS_ACKNOWLEDGE);
    mmio_write32(base, MMIO_STATUS, STATUS_ACKNOWLEDGE | STATUS_DRIVER);

    let device_features = read_device_features(base);
    let mut driver_features: u64 = 0;
    if (device_features >> 32) & (VIRTIO_F_VERSION_1 as u64) != 0 {
        driver_features |= (VIRTIO_F_VERSION_1 as u64) << 32;
    }
    write_driver_features(base, driver_features);

    let status = mmio_read32(base, MMIO_STATUS) | STATUS_FEATURES_OK;
    mmio_write32(base, MMIO_STATUS, status);
    if (mmio_read32(base, MMIO_STATUS) & STATUS_FEATURES_OK) == 0 {
        mmio_write32(base, MMIO_STATUS, status | STATUS_FAILED);
        return false;
    }

    mmio_write32(base, MMIO_QUEUE_SEL, 0);
    let queue_max = mmio_read32(base, MMIO_QUEUE_NUM_MAX) as usize;
    if queue_max < 3 {
        return false;
    }
    let queue_size = core::cmp::min(queue_max, QUEUE_SIZE);
    mmio_write32(base, MMIO_QUEUE_NUM, queue_size as u32);

    let queue = VIRTIO_QUEUE.get();
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
    unsafe {
        ptr::write_bytes(queue as *mut VirtioBlkQueue, 0, 1);
    }
    let desc_addr = mm::kernel_virt_to_phys(queue.desc_addr()) as u64;
    let avail_addr = mm::kernel_virt_to_phys(queue.avail_addr()) as u64;
    let used_addr = mm::kernel_virt_to_phys(queue.used_addr()) as u64;

    mmio_write32(base, MMIO_QUEUE_DESC_LOW, desc_addr as u32);
    mmio_write32(base, MMIO_QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_AVAIL_LOW, avail_addr as u32);
    mmio_write32(base, MMIO_QUEUE_AVAIL_HIGH, (avail_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_USED_LOW, used_addr as u32);
    mmio_write32(base, MMIO_QUEUE_USED_HIGH, (used_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_READY, 1);

    let status = mmio_read32(base, MMIO_STATUS) | STATUS_DRIVER_OK;
    mmio_write32(base, MMIO_STATUS, status);

    VIRTIO_BLK_BASE.store(base, Ordering::Release);
    VIRTIO_BLK_QUEUE_SIZE.store(queue_size, Ordering::Release);
    VIRTIO_BLK_USED_IDX.store(0, Ordering::Release);
    VIRTIO_BLK_IRQ.store(irq as usize, Ordering::Release);
    if irq != 0 {
        plic::enable(irq);
    }
    true
}

fn submit_request(req_type: u32, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
    if !VIRTIO_BLK_READY.load(Ordering::Acquire) {
        return Err(VfsError::NotSupported);
    }
    let base = VIRTIO_BLK_BASE.load(Ordering::Acquire);
    let queue_size = VIRTIO_BLK_QUEUE_SIZE.load(Ordering::Acquire);
    if base == 0 || queue_size == 0 {
        return Err(VfsError::NotSupported);
    }

    loop {
        if VIRTIO_BLK_INFLIGHT.load(Ordering::Acquire) {
            wait_for_queue_event();
            continue;
        }

        let _guard = VIRTIO_QUEUE_LOCK.lock();
        if VIRTIO_BLK_INFLIGHT.load(Ordering::Acquire) {
            drop(_guard);
            wait_for_queue_event();
            continue;
        }
        VIRTIO_BLK_INFLIGHT.store(true, Ordering::Release);

        let status = {
            let queue = VIRTIO_QUEUE.get();
            let req = VirtioBlkReq {
                type_: req_type,
                reserved: 0,
                sector: block_id,
            };
            queue.req = req;
            queue.status = 0xff;

        let req_addr = mm::kernel_virt_to_phys(queue.req_addr()) as u64;
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
        let buf_addr = unsafe {
            let bounce = &mut VIRTIO_BLK_BOUNCE.0;
            if req_type == VIRTIO_BLK_T_OUT {
                bounce.copy_from_slice(&buf[..SECTOR_SIZE]);
            }
            mm::kernel_virt_to_phys(bounce.as_ptr() as usize) as u64
        };
        let status_addr = mm::kernel_virt_to_phys(queue.status_addr()) as u64;

            queue.desc[0] = VirtqDesc {
                addr: req_addr,
                len: core::mem::size_of::<VirtioBlkReq>() as u32,
                flags: DESC_F_NEXT,
                next: 1,
            };
            queue.desc[1] = VirtqDesc {
                addr: buf_addr,
            len: SECTOR_SIZE as u32,
                flags: if req_type == VIRTIO_BLK_T_IN {
                    DESC_F_WRITE | DESC_F_NEXT
                } else {
                    DESC_F_NEXT
                },
                next: 2,
            };
            queue.desc[2] = VirtqDesc {
                addr: status_addr,
                len: 1,
                flags: DESC_F_WRITE,
                next: 0,
            };

// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
        let avail_idx = unsafe { ptr::read_volatile(&queue.avail.idx) };
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
        unsafe {
            ptr::write_volatile(
                &mut queue.avail.ring[(avail_idx as usize) % queue_size],
                0,
            );
        }
        fence(Ordering::SeqCst);
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
        unsafe {
            ptr::write_volatile(&mut queue.avail.idx, avail_idx.wrapping_add(1));
        }

            fence(Ordering::SeqCst);
            mmio_write32(base, MMIO_QUEUE_NOTIFY, 0);

            let mut last_used = VIRTIO_BLK_USED_IDX.load(Ordering::Acquire) as u16;
            drop(_guard);
            wait_for_completion(queue, &mut last_used);

// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
            unsafe { ptr::read_volatile(&queue.status) }
        };

        if req_type == VIRTIO_BLK_T_IN {
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
            unsafe {
                buf[..SECTOR_SIZE].copy_from_slice(&VIRTIO_BLK_BOUNCE.0);
            }
        }
        VIRTIO_BLK_INFLIGHT.store(false, Ordering::Release);
        let _ = VIRTIO_BLK_WAITERS.notify_all();

        if status != 0 {
            return Err(VfsError::Io);
        }
        return Ok(());
    }
}

/// 处理 virtio-blk 中断并唤醒等待任务。
pub fn handle_irq(irq: u32) -> bool {
    let expected = VIRTIO_BLK_IRQ.load(Ordering::Acquire) as u32;
    if expected == 0 || expected != irq {
        return false;
    }
    let base = VIRTIO_BLK_BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    let status = mmio_read32(base, MMIO_INTERRUPT_STATUS);
    if status != 0 {
        mmio_write32(base, MMIO_INTERRUPT_ACK, status);
        fence(Ordering::SeqCst);
    }
    let _ = VIRTIO_BLK_WAITERS.notify_all();
    true
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
    used_event: u16,
}

#[repr(C, align(4))]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
    avail_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioBlkReq {
    type_: u32,
    reserved: u32,
    sector: u64,
}

#[repr(C, align(4096))]
struct VirtioBlkQueue {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    used: VirtqUsed,
    req: VirtioBlkReq,
    status: u8,
}

struct QueueCell {
    inner: UnsafeCell<VirtioBlkQueue>,
}

impl QueueCell {
    const fn new() -> Self {
        const ZERO_DESC: VirtqDesc = VirtqDesc {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        };
        const ZERO_USED: VirtqUsedElem = VirtqUsedElem { id: 0, len: 0 };
        Self {
            inner: UnsafeCell::new(VirtioBlkQueue {
                desc: [ZERO_DESC; QUEUE_SIZE],
                avail: VirtqAvail {
                    flags: 0,
                    idx: 0,
                    ring: [0; QUEUE_SIZE],
                    used_event: 0,
                },
                used: VirtqUsed {
                    flags: 0,
                    idx: 0,
                    ring: [ZERO_USED; QUEUE_SIZE],
                    avail_event: 0,
                },
                req: VirtioBlkReq {
                    type_: 0,
                    reserved: 0,
                    sector: 0,
                },
                status: 0,
            }),
        }
    }

    fn get(&self) -> &mut VirtioBlkQueue {
        // 安全性： 仅通过全局自旋锁串行访问。
        unsafe { &mut *self.inner.get() }
    }
}

unsafe impl Sync for QueueCell {}

struct SpinLock {
    locked: AtomicBool,
}

impl SpinLock {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> SpinGuard<'_> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        SpinGuard { lock: self }
    }
}

struct SpinGuard<'a> {
    lock: &'a SpinLock,
}

impl Drop for SpinGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

fn mmio_read32(base: usize, offset: usize) -> u32 {
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_write32(base: usize, offset: usize, value: u32) {
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
    unsafe { ptr::write_volatile((base + offset) as *mut u32, value) }
}

fn read_device_features(base: usize) -> u64 {
    mmio_write32(base, MMIO_DEVICE_FEATURES_SEL, 0);
    let low = mmio_read32(base, MMIO_DEVICE_FEATURES) as u64;
    mmio_write32(base, MMIO_DEVICE_FEATURES_SEL, 1);
    let high = mmio_read32(base, MMIO_DEVICE_FEATURES) as u64;
    (high << 32) | low
}

fn write_driver_features(base: usize, features: u64) {
    mmio_write32(base, MMIO_DRIVER_FEATURES_SEL, 0);
    mmio_write32(base, MMIO_DRIVER_FEATURES, features as u32);
    mmio_write32(base, MMIO_DRIVER_FEATURES_SEL, 1);
    mmio_write32(base, MMIO_DRIVER_FEATURES, (features >> 32) as u32);
}

fn wait_for_queue_event() {
    if VIRTIO_BLK_IRQ.load(Ordering::Acquire) != 0 {
        let result = VIRTIO_BLK_WAITERS.wait_timeout_ms(VIRTIO_BLK_WAIT_TIMEOUT_MS);
        if result == WaitResult::Timeout {
            crate::cpu::wait_for_interrupt();
        }
    } else {
        spin_loop();
    }
}

fn wait_for_completion(queue: &VirtioBlkQueue, last_used: &mut u16) {
    loop {
// 安全性： 队列/MMIO 内存已映射，且由驱动不变式保护。
        let used_idx = unsafe { ptr::read_volatile(&queue.used.idx) };
        if used_idx != *last_used {
            *last_used = used_idx;
            VIRTIO_BLK_USED_IDX.store(used_idx as usize, Ordering::Release);
            break;
        }
        wait_for_queue_event();
    }
}

impl VirtioBlkQueue {
    fn desc_addr(&self) -> usize {
        self.desc.as_ptr() as usize
    }

    fn avail_addr(&self) -> usize {
        &self.avail as *const _ as usize
    }

    fn used_addr(&self) -> usize {
        &self.used as *const _ as usize
    }

    fn req_addr(&self) -> usize {
        &self.req as *const _ as usize
    }

    fn status_addr(&self) -> usize {
        &self.status as *const _ as usize
    }
}
