use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::ptr;
use core::sync::atomic::{fence, AtomicBool, AtomicUsize, Ordering};

use axnet::{NetDevice, NetError};

use crate::cpu;
use crate::dtb::VirtioMmioDevice;
use crate::mm;
use crate::plic;

const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
const VIRTIO_MMIO_VERSION: u32 = 2;
const VIRTIO_DEVICE_NET: u32 = 1;
const VIRTIO_F_VERSION_1: u32 = 1 << 0;
const VIRTIO_NET_F_MAC: u32 = 1 << 5;

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
const NET_BUF_SIZE: usize = 2048;
const VIRTIO_NET_HDR_LEN: usize = 10;
const RX_QUEUE_INDEX: u32 = 0;
const TX_QUEUE_INDEX: u32 = 1;

const DESC_F_WRITE: u16 = 2;

const NET_CONFIG_MAC: usize = 0x100;

static VIRTIO_NET_READY: AtomicBool = AtomicBool::new(false);
static VIRTIO_NET_BASE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_IRQ: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_RX_QUEUE_SIZE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_TX_QUEUE_SIZE: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_RX_USED: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_TX_USED: AtomicUsize = AtomicUsize::new(0);
static VIRTIO_NET_IRQ_LOGGED: AtomicBool = AtomicBool::new(false);
static VIRTIO_NET_RX_USED_LOGGED: AtomicBool = AtomicBool::new(false);

static VIRTIO_NET_DEVICE: VirtioNetDevice = VirtioNetDevice;

// SAFETY: 仅在 init 阶段写入一次，ready 后只读。
static mut VIRTIO_NET_MAC: [u8; 6] = [0; 6];

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

static RX_LOCK: SpinLock = SpinLock::new();
static TX_LOCK: SpinLock = SpinLock::new();

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

#[repr(C, align(4096))]
struct VirtioNetQueue {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    used: VirtqUsed,
}

struct QueueCell {
    inner: UnsafeCell<VirtioNetQueue>,
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
            inner: UnsafeCell::new(VirtioNetQueue {
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
            }),
        }
    }

    fn get(&self) -> &mut VirtioNetQueue {
        // SAFETY: 队列访问通过自旋锁串行化。
        unsafe { &mut *self.inner.get() }
    }
}

unsafe impl Sync for QueueCell {}

static VIRTIO_NET_RX_QUEUE: QueueCell = QueueCell::new();
static VIRTIO_NET_TX_QUEUE: QueueCell = QueueCell::new();

#[repr(C, align(4096))]
struct RxBuffer {
    data: [[u8; NET_BUF_SIZE]; QUEUE_SIZE],
}

// SAFETY: RX buffer 只在锁保护下读写。
static mut VIRTIO_NET_RX_BUFS: RxBuffer = RxBuffer {
    data: [[0; NET_BUF_SIZE]; QUEUE_SIZE],
};
// SAFETY: TX buffer 只在锁保护下使用。
static mut VIRTIO_NET_TX_BUF: [u8; NET_BUF_SIZE] = [0; NET_BUF_SIZE];

pub struct VirtioNetDevice;

impl NetDevice for VirtioNetDevice {
    fn mac_address(&self) -> [u8; 6] {
        if !VIRTIO_NET_READY.load(Ordering::Acquire) {
            return [0; 6];
        }
        // SAFETY: 只读 MAC，init 时完成写入。
        unsafe { VIRTIO_NET_MAC }
    }

    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        if !VIRTIO_NET_READY.load(Ordering::Acquire) {
            return Err(NetError::NotReady);
        }
        let base = VIRTIO_NET_BASE.load(Ordering::Acquire);
        let queue_size = VIRTIO_NET_RX_QUEUE_SIZE.load(Ordering::Acquire);
        if base == 0 || queue_size == 0 {
            return Err(NetError::NotReady);
        }

        let _guard = RX_LOCK.lock();
        let queue = VIRTIO_NET_RX_QUEUE.get();
        let used_idx = unsafe { ptr::read_volatile(&queue.used.idx) };
        let last_used = VIRTIO_NET_RX_USED.load(Ordering::Acquire) as u16;
        if used_idx == last_used {
            return Err(NetError::WouldBlock);
        }

        let slot = (last_used as usize) % queue_size;
        let used_elem = unsafe { ptr::read_volatile(&queue.used.ring[slot]) };
        let desc_id = used_elem.id as usize;
        let total_len = used_elem.len as usize;
        let payload_len = total_len.saturating_sub(VIRTIO_NET_HDR_LEN);
        if payload_len > buf.len() {
            recycle_rx_desc(queue, queue_size, desc_id, base);
            VIRTIO_NET_RX_USED.store(last_used.wrapping_add(1) as usize, Ordering::Release);
            return Err(NetError::BufferTooSmall);
        }

        // SAFETY: RX buffer 仅在 RX_LOCK 保护下访问。
        unsafe {
            let src = &VIRTIO_NET_RX_BUFS.data[desc_id]
                [VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + payload_len];
            buf[..payload_len].copy_from_slice(src);
        }
        recycle_rx_desc(queue, queue_size, desc_id, base);
        VIRTIO_NET_RX_USED.store(last_used.wrapping_add(1) as usize, Ordering::Release);
        Ok(payload_len)
    }

    fn send(&self, buf: &[u8]) -> Result<(), NetError> {
        if !VIRTIO_NET_READY.load(Ordering::Acquire) {
            return Err(NetError::NotReady);
        }
        let base = VIRTIO_NET_BASE.load(Ordering::Acquire);
        let queue_size = VIRTIO_NET_TX_QUEUE_SIZE.load(Ordering::Acquire);
        if base == 0 || queue_size == 0 {
            return Err(NetError::NotReady);
        }
        if buf.len() + VIRTIO_NET_HDR_LEN > NET_BUF_SIZE {
            return Err(NetError::BufferTooSmall);
        }

        let _guard = TX_LOCK.lock();
        let queue = VIRTIO_NET_TX_QUEUE.get();
        // SAFETY: TX buffer 只在锁保护下使用。
        unsafe {
            VIRTIO_NET_TX_BUF[..VIRTIO_NET_HDR_LEN].fill(0);
            VIRTIO_NET_TX_BUF[VIRTIO_NET_HDR_LEN..VIRTIO_NET_HDR_LEN + buf.len()]
                .copy_from_slice(buf);
        }
        let desc_id = 0;
        let addr = mm::kernel_virt_to_phys(unsafe { VIRTIO_NET_TX_BUF.as_ptr() } as usize) as u64;
        queue.desc[desc_id].addr = addr;
        queue.desc[desc_id].len = (buf.len() + VIRTIO_NET_HDR_LEN) as u32;
        queue.desc[desc_id].flags = 0;
        queue.desc[desc_id].next = 0;

        let avail_idx = queue.avail.idx;
        queue.avail.ring[(avail_idx as usize) % queue_size] = desc_id as u16;
        queue.avail.idx = avail_idx.wrapping_add(1);
        fence(Ordering::SeqCst);
        mmio_write32(base, MMIO_QUEUE_NOTIFY, TX_QUEUE_INDEX);

        wait_for_tx_completion(queue);
        Ok(())
    }

    fn poll(&self) -> bool {
        if !VIRTIO_NET_READY.load(Ordering::Acquire) {
            return false;
        }
        let queue_size = VIRTIO_NET_RX_QUEUE_SIZE.load(Ordering::Acquire);
        if queue_size == 0 {
            return false;
        }
        let queue = VIRTIO_NET_RX_QUEUE.get();
        let used_idx = unsafe { ptr::read_volatile(&queue.used.idx) };
        let last_used = VIRTIO_NET_RX_USED.load(Ordering::Acquire) as u16;
        if used_idx != last_used && !VIRTIO_NET_RX_USED_LOGGED.swap(true, Ordering::AcqRel) {
            crate::println!("virtio-net: rx used idx={} last={}", used_idx, last_used);
        }
        used_idx != last_used
    }
}

pub fn init(virtio_mmio: &[VirtioMmioDevice]) {
    if VIRTIO_NET_READY.load(Ordering::Acquire) {
        return;
    }
    for dev in virtio_mmio {
        if dev.region.size == 0 {
            continue;
        }
        if try_init_device(dev.region.base as usize, dev.irq) {
            VIRTIO_NET_READY.store(true, Ordering::Release);
            let mac = VIRTIO_NET_DEVICE.mac_address();
            crate::println!(
                "virtio-net: ready mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );
            break;
        }
    }
}

#[allow(dead_code)]
pub fn device() -> Option<&'static VirtioNetDevice> {
    if VIRTIO_NET_READY.load(Ordering::Acquire) {
        Some(&VIRTIO_NET_DEVICE)
    } else {
        None
    }
}

pub fn handle_irq(irq: u32) -> bool {
    let expected = VIRTIO_NET_IRQ.load(Ordering::Acquire) as u32;
    if expected == 0 || expected != irq {
        return false;
    }
    let base = VIRTIO_NET_BASE.load(Ordering::Acquire);
    if base == 0 {
        return false;
    }
    if !VIRTIO_NET_IRQ_LOGGED.swap(true, Ordering::AcqRel) {
        crate::println!("virtio-net: irq received");
    }
    let status = mmio_read32(base, MMIO_INTERRUPT_STATUS);
    if status != 0 {
        mmio_write32(base, MMIO_INTERRUPT_ACK, status);
        fence(Ordering::SeqCst);
    }
    axnet::notify_irq();
    true
}

fn try_init_device(base: usize, irq: u32) -> bool {
    if mmio_read32(base, MMIO_MAGIC) != VIRTIO_MMIO_MAGIC {
        return false;
    }
    let version = mmio_read32(base, MMIO_VERSION);
    if version != VIRTIO_MMIO_VERSION {
        return false;
    }
    if mmio_read32(base, MMIO_DEVICE_ID) != VIRTIO_DEVICE_NET {
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
    if (device_features & VIRTIO_NET_F_MAC as u64) != 0 {
        driver_features |= VIRTIO_NET_F_MAC as u64;
    }
    write_driver_features(base, driver_features);

    let status = mmio_read32(base, MMIO_STATUS) | STATUS_FEATURES_OK;
    mmio_write32(base, MMIO_STATUS, status);
    if (mmio_read32(base, MMIO_STATUS) & STATUS_FEATURES_OK) == 0 {
        mmio_write32(base, MMIO_STATUS, status | STATUS_FAILED);
        return false;
    }

    let rx_queue_size = setup_queue(base, RX_QUEUE_INDEX, VIRTIO_NET_RX_QUEUE.get());
    if rx_queue_size == 0 {
        return false;
    }
    let tx_queue_size = setup_queue(base, TX_QUEUE_INDEX, VIRTIO_NET_TX_QUEUE.get());
    if tx_queue_size == 0 {
        return false;
    }

    let status = mmio_read32(base, MMIO_STATUS) | STATUS_DRIVER_OK;
    mmio_write32(base, MMIO_STATUS, status);
    // Notify RX buffers only after DRIVER_OK per VirtIO spec.
    init_rx_buffers(base, rx_queue_size);

    VIRTIO_NET_BASE.store(base, Ordering::Release);
    VIRTIO_NET_IRQ.store(irq as usize, Ordering::Release);
    VIRTIO_NET_RX_QUEUE_SIZE.store(rx_queue_size, Ordering::Release);
    VIRTIO_NET_TX_QUEUE_SIZE.store(tx_queue_size, Ordering::Release);
    VIRTIO_NET_RX_USED.store(0, Ordering::Release);
    VIRTIO_NET_TX_USED.store(0, Ordering::Release);
    if irq != 0 {
        plic::enable(irq);
    }

    if (driver_features & VIRTIO_NET_F_MAC as u64) != 0 {
        let mac = read_mac(base);
        // SAFETY: init 期间单次写入。
        unsafe {
            VIRTIO_NET_MAC = mac;
        }
    }

    true
}

fn setup_queue(base: usize, queue_index: u32, queue: &mut VirtioNetQueue) -> usize {
    mmio_write32(base, MMIO_QUEUE_SEL, queue_index);
    let queue_max = mmio_read32(base, MMIO_QUEUE_NUM_MAX) as usize;
    if queue_max == 0 {
        return 0;
    }
    let queue_size = core::cmp::min(queue_max, QUEUE_SIZE);
    mmio_write32(base, MMIO_QUEUE_NUM, queue_size as u32);

    unsafe {
        ptr::write_bytes(queue as *mut VirtioNetQueue, 0, 1);
    }
    let desc_addr = mm::kernel_virt_to_phys(queue.desc.as_ptr() as usize) as u64;
    let avail_addr = mm::kernel_virt_to_phys(&queue.avail as *const _ as usize) as u64;
    let used_addr = mm::kernel_virt_to_phys(&queue.used as *const _ as usize) as u64;

    mmio_write32(base, MMIO_QUEUE_DESC_LOW, desc_addr as u32);
    mmio_write32(base, MMIO_QUEUE_DESC_HIGH, (desc_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_AVAIL_LOW, avail_addr as u32);
    mmio_write32(base, MMIO_QUEUE_AVAIL_HIGH, (avail_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_USED_LOW, used_addr as u32);
    mmio_write32(base, MMIO_QUEUE_USED_HIGH, (used_addr >> 32) as u32);
    mmio_write32(base, MMIO_QUEUE_READY, 1);

    queue_size
}

fn init_rx_buffers(base: usize, queue_size: usize) {
    let queue = VIRTIO_NET_RX_QUEUE.get();
    // 预投递 RX 描述符，设备写入后更新 used ring。
    for idx in 0..queue_size {
        // SAFETY: RX buffer 在 init 阶段单线程写入。
        let addr = unsafe { VIRTIO_NET_RX_BUFS.data[idx].as_ptr() as usize };
        let phys = mm::kernel_virt_to_phys(addr) as u64;
        queue.desc[idx].addr = phys;
        queue.desc[idx].len = NET_BUF_SIZE as u32;
        queue.desc[idx].flags = DESC_F_WRITE;
        queue.desc[idx].next = 0;
        queue.avail.ring[idx] = idx as u16;
    }
    queue.avail.idx = queue_size as u16;
    fence(Ordering::SeqCst);
    mmio_write32(base, MMIO_QUEUE_NOTIFY, RX_QUEUE_INDEX);
}

fn recycle_rx_desc(queue: &mut VirtioNetQueue, queue_size: usize, desc_id: usize, base: usize) {
    let avail_idx = queue.avail.idx;
    queue.avail.ring[(avail_idx as usize) % queue_size] = desc_id as u16;
    queue.avail.idx = avail_idx.wrapping_add(1);
    fence(Ordering::SeqCst);
    mmio_write32(base, MMIO_QUEUE_NOTIFY, RX_QUEUE_INDEX);
}

fn wait_for_tx_completion(queue: &VirtioNetQueue) {
    let last_used = VIRTIO_NET_TX_USED.load(Ordering::Acquire) as u16;
    loop {
        let used_idx = unsafe { ptr::read_volatile(&queue.used.idx) };
        if used_idx != last_used {
            VIRTIO_NET_TX_USED.store(used_idx as usize, Ordering::Release);
            break;
        }
        wait_for_queue_event();
    }
}

fn wait_for_queue_event() {
    if VIRTIO_NET_IRQ.load(Ordering::Acquire) != 0 {
        cpu::wait_for_interrupt();
    } else {
        spin_loop();
    }
}

fn read_mac(base: usize) -> [u8; 6] {
    let mut mac = [0u8; 6];
    for idx in 0..6 {
        mac[idx] = mmio_read8(base, NET_CONFIG_MAC + idx);
    }
    mac
}

fn mmio_read32(base: usize, offset: usize) -> u32 {
    unsafe { ptr::read_volatile((base + offset) as *const u32) }
}

fn mmio_read8(base: usize, offset: usize) -> u8 {
    unsafe { ptr::read_volatile((base + offset) as *const u8) }
}

fn mmio_write32(base: usize, offset: usize, value: u32) {
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
