#![allow(dead_code)]

use core::arch::asm;
use core::cmp::min;
use core::sync::atomic::{AtomicUsize, Ordering};

const PAGE_SIZE: usize = 4096;
const PAGE_SHIFT: usize = 12;
const PAGE_SIZE_2M: usize = 1 << 21;
const SV39_LEVELS: usize = 3;
const SV39_ENTRIES: usize = 512;

const KERNEL_BASE: usize = 0x8020_0000;

const PTE_V: usize = 1 << 0;
const PTE_R: usize = 1 << 1;
const PTE_W: usize = 1 << 2;
const PTE_X: usize = 1 << 3;
const PTE_U: usize = 1 << 4;
const PTE_G: usize = 1 << 5;
const PTE_A: usize = 1 << 6;
const PTE_D: usize = 1 << 7;

const PPN_SHIFT: usize = 10;
const PPN_WIDTH: usize = 44;
const PPN_MASK: usize = (1usize << PPN_WIDTH) - 1;

const SATP_MODE_SV39: usize = 8 << 60;
const PTE_FLAGS_KERNEL: usize = PTE_V | PTE_R | PTE_W | PTE_X | PTE_G | PTE_A | PTE_D;

#[derive(Copy, Clone, Debug, Default)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: u64,
}

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PhysAddr(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct VirtAddr(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PhysPageNum(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct VirtPageNum(usize);

#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct PageTableEntry {
    bits: usize,
}

pub struct BumpFrameAllocator {
    next: AtomicUsize,
    end: usize,
}

#[repr(C, align(4096))]
struct PageTable {
    entries: [PageTableEntry; SV39_ENTRIES],
}

static MEM_BASE: AtomicUsize = AtomicUsize::new(0);
static MEM_SIZE: AtomicUsize = AtomicUsize::new(0);

pub fn init(memory: Option<MemoryRegion>) {
    if let Some(region) = memory {
        MEM_BASE.store(region.base as usize, Ordering::Relaxed);
        MEM_SIZE.store(region.size as usize, Ordering::Relaxed);
        crate::println!(
            "mm: memory base={:#x} size={:#x}",
            region.base,
            region.size
        );
    } else {
        crate::println!("mm: no memory region from dtb");
    }

    if let Some(region) = memory {
        unsafe {
            if let Some(root) = setup_kernel_page_table(region) {
                enable_paging(root);
                crate::println!("mm: paging enabled (sv39 identity map)");
            } else {
                crate::println!("mm: paging not enabled");
            }
        }
    }
}

impl PhysAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    pub fn floor(self) -> PhysPageNum {
        PhysPageNum(self.0 >> PAGE_SHIFT)
    }

    pub fn ceil(self) -> PhysPageNum {
        PhysPageNum((self.0 + PAGE_SIZE - 1) >> PAGE_SHIFT)
    }
}

impl VirtAddr {
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    pub fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    pub fn sv39_indexes(self) -> [usize; SV39_LEVELS] {
        let vpn = self.0 >> PAGE_SHIFT;
        [
            (vpn >> 18) & 0x1ff,
            (vpn >> 9) & 0x1ff,
            vpn & 0x1ff,
        ]
    }
}

impl PhysPageNum {
    pub const fn new(ppn: usize) -> Self {
        Self(ppn)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub fn addr(self) -> PhysAddr {
        PhysAddr(self.0 << PAGE_SHIFT)
    }
}

impl VirtPageNum {
    pub const fn new(vpn: usize) -> Self {
        Self(vpn)
    }

    pub const fn as_usize(self) -> usize {
        self.0
    }

    pub fn addr(self) -> VirtAddr {
        VirtAddr(self.0 << PAGE_SHIFT)
    }
}

impl PageTableEntry {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub fn new(ppn: PhysPageNum, flags: usize) -> Self {
        let bits = (ppn.as_usize() & PPN_MASK) << PPN_SHIFT | (flags & 0x3ff);
        Self { bits }
    }

    pub fn is_valid(self) -> bool {
        (self.bits & PTE_V) != 0
    }

    pub fn flags(self) -> usize {
        self.bits & 0x3ff
    }

    pub fn ppn(self) -> PhysPageNum {
        PhysPageNum((self.bits >> PPN_SHIFT) & PPN_MASK)
    }
}

impl BumpFrameAllocator {
    pub fn new(start: PhysAddr, end: PhysAddr) -> Self {
        let start = start.align_up(PAGE_SIZE).as_usize();
        let end = end.align_down(PAGE_SIZE).as_usize();
        Self {
            next: AtomicUsize::new(start),
            end,
        }
    }

    pub fn alloc(&self) -> Option<PhysPageNum> {
        let current = self.next.fetch_add(PAGE_SIZE, Ordering::Relaxed);
        if current + PAGE_SIZE > self.end {
            return None;
        }
        Some(PhysPageNum::new(current >> PAGE_SHIFT))
    }
}

impl PageTable {
    const fn new() -> Self {
        Self {
            entries: [PageTableEntry::empty(); SV39_ENTRIES],
        }
    }

    fn zero(&mut self) {
        for entry in &mut self.entries {
            *entry = PageTableEntry::empty();
        }
    }
}

static mut KERNEL_L2: PageTable = PageTable::new();
static mut KERNEL_L1: PageTable = PageTable::new();

unsafe fn setup_kernel_page_table(region: MemoryRegion) -> Option<&'static PageTable> {
    if region.size == 0 {
        return None;
    }

    let base = align_down(region.base as usize, PAGE_SIZE_2M);
    let size = align_up(region.size as usize, PAGE_SIZE_2M);

    if KERNEL_BASE < base || KERNEL_BASE >= base.saturating_add(size) {
        crate::println!(
            "mm: kernel base {:#x} outside memory region",
            KERNEL_BASE
        );
        return None;
    }

    let l2_index = (base >> 30) & 0x1ff;
    let l1_start = (base >> 21) & 0x1ff;
    let entries = min(size / PAGE_SIZE_2M, SV39_ENTRIES - l1_start);

    KERNEL_L2.zero();
    KERNEL_L1.zero();

    for i in 0..entries {
        let pa = base + i * PAGE_SIZE_2M;
        let index = l1_start + i;
        KERNEL_L1.entries[index] =
            PageTableEntry::new(PhysPageNum::new(pa >> PAGE_SHIFT), PTE_FLAGS_KERNEL);
    }

    if entries * PAGE_SIZE_2M < size {
        crate::println!("mm: memory region truncated to 1GiB mapping");
    }

    let l1_pa = virt_to_phys(&KERNEL_L1 as *const _ as usize);
    KERNEL_L2.entries[l2_index] = PageTableEntry::new(PhysPageNum::new(l1_pa >> PAGE_SHIFT), PTE_V);

    Some(&KERNEL_L2)
}

unsafe fn enable_paging(root: &PageTable) {
    let root_pa = virt_to_phys(root as *const _ as usize);
    let satp_value = SATP_MODE_SV39 | (root_pa >> PAGE_SHIFT);
    asm!("csrw satp, {0}", in(reg) satp_value);
    asm!("sfence.vma");
}

const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

#[inline]
const fn virt_to_phys(addr: usize) -> usize {
    addr
}
