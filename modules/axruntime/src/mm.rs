#![allow(dead_code)]
//! Physical/virtual memory management and page table helpers.

use core::arch::asm;
use core::cmp::{max, min};
use core::marker::PhantomData;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Base page size used by the kernel (4KiB).
pub const PAGE_SIZE: usize = 4096;
const PAGE_SHIFT: usize = 12;
const PAGE_SIZE_2M: usize = 1 << 21;
const PAGE_SIZE_1G: usize = 1 << 30;
const SV39_LEVELS: usize = 3;
const SV39_ENTRIES: usize = 512;

const KERNEL_BASE: usize = 0x8020_0000;
const IDENTITY_MAP_SIZE: usize = 1 << 30;

const PTE_V: usize = 1 << 0;
const PTE_R: usize = 1 << 1;
const PTE_W: usize = 1 << 2;
const PTE_X: usize = 1 << 3;
const PTE_U: usize = 1 << 4;
const PTE_G: usize = 1 << 5;
const PTE_A: usize = 1 << 6;
const PTE_D: usize = 1 << 7;
const PTE_COW: usize = 1 << 8;

const PPN_SHIFT: usize = 10;
const PPN_WIDTH: usize = 44;
const PPN_MASK: usize = (1usize << PPN_WIDTH) - 1;

const SATP_MODE_SV39: usize = 8 << 60;
const PTE_FLAGS_KERNEL: usize = PTE_V | PTE_R | PTE_W | PTE_X | PTE_G | PTE_A | PTE_D;
const PTE_FLAGS_DEVICE: usize = PTE_V | PTE_R | PTE_W | PTE_G | PTE_A | PTE_D;
const PTE_FLAGS_USER_CODE: usize = PTE_V | PTE_R | PTE_X | PTE_U | PTE_A;
const PTE_FLAGS_USER_DATA: usize = PTE_V | PTE_R | PTE_W | PTE_U | PTE_A | PTE_D;
const MAX_FRAMES: usize = IDENTITY_MAP_SIZE / PAGE_SIZE;

#[derive(Clone, Copy)]
/// User page mapping permissions.
pub struct UserMapFlags {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub exec: bool,
}

#[derive(Copy, Clone, Debug, Default)]
/// A physical memory region described by the platform.
pub struct MemoryRegion {
    /// Base physical address.
    pub base: u64,
    /// Region size in bytes.
    pub size: u64,
}

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Physical address wrapper.
pub struct PhysAddr(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Virtual address wrapper.
pub struct VirtAddr(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Physical page number wrapper.
pub struct PhysPageNum(usize);

#[repr(transparent)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd)]
/// Virtual page number wrapper.
pub struct VirtPageNum(usize);

#[repr(transparent)]
#[derive(Copy, Clone)]
/// Page table entry wrapper.
pub struct PageTableEntry {
    bits: usize,
}

/// Simple bump allocator for physical frames.
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
static FRAME_BASE: AtomicUsize = AtomicUsize::new(0);
static FRAME_COUNT: AtomicUsize = AtomicUsize::new(0);
static FRAME_ALLOC_READY: AtomicBool = AtomicBool::new(false);
static mut FRAME_ALLOC: MaybeUninit<BumpFrameAllocator> = MaybeUninit::uninit();
static KERNEL_ROOT_PA: AtomicUsize = AtomicUsize::new(0);
static mut FRAME_REFCOUNT: [u16; MAX_FRAMES] = [0; MAX_FRAMES];
static mut FRAME_FREE_LIST: [usize; MAX_FRAMES] = [0; MAX_FRAMES];
static mut FRAME_FREE_LEN: usize = 0;

extern "C" {
    static ekernel: u8;
}

/// Initialize memory management and enable paging.
pub fn init(memory: Option<MemoryRegion>, devices: &[MemoryRegion]) {
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
        init_frame_allocator(region);
        unsafe {
            if let Some(root_pa) = setup_kernel_page_table(region) {
                map_device_regions(root_pa, devices);
                enable_paging(root_pa);
                KERNEL_ROOT_PA.store(root_pa, Ordering::Relaxed);
                crate::println!("mm: paging enabled (sv39 identity map)");
            } else {
                crate::println!("mm: paging not enabled");
            }
        }
    }
}

impl PhysAddr {
    /// Construct a physical address wrapper.
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Return the raw address value.
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Align the address downward to `align`.
    pub fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Align the address upward to `align`.
    pub fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Convert to a physical page number by truncating.
    pub fn floor(self) -> PhysPageNum {
        PhysPageNum(self.0 >> PAGE_SHIFT)
    }

    /// Convert to a physical page number by rounding up.
    pub fn ceil(self) -> PhysPageNum {
        PhysPageNum((self.0 + PAGE_SIZE - 1) >> PAGE_SHIFT)
    }
}

impl VirtAddr {
    /// Construct a virtual address wrapper.
    pub const fn new(addr: usize) -> Self {
        Self(addr)
    }

    /// Return the raw address value.
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Align the address downward to `align`.
    pub fn align_down(self, align: usize) -> Self {
        Self(self.0 & !(align - 1))
    }

    /// Align the address upward to `align`.
    pub fn align_up(self, align: usize) -> Self {
        Self((self.0 + align - 1) & !(align - 1))
    }

    /// Compute SV39 page table indexes for this address.
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
    /// Construct a physical page number wrapper.
    pub const fn new(ppn: usize) -> Self {
        Self(ppn)
    }

    /// Return the raw page number value.
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Convert to a physical address.
    pub fn addr(self) -> PhysAddr {
        PhysAddr(self.0 << PAGE_SHIFT)
    }
}

impl VirtPageNum {
    /// Construct a virtual page number wrapper.
    pub const fn new(vpn: usize) -> Self {
        Self(vpn)
    }

    /// Return the raw page number value.
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Convert to a virtual address.
    pub fn addr(self) -> VirtAddr {
        VirtAddr(self.0 << PAGE_SHIFT)
    }
}

impl PageTableEntry {
    /// Construct an empty page table entry.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Create a page table entry from a PPN and flags.
    pub fn new(ppn: PhysPageNum, flags: usize) -> Self {
        let bits = (ppn.as_usize() & PPN_MASK) << PPN_SHIFT | (flags & 0x3ff);
        Self { bits }
    }

    /// Return true if the entry is valid.
    pub fn is_valid(self) -> bool {
        (self.bits & PTE_V) != 0
    }

    /// Return true if the entry is a leaf mapping.
    pub fn is_leaf(self) -> bool {
        (self.bits & (PTE_R | PTE_W | PTE_X)) != 0
    }

    /// Return the raw flag bits.
    pub fn flags(self) -> usize {
        self.bits & 0x3ff
    }

    /// Return the physical page number stored in the entry.
    pub fn ppn(self) -> PhysPageNum {
        PhysPageNum((self.bits >> PPN_SHIFT) & PPN_MASK)
    }
}

impl BumpFrameAllocator {
    /// Create a bump allocator from the given physical range.
    pub fn new(start: PhysAddr, end: PhysAddr) -> Self {
        let start = start.align_up(PAGE_SIZE).as_usize();
        let end = end.align_down(PAGE_SIZE).as_usize();
        Self {
            next: AtomicUsize::new(start),
            end,
        }
    }

    /// Allocate a contiguous run of frames.
    pub fn alloc_contiguous(&self, count: usize) -> Option<PhysPageNum> {
        let size = count.checked_mul(PAGE_SIZE)?;
        let current = self.next.fetch_add(size, Ordering::Relaxed);
        if current + size > self.end {
            return None;
        }
        Some(PhysPageNum::new(current >> PAGE_SHIFT))
    }

    /// Allocate a single frame.
    pub fn alloc(&self) -> Option<PhysPageNum> {
        self.alloc_contiguous(1)
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

/// Allocate a zeroed physical frame.
pub fn alloc_frame() -> Option<PhysPageNum> {
    if !FRAME_ALLOC_READY.load(Ordering::Acquire) {
        return None;
    }
    let frame = if let Some(pa) = pop_free_frame() {
        let _ = set_refcount(pa, 1);
        PhysPageNum::new(pa >> PAGE_SHIFT)
    } else {
        // SAFETY: initialized once in init_frame_allocator before any allocations.
        let frame = unsafe { FRAME_ALLOC.assume_init_ref().alloc()? };
        let pa = frame.addr().as_usize();
        let _ = set_refcount(pa, 1);
        frame
    };
    // SAFETY: the frame is exclusively owned and identity-mapped.
    unsafe {
        ptr::write_bytes(frame.addr().as_usize() as *mut u8, 0, PAGE_SIZE);
    }
    Some(frame)
}

/// Allocate a zeroed contiguous range of physical frames.
pub fn alloc_contiguous_frames(count: usize) -> Option<PhysPageNum> {
    if !FRAME_ALLOC_READY.load(Ordering::Acquire) {
        return None;
    }
    // Bypass the free list to guarantee physical contiguity for kernel stacks.
    let frame = unsafe { FRAME_ALLOC.assume_init_ref().alloc_contiguous(count)? };
    let pa = frame.addr().as_usize();
    for idx in 0..count {
        let _ = set_refcount(pa + idx * PAGE_SIZE, 1);
    }
    // SAFETY: the frames are exclusively owned and identity-mapped.
    unsafe {
        ptr::write_bytes(pa as *mut u8, 0, count * PAGE_SIZE);
    }
    Some(frame)
}

#[derive(Clone, Copy)]
/// Requested access type for user pointer validation.
pub enum UserAccess {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy)]
/// 用户态指针封装，负责在访问前校验页表权限与范围。
pub struct UserPtr<T> {
    ptr: usize,
    _marker: PhantomData<*const T>,
}

impl<T> UserPtr<T> {
    /// Create a user pointer wrapper for the given virtual address.
    pub const fn new(ptr: usize) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    /// Return the raw virtual address value.
    pub const fn as_usize(self) -> usize {
        self.ptr
    }
}

impl<T: Copy> UserPtr<T> {
    /// Read a value of `T` from user space.
    pub fn read(self, root_pa: usize) -> Option<T> {
        let size = size_of::<T>();
        let mut value = MaybeUninit::<T>::uninit();
        let dst = unsafe {
            core::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size)
        };
        UserSlice::new(self.ptr, size).copy_to_slice(root_pa, dst)?;
        // SAFETY: copy_to_slice 已完整写入 size 字节。
        Some(unsafe { value.assume_init() })
    }

    /// Write a value of `T` into user space.
    pub fn write(self, root_pa: usize, value: T) -> Option<()> {
        let size = size_of::<T>();
        let src = unsafe {
            core::slice::from_raw_parts(&value as *const T as *const u8, size)
        };
        UserSlice::new(self.ptr, size).copy_from_slice(root_pa, src)?;
        Some(())
    }
}

#[derive(Clone, Copy)]
/// 用户态切片封装，按页分段验证并支持复制。
pub struct UserSlice {
    ptr: usize,
    len: usize,
}

impl UserSlice {
    /// Create a user slice wrapper for the given base/length.
    pub const fn new(ptr: usize, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Return the slice length in bytes.
    pub const fn len(self) -> usize {
        self.len
    }

    /// Return true when the slice length is zero.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Iterate over validated chunks of the user slice.
    pub fn for_each_chunk<F>(
        self,
        root_pa: usize,
        access: UserAccess,
        mut f: F,
    ) -> Option<usize>
    where
        F: FnMut(usize, usize) -> Option<()>,
    {
        if self.len == 0 {
            return Some(0);
        }
        let mut addr = self.ptr;
        let mut remaining = self.len;
        let mut processed = 0usize;
        while remaining > 0 {
            let page_off = addr & (PAGE_SIZE - 1);
            let chunk = min(remaining, PAGE_SIZE - page_off);
            let pa = translate_user_ptr(root_pa, addr, chunk, access)?;
            f(pa, chunk)?;
            addr = addr.wrapping_add(chunk);
            remaining -= chunk;
            processed += chunk;
        }
        Some(processed)
    }

    /// Copy data from user space into the destination slice.
    pub fn copy_to_slice(self, root_pa: usize, dst: &mut [u8]) -> Option<usize> {
        if dst.len() < self.len {
            return None;
        }
        let mut offset = 0usize;
        let dst_ptr = dst.as_mut_ptr();
        self.for_each_chunk(root_pa, UserAccess::Read, |pa, chunk| {
            // SAFETY: 已验证用户态权限与范围，且 dst 有足够容量。
            unsafe {
                core::ptr::copy_nonoverlapping(pa as *const u8, dst_ptr.add(offset), chunk);
            }
            offset += chunk;
            Some(())
        })?;
        Some(offset)
    }

    /// Copy data from the source slice into user space.
    pub fn copy_from_slice(self, root_pa: usize, src: &[u8]) -> Option<usize> {
        if src.len() < self.len {
            return None;
        }
        let mut offset = 0usize;
        let src_ptr = src.as_ptr();
        self.for_each_chunk(root_pa, UserAccess::Write, |pa, chunk| {
            // SAFETY: 已验证用户态权限与范围，且 src 有足够数据。
            unsafe {
                core::ptr::copy_nonoverlapping(src_ptr.add(offset), pa as *mut u8, chunk);
            }
            offset += chunk;
            Some(())
        })?;
        Some(offset)
    }
}

/// Return the physical address of the kernel root page table.
pub fn kernel_root_pa() -> usize {
    KERNEL_ROOT_PA.load(Ordering::Relaxed)
}

/// Translate a kernel virtual address into a physical address.
pub fn kernel_virt_to_phys(addr: usize) -> usize {
    // 内核页表保持恒等映射，虚拟地址即物理地址。
    virt_to_phys(addr)
}

/// Return the detected physical memory size in bytes.
pub fn memory_size() -> usize {
    MEM_SIZE.load(Ordering::Relaxed)
}

/// Return the physical address of the currently active root page table.
pub fn current_root_pa() -> usize {
    let satp = read_satp();
    let ppn = satp & PPN_MASK;
    ppn << PAGE_SHIFT
}

/// Build an SATP value for the provided root page table.
pub fn satp_for_root(root_pa: usize) -> usize {
    SATP_MODE_SV39 | (root_pa >> PAGE_SHIFT)
}

/// Flush the local TLB after page table updates.
pub fn flush_tlb() {
    // SAFETY: sfence.vma is safe to issue after updating page tables.
    unsafe {
        asm!("sfence.vma");
    }
}

/// Flush the instruction cache after writing code pages.
pub fn flush_icache() {
    // SAFETY: fence.i syncs instruction stream after writing code.
    unsafe {
        asm!("fence.i");
    }
}

/// Translate and validate a user-space pointer for the requested access.
pub fn translate_user_ptr(root_pa: usize, va: usize, len: usize, access: UserAccess) -> Option<usize> {
    let (pa_base, page_size, flags) = walk_page(root_pa, va)?;
    if (flags & PTE_U) == 0 {
        return None;
    }
    match access {
        UserAccess::Read if (flags & PTE_R) == 0 => return None,
        UserAccess::Write if (flags & PTE_W) == 0 => {
            if (flags & PTE_COW) != 0 && page_size == PAGE_SIZE {
                if !resolve_cow(root_pa, va) {
                    return None;
                }
                return translate_user_ptr(root_pa, va, len, access);
            }
            return None;
        }
        UserAccess::Execute if (flags & PTE_X) == 0 => return None,
        _ => {}
    }
    let offset = va & (page_size - 1);
    if len > page_size.saturating_sub(offset) {
        return None;
    }
    Some(pa_base + offset)
}

fn walk_page(root_pa: usize, va: usize) -> Option<(usize, usize, usize)> {
    if root_pa == 0 {
        return None;
    }
    // SAFETY: early boot uses identity mapping; page table pages are valid.
    let l2 = unsafe { &*(root_pa as *const PageTable) };
    let [l2_idx, l1_idx, l0_idx] = VirtAddr::new(va).sv39_indexes();
    let l2e = l2.entries[l2_idx];
    if !l2e.is_valid() {
        return None;
    }
    if l2e.is_leaf() {
        return Some((l2e.ppn().addr().as_usize(), PAGE_SIZE_1G, l2e.flags()));
    }

    // SAFETY: entry points to a valid next-level table page.
    let l1 = unsafe { &*(l2e.ppn().addr().as_usize() as *const PageTable) };
    let l1e = l1.entries[l1_idx];
    if !l1e.is_valid() {
        return None;
    }
    if l1e.is_leaf() {
        return Some((l1e.ppn().addr().as_usize(), PAGE_SIZE_2M, l1e.flags()));
    }

    // SAFETY: entry points to a valid next-level table page.
    let l0 = unsafe { &*(l1e.ppn().addr().as_usize() as *const PageTable) };
    let l0e = l0.entries[l0_idx];
    if !l0e.is_valid() || !l0e.is_leaf() {
        return None;
    }
    Some((l0e.ppn().addr().as_usize(), PAGE_SIZE, l0e.flags()))
}

fn cow_flags(flags: usize) -> usize {
    if (flags & PTE_W) == 0 {
        return flags;
    }
    let mut new_flags = flags & !(PTE_W | PTE_D);
    new_flags |= PTE_COW;
    new_flags
}

fn walk_pte_mut(root_pa: usize, va: usize) -> Option<(*mut PageTableEntry, usize)> {
    if root_pa == 0 {
        return None;
    }
    // SAFETY: early boot uses identity mapping; root page table is valid.
    let l2 = unsafe { &mut *(root_pa as *mut PageTable) };
    let [l2_idx, l1_idx, l0_idx] = VirtAddr::new(va).sv39_indexes();
    let l2e = &mut l2.entries[l2_idx];
    if !l2e.is_valid() {
        return None;
    }
    if l2e.is_leaf() {
        return Some((l2e as *mut _, PAGE_SIZE_1G));
    }

    // SAFETY: entry points to a valid next-level table page.
    let l1 = unsafe { &mut *(l2e.ppn().addr().as_usize() as *mut PageTable) };
    let l1e = &mut l1.entries[l1_idx];
    if !l1e.is_valid() {
        return None;
    }
    if l1e.is_leaf() {
        return Some((l1e as *mut _, PAGE_SIZE_2M));
    }

    // SAFETY: entry points to a valid next-level table page.
    let l0 = unsafe { &mut *(l1e.ppn().addr().as_usize() as *mut PageTable) };
    let l0e = &mut l0.entries[l0_idx];
    if !l0e.is_valid() || !l0e.is_leaf() {
        return None;
    }
    Some((l0e as *mut _, PAGE_SIZE))
}

fn resolve_cow(root_pa: usize, va: usize) -> bool {
    let (entry_ptr, page_size) = match walk_pte_mut(root_pa, va) {
        Some(value) => value,
        None => return false,
    };
    if page_size != PAGE_SIZE {
        return false;
    }
    // SAFETY: entry_ptr points to a valid PTE in the current page table.
    let entry = unsafe { *entry_ptr };
    let flags = entry.flags();
    if (flags & PTE_COW) == 0 || (flags & PTE_U) == 0 {
        return false;
    }
    let old_pa = entry.ppn().addr().as_usize();
    let count = frame_refcount(old_pa).unwrap_or(1);
    if count <= 1 {
        let new_flags = (flags | PTE_W | PTE_D) & !PTE_COW;
        // SAFETY: entry_ptr points to a valid writable PTE slot.
        unsafe {
            *entry_ptr = PageTableEntry::new(entry.ppn(), new_flags);
        }
        flush_tlb();
        return true;
    }
    let frame = match alloc_frame() {
        Some(frame) => frame,
        None => return false,
    };
    let new_pa = frame.addr().as_usize();
    // SAFETY: old/new pages are identity-mapped and PAGE_SIZE bytes long.
    unsafe {
        ptr::copy_nonoverlapping(old_pa as *const u8, new_pa as *mut u8, PAGE_SIZE);
    }
    let new_flags = (flags | PTE_W | PTE_D) & !PTE_COW;
    // SAFETY: entry_ptr points to a valid writable PTE slot.
    unsafe {
        *entry_ptr = PageTableEntry::new(frame, new_flags);
    }
    let _ = release_frame(old_pa);
    flush_tlb();
    true
}

/// Resolve a copy-on-write fault at the given virtual address.
pub fn handle_cow_fault(root_pa: usize, va: usize) -> bool {
    resolve_cow(root_pa, va)
}

unsafe fn alloc_page_table() -> Option<&'static mut PageTable> {
    let frame = alloc_frame()?;
    let pa = frame.addr().as_usize();
    let table = pa as *mut PageTable;
    // SAFETY: 早期启动阶段使用恒等映射，且帧分配器返回唯一页帧。
    core::ptr::write_bytes(table as *mut u8, 0, PAGE_SIZE);
    Some(&mut *table)
}

fn ensure_table(entry: &mut PageTableEntry) -> Option<&'static mut PageTable> {
    if entry.is_valid() {
        if entry.is_leaf() {
            return None;
        }
        let table_pa = entry.ppn().addr().as_usize();
        let table = table_pa as *mut PageTable;
        // SAFETY: existing page table entry points to a valid table page.
        return Some(unsafe { &mut *table });
    }
    // SAFETY: allocating a fresh page table during early boot.
    let table = unsafe { alloc_page_table()? };
    let pa = virt_to_phys(table as *const _ as usize);
    *entry = PageTableEntry::new(PhysPageNum::new(pa >> PAGE_SHIFT), PTE_V);
    Some(table)
}

/// Map a user code page with RX permissions.
pub fn map_user_code(root_pa: usize, va: usize, pa: usize) -> bool {
    map_page(root_pa, va, pa, PTE_FLAGS_USER_CODE)
}

/// Map a user data page with RW permissions.
pub fn map_user_data(root_pa: usize, va: usize, pa: usize) -> bool {
    map_page(root_pa, va, pa, PTE_FLAGS_USER_DATA)
}

/// Map a user stack page with RW permissions.
pub fn map_user_stack(root_pa: usize, va: usize, pa: usize) -> bool {
    map_page(root_pa, va, pa, PTE_FLAGS_USER_DATA)
}

/// Map a user page with the specified permissions.
pub fn map_user_page(root_pa: usize, va: usize, pa: usize, flags: UserMapFlags) -> bool {
    let mut pte_flags = PTE_V | PTE_U | PTE_A;
    if flags.read {
        pte_flags |= PTE_R;
    }
    if flags.write {
        pte_flags |= PTE_W | PTE_D;
    }
    if flags.exec {
        pte_flags |= PTE_X;
    }
    map_page(root_pa, va, pa, pte_flags)
}

/// Check whether a user virtual page is mapped.
pub fn user_page_mapped(root_pa: usize, va: usize) -> bool {
    let Some(entry) = lookup_user_pte(root_pa, va) else {
        return false;
    };
    entry.is_valid() && entry.is_leaf() && (entry.flags() & PTE_U) != 0
}

/// Unmap a user virtual page.
pub fn unmap_user_page(root_pa: usize, va: usize) -> bool {
    if root_pa == 0 {
        return false;
    }
    let l2 = unsafe { &mut *(root_pa as *mut PageTable) };
    let [l2_idx, l1_idx, l0_idx] = VirtAddr::new(va).sv39_indexes();
    let l2e = l2.entries[l2_idx];
    if !l2e.is_valid() || l2e.is_leaf() {
        return false;
    }
    let l1 = unsafe { &mut *(l2e.ppn().addr().as_usize() as *mut PageTable) };
    let l1e = l1.entries[l1_idx];
    if !l1e.is_valid() || l1e.is_leaf() {
        return false;
    }
    let l0 = unsafe { &mut *(l1e.ppn().addr().as_usize() as *mut PageTable) };
    let entry = &mut l0.entries[l0_idx];
    if !entry.is_valid() || !entry.is_leaf() {
        return false;
    }
    if (entry.flags() & PTE_U) == 0 {
        return false;
    }
    let pa = entry.ppn().addr().as_usize();
    *entry = PageTableEntry::empty();
    let _ = release_frame(pa);

    if table_empty(l0) {
        let l0_pa = l1e.ppn().addr().as_usize();
        l1.entries[l1_idx] = PageTableEntry::empty();
        let _ = release_frame(l0_pa);
        if table_empty(l1) {
            let l1_pa = l2e.ppn().addr().as_usize();
            l2.entries[l2_idx] = PageTableEntry::empty();
            let _ = release_frame(l1_pa);
        }
    }
    true
}

/// Update permissions on a mapped user page.
pub fn protect_user_page(root_pa: usize, va: usize, flags: UserMapFlags) -> bool {
    let Some(entry) = lookup_user_pte_mut(root_pa, va) else {
        return false;
    };
    if !entry.is_valid() || !entry.is_leaf() {
        return false;
    }
    if (entry.flags() & PTE_U) == 0 {
        return false;
    }
    let mut pte_flags = PTE_V | PTE_U | PTE_A;
    if flags.read {
        pte_flags |= PTE_R;
    }
    if flags.write {
        pte_flags |= PTE_W | PTE_D;
    }
    if flags.exec {
        pte_flags |= PTE_X;
    }
    let old_flags = entry.flags();
    if (old_flags & PTE_COW) != 0 {
        pte_flags |= PTE_COW;
        pte_flags &= !PTE_W;
        pte_flags &= !PTE_D;
    }
    *entry = PageTableEntry::new(entry.ppn(), pte_flags);
    true
}

/// Allocate a new user root page table (based on the kernel root).
pub fn alloc_user_root() -> Option<usize> {
    let kernel_root_pa = kernel_root_pa();
    if kernel_root_pa == 0 {
        return None;
    }
    // 复制内核映射前先切换到内核根表，避免依赖旧用户页表内容。
    let current_root = current_root_pa();
    if current_root != kernel_root_pa {
        switch_root(kernel_root_pa);
    }
    // SAFETY: allocate a fresh root page table and copy kernel mappings.
    let root = unsafe { alloc_page_table()? };
    let kernel_root = unsafe { &*(kernel_root_pa as *const PageTable) };
    root.entries = kernel_root.entries;
    if current_root != kernel_root_pa {
        switch_root(current_root);
    }
    Some(virt_to_phys(root as *const _ as usize))
}

fn frame_index(pa: usize) -> Option<usize> {
    let base = FRAME_BASE.load(Ordering::Relaxed);
    let count = FRAME_COUNT.load(Ordering::Relaxed);
    if base == 0 || count == 0 || pa < base {
        return None;
    }
    let offset = pa - base;
    if offset & (PAGE_SIZE - 1) != 0 {
        return None;
    }
    let idx = offset / PAGE_SIZE;
    if idx >= count {
        return None;
    }
    Some(idx)
}

fn set_refcount(pa: usize, count: u16) -> bool {
    let Some(idx) = frame_index(pa) else {
        return false;
    };
    // SAFETY: early boot single-hart; refcount table is only touched here.
    unsafe {
        FRAME_REFCOUNT[idx] = count;
    }
    true
}

fn retain_frame(pa: usize) -> bool {
    let Some(idx) = frame_index(pa) else {
        return false;
    };
    // SAFETY: early boot single-hart; refcount table is only touched here.
    unsafe {
        let current = FRAME_REFCOUNT[idx];
        if current < u16::MAX {
            FRAME_REFCOUNT[idx] = current + 1;
        }
    }
    true
}

fn release_frame(pa: usize) -> bool {
    let Some(idx) = frame_index(pa) else {
        return false;
    };
    // SAFETY: early boot single-hart; refcount table is only touched here.
    unsafe {
        let current = FRAME_REFCOUNT[idx];
        if current == 0 {
            return false;
        }
        if current == 1 {
            FRAME_REFCOUNT[idx] = 0;
            let _ = push_free_frame(pa);
            return true;
        }
        FRAME_REFCOUNT[idx] = current - 1;
    }
    false
}

fn frame_refcount(pa: usize) -> Option<u16> {
    let idx = frame_index(pa)?;
    // SAFETY: early boot single-hart; refcount table is only touched here.
    unsafe { Some(FRAME_REFCOUNT[idx]) }
}

fn with_no_irq<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let sstatus: usize;
    unsafe {
        asm!("csrr {0}, sstatus", out(reg) sstatus);
        asm!("csrci sstatus, 0x2");
    }
    let ret = f();
    unsafe {
        asm!("csrw sstatus, {0}", in(reg) sstatus);
    }
    ret
}

fn push_free_frame(pa: usize) -> bool {
    with_no_irq(|| unsafe {
        if FRAME_FREE_LEN >= MAX_FRAMES {
            return false;
        }
        FRAME_FREE_LIST[FRAME_FREE_LEN] = pa;
        FRAME_FREE_LEN += 1;
        true
    })
}

fn pop_free_frame() -> Option<usize> {
    with_no_irq(|| unsafe {
        if FRAME_FREE_LEN == 0 {
            return None;
        }
        FRAME_FREE_LEN -= 1;
        Some(FRAME_FREE_LIST[FRAME_FREE_LEN])
    })
}

fn table_has_user_l0(table: &PageTable) -> bool {
    for entry in table.entries.iter() {
        if entry.is_valid() && entry.is_leaf() && (entry.flags() & PTE_U) != 0 {
            return true;
        }
    }
    false
}

fn table_has_user_l1(table: &PageTable) -> bool {
    for entry in table.entries.iter() {
        if !entry.is_valid() {
            continue;
        }
        if entry.is_leaf() {
            if (entry.flags() & PTE_U) != 0 {
                return true;
            }
            continue;
        }
        // SAFETY: entry points to a valid next-level table page.
        let l0 = unsafe { &*(entry.ppn().addr().as_usize() as *const PageTable) };
        if table_has_user_l0(l0) {
            return true;
        }
    }
    false
}

/// Clone user mappings from a parent page table for fork/clone.
pub fn clone_user_root(parent_root_pa: usize) -> Option<usize> {
    if parent_root_pa == 0 {
        return None;
    }
    // 基于内核映射创建子根页表，避免直接复用父进程页表页。
    let child_root_pa = alloc_user_root()?;
    // SAFETY: parent/child root page tables are valid in early boot.
    let parent_root = unsafe { &mut *(parent_root_pa as *mut PageTable) };
    let child_root = unsafe { &mut *(child_root_pa as *mut PageTable) };
    let mut ok = true;

    'l2: for l2_idx in 0..SV39_ENTRIES {
        let parent_l2e = parent_root.entries[l2_idx];
        if !parent_l2e.is_valid() {
            continue;
        }
        if parent_l2e.is_leaf() {
            if (parent_l2e.flags() & PTE_U) != 0 {
                if (parent_l2e.flags() & PTE_W) != 0 {
                    ok = false;
                    break 'l2;
                }
                let pa = parent_l2e.ppn().addr().as_usize();
                if !retain_frame(pa) {
                    ok = false;
                    break 'l2;
                }
                child_root.entries[l2_idx] = parent_l2e;
            }
            continue;
        }
        // SAFETY: entry points to a valid next-level table page.
        let parent_l1 = unsafe { &mut *(parent_l2e.ppn().addr().as_usize() as *mut PageTable) };
        if !table_has_user_l1(parent_l1) {
            continue;
        }
        // SAFETY: allocate a fresh L1 page table for the child.
        let Some(child_l1) = (unsafe { alloc_page_table() }) else {
            ok = false;
            break 'l2;
        };
        let child_l1_pa = virt_to_phys(child_l1 as *const _ as usize);
        child_root.entries[l2_idx] =
            PageTableEntry::new(PhysPageNum::new(child_l1_pa >> PAGE_SHIFT), PTE_V);

        for l1_idx in 0..SV39_ENTRIES {
            let parent_l1e = parent_l1.entries[l1_idx];
            if !parent_l1e.is_valid() {
                continue;
            }
            if parent_l1e.is_leaf() {
                if (parent_l1e.flags() & PTE_U) != 0 {
                    if (parent_l1e.flags() & PTE_W) != 0 {
                        ok = false;
                        break 'l2;
                    }
                    let pa = parent_l1e.ppn().addr().as_usize();
                    if !retain_frame(pa) {
                        ok = false;
                        break 'l2;
                    }
                    child_l1.entries[l1_idx] = parent_l1e;
                }
                continue;
            }
            // SAFETY: entry points to a valid next-level table page.
            let parent_l0 = unsafe { &mut *(parent_l1e.ppn().addr().as_usize() as *mut PageTable) };
            if !table_has_user_l0(parent_l0) {
                continue;
            }
            // SAFETY: allocate a fresh L0 page table for the child.
            let Some(child_l0) = (unsafe { alloc_page_table() }) else {
                ok = false;
                break 'l2;
            };
            let child_l0_pa = virt_to_phys(child_l0 as *const _ as usize);
            child_l1.entries[l1_idx] =
                PageTableEntry::new(PhysPageNum::new(child_l0_pa >> PAGE_SHIFT), PTE_V);

            for l0_idx in 0..SV39_ENTRIES {
                let parent_l0e = parent_l0.entries[l0_idx];
                if !parent_l0e.is_valid() || !parent_l0e.is_leaf() {
                    continue;
                }
                if (parent_l0e.flags() & PTE_U) == 0 {
                    continue;
                }
                let new_flags = cow_flags(parent_l0e.flags());
                parent_l0.entries[l0_idx] = PageTableEntry::new(parent_l0e.ppn(), new_flags);
                child_l0.entries[l0_idx] = PageTableEntry::new(parent_l0e.ppn(), new_flags);
                let pa = parent_l0e.ppn().addr().as_usize();
                if !retain_frame(pa) {
                    ok = false;
                    break 'l2;
                }
            }
        }
    }
    if !ok {
        release_user_root(child_root_pa);
        return None;
    }
    flush_tlb();
    Some(child_root_pa)
}

/// Release a user page table and associated user pages.
pub fn release_user_root(root_pa: usize) {
    if root_pa == 0 {
        return;
    }
    let kernel_root_pa = kernel_root_pa();
    if kernel_root_pa == 0 || root_pa == kernel_root_pa {
        return;
    }
    // SAFETY: early boot single-hart; page tables are stable during release.
    let root = unsafe { &mut *(root_pa as *mut PageTable) };
    let kernel_root = unsafe { &*(kernel_root_pa as *const PageTable) };

    for l2_idx in 0..SV39_ENTRIES {
        let l2e = root.entries[l2_idx];
        if !l2e.is_valid() {
            continue;
        }
        if l2e.bits == kernel_root.entries[l2_idx].bits {
            continue;
        }
        if l2e.is_leaf() {
            // 仅处理 4KiB 用户页的释放；大页用户映射暂不支持回收。
            continue;
        }
        let l1_pa = l2e.ppn().addr().as_usize();
        // SAFETY: entry points to a valid next-level table page.
        let l1 = unsafe { &mut *(l1_pa as *mut PageTable) };
        for l1_idx in 0..SV39_ENTRIES {
            let l1e = l1.entries[l1_idx];
            if !l1e.is_valid() {
                continue;
            }
            if l1e.is_leaf() {
                // 仅处理 4KiB 用户页的释放；大页用户映射暂不支持回收。
                continue;
            }
            let l0_pa = l1e.ppn().addr().as_usize();
            // SAFETY: entry points to a valid next-level table page.
            let l0 = unsafe { &mut *(l0_pa as *mut PageTable) };
            for l0_idx in 0..SV39_ENTRIES {
                let l0e = l0.entries[l0_idx];
                if !l0e.is_valid() || !l0e.is_leaf() {
                    continue;
                }
                if (l0e.flags() & PTE_U) == 0 {
                    continue;
                }
                let _ = release_frame(l0e.ppn().addr().as_usize());
            }
            let _ = release_frame(l0_pa);
        }
        let _ = release_frame(l1_pa);
    }
    let _ = release_frame(root_pa);
    flush_tlb();
}

/// Switch the active page table to the provided root.
pub fn switch_root(root_pa: usize) {
    if root_pa == 0 {
        return;
    }
    let satp_value = satp_for_root(root_pa);
    // SAFETY: switching satp requires sfence.vma to synchronize TLB.
    unsafe {
        asm!("csrw satp, {0}", in(reg) satp_value);
        asm!("sfence.vma");
    }
}

fn map_page(root_pa: usize, va: usize, pa: usize, flags: usize) -> bool {
    if root_pa == 0 {
        return false;
    }
    // SAFETY: early boot uses identity mapping; root page table is valid.
    let l2 = unsafe { &mut *(root_pa as *mut PageTable) };
    let [l2_idx, l1_idx, l0_idx] = VirtAddr::new(va).sv39_indexes();
    let l1 = match ensure_table(&mut l2.entries[l2_idx]) {
        Some(table) => table,
        None => return false,
    };
    let l0 = match ensure_table(&mut l1.entries[l1_idx]) {
        Some(table) => table,
        None => return false,
    };
    let entry = &mut l0.entries[l0_idx];
    if entry.is_valid() {
        return false;
    }
    *entry = PageTableEntry::new(PhysPageNum::new(pa >> PAGE_SHIFT), flags);
    true
}

fn lookup_user_pte(root_pa: usize, va: usize) -> Option<PageTableEntry> {
    let entry = lookup_user_pte_mut(root_pa, va)?;
    Some(*entry)
}

fn lookup_user_pte_mut(root_pa: usize, va: usize) -> Option<&'static mut PageTableEntry> {
    if root_pa == 0 {
        return None;
    }
    let l2 = unsafe { &mut *(root_pa as *mut PageTable) };
    let [l2_idx, l1_idx, l0_idx] = VirtAddr::new(va).sv39_indexes();
    let l2e = l2.entries[l2_idx];
    if !l2e.is_valid() {
        return None;
    }
    if l2e.is_leaf() {
        return Some(&mut l2.entries[l2_idx]);
    }
    let l1 = unsafe { &mut *(l2e.ppn().addr().as_usize() as *mut PageTable) };
    let l1e = l1.entries[l1_idx];
    if !l1e.is_valid() {
        return None;
    }
    if l1e.is_leaf() {
        return Some(&mut l1.entries[l1_idx]);
    }
    let l0 = unsafe { &mut *(l1e.ppn().addr().as_usize() as *mut PageTable) };
    Some(&mut l0.entries[l0_idx])
}

fn table_empty(table: &PageTable) -> bool {
    table.entries.iter().all(|entry| !entry.is_valid())
}

fn map_device_regions(root_pa: usize, regions: &[MemoryRegion]) {
    for region in regions {
        if region.size == 0 {
            continue;
        }
        let base = region.base as usize;
        let end = base.saturating_add(region.size as usize);
        let start = align_down(base, PAGE_SIZE);
        let end = align_up(end, PAGE_SIZE);
        let mut addr = start;
        while addr < end {
            let _ = map_page(root_pa, addr, addr, PTE_FLAGS_DEVICE);
            addr += PAGE_SIZE;
        }
    }
}

fn init_frame_allocator(region: MemoryRegion) {
    let base = region.base as usize;
    let size = region.size as usize;
    if size == 0 {
        crate::println!("mm: no usable memory size");
        return;
    }

    let kernel_end = unsafe { &ekernel as *const u8 as usize };
    let mapped_end = base.saturating_add(min(size, IDENTITY_MAP_SIZE));
    let start = align_up(max(kernel_end, base), PAGE_SIZE);
    let end = align_down(mapped_end, PAGE_SIZE);

    if start >= end {
        crate::println!("mm: no usable memory after kernel");
        return;
    }

    let allocator = BumpFrameAllocator::new(PhysAddr::new(start), PhysAddr::new(end));
    // SAFETY: 仅在早期单核初始化时写入，全局只初始化一次。
    unsafe {
        FRAME_ALLOC.write(allocator);
    }
    FRAME_ALLOC_READY.store(true, Ordering::Release);
    FRAME_BASE.store(start, Ordering::Relaxed);
    let count = (end - start) / PAGE_SIZE;
    FRAME_COUNT.store(min(count, MAX_FRAMES), Ordering::Relaxed);
    // SAFETY: early boot single-hart; reset free list length.
    unsafe {
        FRAME_FREE_LEN = 0;
    }
    let pages = (end - start) / PAGE_SIZE;
    crate::println!(
        "mm: frame allocator start={:#x} end={:#x} pages={}",
        start,
        end,
        pages
    );
}

unsafe fn setup_kernel_page_table(region: MemoryRegion) -> Option<usize> {
    // Safety: 仅在早期单核启动阶段调用。
    if region.size == 0 {
        return None;
    }

    let base = align_down(region.base as usize, PAGE_SIZE_2M);
    let size = align_up(min(region.size as usize, IDENTITY_MAP_SIZE), PAGE_SIZE_2M);

    if KERNEL_BASE < base || KERNEL_BASE >= base.saturating_add(size) {
        crate::println!(
            "mm: kernel base {:#x} outside memory region",
            KERNEL_BASE
        );
        return None;
    }

    let l2 = match alloc_page_table() {
        Some(table) => table,
        None => {
            crate::println!("mm: alloc l2 page table failed");
            return None;
        }
    };
    let l1 = match alloc_page_table() {
        Some(table) => table,
        None => {
            crate::println!("mm: alloc l1 page table failed");
            return None;
        }
    };

    let l2_index = (base >> 30) & 0x1ff;
    let l1_start = (base >> 21) & 0x1ff;
    let entries = min(size / PAGE_SIZE_2M, SV39_ENTRIES - l1_start);

    for i in 0..entries {
        let pa = base + i * PAGE_SIZE_2M;
        let index = l1_start + i;
        l1.entries[index] =
            PageTableEntry::new(PhysPageNum::new(pa >> PAGE_SHIFT), PTE_FLAGS_KERNEL);
    }

    if entries * PAGE_SIZE_2M < size {
        crate::println!("mm: memory region truncated to 1GiB mapping");
    }

    let l1_pa = virt_to_phys(l1 as *const _ as usize);
    l2.entries[l2_index] = PageTableEntry::new(PhysPageNum::new(l1_pa >> PAGE_SHIFT), PTE_V);
    let l2_pa = virt_to_phys(l2 as *const _ as usize);

    Some(l2_pa)
}

unsafe fn enable_paging(root_pa: usize) {
    let satp_value = SATP_MODE_SV39 | (root_pa >> PAGE_SHIFT);
    // Safety: 早期阶段仅单核执行，恒等映射保证切换后地址可用。
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

#[inline]
fn read_satp() -> usize {
    let value: usize;
    // SAFETY: reading satp does not modify machine state.
    unsafe {
        asm!("csrr {0}, satp", out(reg) value);
    }
    value
}
