#![allow(dead_code)]

use core::fmt;

use crate::mm::MemoryRegion;

const FDT_MAGIC: u32 = 0xd00dfeed;

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;

const MAX_DEPTH: usize = 16;

#[derive(Copy, Clone, Debug, Default)]
pub struct DtbInfo {
    pub memory: Option<MemoryRegion>,
    pub uart: Option<MemoryRegion>,
    pub timebase_frequency: Option<u64>,
}

#[derive(Copy, Clone, Debug)]
pub enum DtbError {
    NullPointer,
    BadMagic,
    BadOffsets,
    DepthOverflow,
}

#[derive(Copy, Clone, Default)]
struct NodeState {
    is_memory: bool,
    is_uart: bool,
}

#[repr(C)]
struct FdtHeader {
    magic: u32,
    totalsize: u32,
    off_dt_struct: u32,
    off_dt_strings: u32,
    off_mem_rsvmap: u32,
    version: u32,
    last_comp_version: u32,
    boot_cpuid_phys: u32,
    size_dt_strings: u32,
    size_dt_struct: u32,
}

impl FdtHeader {
    unsafe fn read(base: *const u8) -> Self {
        Self {
            magic: read_u32_be(base, 0),
            totalsize: read_u32_be(base, 4),
            off_dt_struct: read_u32_be(base, 8),
            off_dt_strings: read_u32_be(base, 12),
            off_mem_rsvmap: read_u32_be(base, 16),
            version: read_u32_be(base, 20),
            last_comp_version: read_u32_be(base, 24),
            boot_cpuid_phys: read_u32_be(base, 28),
            size_dt_strings: read_u32_be(base, 32),
            size_dt_struct: read_u32_be(base, 36),
        }
    }
}

pub fn parse(dtb_addr: usize) -> Result<DtbInfo, DtbError> {
    if dtb_addr == 0 {
        return Err(DtbError::NullPointer);
    }

    // Safety: dtb_addr points to a valid FDT provided by the firmware.
    let base = dtb_addr as *const u8;
    let header = unsafe { FdtHeader::read(base) };
    if header.magic != FDT_MAGIC {
        return Err(DtbError::BadMagic);
    }

    let totalsize = header.totalsize as usize;
    let struct_off = header.off_dt_struct as usize;
    let strings_off = header.off_dt_strings as usize;
    let struct_size = header.size_dt_struct as usize;
    let strings_size = header.size_dt_strings as usize;

    if struct_off + struct_size > totalsize || strings_off + strings_size > totalsize {
        return Err(DtbError::BadOffsets);
    }

    let struct_base = unsafe { base.add(struct_off) };
    let struct_end = unsafe { struct_base.add(struct_size) };
    let strings_base = unsafe { base.add(strings_off) };

    let mut addr_cells = 2usize;
    let mut size_cells = 2usize;

    let mut info = DtbInfo::default();
    let mut stack = [NodeState::default(); MAX_DEPTH];
    let mut depth = 0usize;

    let mut cursor = struct_base;
    while (cursor as usize) < (struct_end as usize) {
        let token = unsafe { read_u32_be_ptr(cursor) };
        cursor = unsafe { cursor.add(4) };
        match token {
            FDT_BEGIN_NODE => {
                let name_len = unsafe { cstr_len(cursor, struct_end) };
                let name = unsafe { read_str(cursor, name_len) };
                cursor = unsafe { cursor.add(align_up(name_len + 1, 4)) };

                if depth >= MAX_DEPTH {
                    return Err(DtbError::DepthOverflow);
                }

                let mut state = NodeState::default();
                if let Some(node_name) = name {
                    if node_name.starts_with("memory@") {
                        state.is_memory = true;
                    }
                    if node_name.starts_with("uart@") || node_name.starts_with("serial@") {
                        state.is_uart = true;
                    }
                }
                stack[depth] = state;
                depth += 1;
            }
            FDT_END_NODE => {
                if depth > 0 {
                    depth -= 1;
                }
            }
            FDT_PROP => {
                let len = unsafe { read_u32_be_ptr(cursor) } as usize;
                cursor = unsafe { cursor.add(4) };
                let nameoff = unsafe { read_u32_be_ptr(cursor) } as usize;
                cursor = unsafe { cursor.add(4) };
                let value = cursor;
                cursor = unsafe { cursor.add(align_up(len, 4)) };

                if depth == 0 {
                    continue;
                }

                if nameoff >= strings_size {
                    continue;
                }
                let name_len = unsafe {
                    cstr_len(strings_base.add(nameoff), strings_base.add(strings_size))
                };
                let name = unsafe { read_str(strings_base.add(nameoff), name_len) };
                let state = &mut stack[depth - 1];

                match name {
                    Some("#address-cells") if depth == 1 => {
                        if len >= 4 {
                            addr_cells = unsafe { read_u32_be_ptr(value) } as usize;
                        }
                    }
                    Some("#size-cells") if depth == 1 => {
                        if len >= 4 {
                            size_cells = unsafe { read_u32_be_ptr(value) } as usize;
                        }
                    }
                    Some("device_type") => {
                        let str_len = unsafe { cstr_len(value, value.add(len)) };
                        if let Some(kind) = unsafe { read_str(value, str_len) } {
                            if kind == "memory" {
                                state.is_memory = true;
                            }
                        }
                    }
                    Some("timebase-frequency") if info.timebase_frequency.is_none() => {
                        if len >= 4 {
                            let freq = unsafe { read_u32_be_ptr(value) } as u64;
                            info.timebase_frequency = Some(freq);
                        }
                    }
                    Some("compatible") => {
                        if has_uart_compat(value, len) {
                            state.is_uart = true;
                        }
                    }
                    Some("reg") => {
                        if state.is_memory && info.memory.is_none() {
                            if let Some(region) = parse_reg(value, len, addr_cells, size_cells) {
                                info.memory = Some(region);
                            }
                        } else if state.is_uart && info.uart.is_none() {
                            if let Some(region) = parse_reg(value, len, addr_cells, size_cells) {
                                info.uart = Some(region);
                            }
                        }
                    }
                    _ => {}
                }
            }
            FDT_NOP => {}
            FDT_END => break,
            _ => break,
        }
    }

    Ok(info)
}

fn parse_reg(value: *const u8, len: usize, addr_cells: usize, size_cells: usize) -> Option<MemoryRegion> {
    let total_cells = addr_cells + size_cells;
    if total_cells == 0 || total_cells > 4 {
        return None;
    }
    let need = total_cells * 4;
    if len < need {
        return None;
    }
    let addr = read_cells(value, addr_cells)?;
    let size = read_cells(unsafe { value.add(addr_cells * 4) }, size_cells)?;
    Some(MemoryRegion { base: addr, size })
}

fn read_cells(value: *const u8, cells: usize) -> Option<u64> {
    if cells == 0 || cells > 2 {
        return None;
    }
    let mut out = 0u64;
    for idx in 0..cells {
        let cell = unsafe { read_u32_be_ptr(value.add(idx * 4)) } as u64;
        out = (out << 32) | cell;
    }
    Some(out)
}

fn has_uart_compat(value: *const u8, len: usize) -> bool {
    let mut offset = 0usize;
    while offset < len {
        let ptr = unsafe { value.add(offset) };
        let part_len = unsafe { cstr_len(ptr, value.add(len)) };
        if part_len == 0 {
            offset += 1;
            continue;
        }
        let s = unsafe { read_str(ptr, part_len) };
        if matches!(s, Some("ns16550a") | Some("ns16550") | Some("uart8250")) {
            return true;
        }
        offset += part_len + 1;
    }
    false
}

unsafe fn read_u32_be(base: *const u8, offset: usize) -> u32 {
    read_u32_be_ptr(base.add(offset))
}

unsafe fn read_u32_be_ptr(ptr: *const u8) -> u32 {
    let raw = core::ptr::read_unaligned(ptr as *const u32);
    u32::from_be(raw)
}

unsafe fn cstr_len(start: *const u8, end: *const u8) -> usize {
    let mut p = start;
    while p < end {
        if *p == 0 {
            break;
        }
        p = p.add(1);
    }
    p as usize - start as usize
}

unsafe fn read_str<'a>(ptr: *const u8, len: usize) -> Option<&'a str> {
    if len == 0 {
        return Some("");
    }
    let bytes = core::slice::from_raw_parts(ptr, len);
    core::str::from_utf8(bytes).ok()
}

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

impl fmt::Display for DtbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
