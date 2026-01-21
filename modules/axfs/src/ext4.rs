//! ext4 文件系统实现。
//!
//! 中文注释：这里实现的是“最小可用”的 ext4 子集，主要面向 Aurora 的根文件系统。
//! - 支持：超级块/块组描述符/位图、inode、目录项遍历、读写/创建/截断。
//! - 寻址：同时支持 extent 树与传统间接块，但写入路径只实现了最小集。
//! - 简化：只在第 0 块组分配 inode/数据块，不做跨块组均衡。
//! - 不支持：日志(journal)、metadata_csum 校验、复杂特性（配额/xattr/ACL）。
//! - 风险：元数据校验未维护，宿主机工具可能提示“校验不一致”。

use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::block::{BlockCache, BlockDevice, BlockId};

// ====== 磁盘结构相关常量 ======
// ext4 根目录 inode 固定为 2。
const EXT4_ROOT_INODE: InodeId = 2;
// ext4 魔数。
const EXT4_MAGIC: u16 = 0xef53;
// 超级块位于偏移 1024 字节处，大小固定 1024 字节。
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
// 超级块字段偏移（只取本实现需要的最小集合）。
const SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET: usize = 24;
const SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET: usize = 32;
const SUPERBLOCK_INODES_PER_GROUP_OFFSET: usize = 40;
const SUPERBLOCK_MAGIC_OFFSET: usize = 56;
const SUPERBLOCK_INODE_SIZE_OFFSET: usize = 88;
// 块组描述符大小与字段偏移。
const GROUP_DESC_SIZE: usize = 32;
const GROUP_DESC_BLOCK_BITMAP_OFFSET: usize = 0;
const GROUP_DESC_INODE_BITMAP_OFFSET: usize = 4;
const GROUP_DESC_INODE_TABLE_OFFSET: usize = 8;
// inode 结构中的字段偏移（仅解析所需字段）。
const INODE_MODE_OFFSET: usize = 0;
const INODE_SIZE_LO_OFFSET: usize = 4;
const INODE_FLAGS_OFFSET: usize = 32;
const INODE_BLOCK_OFFSET: usize = 40;
const INODE_BLOCK_LEN: usize = 60;
const INODE_SIZE_HIGH_OFFSET: usize = 108;
// extents 标志位（inode.flags 中）。
const EXT4_EXTENTS_FLAG: u32 = 0x0008_0000;
// extent header/entry 相关常量。
const EXTENT_HEADER_MAGIC: u16 = 0xf30a;
const EXTENT_HEADER_SIZE: usize = 12;
const EXTENT_ENTRY_SIZE: usize = 12;
const EXTENT_LEN_MAX: u16 = 0x7fff;
const EXTENT_INODE_CAPACITY: usize = (INODE_BLOCK_LEN - EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE;
// scratch 缓冲区大小（与最大支持块大小一致）。
const EXT4_SCRATCH_SIZE: usize = 4096;
// inode mode 的类型位。
const EXT4_MODE_DIR: u16 = 0x4000;
const EXT4_MODE_FILE: u16 = 0x8000;
// 目录项 header 以及类型码。
const EXT4_DIR_ENTRY_HEADER: usize = 8;
const EXT4_DIR_ENTRY_FILE: u8 = 1;
const EXT4_DIR_ENTRY_DIR: u8 = 2;
const EXT4_DIR_ENTRY_CHAR: u8 = 3;
const EXT4_DIR_ENTRY_BLOCK: u8 = 4;
const EXT4_DIR_ENTRY_FIFO: u8 = 5;
const EXT4_DIR_ENTRY_SOCKET: u8 = 6;
const EXT4_DIR_ENTRY_SYMLINK: u8 = 7;
// inode.blocks 中前 12 个为直接块指针（经典 ext2/3/4 格式）。
const EXT4_DIRECT_BLOCKS: usize = 12;

// 全局 scratch 缓冲区：解析/构造元数据时复用，避免堆分配，用自旋锁串行访问。
// 注意：这意味着所有读写都会串行化，换取实现简单。
struct ScratchLock {
    locked: AtomicBool,
    buf: UnsafeCell<[u8; EXT4_SCRATCH_SIZE]>,
}

unsafe impl Sync for ScratchLock {}

impl ScratchLock {
    // 初始化 scratch 锁与缓冲区。
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            buf: UnsafeCell::new([0u8; EXT4_SCRATCH_SIZE]),
        }
    }

    // 获取互斥访问权（自旋等待）。
    fn lock(&self) -> ScratchGuard<'_> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        ScratchGuard { lock: self }
    }
}

struct ScratchGuard<'a> {
    lock: &'a ScratchLock,
}

impl<'a> ScratchGuard<'a> {
    // 返回可变缓冲区引用，生命周期由 guard 控制。
    fn get_mut(&self) -> &mut [u8; EXT4_SCRATCH_SIZE] {
        // 安全性： guard 确保对 scratch 缓冲区的独占访问。
        unsafe { &mut *self.lock.buf.get() }
    }
}

impl Drop for ScratchGuard<'_> {
    // 释放锁。
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

static EXT4_SCRATCH: ScratchLock = ScratchLock::new();

#[derive(Clone, Copy, Debug)]
/// 本实现需要的 ext4 超级块字段。
/// 仅解析本实现需要的字段，忽略其他 ext4 特性位。
/// 字段偏移来自 ext4 超级块布局（1KiB 处）。
pub struct SuperBlock {
    /// log2(block_size / 1024)。
    pub log_block_size: u32,
    /// 每组块数。
    pub blocks_per_group: u32,
    /// 每组 inode 数。
    pub inodes_per_group: u32,
    /// inode 大小（字节）。
    pub inode_size: u16,
    /// ext4 魔数。
    pub magic: u16,
}

impl SuperBlock {
    /// 从给定缓冲解析超级块。
    /// 校验 magic，并检查 block size / inode size 是否处于可支持范围。
    pub fn parse(buf: &[u8]) -> VfsResult<Self> {
        if buf.len() < SUPERBLOCK_SIZE {
            return Err(VfsError::Invalid);
        }
        let magic = read_u16(buf, SUPERBLOCK_MAGIC_OFFSET);
        if magic != EXT4_MAGIC {
            return Err(VfsError::Invalid);
        }
        let log_block_size = read_u32(buf, SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET);
        let blocks_per_group = read_u32(buf, SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET);
        let inodes_per_group = read_u32(buf, SUPERBLOCK_INODES_PER_GROUP_OFFSET);
        let inode_size = read_u16(buf, SUPERBLOCK_INODE_SIZE_OFFSET);
        // ext4 约定 block_size = 1024 << log_block_size。
        let block_size = 1024u32.checked_shl(log_block_size).ok_or(VfsError::Invalid)?;
        if block_size < 1024 || !block_size.is_power_of_two() || inode_size == 0 {
            return Err(VfsError::Invalid);
        }
        Ok(Self {
            log_block_size,
            blocks_per_group,
            inodes_per_group,
            inode_size,
            magic,
        })
    }

    /// 返回文件系统块大小（字节）。
    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }
}

#[derive(Clone, Copy, Debug)]
/// 块组描述符：只使用位图和 inode 表的起始块号。
/// 注意：这里没有解析 free counts，也不更新 group 统计信息。
struct GroupDesc {
    block_bitmap: u32,
    inode_bitmap: u32,
    inode_table: u32,
}

impl GroupDesc {
    // 解析块组描述符，提取位图与 inode 表位置。
    fn parse(buf: &[u8]) -> VfsResult<Self> {
        if buf.len() < GROUP_DESC_SIZE {
            return Err(VfsError::Invalid);
        }
        let block_bitmap = read_u32(buf, GROUP_DESC_BLOCK_BITMAP_OFFSET);
        let inode_bitmap = read_u32(buf, GROUP_DESC_INODE_BITMAP_OFFSET);
        let inode_table = read_u32(buf, GROUP_DESC_INODE_TABLE_OFFSET);
        if block_bitmap == 0 || inode_bitmap == 0 || inode_table == 0 {
            return Err(VfsError::Invalid);
        }
        Ok(Self {
            block_bitmap,
            inode_bitmap,
            inode_table,
        })
    }
}

#[derive(Clone, Copy, Debug)]
/// inode 元数据（只保留读写/寻址所需字段）。
/// blocks 数组在 extents 模式下存放 extent header/entries 原始字节。
struct Ext4Inode {
    mode: u16,
    size: u64,
    flags: u32,
    blocks: [u32; 15],
}

/// 基于块设备的 ext4 文件系统。
/// 通过 BlockCache 读写块设备，并实现 VfsOps 接口供内核使用。
pub struct Ext4Fs<'a> {
    cache: BlockCache<'a>,
    superblock: SuperBlock,
}

impl<'a> Ext4Fs<'a> {
    /// 从块设备创建 ext4 文件系统。
    /// 1) 使用 BlockCache 访问块设备
    /// 2) 读取超级块并解析
    pub fn new(device: &'a dyn BlockDevice) -> VfsResult<Self> {
        let cache = BlockCache::new(device);
        let block_size = cache.block_size();
        if block_size == 0 || block_size > 4096 {
            return Err(VfsError::Invalid);
        }
        let mut buf = [0u8; SUPERBLOCK_SIZE];
        read_bytes(&cache, SUPERBLOCK_OFFSET, &mut buf)?;
        let superblock = SuperBlock::parse(&buf)?;
        Ok(Self { cache, superblock })
    }

    /// 返回解析后的超级块。
    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }

    /// 返回文件系统块大小（字节）。
    pub fn fs_block_size(&self) -> u32 {
        self.superblock.block_size()
    }

    /// 将文件系统块读入给定缓冲区。
    pub fn read_block(&self, block: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        self.cache.read_block(block, buf)
    }

    // 读取块组描述符：block size=1024 时表从块 2 开始，否则从块 1 开始。
    // ext4 的组描述符表紧跟超级块之后。
    fn read_group_desc(&self, group: u32) -> VfsResult<GroupDesc> {
        let block_size = self.fs_block_size();
        // block_size=1024 时：block0=引导区，block1=超级块，block2=组描述符表。
        let table_block = if block_size == 1024 { 2 } else { 1 };
        let offset = table_block as u64 * block_size as u64
            + group as u64 * GROUP_DESC_SIZE as u64;
        let mut buf = [0u8; GROUP_DESC_SIZE];
        read_bytes(&self.cache, offset, &mut buf)?;
        GroupDesc::parse(&buf)
    }

    // 通过 inode 号计算其所在块组与表项偏移。
    // 公式：inode_index = inode-1，group = inode_index / inodes_per_group。
    fn inode_location(&self, inode: InodeId) -> VfsResult<(u64, usize)> {
        if inode == 0 {
            return Err(VfsError::NotFound);
        }
        let inode_index = inode - 1;
        let inodes_per_group = self.superblock.inodes_per_group as u64;
        if inodes_per_group == 0 {
            return Err(VfsError::Invalid);
        }
        let group = (inode_index / inodes_per_group) as u32;
        let index = (inode_index % inodes_per_group) as u32;
        let inode_size = self.superblock.inode_size as usize;
        // 这里使用 512B 的临时缓冲；超过则不支持。
        if inode_size == 0 || inode_size > 512 {
            return Err(VfsError::Invalid);
        }
        let desc = self.read_group_desc(group)?;
        let block_size = self.fs_block_size() as u64;
        let inode_table = desc.inode_table as u64;
        let offset = inode_table * block_size + index as u64 * inode_size as u64;
        Ok((offset, inode_size))
    }

    // 读取 inode 元数据：模式/大小/flags/块映射字段。
    // size 需要拼接 low/high 两部分（大于 4GiB 时使用 high）。
    fn read_inode(&self, inode: InodeId) -> VfsResult<Ext4Inode> {
        let (offset, inode_size) = self.inode_location(inode)?;
        let mut buf = [0u8; 512];
        read_bytes(&self.cache, offset, &mut buf[..inode_size])?;
        // mode/size/flags/blocks 是最基本信息。
        let mode = read_u16(&buf, INODE_MODE_OFFSET);
        let size_lo = read_u32(&buf, INODE_SIZE_LO_OFFSET) as u64;
        let size_high = if inode_size >= INODE_SIZE_HIGH_OFFSET + 4 {
            read_u32(&buf, INODE_SIZE_HIGH_OFFSET) as u64
        } else {
            0
        };
        let size = size_lo | (size_high << 32);
        let flags = read_u32(&buf, INODE_FLAGS_OFFSET);
        if INODE_BLOCK_OFFSET + INODE_BLOCK_LEN > inode_size {
            return Err(VfsError::Invalid);
        }
        let mut blocks = [0u32; 15];
        for i in 0..15 {
            let off = INODE_BLOCK_OFFSET + i * 4;
            blocks[i] = read_u32(&buf, off);
        }
        Ok(Ext4Inode {
            mode,
            size,
            flags,
            blocks,
        })
    }

    // 写回 inode 元数据，保留未覆盖字段（先读后写）。
    // 只更新 mode/size/flags/blocks，不处理校验与日志。
    fn write_inode(&self, inode: InodeId, inode_meta: &Ext4Inode) -> VfsResult<()> {
        let (offset, inode_size) = self.inode_location(inode)?;
        let mut buf = [0u8; 512];
        read_bytes(&self.cache, offset, &mut buf[..inode_size])?;
        write_u16(&mut buf, INODE_MODE_OFFSET, inode_meta.mode);
        write_u32(&mut buf, INODE_SIZE_LO_OFFSET, inode_meta.size as u32);
        if inode_size >= INODE_SIZE_HIGH_OFFSET + 4 {
            write_u32(&mut buf, INODE_SIZE_HIGH_OFFSET, (inode_meta.size >> 32) as u32);
        }
        write_u32(&mut buf, INODE_FLAGS_OFFSET, inode_meta.flags);
        if INODE_BLOCK_OFFSET + INODE_BLOCK_LEN > inode_size {
            return Err(VfsError::Invalid);
        }
        for (idx, block) in inode_meta.blocks.iter().enumerate() {
            write_u32(&mut buf, INODE_BLOCK_OFFSET + idx * 4, *block);
        }
        write_bytes(&self.cache, offset, &buf[..inode_size])
    }

    // 逻辑块 -> 物理块映射：优先 extents，否则走传统间接块。
    // extents 模式下 blocks 数组中存的是 extent header/entries。
    fn map_block(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        if (inode.flags & EXT4_EXTENTS_FLAG) != 0 {
            return self.map_extent_tree(inode, logical);
        }
        self.map_indirect_block(inode, logical)
    }

    // 从 inode 读取数据：
    // - 按块读取，支持任意 offset
    // - 若逻辑块未分配（稀疏文件），返回 0 填充
    fn read_from_inode(&self, inode: &Ext4Inode, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        // 读取长度不超过文件尾。
        let max = core::cmp::min(buf.len() as u64, inode.size - offset) as usize;
        let block_size = self.fs_block_size() as usize;
        let mut remaining = max;
        let mut total = 0usize;
        let mut cur_offset = offset;
        while remaining > 0 {
            let block_index = (cur_offset / block_size as u64) as u32;
            let in_block = (cur_offset % block_size as u64) as usize;
            let to_copy = core::cmp::min(remaining, block_size - in_block);
            match self.map_block(inode, block_index)? {
                Some(phys) => {
                    // 有物理映射：按实际物理块读取。
                    let block_offset = phys * block_size as u64 + in_block as u64;
                    read_bytes(&self.cache, block_offset, &mut buf[total..total + to_copy])?;
                }
                None => {
                    // 稀疏空洞：以零填充，不视为 EOF。
                    buf[total..total + to_copy].fill(0);
                }
            }
            total += to_copy;
            remaining -= to_copy;
            cur_offset += to_copy as u64;
        }
        Ok(total)
    }

    // 线性扫描目录项（ext4 dirent 格式），回调可返回 true 终止遍历。
    // ext4 目录项是“变长记录”，每条记录包含 inode/rec_len/name_len/file_type。
    fn scan_dir_entries(
        &self,
        inode: &Ext4Inode,
        mut visit: impl FnMut(InodeId, &[u8], FileType) -> VfsResult<bool>,
    ) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        let mut offset = 0u64;
        let mut scratch = [0u8; 4096];
        // 目录也是普通文件：按块读取再解析 dirent。
        while offset < inode.size {
            let read = self.read_from_inode(inode, offset, &mut scratch[..block_size])?;
            if read == 0 {
                break;
            }
            let mut pos = 0usize;
            while pos + 8 <= read {
                let inode_num = read_u32(&scratch, pos) as InodeId;
                let rec_len = read_u16(&scratch, pos + 4) as usize;
                // rec_len 表示该记录占用的总空间（含填充）。
                if rec_len < 8 || pos + rec_len > read {
                    break;
                }
                let name_len = scratch[pos + 6] as usize;
                let file_type_raw = scratch[pos + 7];
                if inode_num != 0 && name_len <= rec_len - 8 {
                    // 只在 inode != 0 且 name_len 合法时，认为这条记录有效。
                    let name = &scratch[pos + 8..pos + 8 + name_len];
                    let file_type = match file_type_raw {
                        1 => FileType::File,
                        2 => FileType::Dir,
                        3 => FileType::Char,
                        4 => FileType::Block,
                        5 => FileType::Fifo,
                        6 => FileType::Socket,
                        7 => FileType::Symlink,
                        _ => {
                            // file_type_raw 未识别时，退回读取 inode 判断类型。
                            let inode_meta = self.read_inode(inode_num)?;
                            inode_mode_type(inode_meta.mode)
                        }
                    };
                    if visit(inode_num, name, file_type)? {
                        return Ok(());
                    }
                }
                pos += rec_len;
            }
            offset += block_size as u64;
        }
        Ok(())
    }

    // extent 树查找：从 inode 内的 extent header 开始，按 depth 逐层下钻。
    fn map_extent_tree(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        // inode.blocks 中保存了 extent header/entries 的原始字节。
        let mut raw = [0u8; INODE_BLOCK_LEN];
        for (idx, block) in inode.blocks.iter().enumerate() {
            let offset = idx * 4;
            raw[offset..offset + 4].copy_from_slice(&block.to_le_bytes());
        }
        let header = parse_extent_header(&raw)?;
        // depth=0 表示所有 extent 都在 inode 内。
        if header.depth == 0 {
            return map_extent_entries(&raw, header.entries, logical);
        }
        // depth>0：需要按索引逐层下钻到叶子。
        let mut next = match find_extent_index(&raw, header.entries, logical)? {
            Some(block) => block,
            None => return Ok(None),
        };

        let block_size = self.fs_block_size() as usize;
        let mut scratch = [0u8; 4096];
        loop {
            self.read_fs_block(next, &mut scratch[..block_size])?;
            let header = parse_extent_header(&scratch)?;
            if header.depth == 0 {
                return map_extent_entries(&scratch, header.entries, logical);
            }
            // 继续下钻：根据逻辑块选择下一层索引指向的块。
            match find_extent_index(&scratch, header.entries, logical)? {
                Some(block) => next = block,
                None => return Ok(None),
            }
        }
    }

    // 传统间接块寻址：
    // - 0..11 直接块
    // - 12   一级间接
    // - 13   二级间接
    // - 14   三级间接
    fn map_indirect_block(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        // 直接块：inode.blocks[0..12]
        if logical < EXT4_DIRECT_BLOCKS as u32 {
            let phys = inode.blocks[logical as usize];
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        let block_size = self.fs_block_size() as u64;
        let ptrs_per_block = block_size / 4;
        if ptrs_per_block == 0 {
            return Err(VfsError::Invalid);
        }

        // 一级间接：inode.blocks[12]
        let mut index = logical as u64 - EXT4_DIRECT_BLOCKS as u64;
        if index < ptrs_per_block {
            // 从单级间接块中读取第 index 个指针。
            let phys = self.read_indirect_ptr(inode.blocks[12], index, block_size)?;
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        // 二级间接：inode.blocks[13]
        index -= ptrs_per_block;
        let ptrs_per_block2 = ptrs_per_block * ptrs_per_block;
        if index < ptrs_per_block2 {
            let first = index / ptrs_per_block;
            let second = index % ptrs_per_block;
            // 先在二级索引中定位到一级间接块，再取具体指针。
            let indirect = self.read_indirect_ptr(inode.blocks[13], first, block_size)?;
            if indirect == 0 {
                return Ok(None);
            }
            let phys = self.read_indirect_ptr(indirect, second, block_size)?;
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        // 三级间接：inode.blocks[14]
        index -= ptrs_per_block2;
        let ptrs_per_block3 = ptrs_per_block2 * ptrs_per_block;
        if index < ptrs_per_block3 {
            let first = index / ptrs_per_block2;
            let rem = index % ptrs_per_block2;
            let second = rem / ptrs_per_block;
            let third = rem % ptrs_per_block;
            // 三级间接：三级索引 -> 二级索引 -> 一级索引 -> 数据块。
            let indirect = self.read_indirect_ptr(inode.blocks[14], first, block_size)?;
            if indirect == 0 {
                return Ok(None);
            }
            let indirect = self.read_indirect_ptr(indirect, second, block_size)?;
            if indirect == 0 {
                return Ok(None);
            }
            let phys = self.read_indirect_ptr(indirect, third, block_size)?;
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        Err(VfsError::NotSupported)
    }

    // 分配数据块：按 inode 的寻址方式（extent/间接块）更新映射。
    // 注意：这里只实现了一级间接的“新增”，二/三级间接不支持扩容。
    fn allocate_data_block(&self, inode: &mut Ext4Inode, block_index: u32) -> VfsResult<u64> {
        if (inode.flags & EXT4_EXTENTS_FLAG) != 0 {
            return self.allocate_extent_block(inode, block_index);
        }
        if block_index < EXT4_DIRECT_BLOCKS as u32 {
            // 直接块：直接在 inode.blocks 中填入物理块号。
            let new_block = self.allocate_block()?;
            inode.blocks[block_index as usize] = new_block;
            self.zero_fs_block(new_block)?;
            return Ok(new_block as u64);
        }
        let block_size = self.fs_block_size() as u64;
        let ptrs_per_block = block_size / 4;
        if ptrs_per_block == 0 {
            return Err(VfsError::Invalid);
        }
        let index = block_index as u64 - EXT4_DIRECT_BLOCKS as u64;
        // 这里只支持一级间接扩展：超过范围直接 NotSupported。
        if index >= ptrs_per_block {
            return Err(VfsError::NotSupported);
        }
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        let indirect_block = if inode.blocks[12] == 0 {
            // 首次进入一级间接：先分配间接块本身，再写 0。
            let block = self.allocate_block()?;
            inode.blocks[12] = block;
            self.zero_fs_block(block)?;
            scratch[..block_size as usize].fill(0);
            block as u64
        } else {
            let block = inode.blocks[12] as u64;
            self.read_fs_block(block, &mut scratch[..block_size as usize])?;
            block
        };
        let entry_offset = (index * 4) as usize;
        let current = read_u32(&scratch, entry_offset);
        if current != 0 {
            return Ok(current as u64);
        }
        let new_block = self.allocate_block()?;
        write_u32(&mut scratch, entry_offset, new_block);
        self.write_fs_block(indirect_block, &scratch[..block_size as usize])?;
        self.zero_fs_block(new_block)?;
        Ok(new_block as u64)
    }

    // extent 分配入口：支持 depth 0/1/2 的 extent 树。
    // 如 inode 中 extents 为空，则先初始化 extent header。
    fn allocate_extent_block(&self, inode: &mut Ext4Inode, block_index: u32) -> VfsResult<u64> {
        let mut raw = inode_extent_raw(inode);
        let mut header = match parse_extent_header(&raw) {
            Ok(header) => header,
            Err(VfsError::NotSupported) => {
                if raw.iter().all(|&b| b == 0) {
                    init_extent_raw(&mut raw);
                    ExtentHeader { entries: 0, depth: 0 }
                } else {
                    return Err(VfsError::NotSupported);
                }
            }
            Err(err) => return Err(err),
        };
        match header.depth {
            0 => self.allocate_extent_block_in_inode(inode, &mut raw, &mut header, block_index),
            1 => self.allocate_extent_block_in_tree(inode, &mut raw, &mut header, block_index, None),
            _ => Err(VfsError::NotSupported),
        }
    }

    // depth=0：extent 全部存放在 inode 内部。
    // 插入新 extent 时尝试与前一个 extent 合并，避免碎片。
    fn allocate_extent_block_in_inode(
        &self,
        inode: &mut Ext4Inode,
        raw: &mut [u8; INODE_BLOCK_LEN],
        header: &mut ExtentHeader,
        block_index: u32,
    ) -> VfsResult<u64> {
        if header.entries as usize > EXTENT_INODE_CAPACITY {
            return Err(VfsError::Invalid);
        }
        // 拷贝当前 inode 内的 extent entries，便于排序/插入/合并。
        let mut entries = [ExtentEntry::default(); EXTENT_INODE_CAPACITY];
        let count = header.entries as usize;
        for idx in 0..count {
            entries[idx] = read_extent_entry(raw, idx);
        }

        // 命中已有 extent：直接计算物理块位置。
        for entry in entries.iter().take(count) {
            if entry.covers(block_index) {
                let phys = entry.start + (block_index - entry.block) as u64;
                return Ok(phys);
            }
        }

        // 找到插入位置（按逻辑块号排序）。
        let mut insert_pos = count;
        for idx in 0..count {
            if block_index < entries[idx].block {
                insert_pos = idx;
                break;
            }
        }

        // 分配新的物理块，默认先尝试合并。
        let new_block = self.allocate_block()?;
        self.zero_fs_block(new_block)?;
        let new_start = new_block as u64;

        // 尝试与前一个 extent 合并（逻辑连续 + 物理连续）。
        if insert_pos > 0 {
            let prev = entries[insert_pos - 1];
            if prev.can_extend(block_index, new_start) {
                let mut updated = prev;
                updated.len += 1;
                entries[insert_pos - 1] = updated;
                write_extent_header(raw, header.entries, header.depth, EXTENT_INODE_CAPACITY as u16);
                for idx in 0..count {
                    write_extent_entry(raw, idx, entries[idx]);
                }
                store_inode_extents(inode, raw);
                return Ok(new_start);
            }
        }

        // inode 内空间足够：插入新 extent，并保持有序。
        if count < EXTENT_INODE_CAPACITY {
            for idx in (insert_pos..count).rev() {
                entries[idx + 1] = entries[idx];
            }
            entries[insert_pos] = ExtentEntry {
                block: block_index,
                len: 1,
                start: new_start,
            };
            header.entries = (count + 1) as u16;
            write_extent_header(raw, header.entries, header.depth, EXTENT_INODE_CAPACITY as u16);
            for idx in 0..(count + 1) {
                write_extent_entry(raw, idx, entries[idx]);
            }
            store_inode_extents(inode, raw);
            return Ok(new_start);
        }

        // inode 内 extent 已满：升级为 extent 树（depth=1）后再插入。
        self.upgrade_inode_extents(inode, raw, entries, count, block_index, new_start)
    }

    // depth=1：inode 指向 extent 索引块，索引块再指向叶子块。
    // 这里只实现“按逻辑块号选择叶子”的简单策略。
    fn allocate_extent_block_in_tree(
        &self,
        inode: &mut Ext4Inode,
        raw: &mut [u8; INODE_BLOCK_LEN],
        header: &mut ExtentHeader,
        block_index: u32,
        prealloc: Option<u64>,
    ) -> VfsResult<u64> {
        if header.depth == 2 {
            return self.allocate_extent_block_in_depth2(inode, raw, header, block_index, prealloc);
        }
        if header.depth != 1 {
            return Err(VfsError::NotSupported);
        }
        if header.entries as usize > EXTENT_INODE_CAPACITY {
            return Err(VfsError::Invalid);
        }
        // root 层索引 entries（inode 中保存）。
        let mut indices = [ExtentIndex::default(); EXTENT_INODE_CAPACITY];
        let index_count = header.entries as usize;
        for idx in 0..index_count {
            indices[idx] = read_extent_index(raw, idx);
        }
        if index_count == 0 {
            return Err(VfsError::Invalid);
        }
        // 选择逻辑块所在的叶子块：取最后一个 ei_block <= logical。
        let mut chosen = 0usize;
        for idx in 1..index_count {
            if block_index >= indices[idx].block {
                chosen = idx;
            } else {
                break;
            }
        }
        let leaf_block = indices[chosen].leaf;
        let block_size = self.fs_block_size() as usize;
        let leaf_capacity = extent_capacity(block_size);
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        self.read_fs_block(leaf_block, &mut scratch[..block_size])?;
        let mut leaf_header = parse_extent_header(&scratch)?;
        if leaf_header.depth != 0 {
            return Err(VfsError::Invalid);
        }
        let mut leaf_entries = leaf_header.entries as usize;
        if leaf_entries > leaf_capacity {
            return Err(VfsError::Invalid);
        }

        // 命中叶子 extent，直接返回。
        for idx in 0..leaf_entries {
            let entry = read_extent_entry(&scratch, idx);
            if entry.covers(block_index) {
                let phys = entry.start + (block_index - entry.block) as u64;
                return Ok(phys);
            }
        }

        // 查找插入位置（保持逻辑块顺序）。
        let mut insert_pos = leaf_entries;
        for idx in 0..leaf_entries {
            let entry = read_extent_entry(&scratch, idx);
            if block_index < entry.block {
                insert_pos = idx;
                break;
            }
        }

        // 可能由上层提前分配物理块，否则现在分配。
        let new_start = match prealloc {
            Some(addr) => addr,
            None => {
                let new_block = self.allocate_block()?;
                self.zero_fs_block(new_block)?;
                new_block as u64
            }
        };

        // 尝试与前一 extent 合并。
        if insert_pos > 0 {
            let prev = read_extent_entry(&scratch, insert_pos - 1);
            if prev.can_extend(block_index, new_start) {
                let mut updated = prev;
                updated.len += 1;
                write_extent_entry(&mut scratch, insert_pos - 1, updated);
                write_extent_header(&mut scratch, leaf_header.entries, leaf_header.depth, leaf_capacity as u16);
                self.write_fs_block(leaf_block, &scratch[..block_size])?;
                return Ok(new_start);
            }
        }

        // 叶子还有空间：插入新 extent。
        if leaf_entries < leaf_capacity {
            let start = extent_entry_offset(insert_pos);
            let end = extent_entry_offset(leaf_entries);
            let dst = extent_entry_offset(insert_pos + 1);
            scratch.copy_within(start..end, dst);
            write_extent_entry(
                &mut scratch,
                insert_pos,
                ExtentEntry {
                    block: block_index,
                    len: 1,
                    start: new_start,
                },
            );
            leaf_entries += 1;
            leaf_header.entries = leaf_entries as u16;
            write_extent_header(&mut scratch, leaf_header.entries, leaf_header.depth, leaf_capacity as u16);
            self.write_fs_block(leaf_block, &scratch[..block_size])?;
            return Ok(new_start);
        }

        // 叶子已满：分配新叶子块。
        let new_leaf = self.allocate_block()?;
        self.zero_fs_block(new_leaf)?;
        let mut leaf_raw = [0u8; EXT4_SCRATCH_SIZE];
        write_extent_header(&mut leaf_raw, 1, 0, leaf_capacity as u16);
        write_extent_entry(
            &mut leaf_raw,
            0,
            ExtentEntry {
                block: block_index,
                len: 1,
                start: new_start,
            },
        );
        self.write_fs_block(new_leaf as u64, &leaf_raw[..block_size])?;

        // root 已满则升级为 depth=2，再递归写入。
        if index_count >= EXTENT_INODE_CAPACITY {
            self.upgrade_extent_root_to_depth2(inode, raw, header)?;
            return self.allocate_extent_block_in_tree(inode, raw, header, block_index, Some(new_start));
        }
        // root 仍有空间：插入新的索引 entry。
        let new_index = ExtentIndex {
            block: block_index,
            leaf: new_leaf as u64,
        };
        let mut insert_idx = index_count;
        for idx in 0..index_count {
            if new_index.block < indices[idx].block {
                insert_idx = idx;
                break;
            }
        }
        let start = extent_entry_offset(insert_idx);
        let end = extent_entry_offset(index_count);
        let dst = extent_entry_offset(insert_idx + 1);
        raw.copy_within(start..end, dst);
        write_extent_index(raw, insert_idx, new_index);
        header.entries = (index_count + 1) as u16;
        write_extent_header(raw, header.entries, header.depth, EXTENT_INODE_CAPACITY as u16);
        store_inode_extents(inode, raw);
        Ok(new_start)
    }

    // depth=2：root -> index -> leaf 的三层树。
    // 逻辑与 depth=1 相同，只是多了一层索引块。
    fn allocate_extent_block_in_depth2(
        &self,
        inode: &mut Ext4Inode,
        raw: &mut [u8; INODE_BLOCK_LEN],
        header: &mut ExtentHeader,
        block_index: u32,
        prealloc: Option<u64>,
    ) -> VfsResult<u64> {
        if header.entries as usize > EXTENT_INODE_CAPACITY {
            return Err(VfsError::Invalid);
        }
        // 读取 root 层索引（inode 内）。
        let mut root_indices = [ExtentIndex::default(); EXTENT_INODE_CAPACITY];
        let root_count = header.entries as usize;
        for idx in 0..root_count {
            root_indices[idx] = read_extent_index(raw, idx);
        }
        if root_count == 0 {
            return Err(VfsError::Invalid);
        }
        // 选择 index block：取最后一个 block <= logical。
        let mut root_pos = 0usize;
        for idx in 1..root_count {
            if block_index >= root_indices[idx].block {
                root_pos = idx;
            } else {
                break;
            }
        }
        let index_block = root_indices[root_pos].leaf;
        let block_size = self.fs_block_size() as usize;
        let index_capacity = extent_capacity(block_size);
        let mut index_buf = [0u8; EXT4_SCRATCH_SIZE];
        self.read_fs_block(index_block, &mut index_buf[..block_size])?;
        let mut index_header = parse_extent_header(&index_buf)?;
        if index_header.depth != 1 {
            return Err(VfsError::Invalid);
        }
        let mut index_count = index_header.entries as usize;
        if index_count == 0 || index_count > index_capacity {
            return Err(VfsError::Invalid);
        }
        // index 层选择叶子块。
        let mut leaf_index = read_extent_index(&index_buf, 0);
        for idx in 1..index_count {
            let entry = read_extent_index(&index_buf, idx);
            if block_index >= entry.block {
                leaf_index = entry;
            } else {
                break;
            }
        }
        let leaf_block = leaf_index.leaf;
        let leaf_capacity = extent_capacity(block_size);
        let mut leaf_buf = [0u8; EXT4_SCRATCH_SIZE];
        self.read_fs_block(leaf_block, &mut leaf_buf[..block_size])?;
        let mut leaf_header = parse_extent_header(&leaf_buf)?;
        if leaf_header.depth != 0 {
            return Err(VfsError::Invalid);
        }
        let mut leaf_entries = leaf_header.entries as usize;
        if leaf_entries > leaf_capacity {
            return Err(VfsError::Invalid);
        }
        // 若已有覆盖，直接返回。
        for idx in 0..leaf_entries {
            let entry = read_extent_entry(&leaf_buf, idx);
            if entry.covers(block_index) {
                let phys = entry.start + (block_index - entry.block) as u64;
                return Ok(phys);
            }
        }

        // 计算插入位置（保持逻辑块顺序）。
        let mut insert_pos = leaf_entries;
        for idx in 0..leaf_entries {
            let entry = read_extent_entry(&leaf_buf, idx);
            if block_index < entry.block {
                insert_pos = idx;
                break;
            }
        }

        // 分配或复用物理块。
        let new_start = match prealloc {
            Some(addr) => addr,
            None => {
                let new_block = self.allocate_block()?;
                self.zero_fs_block(new_block)?;
                new_block as u64
            }
        };

        // 尝试与前一个 extent 合并。
        if insert_pos > 0 {
            let prev = read_extent_entry(&leaf_buf, insert_pos - 1);
            if prev.can_extend(block_index, new_start) {
                let mut updated = prev;
                updated.len += 1;
                write_extent_entry(&mut leaf_buf, insert_pos - 1, updated);
                write_extent_header(&mut leaf_buf, leaf_header.entries, leaf_header.depth, leaf_capacity as u16);
                self.write_fs_block(leaf_block, &leaf_buf[..block_size])?;
                return Ok(new_start);
            }
        }

        // 叶子有空间：直接插入。
        if leaf_entries < leaf_capacity {
            let start = extent_entry_offset(insert_pos);
            let end = extent_entry_offset(leaf_entries);
            let dst = extent_entry_offset(insert_pos + 1);
            leaf_buf.copy_within(start..end, dst);
            write_extent_entry(
                &mut leaf_buf,
                insert_pos,
                ExtentEntry {
                    block: block_index,
                    len: 1,
                    start: new_start,
                },
            );
            leaf_entries += 1;
            leaf_header.entries = leaf_entries as u16;
            write_extent_header(&mut leaf_buf, leaf_header.entries, leaf_header.depth, leaf_capacity as u16);
            self.write_fs_block(leaf_block, &leaf_buf[..block_size])?;
            return Ok(new_start);
        }

        // 叶子已满：新建叶子，并处理 index 层扩展。
        let new_leaf = self.allocate_block()?;
        self.zero_fs_block(new_leaf)?;
        let mut new_leaf_buf = [0u8; EXT4_SCRATCH_SIZE];
        write_extent_header(&mut new_leaf_buf, 1, 0, leaf_capacity as u16);
        write_extent_entry(
            &mut new_leaf_buf,
            0,
            ExtentEntry {
                block: block_index,
                len: 1,
                start: new_start,
            },
        );
        self.write_fs_block(new_leaf as u64, &new_leaf_buf[..block_size])?;

        // index 层还有空间：插入新索引。
        if index_count < index_capacity {
            let new_index = ExtentIndex {
                block: block_index,
                leaf: new_leaf as u64,
            };
            let mut insert_idx = index_count;
            for idx in 0..index_count {
                let entry = read_extent_index(&index_buf, idx);
                if new_index.block < entry.block {
                    insert_idx = idx;
                    break;
                }
            }
            let start = extent_entry_offset(insert_idx);
            let end = extent_entry_offset(index_count);
            let dst = extent_entry_offset(insert_idx + 1);
            index_buf.copy_within(start..end, dst);
            write_extent_index(&mut index_buf, insert_idx, new_index);
            index_count += 1;
            index_header.entries = index_count as u16;
            write_extent_header(&mut index_buf, index_header.entries, index_header.depth, index_capacity as u16);
            self.write_fs_block(index_block, &index_buf[..block_size])?;
            return Ok(new_start);
        }

        // index 层也满：再新建 index block，并把它挂到 root。
        let last_entry = read_extent_index(&index_buf, index_count - 1);
        if block_index <= last_entry.block {
            return Err(VfsError::NotSupported);
        }
        let new_index_block = self.allocate_block()?;
        self.zero_fs_block(new_index_block)?;
        let mut new_index_buf = [0u8; EXT4_SCRATCH_SIZE];
        write_extent_header(&mut new_index_buf, 1, 1, index_capacity as u16);
        write_extent_index(
            &mut new_index_buf,
            0,
            ExtentIndex {
                block: block_index,
                leaf: new_leaf as u64,
            },
        );
        self.write_fs_block(new_index_block as u64, &new_index_buf[..block_size])?;

        if root_count >= EXTENT_INODE_CAPACITY {
            return Err(VfsError::NotSupported);
        }
        let new_root = ExtentIndex {
            block: block_index,
            leaf: new_index_block as u64,
        };
        let mut insert_root = root_count;
        for idx in 0..root_count {
            if new_root.block < root_indices[idx].block {
                insert_root = idx;
                break;
            }
        }
        let start = extent_entry_offset(insert_root);
        let end = extent_entry_offset(root_count);
        let dst = extent_entry_offset(insert_root + 1);
        raw.copy_within(start..end, dst);
        write_extent_index(raw, insert_root, new_root);
        header.entries = (root_count + 1) as u16;
        write_extent_header(raw, header.entries, header.depth, EXTENT_INODE_CAPACITY as u16);
        store_inode_extents(inode, raw);
        Ok(new_start)
    }

    // 将 extent 根从 depth=1 升级到 depth=2。
    fn upgrade_extent_root_to_depth2(
        &self,
        inode: &mut Ext4Inode,
        raw: &mut [u8; INODE_BLOCK_LEN],
        header: &mut ExtentHeader,
    ) -> VfsResult<()> {
        if header.depth != 1 {
            return Err(VfsError::Invalid);
        }
        // 将 root（depth=1）升级为 depth=2：
        // 把原来的 index entries 写入一个新的 index block，再让 root 指向它。
        let count = header.entries as usize;
        if count == 0 || count > EXTENT_INODE_CAPACITY {
            return Err(VfsError::Invalid);
        }
        let block_size = self.fs_block_size() as usize;
        let index_capacity = extent_capacity(block_size);
        let index_block = self.allocate_block()?;
        self.zero_fs_block(index_block)?;
        let mut index_buf = [0u8; EXT4_SCRATCH_SIZE];
        write_extent_header(&mut index_buf, count as u16, 1, index_capacity as u16);
        for idx in 0..count {
            let entry = read_extent_index(raw, idx);
            write_extent_index(&mut index_buf, idx, entry);
        }
        self.write_fs_block(index_block as u64, &index_buf[..block_size])?;
        let first_block = read_extent_index(raw, 0).block;
        raw.fill(0);
        write_extent_header(raw, 1, 2, EXTENT_INODE_CAPACITY as u16);
        write_extent_index(
            raw,
            0,
            ExtentIndex {
                block: first_block,
                leaf: index_block as u64,
            },
        );
        store_inode_extents(inode, raw);
        header.entries = 1;
        header.depth = 2;
        Ok(())
    }

    // inode 内 extent 迁移到独立叶子块，并把 inode 变成 depth=1 根。
    fn upgrade_inode_extents(
        &self,
        inode: &mut Ext4Inode,
        raw: &mut [u8; INODE_BLOCK_LEN],
        entries: [ExtentEntry; EXTENT_INODE_CAPACITY],
        count: usize,
        block_index: u32,
        new_start: u64,
    ) -> VfsResult<u64> {
        // inode 内 extent 已满：把 entries 下沉到新叶子块，
        // 然后把 inode 改为 depth=1 的索引根。
        let block_size = self.fs_block_size() as usize;
        let leaf_capacity = extent_capacity(block_size);
        let leaf_block = self.allocate_block()?;
        self.zero_fs_block(leaf_block)?;
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        write_extent_header(&mut scratch, count as u16, 0, leaf_capacity as u16);
        for idx in 0..count {
            write_extent_entry(&mut scratch, idx, entries[idx]);
        }
        self.write_fs_block(leaf_block as u64, &scratch[..block_size])?;

        raw.fill(0);
        write_extent_header(raw, 1, 1, EXTENT_INODE_CAPACITY as u16);
        let first_block = entries[0].block;
        write_extent_index(
            raw,
            0,
            ExtentIndex {
                block: first_block,
                leaf: leaf_block as u64,
            },
        );
        store_inode_extents(inode, raw);
        let mut header = ExtentHeader { entries: 1, depth: 1 };
        self.allocate_extent_block_in_tree(inode, raw, &mut header, block_index, Some(new_start))
    }

    // 读取间接块中的第 index 个指针。
    fn read_indirect_ptr(&self, block: u32, index: u64, block_size: u64) -> VfsResult<u32> {
        if block == 0 {
            return Ok(0);
        }
        // indirect block 中按 u32 存放指针。
        let offset = block as u64 * block_size + index * 4;
        let mut buf = [0u8; 4];
        read_bytes(&self.cache, offset, &mut buf)?;
        Ok(read_u32(&buf, 0))
    }

    // 读取一个文件系统块（按 fs_block_size）。
    fn read_fs_block(&self, block: u64, buf: &mut [u8]) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        if buf.len() < block_size {
            return Err(VfsError::Invalid);
        }
        // block 号是文件系统块号（不是设备扇区号）。
        let offset = block * block_size as u64;
        read_bytes(&self.cache, offset, &mut buf[..block_size])
    }

    // 写入一个文件系统块（按 fs_block_size）。
    fn write_fs_block(&self, block: u64, buf: &[u8]) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        if buf.len() < block_size {
            return Err(VfsError::Invalid);
        }
        // 写入整个文件系统块。
        let offset = block * block_size as u64;
        write_bytes(&self.cache, offset, &buf[..block_size])
    }

    // 从位图中分配一个空闲位并置位。
    // 这里不更新块组/超级块的 free count，仅修改位图本身。
    fn alloc_from_bitmap(&self, bitmap_block: u32, total_bits: u32) -> VfsResult<u32> {
        let block_size = self.fs_block_size() as usize;
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        self.read_fs_block(bitmap_block as u64, &mut scratch[..block_size])?;
        let mut chosen: Option<u32> = None;
        // 位图按字节扫描，找到第一个 0 bit 并置为 1。
        for (byte_idx, byte) in scratch[..block_size].iter_mut().enumerate() {
            if *byte == 0xff {
                continue;
            }
            for bit in 0..8u8 {
                let index = byte_idx as u32 * 8 + bit as u32;
                if index >= total_bits {
                    break;
                }
                let mask = 1u8 << bit;
                if (*byte & mask) == 0 {
                    *byte |= mask;
                    chosen = Some(index);
                    break;
                }
            }
            if chosen.is_some() {
                break;
            }
        }
        let index = chosen.ok_or(VfsError::NoMem)?;
        self.write_fs_block(bitmap_block as u64, &scratch[..block_size])?;
        Ok(index)
    }

    // 简化实现：只在第 0 号块组分配 inode。
    // 未做跨组扩展，也不检查保留 inode 范围。
    fn allocate_inode(&self) -> VfsResult<InodeId> {
        let desc = self.read_group_desc(0)?;
        let total = self.superblock.inodes_per_group;
        if total == 0 {
            return Err(VfsError::Invalid);
        }
        let index = self.alloc_from_bitmap(desc.inode_bitmap, total)?;
        // inode 编号从 1 开始，因此需要 +1。
        Ok(index as InodeId + 1)
    }

    // 简化实现：只在第 0 号块组分配数据块。
    // 未考虑块组内的“保留块/元数据块”布局。
    fn allocate_block(&self) -> VfsResult<u32> {
        let desc = self.read_group_desc(0)?;
        let total = self.superblock.blocks_per_group;
        if total == 0 {
            return Err(VfsError::Invalid);
        }
        self.alloc_from_bitmap(desc.block_bitmap, total)
    }

    fn zero_fs_block(&self, block: u32) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        scratch[..block_size].fill(0);
        // 新分配的数据块通常需要清零，避免泄漏旧数据。
        self.write_fs_block(block as u64, &scratch[..block_size])
    }

    // 在目录文件中插入一条 dirent。
    // ext4 的 dirent 是变长记录，最后一条记录通常占满剩余空间。
    fn insert_dir_entry(&self, dir_inode: InodeId, name: &str, inode: InodeId, kind: FileType) -> VfsResult<()> {
        let name_bytes = name.as_bytes();
        if name_bytes.is_empty() || name_bytes.len() > axvfs::MAX_NAME_LEN {
            return Err(VfsError::Invalid);
        }
        let inode_meta = self.read_inode(dir_inode)?;
        if inode_mode_type(inode_meta.mode) != FileType::Dir {
            return Err(VfsError::NotDir);
        }
        let block_size = self.fs_block_size() as usize;
        let entry_len = dir_entry_size(name_bytes.len());
        let mut scratch = [0u8; EXT4_SCRATCH_SIZE];
        let total_blocks = ((inode_meta.size + block_size as u64 - 1) / block_size as u64) as u32;
        if total_blocks == 0 {
            return Err(VfsError::NoMem);
        }

        // 遍历目录数据块，寻找可放置新条目的空洞。
        for block_index in 0..total_blocks {
            let Some(block) = self.map_block(&inode_meta, block_index)? else {
                continue;
            };
            self.read_fs_block(block, &mut scratch[..block_size])?;
            let mut pos = 0usize;
            let mut last_entry: Option<(usize, usize, usize)> = None;
            while pos + EXT4_DIR_ENTRY_HEADER <= block_size {
                let inode_num = read_u32(&scratch, pos) as usize;
                let rec_len = read_u16(&scratch, pos + 4) as usize;
                if rec_len < EXT4_DIR_ENTRY_HEADER || pos + rec_len > block_size {
                    break;
                }
                let name_len = scratch[pos + 6] as usize;
                if inode_num == 0 {
                    // 空洞：可直接复用这条记录空间。
                    if rec_len >= entry_len {
                        write_dir_entry(&mut scratch, pos, inode, name_bytes, kind, rec_len as u16)?;
                        return self.write_fs_block(block, &scratch[..block_size]);
                    }
                    break;
                }
                let actual = dir_entry_size(name_len);
                last_entry = Some((pos, rec_len, actual));
                pos += rec_len;
            }

            let Some((last_pos, last_len, last_actual)) = last_entry else {
                continue;
            };
            if last_len < last_actual {
                return Err(VfsError::Invalid);
            }
            // last_len 是记录占用的总空间，last_actual 是实际必要长度。
            // 多出的空间可拆出新的目录项。
            let free = last_len - last_actual;
            if free < entry_len {
                continue;
            }
            write_u16(&mut scratch, last_pos + 4, last_actual as u16);
            let new_pos = last_pos + last_actual;
            write_dir_entry(&mut scratch, new_pos, inode, name_bytes, kind, free as u16)?;
            return self.write_fs_block(block, &scratch[..block_size]);
        }

        Err(VfsError::NoMem)
    }
}

// ====== VFS 接口实现 ======
// VFS 入口：将 ext4 解析/读写能力暴露给上层内核。
// 注意：只实现最基本的文件操作，删除/重命名等未实现。
impl VfsOps for Ext4Fs<'_> {
    // 返回根目录 inode（ext4 固定为 2）。
    fn root(&self) -> VfsResult<InodeId> {
        Ok(EXT4_ROOT_INODE)
    }

    // 目录查找：线性扫描目录项（不做哈希索引）。
    // 这意味着目录很大时性能较差。
    fn lookup(&self, parent: InodeId, name: &str) -> VfsResult<Option<InodeId>> {
        let parent_inode = self.read_inode(parent)?;
        if inode_mode_type(parent_inode.mode) != FileType::Dir {
            return Err(VfsError::NotDir);
        }
        let target = name.as_bytes();
        let mut found = None;
        self.scan_dir_entries(&parent_inode, |inode_num, entry_name, _file_type| {
            if entry_name == target {
                found = Some(inode_num);
                return Ok(true);
            }
            Ok(false)
        })?;
        Ok(found)
    }

    // 仅支持创建普通文件，默认使用 extent 寻址。
    // 不维护 nlink/ctime/mtime 等完整元数据。
    fn create(&self, parent: InodeId, name: &str, kind: FileType, mode: u16) -> VfsResult<InodeId> {
        if kind != FileType::File {
            return Err(VfsError::NotSupported);
        }
        if name.is_empty() || name.len() > axvfs::MAX_NAME_LEN {
            return Err(VfsError::Invalid);
        }
        let parent_inode = self.read_inode(parent)?;
        if inode_mode_type(parent_inode.mode) != FileType::Dir {
            return Err(VfsError::NotDir);
        }
        // 1) 分配 inode 号。
        let inode = self.allocate_inode()?;
        let mut inode_meta = Ext4Inode {
            mode: EXT4_MODE_FILE | (mode & 0o777),
            size: 0,
            flags: EXT4_EXTENTS_FLAG,
            blocks: [0u32; 15],
        };
        // 2) 初始化 extent 根。
        init_inode_extents(&mut inode_meta);
        // 3) 写回 inode 表。
        self.write_inode(inode, &inode_meta)?;
        // 4) 在父目录插入目录项。
        self.insert_dir_entry(parent, name, inode, kind)?;
        Ok(inode)
    }

    // 删除/重命名未实现。
    fn remove(&self, _parent: InodeId, _name: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    // 返回文件类型/大小/权限元数据。
    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata> {
        let inode_meta = self.read_inode(inode)?;
        let file_type = inode_mode_type(inode_meta.mode);
        let mode = (inode_meta.mode & 0o777) as u16;
        // 这里只返回最小元数据：类型/大小/权限。
        Ok(Metadata::new(file_type, inode_meta.size, mode))
    }

    // 对文件进行读取（目录不支持 read_at）。
    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) == FileType::Dir {
            return Err(VfsError::NotDir);
        }
        // 复用 inode 读取逻辑（支持稀疏文件零填充）。
        self.read_from_inode(&inode_meta, offset, buf)
    }

    // 写入路径：按块映射/分配写入，不涉及日志与复杂 extent 重平衡。
    // 写入后只更新 inode.size，不更新校验/日志。
    fn write_at(&self, inode: InodeId, offset: u64, buf: &[u8]) -> VfsResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) == FileType::Dir {
            return Err(VfsError::NotDir);
        }
        // 最小写入路径：仅直/间接块，不做 extent 扩展或日志。
        // 这里没有预分配/延迟分配逻辑，按需分配块即可。
        let block_size = self.fs_block_size() as u64;
        let mut total = 0usize;
        let mut cur_offset = offset;
        while total < buf.len() {
            let block_index = (cur_offset / block_size) as u32;
            let in_block = (cur_offset % block_size) as usize;
            let to_copy = core::cmp::min(buf.len() - total, block_size as usize - in_block);
            let phys = match self.map_block(&inode_meta, block_index)? {
                Some(block) => block,
                None => self.allocate_data_block(&mut inode_meta, block_index)?,
            };
            // 计算物理块内偏移并写入。
            let block_offset = phys * block_size + in_block as u64;
            write_bytes(&self.cache, block_offset, &buf[total..total + to_copy])?;
            total += to_copy;
            cur_offset += to_copy as u64;
        }
        // 若写入越过文件尾，更新 size。
        let end = offset + total as u64;
        if end > inode_meta.size {
            inode_meta.size = end;
        }
        self.write_inode(inode, &inode_meta)?;
        Ok(total)
    }

    // 读取目录项列表（offset 为条目序号偏移）。
    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
        let inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) != FileType::Dir {
            return Err(VfsError::NotDir);
        }
        // offset 是“目录项序号”，不是字节偏移。
        let mut index = 0usize;
        let mut written = 0usize;
        self.scan_dir_entries(&inode_meta, |inode_num, name, file_type| {
            if index < offset {
                index += 1;
                return Ok(false);
            }
            if written >= entries.len() {
                return Ok(true);
            }
            let mut entry = DirEntry::empty();
            entry.ino = inode_num;
            entry.file_type = file_type;
            entry.set_name(name)?;
            entries[written] = entry;
            written += 1;
            index += 1;
            Ok(false)
        })?;
        Ok(written)
    }

    // 仅刷写块缓存，不包含日志提交。
    fn flush(&self) -> VfsResult<()> {
        self.cache.flush()
    }

    // 截断：缩小仅更新 size，不回收块；增长按需分配块。
    // 这会造成“逻辑释放但物理块仍占用”的情况。
    fn truncate(&self, inode: InodeId, size: u64) -> VfsResult<()> {
        let mut inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) == FileType::Dir {
            return Err(VfsError::NotDir);
        }
        if size <= inode_meta.size {
            // 最小截断：仅缩小 size，不回收块。
            inode_meta.size = size;
            return self.write_inode(inode, &inode_meta);
        }
        // 扩容路径：确保每个需要的逻辑块都有映射。
        let block_size = self.fs_block_size() as u64;
        let blocks_needed = (size + block_size - 1) / block_size;
        for block_index in 0..blocks_needed {
            let block_index = block_index as u32;
            if self.map_block(&inode_meta, block_index)?.is_none() {
                let _ = self.allocate_data_block(&mut inode_meta, block_index)?;
            }
        }
        inode_meta.size = size;
        self.write_inode(inode, &inode_meta)
    }
}

// 从任意字节偏移读取数据：跨块时用 scratch 缓冲拼接。
fn read_bytes(cache: &BlockCache<'_>, offset: u64, buf: &mut [u8]) -> VfsResult<()> {
    let block_size = cache.block_size();
    if block_size == 0 || block_size > EXT4_SCRATCH_SIZE {
        return Err(VfsError::Invalid);
    }
    let block_size_u64 = block_size as u64;
    // 通过全局 scratch 锁保证跨块读的临时缓冲安全。
    let guard = EXT4_SCRATCH.lock();
    let scratch = guard.get_mut();
    // remaining/cur_offset 用于跨块读取。
    let mut remaining = buf.len();
    let mut buf_offset = 0usize;
    let mut cur_offset = offset;
    while remaining > 0 {
        let block_id = cur_offset / block_size_u64;
        let in_block = (cur_offset % block_size_u64) as usize;
        let to_copy = core::cmp::min(remaining, block_size - in_block);
        // 读整块到 scratch，再拷贝需要的那一段。
        cache.read_block(block_id, &mut scratch[..block_size])?;
        buf[buf_offset..buf_offset + to_copy]
            .copy_from_slice(&scratch[in_block..in_block + to_copy]);
        remaining -= to_copy;
        buf_offset += to_copy;
        cur_offset += to_copy as u64;
    }
    Ok(())
}

// 从任意字节偏移写入数据：非整块写入会先读后写。
// 这是最简的 RMW（read-modify-write），不做写合并优化。
fn write_bytes(cache: &BlockCache<'_>, offset: u64, buf: &[u8]) -> VfsResult<()> {
    let block_size = cache.block_size();
    if block_size == 0 || block_size > EXT4_SCRATCH_SIZE {
        return Err(VfsError::Invalid);
    }
    let block_size_u64 = block_size as u64;
    // 写入同样需要 scratch（非整块写入时会读旧块内容）。
    let guard = EXT4_SCRATCH.lock();
    let scratch = guard.get_mut();
    // 写入可能跨多个块；对非整块写入先读再改写。
    let mut remaining = buf.len();
    let mut buf_offset = 0usize;
    let mut cur_offset = offset;
    while remaining > 0 {
        let block_id = cur_offset / block_size_u64;
        let in_block = (cur_offset % block_size_u64) as usize;
        let to_copy = core::cmp::min(remaining, block_size - in_block);
        if in_block == 0 && to_copy == block_size {
            // 覆盖整个块：直接写。
            cache.write_block(block_id, &buf[buf_offset..buf_offset + block_size])?;
        } else {
            // 部分块：RMW（read-modify-write）。
            cache.read_block(block_id, &mut scratch[..block_size])?;
            scratch[in_block..in_block + to_copy]
                .copy_from_slice(&buf[buf_offset..buf_offset + to_copy]);
            cache.write_block(block_id, &scratch[..block_size])?;
        }
        remaining -= to_copy;
        buf_offset += to_copy;
        cur_offset += to_copy as u64;
    }
    Ok(())
}

// 小端序读取 u16。
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

// 小端序读取 u32。
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

// 小端序写入 u16。
fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

// 小端序写入 u32。
fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

// 根据 inode mode 的类型位映射为 VFS FileType。
fn inode_mode_type(mode: u16) -> FileType {
    match mode & 0xf000 {
        EXT4_MODE_DIR => FileType::Dir,
        EXT4_MODE_FILE => FileType::File,
        0x2000 => FileType::Char,
        0x6000 => FileType::Block,
        0x1000 => FileType::Fifo,
        0xa000 => FileType::Symlink,
        0xc000 => FileType::Socket,
        _ => FileType::File,
    }
}

// dirent 记录长度需 4 字节对齐（ext4 目录项规则）。
// rec_len 一般是“向上取整后的长度”，以便留空洞给后续插入。
// ====== 目录项（dirent）辅助函数 ======
fn dir_entry_size(name_len: usize) -> usize {
    let size = EXT4_DIR_ENTRY_HEADER + name_len;
    (size + 3) & !3
}

// FileType 映射到 ext4 dirent 的类型码。
fn dir_entry_type(kind: FileType) -> u8 {
    match kind {
        FileType::File => EXT4_DIR_ENTRY_FILE,
        FileType::Dir => EXT4_DIR_ENTRY_DIR,
        FileType::Char => EXT4_DIR_ENTRY_CHAR,
        FileType::Block => EXT4_DIR_ENTRY_BLOCK,
        FileType::Fifo => EXT4_DIR_ENTRY_FIFO,
        FileType::Socket => EXT4_DIR_ENTRY_SOCKET,
        FileType::Symlink => EXT4_DIR_ENTRY_SYMLINK,
    }
}

// 写入一条目录项：inode + rec_len + name_len + file_type + name。
fn write_dir_entry(buf: &mut [u8], offset: usize, inode: InodeId, name: &[u8], kind: FileType, rec_len: u16) -> VfsResult<()> {
    if name.len() > axvfs::MAX_NAME_LEN || rec_len as usize > buf.len().saturating_sub(offset) {
        return Err(VfsError::Invalid);
    }
    write_u32(buf, offset, inode as u32);
    write_u16(buf, offset + 4, rec_len);
    buf[offset + 6] = name.len() as u8;
    buf[offset + 7] = dir_entry_type(kind);
    let name_off = offset + EXT4_DIR_ENTRY_HEADER;
    buf[name_off..name_off + name.len()].copy_from_slice(name);
    Ok(())
}

// extent header（磁盘格式）：
// - magic: 固定为 EXTENT_HEADER_MAGIC
// - entries: 当前有效条目数
// - max: 最大容量（写入时由容量计算得出）
// - depth: 0=叶子，>0 为索引层
// ====== Extent 相关结构与辅助函数 ======
struct ExtentHeader {
    entries: u16,
    depth: u16,
}

#[derive(Clone, Copy)]
// 叶子 extent：覆盖一段连续逻辑块 -> 物理块范围。
// block 是逻辑起点，len 是长度，start 是物理起点。
struct ExtentEntry {
    block: u32,
    len: u16,
    start: u64,
}

impl Default for ExtentEntry {
    // 默认零值，表示“空 extent”。
    fn default() -> Self {
        Self {
            block: 0,
            len: 0,
            start: 0,
        }
    }
}

impl ExtentEntry {
    fn covers(&self, logical: u32) -> bool {
        // 判断逻辑块是否落在该 extent 覆盖范围内。
        if self.len == 0 {
            return false;
        }
        logical >= self.block && logical < self.block + self.len as u32
    }

    fn can_extend(&self, logical: u32, phys: u64) -> bool {
        // 新块与当前 extent 是否连续（逻辑连续 + 物理连续）。
        if self.len == 0 || self.len >= EXTENT_LEN_MAX {
            return false;
        }
        logical == self.block + self.len as u32 && phys == self.start + self.len as u64
    }
}

#[derive(Clone, Copy)]
// 索引 extent：指向下一层 extent block。
// block 表示逻辑块起点，leaf 为下一层块号。
struct ExtentIndex {
    block: u32,
    leaf: u64,
}

impl Default for ExtentIndex {
    // 默认零值，表示“空索引”。
    fn default() -> Self {
        Self { block: 0, leaf: 0 }
    }
}

// 解析 extent header；若 magic 不匹配则视为“不支持 extents”。
fn parse_extent_header(buf: &[u8]) -> VfsResult<ExtentHeader> {
    if buf.len() < EXTENT_HEADER_SIZE {
        return Err(VfsError::Invalid);
    }
    let magic = read_u16(buf, 0);
    if magic != EXTENT_HEADER_MAGIC {
        return Err(VfsError::NotSupported);
    }
    // buf[2..4] = entries，buf[4..6] = max（此实现不使用）。
    let entries = read_u16(buf, 2);
    let depth = read_u16(buf, 6);
    Ok(ExtentHeader { entries, depth })
}

// 初始化 inode 内的 extent 区域（空 extent 树）。
fn init_inode_extents(inode: &mut Ext4Inode) {
    let mut raw = [0u8; INODE_BLOCK_LEN];
    init_extent_raw(&mut raw);
    store_inode_extents(inode, &raw);
}

// 初始化 extent 原始缓冲（清零 + 写入 header）。
fn init_extent_raw(raw: &mut [u8; INODE_BLOCK_LEN]) {
    raw.fill(0);
    write_extent_header(raw, 0, 0, EXTENT_INODE_CAPACITY as u16);
}

// 写入 extent header：max 由容量计算得到。
fn write_extent_header(buf: &mut [u8], entries: u16, depth: u16, max: u16) {
    write_u16(buf, 0, EXTENT_HEADER_MAGIC);
    write_u16(buf, 2, entries);
    write_u16(buf, 4, max);
    write_u16(buf, 6, depth);
    write_u32(buf, 8, 0);
}

// 一个 extent block 中可容纳的 entry 数量。
fn extent_capacity(block_size: usize) -> usize {
    if block_size <= EXTENT_HEADER_SIZE {
        return 0;
    }
    (block_size - EXTENT_HEADER_SIZE) / EXTENT_ENTRY_SIZE
}

// 计算第 idx 个 extent entry 在块内的偏移。
fn extent_entry_offset(idx: usize) -> usize {
    EXTENT_HEADER_SIZE + idx * EXTENT_ENTRY_SIZE
}

// 从 inode.blocks 取出 extent 原始字节（按 u32 小端拼接）。
fn inode_extent_raw(inode: &Ext4Inode) -> [u8; INODE_BLOCK_LEN] {
    let mut raw = [0u8; INODE_BLOCK_LEN];
    for (idx, block) in inode.blocks.iter().enumerate() {
        let offset = idx * 4;
        raw[offset..offset + 4].copy_from_slice(&block.to_le_bytes());
    }
    raw
}

// 将 extent 原始字节写回 inode.blocks。
fn store_inode_extents(inode: &mut Ext4Inode, raw: &[u8; INODE_BLOCK_LEN]) {
    for idx in 0..inode.blocks.len() {
        let offset = idx * 4;
        inode.blocks[idx] = read_u32(raw, offset);
    }
}

fn read_extent_entry(buf: &[u8], idx: usize) -> ExtentEntry {
    // 叶子 extent entry 的字段布局：
    // ee_block / ee_len / ee_start_hi / ee_start_lo
    let offset = extent_entry_offset(idx);
    let ee_block = read_u32(buf, offset);
    // ee_len 的高位可能包含未初始化标志，需掩掉。
    let ee_len = read_u16(buf, offset + 4) & EXTENT_LEN_MAX;
    let ee_start_hi = read_u16(buf, offset + 6) as u32;
    let ee_start_lo = read_u32(buf, offset + 8);
    let start = ((ee_start_hi as u64) << 32) | ee_start_lo as u64;
    ExtentEntry {
        block: ee_block,
        len: ee_len,
        start,
    }
}

// 写入叶子 extent entry。
fn write_extent_entry(buf: &mut [u8], idx: usize, entry: ExtentEntry) {
    let offset = extent_entry_offset(idx);
    write_u32(buf, offset, entry.block);
    write_u16(buf, offset + 4, entry.len);
    write_u16(buf, offset + 6, (entry.start >> 32) as u16);
    write_u32(buf, offset + 8, entry.start as u32);
}

fn read_extent_index(buf: &[u8], idx: usize) -> ExtentIndex {
    // 索引 entry：逻辑块起点 + 叶子块物理地址。
    let offset = extent_entry_offset(idx);
    let block = read_u32(buf, offset);
    let leaf_lo = read_u32(buf, offset + 4);
    let leaf_hi = read_u16(buf, offset + 8) as u32;
    let leaf = ((leaf_hi as u64) << 32) | leaf_lo as u64;
    ExtentIndex { block, leaf }
}

// 写入索引 extent entry。
fn write_extent_index(buf: &mut [u8], idx: usize, entry: ExtentIndex) {
    let offset = extent_entry_offset(idx);
    write_u32(buf, offset, entry.block);
    write_u32(buf, offset + 4, entry.leaf as u32);
    write_u16(buf, offset + 8, (entry.leaf >> 32) as u16);
    write_u16(buf, offset + 10, 0);
}

// 线性扫描叶子 extent entries，返回逻辑块对应的物理块。
fn map_extent_entries(buf: &[u8], entries: u16, logical: u32) -> VfsResult<Option<u64>> {
    // entries 数量通常较小，线性扫描足够。
    let mut offset = EXTENT_HEADER_SIZE;
    for _ in 0..entries {
        if offset + EXTENT_ENTRY_SIZE > buf.len() {
            break;
        }
        let ee_block = read_u32(buf, offset);
        let ee_len = read_u16(buf, offset + 4) & EXTENT_LEN_MAX;
        let ee_start_hi = read_u16(buf, offset + 6) as u32;
        let ee_start_lo = read_u32(buf, offset + 8);
        if logical >= ee_block && logical < ee_block + ee_len as u32 {
            let phys = ((ee_start_hi as u64) << 32) | ee_start_lo as u64;
            return Ok(Some(phys + (logical - ee_block) as u64));
        }
        offset += EXTENT_ENTRY_SIZE;
    }
    Ok(None)
}

// 线性扫描索引 entries，选择最后一个 ei_block <= logical 的叶子块。
fn find_extent_index(buf: &[u8], entries: u16, logical: u32) -> VfsResult<Option<u64>> {
    // 该策略等价于在有序索引上做“右侧匹配”。
    let mut offset = EXTENT_HEADER_SIZE;
    let mut chosen: Option<u64> = None;
    for _ in 0..entries {
        if offset + EXTENT_ENTRY_SIZE > buf.len() {
            break;
        }
        let ei_block = read_u32(buf, offset);
        let ei_leaf_lo = read_u32(buf, offset + 4);
        let ei_leaf_hi = read_u16(buf, offset + 8) as u32;
        if logical >= ei_block {
            chosen = Some(((ei_leaf_hi as u64) << 32) | ei_leaf_lo as u64);
        } else {
            break;
        }
        offset += EXTENT_ENTRY_SIZE;
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::{env, fs, vec, vec::Vec};

    // 单元测试使用的 inode size（与构造的测试镜像保持一致）。
    const TEST_INODE_SIZE: usize = 128;

    // 基于固定数组的内存块设备，用于小型镜像测试。
    struct TestBlockDevice {
        block_size: usize,
        data: RefCell<[u8; 32 * 1024]>,
    }

    impl BlockDevice for TestBlockDevice {
        // 返回块大小。
        fn block_size(&self) -> usize {
            self.block_size
        }

        // 从内存中读出一个块。
        fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let data = self.data.borrow();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            buf[..self.block_size].copy_from_slice(&data[offset..offset + self.block_size]);
            Ok(())
        }

        // 将一个块写回内存。
        fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let mut data = self.data.borrow_mut();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            data[offset..offset + self.block_size].copy_from_slice(&buf[..self.block_size]);
            Ok(())
        }

        // 测试块设备不需要实际 flush。
        fn flush(&self) -> VfsResult<()> {
            Ok(())
        }
    }

    // 基于 Vec 的内存块设备，用于较大测试镜像。
    struct FileBlockDevice {
        block_size: usize,
        data: RefCell<Vec<u8>>,
    }

    impl BlockDevice for FileBlockDevice {
        // 返回块大小。
        fn block_size(&self) -> usize {
            self.block_size
        }

        // 从 Vec 中读出一个块。
        fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let data = self.data.borrow();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            buf[..self.block_size].copy_from_slice(&data[offset..offset + self.block_size]);
            Ok(())
        }

        // 将一个块写回 Vec。
        fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let mut data = self.data.borrow_mut();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            data[offset..offset + self.block_size].copy_from_slice(&buf[..self.block_size]);
            Ok(())
        }

        // 测试块设备不需要实际 flush。
        fn flush(&self) -> VfsResult<()> {
            Ok(())
        }
    }

    #[test]
    // 验证超级块解析与 block_size 计算。
    fn parse_superblock() {
        let mut data = [0u8; 32 * 1024];
        let sb = &mut data[SUPERBLOCK_OFFSET as usize..SUPERBLOCK_OFFSET as usize + SUPERBLOCK_SIZE];
        sb[SUPERBLOCK_MAGIC_OFFSET..SUPERBLOCK_MAGIC_OFFSET + 2].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
        sb[SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET..SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&0u32.to_le_bytes());
        sb[SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET..SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET + 4]
            .copy_from_slice(&8192u32.to_le_bytes());
        sb[SUPERBLOCK_INODES_PER_GROUP_OFFSET..SUPERBLOCK_INODES_PER_GROUP_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());
        sb[SUPERBLOCK_INODE_SIZE_OFFSET..SUPERBLOCK_INODE_SIZE_OFFSET + 2]
            .copy_from_slice(&128u16.to_le_bytes());
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        assert_eq!(fs.superblock().magic, EXT4_MAGIC);
        assert_eq!(fs.fs_block_size(), 1024);
    }

    #[test]
    // 构造最小 ext4 镜像，验证 lookup/read 的基本路径。
    fn lookup_and_read_init() {
        let mut data = [0u8; 32 * 1024];
        let file_data = b"init-data";
        build_minimal_ext4(&mut data, file_data);
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.lookup(root, "init").unwrap().unwrap();
        let mut buf = [0u8; 16];
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(&buf[..read], file_data);
    }

    #[test]
    // 构造带 extent 树的镜像，验证 extent 查找路径。
    fn lookup_and_read_init_extent_tree() {
        let mut data = [0u8; 32 * 1024];
        let file_data = b"extent-tree";
        build_ext4_with_extent_tree(&mut data, file_data);
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.lookup(root, "init").unwrap().unwrap();
        let mut buf = [0u8; 16];
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(&buf[..read], file_data);
    }

    #[test]
    // 构造带间接块的镜像，验证间接块寻址读。
    fn read_indirect_block() {
        let mut data = [0u8; 32 * 1024];
        let file_data = b"indirect";
        build_ext4_with_indirect(&mut data, file_data);
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.lookup(root, "init").unwrap().unwrap();
        let mut buf = [0u8; 8];
        let offset = (1024 * 12) as u64;
        let read = fs.read_at(inode, offset, &mut buf).unwrap();
        assert_eq!(read, file_data.len());
        assert_eq!(&buf[..read], file_data);
    }

    #[test]
    // 使用真实 ext4 镜像（环境变量指定）做完整目录与文件读取。
    fn ext4_init_image() {
        let path = match env::var("AXFS_EXT4_IMAGE") {
            Ok(value) => value,
            Err(_) => return,
        };
        let data = fs::read(&path).expect("read ext4 image");
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).expect("open ext4 image");
        let root = fs.root().expect("root inode");
        let mut entries = [DirEntry::empty(); 2];
        let mut root_names: Vec<Vec<u8>> = Vec::new();
        let mut offset = 0usize;
        loop {
            let count = fs.read_dir(root, offset, &mut entries).expect("read root dir");
            if count == 0 {
                break;
            }
            for entry in &entries[..count] {
                let name = entry.name();
                if name != b"." && name != b".." {
                    root_names.push(name.to_vec());
                }
            }
            offset += count;
        }
        assert!(root_names.iter().any(|name| name == b"init"));
        assert!(root_names.iter().any(|name| name == b"etc"));
        let inode = fs.lookup(root, "init").expect("lookup init").expect("init inode");
        let meta = fs.metadata(inode).expect("init metadata");
        let mut buf = vec![0u8; 8192];
        let read = fs.read_at(inode, 0, &mut buf).expect("read init");
        assert!(read >= 4);
        assert_eq!(&buf[..4], b"\x7fELF");
        if meta.size > 4096 {
            let mut tail = [0u8; 64];
            let read_tail = fs.read_at(inode, 4096, &mut tail).expect("read init tail");
            assert!(read_tail > 0);
        }

        let etc_inode = fs.lookup(root, "etc").expect("lookup etc").expect("etc inode");
        let mut etc_names: Vec<Vec<u8>> = Vec::new();
        let mut etc_offset = 0usize;
        loop {
            let count = fs.read_dir(etc_inode, etc_offset, &mut entries).expect("read /etc");
            if count == 0 {
                break;
            }
            for entry in &entries[..count] {
                let name = entry.name();
                if name != b"." && name != b".." {
                    etc_names.push(name.to_vec());
                }
            }
            etc_offset += count;
        }
        assert!(etc_names.iter().any(|name| name == b"issue"));
        assert!(etc_names.iter().any(|name| name == b"large"));
        let issue_inode = fs.lookup(etc_inode, "issue").expect("lookup issue").expect("issue inode");
        let expected_issue = b"Aurora ext4 test\n";
        let mut issue_buf = vec![0u8; expected_issue.len()];
        let issue_read = fs.read_at(issue_inode, 0, &mut issue_buf).expect("read /etc/issue");
        assert_eq!(issue_read, expected_issue.len());
        assert_eq!(issue_buf, expected_issue);

        let large_inode = fs.lookup(etc_inode, "large").expect("lookup large").expect("large inode");
        let large_meta = fs.metadata(large_inode).expect("large metadata");
        assert!(large_meta.size >= 4096 + 64);
        let mut large_buf = [0u8; 64];
        let read_head = fs.read_at(large_inode, 0, &mut large_buf).expect("read /etc/large head");
        assert_eq!(read_head, large_buf.len());
        assert!(large_buf.iter().all(|&b| b == b'Z'));
        let read_mid = fs.read_at(large_inode, 4096, &mut large_buf).expect("read /etc/large mid");
        assert_eq!(read_mid, large_buf.len());
        assert!(large_buf.iter().all(|&b| b == b'Z'));
    }

    #[test]
    // 覆盖 create/write/truncate 的基础写路径。
    fn create_write_truncate() {
        let mut data = vec![0u8; 64 * 1024];
        build_ext4_for_write(&mut data);
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.create(root, "log", FileType::File, 0o644).unwrap();
        let payload = b"hello-ext4";
        let written = fs.write_at(inode, 0, payload).unwrap();
        assert_eq!(written, payload.len());
        let meta = fs.metadata(inode).unwrap();
        assert_eq!(meta.size, payload.len() as u64);
        let mut buf = [0u8; 16];
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(&buf[..read], payload);
        fs.truncate(inode, 5).unwrap();
        let meta = fs.metadata(inode).unwrap();
        assert_eq!(meta.size, 5);
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(read, 5);
        assert_eq!(&buf[..read], &payload[..read]);
    }

    #[test]
    // 触发一级间接块写入路径。
    fn write_indirect_block() {
        let mut data = vec![0u8; 128 * 1024];
        build_ext4_for_write(&mut data);
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.create(root, "big", FileType::File, 0o644).unwrap();
        let block_size = fs.fs_block_size() as usize;
        let offset = block_size * EXT4_DIRECT_BLOCKS;
        let payload = b"indirect-write";
        let written = fs.write_at(inode, offset as u64, payload).unwrap();
        assert_eq!(written, payload.len());
        let meta = fs.metadata(inode).unwrap();
        assert_eq!(meta.size, (offset + payload.len()) as u64);
        let mut buf = [0u8; 32];
        let read = fs.read_at(inode, offset as u64, &mut buf).unwrap();
        assert_eq!(read, payload.len());
        assert_eq!(&buf[..read], payload);
    }

    #[test]
    // 验证稀疏文件读写（未分配块应返回 0）。
    fn write_extent_sparse() {
        let mut data = vec![0u8; 128 * 1024];
        build_ext4_for_write(&mut data);
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.create(root, "sparse", FileType::File, 0o644).unwrap();
        let block_size = fs.fs_block_size() as usize;
        let payload = b"tail";
        let offset = block_size * 2;
        let written = fs.write_at(inode, offset as u64, payload).unwrap();
        assert_eq!(written, payload.len());
        let mut buf = [0u8; 8];
        let read = fs.read_at(inode, offset as u64, &mut buf).unwrap();
        assert_eq!(&buf[..read], payload);
        let mut hole = [1u8; 8];
        let read = fs.read_at(inode, block_size as u64, &mut hole).unwrap();
        assert_eq!(read, hole.len());
        assert!(hole.iter().all(|&b| b == 0));
    }

    #[test]
    // 触发 depth=1 的 extent 树写入路径。
    fn write_extent_depth1() {
        let mut data = vec![0u8; 256 * 1024];
        build_ext4_for_write(&mut data);
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.create(root, "scatter", FileType::File, 0o644).unwrap();
        let block_size = fs.fs_block_size() as usize;
        let offsets = [0, 2, 4, 6, 8];
        for (idx, blk) in offsets.iter().enumerate() {
            let payload = [b'A' + idx as u8];
            let off = (*blk * block_size) as u64;
            let written = fs.write_at(inode, off, &payload).unwrap();
            assert_eq!(written, payload.len());
        }
        for (idx, blk) in offsets.iter().enumerate() {
            let mut buf = [0u8; 1];
            let off = (*blk * block_size) as u64;
            let read = fs.read_at(inode, off, &mut buf).unwrap();
            assert_eq!(read, 1);
            assert_eq!(buf[0], b'A' + idx as u8);
        }
    }

    #[test]
    // 触发 depth=2 的 extent 树写入路径。
    fn write_extent_depth2() {
        let mut data = vec![0u8; 1024 * 1024];
        build_ext4_for_write(&mut data);
        let dev = FileBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Ext4Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let inode = fs.create(root, "depth2", FileType::File, 0o644).unwrap();
        let block_size = fs.fs_block_size() as usize;
        let leaf_capacity = extent_capacity(block_size);
        let total_entries = leaf_capacity * EXTENT_INODE_CAPACITY + 1;
        for idx in 0..total_entries {
            let block_index = idx * 2;
            let offset = block_index * block_size;
            let payload = [b'a' + (idx % 26) as u8];
            let written = fs.write_at(inode, offset as u64, &payload).unwrap();
            assert_eq!(written, payload.len());
        }
        let mut buf = [0u8; 1];
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(read, 1);
        assert_eq!(buf[0], b'a');
        let last_idx = total_entries - 1;
        let last_offset = (last_idx * 2 * block_size) as u64;
        let read = fs.read_at(inode, last_offset, &mut buf).unwrap();
        assert_eq!(read, 1);
        assert_eq!(buf[0], b'a' + (last_idx % 26) as u8);
    }

    // 构造一个最小 ext4 镜像：根目录包含 init 文件。
    fn build_minimal_ext4(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
        const BLOCK_BITMAP_BLOCK: usize = 3;
        const INODE_BITMAP_BLOCK: usize = 4;
        const INODE_TABLE_BLOCK: usize = 5;
        const ROOT_DIR_BLOCK: usize = 6;
        const INIT_BLOCK: usize = 7;
        buf.fill(0);

        let sb = &mut buf[SUPERBLOCK_OFFSET as usize..SUPERBLOCK_OFFSET as usize + SUPERBLOCK_SIZE];
        write_u16(sb, SUPERBLOCK_MAGIC_OFFSET, EXT4_MAGIC);
        write_u32(sb, SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET, 0);
        write_u32(sb, SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET, 8192);
        write_u32(sb, SUPERBLOCK_INODES_PER_GROUP_OFFSET, 8);
        write_u16(sb, SUPERBLOCK_INODE_SIZE_OFFSET, TEST_INODE_SIZE as u16);

        let gd_offset = BLOCK_SIZE * 2;
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_BLOCK_BITMAP_OFFSET,
            BLOCK_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_BITMAP_OFFSET,
            INODE_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_TABLE_OFFSET,
            INODE_TABLE_BLOCK as u32,
        );

        let inode_table_offset = INODE_TABLE_BLOCK * BLOCK_SIZE;
        let mut root_blocks = [0u32; 15];
        root_blocks[0] = ROOT_DIR_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            2,
            0x4000 | 0o755,
            BLOCK_SIZE as u32,
            0,
            &root_blocks,
        );
        let mut init_blocks = [0u32; 15];
        init_blocks[0] = INIT_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            3,
            0x8000 | 0o644,
            file_data.len() as u32,
            0,
            &init_blocks,
        );

        let dir_offset = ROOT_DIR_BLOCK * BLOCK_SIZE;
        let dir = &mut buf[dir_offset..dir_offset + BLOCK_SIZE];
        write_dir_entry(dir, 0, 2, b".", 2, 12);
        write_dir_entry(dir, 12, 2, b"..", 2, 12);
        let rest = (BLOCK_SIZE - 24) as u16;
        write_dir_entry(dir, 24, 3, b"init", 1, rest);

        let init_offset = INIT_BLOCK * BLOCK_SIZE;
        let len = core::cmp::min(file_data.len(), BLOCK_SIZE);
        buf[init_offset..init_offset + len].copy_from_slice(&file_data[..len]);
    }

    // 构造一个使用 extent 树（depth=1）的镜像。
    fn build_ext4_with_extent_tree(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
        const BLOCK_BITMAP_BLOCK: usize = 3;
        const INODE_BITMAP_BLOCK: usize = 4;
        const INODE_TABLE_BLOCK: usize = 5;
        const ROOT_DIR_BLOCK: usize = 6;
        const INIT_BLOCK: usize = 7;
        const EXTENT_LEAF_BLOCK: usize = 8;

        let sb = &mut buf[SUPERBLOCK_OFFSET as usize..SUPERBLOCK_OFFSET as usize + SUPERBLOCK_SIZE];
        write_u16(sb, SUPERBLOCK_MAGIC_OFFSET, EXT4_MAGIC);
        write_u32(sb, SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET, 0);
        write_u32(sb, SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET, 8192);
        write_u32(sb, SUPERBLOCK_INODES_PER_GROUP_OFFSET, 8);
        write_u16(sb, SUPERBLOCK_INODE_SIZE_OFFSET, TEST_INODE_SIZE as u16);

        let gd_offset = BLOCK_SIZE * 2;
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_BLOCK_BITMAP_OFFSET,
            BLOCK_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_BITMAP_OFFSET,
            INODE_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_TABLE_OFFSET,
            INODE_TABLE_BLOCK as u32,
        );

        let inode_table_offset = INODE_TABLE_BLOCK * BLOCK_SIZE;
        let mut root_blocks = [0u32; 15];
        root_blocks[0] = ROOT_DIR_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            2,
            0x4000 | 0o755,
            BLOCK_SIZE as u32,
            0,
            &root_blocks,
        );

        let mut raw = [0u8; INODE_BLOCK_LEN];
        write_u16(&mut raw, 0, EXTENT_HEADER_MAGIC);
        write_u16(&mut raw, 2, 1);
        write_u16(&mut raw, 4, 1);
        write_u16(&mut raw, 6, 1);
        write_u32(&mut raw, 8, 0);
        write_u32(&mut raw, 12, 0);
        write_u32(&mut raw, 16, EXTENT_LEAF_BLOCK as u32);
        write_u16(&mut raw, 20, 0);
        write_u16(&mut raw, 22, 0);

        let mut init_blocks = [0u32; 15];
        for i in 0..15 {
            let off = i * 4;
            init_blocks[i] = read_u32(&raw, off);
        }
        write_inode(
            &mut buf[inode_table_offset..],
            3,
            0x8000 | 0o644,
            file_data.len() as u32,
            EXT4_EXTENTS_FLAG,
            &init_blocks,
        );

        let leaf_offset = EXTENT_LEAF_BLOCK * BLOCK_SIZE;
        let leaf = &mut buf[leaf_offset..leaf_offset + BLOCK_SIZE];
        write_u16(leaf, 0, EXTENT_HEADER_MAGIC);
        write_u16(leaf, 2, 1);
        write_u16(leaf, 4, 1);
        write_u16(leaf, 6, 0);
        write_u32(leaf, 8, 0);
        write_u32(leaf, 12, 0);
        write_u16(leaf, 16, 1);
        write_u16(leaf, 18, 0);
        write_u32(leaf, 20, INIT_BLOCK as u32);

        let dir_offset = ROOT_DIR_BLOCK * BLOCK_SIZE;
        let dir = &mut buf[dir_offset..dir_offset + BLOCK_SIZE];
        write_dir_entry(dir, 0, 2, b".", 2, 12);
        write_dir_entry(dir, 12, 2, b"..", 2, 12);
        let rest = (BLOCK_SIZE - 24) as u16;
        write_dir_entry(dir, 24, 3, b"init", 1, rest);

        let init_offset = INIT_BLOCK * BLOCK_SIZE;
        let len = core::cmp::min(file_data.len(), BLOCK_SIZE);
        buf[init_offset..init_offset + len].copy_from_slice(&file_data[..len]);
    }

    // 构造一个使用间接块寻址的镜像。
    fn build_ext4_with_indirect(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
        const BLOCK_BITMAP_BLOCK: usize = 3;
        const INODE_BITMAP_BLOCK: usize = 4;
        const INODE_TABLE_BLOCK: usize = 5;
        const ROOT_DIR_BLOCK: usize = 6;
        const INDIRECT_BLOCK: usize = 7;
        const INIT_BLOCK: usize = 8;

        let sb = &mut buf[SUPERBLOCK_OFFSET as usize..SUPERBLOCK_OFFSET as usize + SUPERBLOCK_SIZE];
        write_u16(sb, SUPERBLOCK_MAGIC_OFFSET, EXT4_MAGIC);
        write_u32(sb, SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET, 0);
        write_u32(sb, SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET, 8192);
        write_u32(sb, SUPERBLOCK_INODES_PER_GROUP_OFFSET, 8);
        write_u16(sb, SUPERBLOCK_INODE_SIZE_OFFSET, TEST_INODE_SIZE as u16);

        let gd_offset = BLOCK_SIZE * 2;
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_BLOCK_BITMAP_OFFSET,
            BLOCK_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_BITMAP_OFFSET,
            INODE_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_TABLE_OFFSET,
            INODE_TABLE_BLOCK as u32,
        );

        let inode_table_offset = INODE_TABLE_BLOCK * BLOCK_SIZE;
        let mut root_blocks = [0u32; 15];
        root_blocks[0] = ROOT_DIR_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            2,
            0x4000 | 0o755,
            BLOCK_SIZE as u32,
            0,
            &root_blocks,
        );

        let mut init_blocks = [0u32; 15];
        init_blocks[12] = INDIRECT_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            3,
            0x8000 | 0o644,
            (BLOCK_SIZE * 13) as u32,
            0,
            &init_blocks,
        );

        let indirect_offset = INDIRECT_BLOCK * BLOCK_SIZE;
        write_u32(&mut buf[indirect_offset..indirect_offset + BLOCK_SIZE], 0, INIT_BLOCK as u32);

        let dir_offset = ROOT_DIR_BLOCK * BLOCK_SIZE;
        let dir = &mut buf[dir_offset..dir_offset + BLOCK_SIZE];
        write_dir_entry(dir, 0, 2, b".", 2, 12);
        write_dir_entry(dir, 12, 2, b"..", 2, 12);
        let rest = (BLOCK_SIZE - 24) as u16;
        write_dir_entry(dir, 24, 3, b"init", 1, rest);

        let init_offset = INIT_BLOCK * BLOCK_SIZE;
        let len = core::cmp::min(file_data.len(), BLOCK_SIZE);
        buf[init_offset..init_offset + len].copy_from_slice(&file_data[..len]);
    }

    // 构造一个可写测试镜像：含空 root 目录与位图初始化。
    fn build_ext4_for_write(buf: &mut [u8]) {
        const BLOCK_SIZE: usize = 1024;
        const BLOCK_BITMAP_BLOCK: usize = 3;
        const INODE_BITMAP_BLOCK: usize = 4;
        const INODE_TABLE_BLOCK: usize = 5;
        const ROOT_DIR_BLOCK: usize = 6;

        buf.fill(0);

        let sb = &mut buf[SUPERBLOCK_OFFSET as usize..SUPERBLOCK_OFFSET as usize + SUPERBLOCK_SIZE];
        write_u16(sb, SUPERBLOCK_MAGIC_OFFSET, EXT4_MAGIC);
        write_u32(sb, SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET, 0);
        write_u32(sb, SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET, 8192);
        write_u32(sb, SUPERBLOCK_INODES_PER_GROUP_OFFSET, 32);
        write_u16(sb, SUPERBLOCK_INODE_SIZE_OFFSET, TEST_INODE_SIZE as u16);

        let gd_offset = BLOCK_SIZE * 2;
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_BLOCK_BITMAP_OFFSET,
            BLOCK_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_BITMAP_OFFSET,
            INODE_BITMAP_BLOCK as u32,
        );
        write_u32(
            &mut buf[gd_offset..gd_offset + GROUP_DESC_SIZE],
            GROUP_DESC_INODE_TABLE_OFFSET,
            INODE_TABLE_BLOCK as u32,
        );

        let bb_offset = BLOCK_BITMAP_BLOCK * BLOCK_SIZE;
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], 0);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], 1);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], 2);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], BLOCK_BITMAP_BLOCK);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], INODE_BITMAP_BLOCK);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], INODE_TABLE_BLOCK);
        set_bitmap(&mut buf[bb_offset..bb_offset + BLOCK_SIZE], ROOT_DIR_BLOCK);

        let ib_offset = INODE_BITMAP_BLOCK * BLOCK_SIZE;
        set_bitmap(&mut buf[ib_offset..ib_offset + BLOCK_SIZE], 0);
        set_bitmap(&mut buf[ib_offset..ib_offset + BLOCK_SIZE], 1);

        let inode_table_offset = INODE_TABLE_BLOCK * BLOCK_SIZE;
        let mut root_blocks = [0u32; 15];
        root_blocks[0] = ROOT_DIR_BLOCK as u32;
        write_inode(
            &mut buf[inode_table_offset..],
            2,
            0x4000 | 0o755,
            BLOCK_SIZE as u32,
            0,
            &root_blocks,
        );

        let dir_offset = ROOT_DIR_BLOCK * BLOCK_SIZE;
        let dir = &mut buf[dir_offset..dir_offset + BLOCK_SIZE];
        write_dir_entry(dir, 0, 2, b".", 2, 12);
        write_dir_entry(dir, 12, 2, b"..", 2, (BLOCK_SIZE - 12) as u16);
    }

    // 写入 inode 表项（仅写入本测试需要的字段）。
    fn write_inode(buf: &mut [u8], inode_num: u32, mode: u16, size: u32, flags: u32, blocks: &[u32; 15]) {
        let index = (inode_num - 1) as usize;
        let base = index * TEST_INODE_SIZE;
        write_u16(&mut buf[base..base + TEST_INODE_SIZE], INODE_MODE_OFFSET, mode);
        write_u32(&mut buf[base..base + TEST_INODE_SIZE], INODE_SIZE_LO_OFFSET, size);
        write_u32(&mut buf[base..base + TEST_INODE_SIZE], INODE_FLAGS_OFFSET, flags);
        for (idx, block) in blocks.iter().enumerate() {
            write_u32(
                &mut buf[base..base + TEST_INODE_SIZE],
                INODE_BLOCK_OFFSET + idx * 4,
                *block,
            );
        }
    }

    // 写入目录项（测试构造镜像使用的简化版本）。
    fn write_dir_entry(buf: &mut [u8], offset: usize, inode: u32, name: &[u8], kind: u8, rec_len: u16) {
        write_u32(&mut buf[offset..], 0, inode);
        write_u16(&mut buf[offset..], 4, rec_len);
        buf[offset + 6] = name.len() as u8;
        buf[offset + 7] = kind;
        let name_off = offset + 8;
        buf[name_off..name_off + name.len()].copy_from_slice(name);
    }

    // 小端序写入 u16（测试构造镜像使用）。
    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        buf[offset..offset + 2].copy_from_slice(&bytes);
    }

    // 小端序写入 u32（测试构造镜像使用）。
    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        buf[offset..offset + 4].copy_from_slice(&bytes);
    }

    // 设置位图中的某一位为 1。
    fn set_bitmap(buf: &mut [u8], bit: usize) {
        let byte = bit / 8;
        let offset = bit % 8;
        buf[byte] |= 1u8 << offset;
    }
}
