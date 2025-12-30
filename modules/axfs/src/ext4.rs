use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult};

use crate::block::{BlockCache, BlockDevice, BlockId};

const EXT4_ROOT_INODE: InodeId = 2;
const EXT4_MAGIC: u16 = 0xef53;
const SUPERBLOCK_OFFSET: u64 = 1024;
const SUPERBLOCK_SIZE: usize = 1024;
const SUPERBLOCK_LOG_BLOCK_SIZE_OFFSET: usize = 24;
const SUPERBLOCK_BLOCKS_PER_GROUP_OFFSET: usize = 32;
const SUPERBLOCK_INODES_PER_GROUP_OFFSET: usize = 40;
const SUPERBLOCK_MAGIC_OFFSET: usize = 56;
const SUPERBLOCK_INODE_SIZE_OFFSET: usize = 88;
const GROUP_DESC_SIZE: usize = 32;
const GROUP_DESC_INODE_TABLE_OFFSET: usize = 8;
const INODE_MODE_OFFSET: usize = 0;
const INODE_SIZE_LO_OFFSET: usize = 4;
const INODE_FLAGS_OFFSET: usize = 32;
const INODE_BLOCK_OFFSET: usize = 40;
const INODE_BLOCK_LEN: usize = 60;
const INODE_SIZE_HIGH_OFFSET: usize = 108;
const EXT4_EXTENTS_FLAG: u32 = 0x0008_0000;
const EXTENT_HEADER_MAGIC: u16 = 0xf30a;

#[derive(Clone, Copy, Debug)]
pub struct SuperBlock {
    pub log_block_size: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub magic: u16,
}

impl SuperBlock {
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

    pub fn block_size(&self) -> u32 {
        1024u32 << self.log_block_size
    }
}

#[derive(Clone, Copy, Debug)]
struct GroupDesc {
    inode_table: u32,
}

impl GroupDesc {
    fn parse(buf: &[u8]) -> VfsResult<Self> {
        if buf.len() < GROUP_DESC_SIZE {
            return Err(VfsError::Invalid);
        }
        let inode_table = read_u32(buf, GROUP_DESC_INODE_TABLE_OFFSET);
        if inode_table == 0 {
            return Err(VfsError::Invalid);
        }
        Ok(Self { inode_table })
    }
}

#[derive(Clone, Copy, Debug)]
struct Ext4Inode {
    mode: u16,
    size: u64,
    flags: u32,
    blocks: [u32; 15],
}

pub struct Ext4Fs<'a> {
    cache: BlockCache<'a>,
    superblock: SuperBlock,
}

impl<'a> Ext4Fs<'a> {
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

    pub fn superblock(&self) -> &SuperBlock {
        &self.superblock
    }

    pub fn fs_block_size(&self) -> u32 {
        self.superblock.block_size()
    }

    pub fn read_block(&self, block: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        self.cache.read_block(block, buf)
    }

    fn read_group_desc(&self, group: u32) -> VfsResult<GroupDesc> {
        let block_size = self.fs_block_size();
        let table_block = if block_size == 1024 { 2 } else { 1 };
        let offset = table_block as u64 * block_size as u64
            + group as u64 * GROUP_DESC_SIZE as u64;
        let mut buf = [0u8; GROUP_DESC_SIZE];
        read_bytes(&self.cache, offset, &mut buf)?;
        GroupDesc::parse(&buf)
    }

    fn read_inode(&self, inode: InodeId) -> VfsResult<Ext4Inode> {
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
        if inode_size == 0 || inode_size > 512 {
            return Err(VfsError::Invalid);
        }
        let desc = self.read_group_desc(group)?;
        let block_size = self.fs_block_size() as u64;
        let inode_table = desc.inode_table as u64;
        let offset = inode_table * block_size + index as u64 * inode_size as u64;
        let mut buf = [0u8; 512];
        read_bytes(&self.cache, offset, &mut buf[..inode_size])?;
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

    fn map_block(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        if (inode.flags & EXT4_EXTENTS_FLAG) != 0 {
            return self.map_extent_tree(inode, logical);
        }
        self.map_indirect_block(inode, logical)
    }

    fn read_from_inode(&self, inode: &Ext4Inode, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if offset >= inode.size {
            return Ok(0);
        }
        let max = core::cmp::min(buf.len() as u64, inode.size - offset) as usize;
        let block_size = self.fs_block_size() as usize;
        let mut remaining = max;
        let mut total = 0usize;
        let mut cur_offset = offset;
        let mut scratch = [0u8; 4096];
        while remaining > 0 {
            let block_index = (cur_offset / block_size as u64) as u32;
            let in_block = (cur_offset % block_size as u64) as usize;
            let to_copy = core::cmp::min(remaining, block_size - in_block);
            let Some(phys) = self.map_block(inode, block_index)? else {
                return Ok(total);
            };
            let block_offset = phys * block_size as u64;
            read_bytes(&self.cache, block_offset, &mut scratch[..block_size])?;
            buf[total..total + to_copy]
                .copy_from_slice(&scratch[in_block..in_block + to_copy]);
            total += to_copy;
            remaining -= to_copy;
            cur_offset += to_copy as u64;
        }
        Ok(total)
    }

    fn scan_dir_entries(
        &self,
        inode: &Ext4Inode,
        mut visit: impl FnMut(InodeId, &[u8], FileType) -> VfsResult<bool>,
    ) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        let mut offset = 0u64;
        let mut scratch = [0u8; 4096];
        while offset < inode.size {
            let read = self.read_from_inode(inode, offset, &mut scratch[..block_size])?;
            if read == 0 {
                break;
            }
            let mut pos = 0usize;
            while pos + 8 <= read {
                let inode_num = read_u32(&scratch, pos) as InodeId;
                let rec_len = read_u16(&scratch, pos + 4) as usize;
                if rec_len < 8 || pos + rec_len > read {
                    break;
                }
                let name_len = scratch[pos + 6] as usize;
                let file_type_raw = scratch[pos + 7];
                if inode_num != 0 && name_len <= rec_len - 8 {
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

    fn map_extent_tree(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        let mut raw = [0u8; INODE_BLOCK_LEN];
        for (idx, block) in inode.blocks.iter().enumerate() {
            let offset = idx * 4;
            raw[offset..offset + 4].copy_from_slice(&block.to_le_bytes());
        }
        let header = parse_extent_header(&raw)?;
        if header.depth == 0 {
            return map_extent_entries(&raw, header.entries, logical);
        }
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
            match find_extent_index(&scratch, header.entries, logical)? {
                Some(block) => next = block,
                None => return Ok(None),
            }
        }
    }

    fn map_indirect_block(&self, inode: &Ext4Inode, logical: u32) -> VfsResult<Option<u64>> {
        if logical < 12 {
            let phys = inode.blocks[logical as usize];
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        let block_size = self.fs_block_size() as u64;
        let ptrs_per_block = block_size / 4;
        if ptrs_per_block == 0 {
            return Err(VfsError::Invalid);
        }

        let mut index = logical as u64 - 12;
        if index < ptrs_per_block {
            let phys = self.read_indirect_ptr(inode.blocks[12], index, block_size)?;
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        index -= ptrs_per_block;
        let ptrs_per_block2 = ptrs_per_block * ptrs_per_block;
        if index < ptrs_per_block2 {
            let first = index / ptrs_per_block;
            let second = index % ptrs_per_block;
            let indirect = self.read_indirect_ptr(inode.blocks[13], first, block_size)?;
            if indirect == 0 {
                return Ok(None);
            }
            let phys = self.read_indirect_ptr(indirect, second, block_size)?;
            return Ok(if phys == 0 { None } else { Some(phys as u64) });
        }

        index -= ptrs_per_block2;
        let ptrs_per_block3 = ptrs_per_block2 * ptrs_per_block;
        if index < ptrs_per_block3 {
            let first = index / ptrs_per_block2;
            let rem = index % ptrs_per_block2;
            let second = rem / ptrs_per_block;
            let third = rem % ptrs_per_block;
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

    fn read_indirect_ptr(&self, block: u32, index: u64, block_size: u64) -> VfsResult<u32> {
        if block == 0 {
            return Ok(0);
        }
        let offset = block as u64 * block_size + index * 4;
        let mut buf = [0u8; 4];
        read_bytes(&self.cache, offset, &mut buf)?;
        Ok(read_u32(&buf, 0))
    }

    fn read_fs_block(&self, block: u64, buf: &mut [u8]) -> VfsResult<()> {
        let block_size = self.fs_block_size() as usize;
        if buf.len() < block_size {
            return Err(VfsError::Invalid);
        }
        let offset = block * block_size as u64;
        read_bytes(&self.cache, offset, &mut buf[..block_size])
    }
}

impl VfsOps for Ext4Fs<'_> {
    fn root(&self) -> VfsResult<InodeId> {
        Ok(EXT4_ROOT_INODE)
    }

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

    fn create(&self, _parent: InodeId, _name: &str, _kind: FileType, _mode: u16) -> VfsResult<InodeId> {
        Err(VfsError::NotSupported)
    }

    fn remove(&self, _parent: InodeId, _name: &str) -> VfsResult<()> {
        Err(VfsError::NotSupported)
    }

    fn metadata(&self, inode: InodeId) -> VfsResult<Metadata> {
        let inode_meta = self.read_inode(inode)?;
        let file_type = inode_mode_type(inode_meta.mode);
        let mode = (inode_meta.mode & 0o777) as u16;
        Ok(Metadata::new(file_type, inode_meta.size, mode))
    }

    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) == FileType::Dir {
            return Err(VfsError::NotDir);
        }
        self.read_from_inode(&inode_meta, offset, buf)
    }

    fn write_at(&self, _inode: InodeId, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
        let inode_meta = self.read_inode(inode)?;
        if inode_mode_type(inode_meta.mode) != FileType::Dir {
            return Err(VfsError::NotDir);
        }
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

}

fn read_bytes(cache: &BlockCache<'_>, offset: u64, buf: &mut [u8]) -> VfsResult<()> {
    let block_size = cache.block_size();
    if block_size == 0 || block_size > 4096 {
        return Err(VfsError::Invalid);
    }
    let block_size_u64 = block_size as u64;
    let mut scratch = [0u8; 4096];
    let mut remaining = buf.len();
    let mut buf_offset = 0usize;
    let mut cur_offset = offset;
    while remaining > 0 {
        let block_id = cur_offset / block_size_u64;
        let in_block = (cur_offset % block_size_u64) as usize;
        let to_copy = core::cmp::min(remaining, block_size - in_block);
        cache.read_block(block_id, &mut scratch[..block_size])?;
        buf[buf_offset..buf_offset + to_copy]
            .copy_from_slice(&scratch[in_block..in_block + to_copy]);
        remaining -= to_copy;
        buf_offset += to_copy;
        cur_offset += to_copy as u64;
    }
    Ok(())
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

fn inode_mode_type(mode: u16) -> FileType {
    match mode & 0xf000 {
        0x4000 => FileType::Dir,
        0x8000 => FileType::File,
        0x2000 => FileType::Char,
        0x6000 => FileType::Block,
        0x1000 => FileType::Fifo,
        0xa000 => FileType::Symlink,
        0xc000 => FileType::Socket,
        _ => FileType::File,
    }
}

struct ExtentHeader {
    entries: u16,
    depth: u16,
}

fn parse_extent_header(buf: &[u8]) -> VfsResult<ExtentHeader> {
    if buf.len() < 12 {
        return Err(VfsError::Invalid);
    }
    let magic = read_u16(buf, 0);
    if magic != EXTENT_HEADER_MAGIC {
        return Err(VfsError::NotSupported);
    }
    let entries = read_u16(buf, 2);
    let depth = read_u16(buf, 6);
    Ok(ExtentHeader { entries, depth })
}

fn map_extent_entries(buf: &[u8], entries: u16, logical: u32) -> VfsResult<Option<u64>> {
    let mut offset = 12usize;
    for _ in 0..entries {
        if offset + 12 > buf.len() {
            break;
        }
        let ee_block = read_u32(buf, offset);
        let ee_len = read_u16(buf, offset + 4) & 0x7fff;
        let ee_start_hi = read_u16(buf, offset + 6) as u32;
        let ee_start_lo = read_u32(buf, offset + 8);
        if logical >= ee_block && logical < ee_block + ee_len as u32 {
            let phys = ((ee_start_hi as u64) << 32) | ee_start_lo as u64;
            return Ok(Some(phys + (logical - ee_block) as u64));
        }
        offset += 12;
    }
    Ok(None)
}

fn find_extent_index(buf: &[u8], entries: u16, logical: u32) -> VfsResult<Option<u64>> {
    let mut offset = 12usize;
    let mut chosen: Option<u64> = None;
    for _ in 0..entries {
        if offset + 12 > buf.len() {
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
        offset += 12;
    }
    Ok(chosen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    const TEST_INODE_SIZE: usize = 128;

    struct TestBlockDevice {
        block_size: usize,
        data: RefCell<[u8; 32 * 1024]>,
    }

    impl BlockDevice for TestBlockDevice {
        fn block_size(&self) -> usize {
            self.block_size
        }

        fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let data = self.data.borrow();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            buf[..self.block_size].copy_from_slice(&data[offset..offset + self.block_size]);
            Ok(())
        }

        fn write_block(&self, _block_id: BlockId, _buf: &[u8]) -> VfsResult<()> {
            Err(VfsError::NotSupported)
        }

        fn flush(&self) -> VfsResult<()> {
            Ok(())
        }
    }

    #[test]
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

    fn build_minimal_ext4(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
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

    fn build_ext4_with_extent_tree(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
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

    fn build_ext4_with_indirect(buf: &mut [u8], file_data: &[u8]) {
        const BLOCK_SIZE: usize = 1024;
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

    fn write_dir_entry(buf: &mut [u8], offset: usize, inode: u32, name: &[u8], kind: u8, rec_len: u16) {
        write_u32(&mut buf[offset..], 0, inode);
        write_u16(&mut buf[offset..], 4, rec_len);
        buf[offset + 6] = name.len() as u8;
        buf[offset + 7] = kind;
        let name_off = offset + 8;
        buf[name_off..name_off + name.len()].copy_from_slice(name);
    }

    fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
        let bytes = value.to_le_bytes();
        buf[offset..offset + 2].copy_from_slice(&bytes);
    }

    fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        buf[offset..offset + 4].copy_from_slice(&bytes);
    }
}
