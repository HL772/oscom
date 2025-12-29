use axvfs::{DirEntry, FileType, InodeId, Metadata, VfsError, VfsOps, VfsResult, MAX_NAME_LEN};

use crate::block::{BlockCache, BlockDevice, BlockId};

const BPB_SIZE: usize = 512;
const BPB_SIGNATURE_OFFSET: usize = 510;
const BPB_SIGNATURE: u16 = 0xaa55;
const BPB_BYTES_PER_SECTOR_OFFSET: usize = 11;
const BPB_SECTORS_PER_CLUSTER_OFFSET: usize = 13;
const BPB_RESERVED_SECTORS_OFFSET: usize = 14;
const BPB_NUM_FATS_OFFSET: usize = 16;
const BPB_ROOT_ENTRIES_OFFSET: usize = 17;
const BPB_TOTAL_SECTORS_16_OFFSET: usize = 19;
const BPB_FAT_SIZE_16_OFFSET: usize = 22;
const BPB_TOTAL_SECTORS_32_OFFSET: usize = 32;
const BPB_FAT_SIZE_32_OFFSET: usize = 36;
const BPB_ROOT_CLUSTER_OFFSET: usize = 44;
const DIR_ENTRY_SIZE: usize = 32;
const FAT_ENTRY_SIZE: usize = 4;
const FAT32_EOC_MIN: u32 = 0x0fff_fff8;
const ATTR_LONG_NAME: u8 = 0x0f;
const ATTR_DIRECTORY: u8 = 0x10;
const ATTR_VOLUME_ID: u8 = 0x08;
const INODE_DIR_FLAG: u64 = 1 << 62;
const INODE_TAG: u64 = 1 << 63;
const INODE_CLUSTER_SHIFT: u64 = 32;
const INODE_CLUSTER_MASK: u64 = 0x3fff_ffff;

#[derive(Clone, Copy, Debug)]
pub struct Bpb {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub num_fats: u8,
    pub total_sectors: u32,
    pub sectors_per_fat: u32,
    pub root_cluster: u32,
}

impl Bpb {
    pub fn parse(buf: &[u8]) -> VfsResult<Self> {
        if buf.len() < BPB_SIZE {
            return Err(VfsError::Invalid);
        }
        let sig = u16::from_le_bytes([buf[BPB_SIGNATURE_OFFSET], buf[BPB_SIGNATURE_OFFSET + 1]]);
        if sig != BPB_SIGNATURE {
            return Err(VfsError::Invalid);
        }
        let bytes_per_sector = u16::from_le_bytes([
            buf[BPB_BYTES_PER_SECTOR_OFFSET],
            buf[BPB_BYTES_PER_SECTOR_OFFSET + 1],
        ]);
        let sectors_per_cluster = buf[BPB_SECTORS_PER_CLUSTER_OFFSET];
        let reserved_sectors = u16::from_le_bytes([
            buf[BPB_RESERVED_SECTORS_OFFSET],
            buf[BPB_RESERVED_SECTORS_OFFSET + 1],
        ]);
        let num_fats = buf[BPB_NUM_FATS_OFFSET];
        let root_entries = u16::from_le_bytes([
            buf[BPB_ROOT_ENTRIES_OFFSET],
            buf[BPB_ROOT_ENTRIES_OFFSET + 1],
        ]);
        let total_sectors_16 = u16::from_le_bytes([
            buf[BPB_TOTAL_SECTORS_16_OFFSET],
            buf[BPB_TOTAL_SECTORS_16_OFFSET + 1],
        ]);
        let fat_size_16 = u16::from_le_bytes([
            buf[BPB_FAT_SIZE_16_OFFSET],
            buf[BPB_FAT_SIZE_16_OFFSET + 1],
        ]);
        let total_sectors_32 = u32::from_le_bytes([
            buf[BPB_TOTAL_SECTORS_32_OFFSET],
            buf[BPB_TOTAL_SECTORS_32_OFFSET + 1],
            buf[BPB_TOTAL_SECTORS_32_OFFSET + 2],
            buf[BPB_TOTAL_SECTORS_32_OFFSET + 3],
        ]);
        let fat_size_32 = u32::from_le_bytes([
            buf[BPB_FAT_SIZE_32_OFFSET],
            buf[BPB_FAT_SIZE_32_OFFSET + 1],
            buf[BPB_FAT_SIZE_32_OFFSET + 2],
            buf[BPB_FAT_SIZE_32_OFFSET + 3],
        ]);
        let root_cluster = u32::from_le_bytes([
            buf[BPB_ROOT_CLUSTER_OFFSET],
            buf[BPB_ROOT_CLUSTER_OFFSET + 1],
            buf[BPB_ROOT_CLUSTER_OFFSET + 2],
            buf[BPB_ROOT_CLUSTER_OFFSET + 3],
        ]);
        let total_sectors = if total_sectors_16 != 0 {
            total_sectors_16 as u32
        } else {
            total_sectors_32
        };
        let sectors_per_fat = if fat_size_16 != 0 {
            fat_size_16 as u32
        } else {
            fat_size_32
        };
        if bytes_per_sector == 0
            || sectors_per_cluster == 0
            || reserved_sectors == 0
            || num_fats == 0
            || total_sectors == 0
            || sectors_per_fat == 0
            || root_entries != 0
            || root_cluster < 2
        {
            return Err(VfsError::Invalid);
        }
        Ok(Self {
            bytes_per_sector,
            sectors_per_cluster,
            reserved_sectors,
            num_fats,
            total_sectors,
            sectors_per_fat,
            root_cluster,
        })
    }

    pub fn fat_start_sector(&self) -> u32 {
        self.reserved_sectors as u32
    }

    pub fn data_start_sector(&self) -> u32 {
        self.fat_start_sector() + self.sectors_per_fat * self.num_fats as u32
    }
}

fn fat_inode(cluster: u32, size: u32, is_dir: bool) -> InodeId {
    let mut value = INODE_TAG | ((cluster as u64 & INODE_CLUSTER_MASK) << INODE_CLUSTER_SHIFT) | size as u64;
    if is_dir {
        value |= INODE_DIR_FLAG;
    }
    value
}

fn inode_cluster(inode: InodeId) -> u32 {
    ((inode >> INODE_CLUSTER_SHIFT) & INODE_CLUSTER_MASK) as u32
}

fn inode_size(inode: InodeId) -> u32 {
    (inode & 0xffff_ffff) as u32
}

fn inode_is_dir(inode: InodeId) -> bool {
    (inode & INODE_DIR_FLAG) != 0
}

pub struct Fat32Fs<'a> {
    cache: BlockCache<'a>,
    bpb: Bpb,
}

struct FatDirEntry {
    name: [u8; MAX_NAME_LEN],
    name_len: usize,
    file_type: FileType,
    cluster: u32,
    size: u32,
}

struct LfnState {
    buf: [u16; 260],
    expected: u8,
    active: bool,
}

impl LfnState {
    fn new() -> Self {
        Self {
            buf: [0; 260],
            expected: 0,
            active: false,
        }
    }

    fn reset(&mut self) {
        self.buf = [0; 260];
        self.expected = 0;
        self.active = false;
    }

    fn push(&mut self, entry: &[u8]) {
        let order = entry[0] & 0x1f;
        let is_last = (entry[0] & 0x40) != 0;
        if is_last {
            self.reset();
            self.active = true;
            self.expected = order;
        }
        if !self.active || order == 0 || order != self.expected {
            self.reset();
            return;
        }
        let index = (order - 1) as usize * 13;
        if index + 13 > self.buf.len() {
            self.reset();
            return;
        }
        let chars = [
            read_u16(entry, 1),
            read_u16(entry, 3),
            read_u16(entry, 5),
            read_u16(entry, 7),
            read_u16(entry, 9),
            read_u16(entry, 14),
            read_u16(entry, 16),
            read_u16(entry, 18),
            read_u16(entry, 20),
            read_u16(entry, 22),
            read_u16(entry, 24),
            read_u16(entry, 28),
            read_u16(entry, 30),
        ];
        for (idx, ch) in chars.iter().enumerate() {
            self.buf[index + idx] = *ch;
        }
        self.expected -= 1;
    }

    fn take_name(&mut self) -> Option<([u8; MAX_NAME_LEN], usize)> {
        if !self.active || self.expected != 0 {
            self.reset();
            return None;
        }
        let mut name = [0u8; MAX_NAME_LEN];
        let mut len = 0usize;
        for ch in self.buf.iter() {
            if *ch == 0 || *ch == 0xffff {
                break;
            }
            if len >= MAX_NAME_LEN {
                break;
            }
            name[len] = if *ch <= 0x7f { *ch as u8 } else { b'?' };
            len += 1;
        }
        self.reset();
        if len == 0 {
            None
        } else {
            Some((name, len))
        }
    }
}

impl<'a> Fat32Fs<'a> {
    pub fn new(device: &'a dyn BlockDevice) -> VfsResult<Self> {
        let cache = BlockCache::new(device);
        let block_size = cache.block_size();
        if block_size < BPB_SIZE || block_size > 4096 {
            return Err(VfsError::Invalid);
        }
        let mut sector = [0u8; 4096];
        cache.read_block(0, &mut sector[..block_size])?;
        let bpb = Bpb::parse(&sector[..block_size])?;
        if bpb.bytes_per_sector as usize != block_size {
            return Err(VfsError::Invalid);
        }
        Ok(Self { cache, bpb })
    }

    pub fn bpb(&self) -> &Bpb {
        &self.bpb
    }

    pub fn cluster_to_sector(&self, cluster: u32) -> u32 {
        let cluster_index = cluster.saturating_sub(2);
        self.bpb.data_start_sector()
            + cluster_index * self.bpb.sectors_per_cluster as u32
    }

    pub fn read_sector(&self, sector: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        self.cache.read_block(sector, buf)
    }

    fn bytes_per_sector(&self) -> usize {
        self.bpb.bytes_per_sector as usize
    }

    fn cluster_size(&self) -> usize {
        self.bytes_per_sector() * self.bpb.sectors_per_cluster as usize
    }

    fn read_fat_entry(&self, cluster: u32) -> VfsResult<u32> {
        let bytes_per_sector = self.bytes_per_sector();
        let fat_offset = cluster as usize * FAT_ENTRY_SIZE;
        let sector = self.bpb.fat_start_sector()
            + (fat_offset / bytes_per_sector) as u32;
        let in_sector = fat_offset % bytes_per_sector;
        let mut scratch = [0u8; 4096];
        self.read_sector(sector as BlockId, &mut scratch[..bytes_per_sector])?;
        if in_sector + FAT_ENTRY_SIZE <= bytes_per_sector {
            let raw = u32::from_le_bytes([
                scratch[in_sector],
                scratch[in_sector + 1],
                scratch[in_sector + 2],
                scratch[in_sector + 3],
            ]);
            Ok(raw & 0x0fff_ffff)
        } else {
            let mut next = [0u8; 4];
            let first = bytes_per_sector - in_sector;
            next[..first].copy_from_slice(&scratch[in_sector..bytes_per_sector]);
            self.read_sector((sector + 1) as BlockId, &mut scratch[..bytes_per_sector])?;
            next[first..].copy_from_slice(&scratch[..FAT_ENTRY_SIZE - first]);
            Ok(u32::from_le_bytes(next) & 0x0fff_ffff)
        }
    }

    fn next_cluster(&self, cluster: u32) -> VfsResult<Option<u32>> {
        let entry = self.read_fat_entry(cluster)?;
        if entry == 0 || entry >= FAT32_EOC_MIN {
            Ok(None)
        } else {
            Ok(Some(entry))
        }
    }

    fn read_cluster_bytes(
        &self,
        cluster: u32,
        offset: usize,
        buf: &mut [u8],
    ) -> VfsResult<usize> {
        let cluster_size = self.cluster_size();
        if offset >= cluster_size {
            return Ok(0);
        }
        let bytes_per_sector = self.bytes_per_sector();
        let mut remaining = core::cmp::min(buf.len(), cluster_size - offset);
        let mut copied = 0usize;
        let mut sector_index = offset / bytes_per_sector;
        let mut sector_offset = offset % bytes_per_sector;
        let mut scratch = [0u8; 4096];
        while remaining > 0 && sector_index < self.bpb.sectors_per_cluster as usize {
            let sector = self.cluster_to_sector(cluster) + sector_index as u32;
            self.read_sector(sector as BlockId, &mut scratch[..bytes_per_sector])?;
            let take = core::cmp::min(remaining, bytes_per_sector - sector_offset);
            buf[copied..copied + take]
                .copy_from_slice(&scratch[sector_offset..sector_offset + take]);
            copied += take;
            remaining -= take;
            sector_index += 1;
            sector_offset = 0;
        }
        Ok(copied)
    }

    fn scan_dir_entries(
        &self,
        cluster: u32,
        mut visit: impl FnMut(&FatDirEntry) -> VfsResult<bool>,
    ) -> VfsResult<()> {
        if cluster < 2 {
            return Err(VfsError::Invalid);
        }
        let bytes_per_sector = self.bytes_per_sector();
        let mut current = cluster;
        let mut lfn = LfnState::new();
        let mut scratch = [0u8; 4096];
        loop {
            for sector_index in 0..self.bpb.sectors_per_cluster {
                let sector = self.cluster_to_sector(current) + sector_index as u32;
                self.read_sector(sector as BlockId, &mut scratch[..bytes_per_sector])?;
                let mut offset = 0usize;
                while offset + DIR_ENTRY_SIZE <= bytes_per_sector {
                    let entry = &scratch[offset..offset + DIR_ENTRY_SIZE];
                    let first = entry[0];
                    if first == 0x00 {
                        return Ok(());
                    }
                    if first == 0xe5 {
                        lfn.reset();
                        offset += DIR_ENTRY_SIZE;
                        continue;
                    }
                    let attr = entry[11];
                    if attr == ATTR_LONG_NAME {
                        lfn.push(entry);
                        offset += DIR_ENTRY_SIZE;
                        continue;
                    }
                    if (attr & ATTR_VOLUME_ID) != 0 {
                        lfn.reset();
                        offset += DIR_ENTRY_SIZE;
                        continue;
                    }
                    let (name, name_len) = lfn.take_name().unwrap_or_else(|| short_name(entry));
                    let cluster_high = read_u16(entry, 20) as u32;
                    let cluster_low = read_u16(entry, 26) as u32;
                    let start_cluster = (cluster_high << 16) | cluster_low;
                    let size = read_u32(entry, 28);
                    let is_dir = (attr & ATTR_DIRECTORY) != 0;
                    let file_type = if is_dir { FileType::Dir } else { FileType::File };
                    let dirent = FatDirEntry {
                        name,
                        name_len,
                        file_type,
                        cluster: start_cluster,
                        size,
                    };
                    if visit(&dirent)? {
                        return Ok(());
                    }
                    offset += DIR_ENTRY_SIZE;
                }
            }
            match self.next_cluster(current)? {
                Some(next) => current = next,
                None => break,
            }
        }
        Ok(())
    }
}

fn short_name(entry: &[u8]) -> ([u8; MAX_NAME_LEN], usize) {
    let mut name = [0u8; MAX_NAME_LEN];
    let mut len = 0usize;
    let base = &entry[0..8];
    let ext = &entry[8..11];
    let base_len = base
        .iter()
        .rposition(|ch| *ch != b' ')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    for ch in &base[..base_len] {
        name[len] = ch.to_ascii_lowercase();
        len += 1;
    }
    let ext_len = ext
        .iter()
        .rposition(|ch| *ch != b' ')
        .map(|idx| idx + 1)
        .unwrap_or(0);
    if ext_len > 0 && len + 1 < MAX_NAME_LEN {
        name[len] = b'.';
        len += 1;
        for ch in &ext[..ext_len] {
            if len >= MAX_NAME_LEN {
                break;
            }
            name[len] = ch.to_ascii_lowercase();
            len += 1;
        }
    }
    (name, len)
}

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn eq_ignore_ascii_case(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
}

pub fn build_minimal_image(buf: &mut [u8], file_name: &str, file_data: &[u8]) -> VfsResult<usize> {
    let bytes_per_sector = 512usize;
    let sectors_per_cluster = 1usize;
    let reserved_sectors = 1usize;
    let num_fats = 1usize;
    let root_cluster = 2u32;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let data_clusters = if file_data.is_empty() {
        0usize
    } else {
        (file_data.len() + cluster_size - 1) / cluster_size
    };
    let file_start_cluster = if data_clusters == 0 {
        0u32
    } else {
        root_cluster + 1
    };
    let last_cluster = if data_clusters == 0 {
        root_cluster
    } else {
        root_cluster + data_clusters as u32
    };
    let fat_entries = (last_cluster + 1) as usize;
    let fat_bytes = fat_entries * FAT_ENTRY_SIZE;
    let sectors_per_fat = (fat_bytes + bytes_per_sector - 1) / bytes_per_sector;
    let total_sectors = reserved_sectors
        + num_fats * sectors_per_fat
        + (1 + data_clusters) * sectors_per_cluster;
    let total_bytes = total_sectors * bytes_per_sector;
    if buf.len() < total_bytes {
        return Err(VfsError::NoMem);
    }
    buf[..total_bytes].fill(0);
    let bpb = &mut buf[..bytes_per_sector];
    write_u16(bpb, BPB_BYTES_PER_SECTOR_OFFSET, bytes_per_sector as u16);
    bpb[BPB_SECTORS_PER_CLUSTER_OFFSET] = sectors_per_cluster as u8;
    write_u16(bpb, BPB_RESERVED_SECTORS_OFFSET, reserved_sectors as u16);
    bpb[BPB_NUM_FATS_OFFSET] = num_fats as u8;
    write_u16(bpb, BPB_ROOT_ENTRIES_OFFSET, 0);
    write_u16(bpb, BPB_TOTAL_SECTORS_16_OFFSET, 0);
    write_u16(bpb, BPB_FAT_SIZE_16_OFFSET, 0);
    write_u32(bpb, BPB_TOTAL_SECTORS_32_OFFSET, total_sectors as u32);
    write_u32(bpb, BPB_FAT_SIZE_32_OFFSET, sectors_per_fat as u32);
    write_u32(bpb, BPB_ROOT_CLUSTER_OFFSET, root_cluster);
    bpb[BPB_SIGNATURE_OFFSET] = 0x55;
    bpb[BPB_SIGNATURE_OFFSET + 1] = 0xaa;

    let fat_offset = reserved_sectors * bytes_per_sector;
    let fat = &mut buf[fat_offset..fat_offset + sectors_per_fat * bytes_per_sector];
    write_fat_entry(fat, 0, 0x0fff_fff8);
    write_fat_entry(fat, 1, 0x0fff_ffff);
    write_fat_entry(fat, root_cluster as usize, 0x0fff_ffff);
    if data_clusters > 0 {
        for idx in 0..data_clusters {
            let cluster = file_start_cluster + idx as u32;
            let next = if idx + 1 == data_clusters {
                0x0fff_ffff
            } else {
                cluster + 1
            };
            write_fat_entry(fat, cluster as usize, next);
        }
    }

    let data_start = (reserved_sectors + num_fats * sectors_per_fat) * bytes_per_sector;
    let root_dir_offset = data_start;
    let root_dir = &mut buf[root_dir_offset..root_dir_offset + cluster_size];
    write_dir_entry(root_dir, 0, b".", ATTR_DIRECTORY, root_cluster, 0);
    write_dir_entry(root_dir, 1, b"..", ATTR_DIRECTORY, root_cluster, 0);
    let short = encode_short_name(file_name)?;
    write_dir_entry(root_dir, 2, &short, 0x20, file_start_cluster, file_data.len() as u32);

    if data_clusters > 0 {
        let mut remaining = file_data;
        let mut cluster = file_start_cluster;
        while !remaining.is_empty() {
            let offset = data_start + (cluster - root_cluster) as usize * cluster_size;
            let chunk = core::cmp::min(cluster_size, remaining.len());
            buf[offset..offset + chunk].copy_from_slice(&remaining[..chunk]);
            remaining = &remaining[chunk..];
            cluster += 1;
        }
    }

    Ok(total_bytes)
}

fn encode_short_name(name: &str) -> VfsResult<[u8; 11]> {
    let mut buf = [b' '; 11];
    let (base, ext) = match name.split_once('.') {
        Some((base, ext)) => (base, ext),
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err(VfsError::Invalid);
    }
    for (idx, ch) in base.bytes().enumerate() {
        if !ch.is_ascii() {
            return Err(VfsError::Invalid);
        }
        buf[idx] = ch.to_ascii_uppercase();
    }
    for (idx, ch) in ext.bytes().enumerate() {
        if !ch.is_ascii() {
            return Err(VfsError::Invalid);
        }
        buf[8 + idx] = ch.to_ascii_uppercase();
    }
    Ok(buf)
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 2].copy_from_slice(&bytes);
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_le_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

fn write_fat_entry(fat: &mut [u8], index: usize, value: u32) {
    let offset = index * FAT_ENTRY_SIZE;
    if offset + FAT_ENTRY_SIZE > fat.len() {
        return;
    }
    let bytes = value.to_le_bytes();
    fat[offset..offset + FAT_ENTRY_SIZE].copy_from_slice(&bytes);
}

fn write_dir_entry(dir: &mut [u8], index: usize, name: &[u8], attr: u8, cluster: u32, size: u32) {
    let offset = index * DIR_ENTRY_SIZE;
    if offset + DIR_ENTRY_SIZE > dir.len() {
        return;
    }
    let entry = &mut dir[offset..offset + DIR_ENTRY_SIZE];
    entry.fill(0);
    if name.len() == 11 {
        entry[..11].copy_from_slice(name);
    } else if name == b"." {
        entry[..1].copy_from_slice(b".");
    } else if name == b".." {
        entry[..2].copy_from_slice(b"..");
    } else {
        entry[..core::cmp::min(name.len(), 11)].copy_from_slice(&name[..core::cmp::min(name.len(), 11)]);
    }
    entry[11] = attr;
    write_u16(entry, 20, (cluster >> 16) as u16);
    write_u16(entry, 26, (cluster & 0xffff) as u16);
    write_u32(entry, 28, size);
}

impl VfsOps for Fat32Fs<'_> {
    fn root(&self) -> VfsResult<InodeId> {
        Ok(fat_inode(self.bpb.root_cluster, 0, true))
    }

    fn lookup(&self, parent: InodeId, name: &str) -> VfsResult<Option<InodeId>> {
        if !inode_is_dir(parent) {
            return Err(VfsError::NotDir);
        }
        let cluster = inode_cluster(parent);
        let target = name.as_bytes();
        let mut found = None;
        self.scan_dir_entries(cluster, |entry| {
            let entry_name = &entry.name[..entry.name_len];
            if eq_ignore_ascii_case(entry_name, target) {
                let inode = fat_inode(entry.cluster, entry.size, entry.file_type == FileType::Dir);
                found = Some(inode);
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
        let file_type = if inode_is_dir(inode) {
            FileType::Dir
        } else {
            FileType::File
        };
        let size = inode_size(inode) as u64;
        let mode = if file_type == FileType::Dir { 0o755 } else { 0o644 };
        Ok(Metadata::new(file_type, size, mode))
    }

    fn read_at(&self, inode: InodeId, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        if inode_is_dir(inode) {
            return Err(VfsError::NotDir);
        }
        let size = inode_size(inode) as usize;
        let offset = offset as usize;
        if offset >= size {
            return Ok(0);
        }
        let to_read = core::cmp::min(buf.len(), size - offset);
        let cluster_size = self.cluster_size();
        let mut cluster = inode_cluster(inode);
        if cluster < 2 {
            return Ok(0);
        }
        let mut skip = offset / cluster_size;
        let mut in_cluster = offset % cluster_size;
        while skip > 0 {
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => return Ok(0),
            }
            skip -= 1;
        }
        let mut remaining = to_read;
        let mut total = 0usize;
        while remaining > 0 {
            let chunk = core::cmp::min(remaining, cluster_size - in_cluster);
            let copied = self.read_cluster_bytes(cluster, in_cluster, &mut buf[total..total + chunk])?;
            total += copied;
            remaining -= copied;
            if remaining == 0 || copied == 0 {
                break;
            }
            in_cluster = 0;
            match self.next_cluster(cluster)? {
                Some(next) => cluster = next,
                None => break,
            }
        }
        Ok(total)
    }

    fn write_at(&self, _inode: InodeId, _offset: u64, _buf: &[u8]) -> VfsResult<usize> {
        Err(VfsError::NotSupported)
    }

    fn read_dir(&self, inode: InodeId, offset: usize, entries: &mut [DirEntry]) -> VfsResult<usize> {
        if !inode_is_dir(inode) {
            return Err(VfsError::NotDir);
        }
        let cluster = inode_cluster(inode);
        let mut index = 0usize;
        let mut written = 0usize;
        self.scan_dir_entries(cluster, |entry| {
            if index < offset {
                index += 1;
                return Ok(false);
            }
            if written >= entries.len() {
                return Ok(true);
            }
            let mut dirent = DirEntry::empty();
            dirent.ino = fat_inode(entry.cluster, entry.size, entry.file_type == FileType::Dir);
            dirent.file_type = entry.file_type;
            dirent.set_name(&entry.name[..entry.name_len])?;
            entries[written] = dirent;
            written += 1;
            index += 1;
            Ok(false)
        })?;
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    const IMAGE_SIZE: usize = 16 * 1024;

    struct TestBlockDevice {
        block_size: usize,
        data: RefCell<[u8; IMAGE_SIZE]>,
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
    fn parse_bpb() {
        let mut data = [0u8; IMAGE_SIZE];
        data[BPB_SIGNATURE_OFFSET] = 0x55;
        data[BPB_SIGNATURE_OFFSET + 1] = 0xaa;
        data[BPB_BYTES_PER_SECTOR_OFFSET..BPB_BYTES_PER_SECTOR_OFFSET + 2]
            .copy_from_slice(&512u16.to_le_bytes());
        data[BPB_SECTORS_PER_CLUSTER_OFFSET] = 1;
        data[BPB_RESERVED_SECTORS_OFFSET..BPB_RESERVED_SECTORS_OFFSET + 2]
            .copy_from_slice(&32u16.to_le_bytes());
        data[BPB_NUM_FATS_OFFSET] = 2;
        data[BPB_TOTAL_SECTORS_32_OFFSET..BPB_TOTAL_SECTORS_32_OFFSET + 4]
            .copy_from_slice(&2048u32.to_le_bytes());
        data[BPB_FAT_SIZE_32_OFFSET..BPB_FAT_SIZE_32_OFFSET + 4]
            .copy_from_slice(&1u32.to_le_bytes());
        data[BPB_ROOT_CLUSTER_OFFSET..BPB_ROOT_CLUSTER_OFFSET + 4]
            .copy_from_slice(&2u32.to_le_bytes());
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Fat32Fs::new(&dev).unwrap();
        assert_eq!(fs.bpb().bytes_per_sector, 512);
        assert_eq!(fs.bpb().root_cluster, 2);
        assert_eq!(fs.cluster_to_sector(2), fs.bpb().data_start_sector());
    }

    #[test]
    fn dir_lookup_and_read() {
        let mut data = [0u8; IMAGE_SIZE];
        let file_data = b"init-data";
        build_minimal_image(&mut data, "init", file_data).unwrap();
        let dev = TestBlockDevice {
            block_size: 512,
            data: RefCell::new(data),
        };
        let fs = Fat32Fs::new(&dev).unwrap();
        let root = fs.root().unwrap();
        let mut entries = [DirEntry::empty(); 4];
        let count = fs.read_dir(root, 0, &mut entries).unwrap();
        assert!(entries[..count].iter().any(|e| e.name() == b"init"));
        let inode = fs.lookup(root, "init").unwrap().unwrap();
        let mut buf = [0u8; 16];
        let read = fs.read_at(inode, 0, &mut buf).unwrap();
        assert_eq!(&buf[..read], file_data);
    }
}
