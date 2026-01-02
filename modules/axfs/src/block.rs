//! Block device abstraction and a small write-back cache.

use axvfs::{VfsError, VfsResult};
use core::cell::UnsafeCell;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicBool, Ordering};

/// Logical block identifier.
pub type BlockId = u64;

/// Abstract block device interface.
pub trait BlockDevice {
    /// Return the block size in bytes.
    fn block_size(&self) -> usize;
    /// Read a block into the provided buffer.
    fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()>;
    /// Write a block from the provided buffer.
    fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()>;
    /// Flush any buffered writes to the device.
    fn flush(&self) -> VfsResult<()>;
}

const BLOCK_CACHE_LINES: usize = 32;
const BLOCK_CACHE_MAX_SIZE: usize = 4096;

#[derive(Clone, Copy)]
struct CacheEntry {
    block_id: BlockId,
    valid: bool,
    dirty: bool,
    buf: [u8; BLOCK_CACHE_MAX_SIZE],
}

impl CacheEntry {
    const fn new() -> Self {
        Self {
            block_id: 0,
            valid: false,
            dirty: false,
            buf: [0u8; BLOCK_CACHE_MAX_SIZE],
        }
    }
}

struct CacheState {
    entries: [CacheEntry; BLOCK_CACHE_LINES],
}

impl CacheState {
    const fn new() -> Self {
        Self {
            entries: [CacheEntry::new(); BLOCK_CACHE_LINES],
        }
    }
}

struct CacheLock {
    locked: AtomicBool,
    state: UnsafeCell<CacheState>,
}

unsafe impl Sync for CacheLock {}

impl CacheLock {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            state: UnsafeCell::new(CacheState::new()),
        }
    }

    fn lock(&self) -> CacheGuard<'_> {
        while self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            spin_loop();
        }
        CacheGuard { lock: self }
    }
}

struct CacheGuard<'a> {
    lock: &'a CacheLock,
}

impl<'a> CacheGuard<'a> {
    fn state_mut(&self) -> &mut CacheState {
        // SAFETY: guarded by spin lock.
        unsafe { &mut *self.lock.state.get() }
    }
}

impl Drop for CacheGuard<'_> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
    }
}

/// Fixed-size block cache with a write-back policy.
pub struct BlockCache<'a> {
    device: &'a dyn BlockDevice,
    block_size: usize,
    cache: CacheLock,
}

impl<'a> BlockCache<'a> {
    /// Create a new block cache over a device.
    pub fn new(device: &'a dyn BlockDevice) -> Self {
        let block_size = device.block_size();
        Self {
            device,
            block_size,
            cache: CacheLock::new(),
        }
    }

    /// Return the block size in bytes.
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Read a block with caching.
    pub fn read_block(&self, block_id: BlockId, buf: &mut [u8]) -> VfsResult<()> {
        if buf.len() < self.block_size {
            return Err(VfsError::Invalid);
        }
        if self.block_size > BLOCK_CACHE_MAX_SIZE {
            return self.device.read_block(block_id, &mut buf[..self.block_size]);
        }
        let guard = self.cache.lock();
        let state = guard.state_mut();
        let index = (block_id as usize) % BLOCK_CACHE_LINES;
        let entry = &mut state.entries[index];
        if !entry.valid || entry.block_id != block_id {
            if entry.valid && entry.dirty {
                self.device
                    .write_block(entry.block_id, &entry.buf[..self.block_size])?;
                entry.dirty = false;
            }
            self.device
                .read_block(block_id, &mut entry.buf[..self.block_size])?;
            entry.block_id = block_id;
            entry.valid = true;
        }
        buf[..self.block_size].copy_from_slice(&entry.buf[..self.block_size]);
        Ok(())
    }

    /// Write a block with caching.
    pub fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
        if buf.len() < self.block_size {
            return Err(VfsError::Invalid);
        }
        if self.block_size > BLOCK_CACHE_MAX_SIZE {
            return self.device.write_block(block_id, &buf[..self.block_size]);
        }
        let guard = self.cache.lock();
        let state = guard.state_mut();
        let index = (block_id as usize) % BLOCK_CACHE_LINES;
        let entry = &mut state.entries[index];
        if entry.valid && entry.block_id != block_id && entry.dirty {
            self.device
                .write_block(entry.block_id, &entry.buf[..self.block_size])?;
        }
        entry.block_id = block_id;
        entry.valid = true;
        entry.dirty = true;
        entry.buf[..self.block_size].copy_from_slice(&buf[..self.block_size]);
        Ok(())
    }

    /// Flush dirty cache entries to the device.
    pub fn flush(&self) -> VfsResult<()> {
        if self.block_size <= BLOCK_CACHE_MAX_SIZE {
            let guard = self.cache.lock();
            let state = guard.state_mut();
            for entry in state.entries.iter_mut() {
                if entry.valid && entry.dirty {
                    self.device
                        .write_block(entry.block_id, &entry.buf[..self.block_size])?;
                    entry.dirty = false;
                }
            }
        }
        self.device.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;

    struct TestBlockDevice {
        block_size: usize,
        data: RefCell<[u8; 8]>,
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

        fn write_block(&self, block_id: BlockId, buf: &[u8]) -> VfsResult<()> {
            let offset = block_id as usize * self.block_size;
            let mut data = self.data.borrow_mut();
            if offset + self.block_size > data.len() {
                return Err(VfsError::NotFound);
            }
            data[offset..offset + self.block_size].copy_from_slice(&buf[..self.block_size]);
            Ok(())
        }

        fn flush(&self) -> VfsResult<()> {
            Ok(())
        }
    }

    #[test]
    fn block_cache_passthrough() {
        let dev = TestBlockDevice {
            block_size: 4,
            data: RefCell::new([0u8; 8]),
        };
        let cache = BlockCache::new(&dev);
        let buf = [1u8, 2, 3, 4];
        cache.write_block(1, &buf).unwrap();
        let mut read = [0u8; 4];
        cache.read_block(1, &mut read).unwrap();
        assert_eq!(read, buf);
    }

    #[test]
    fn block_cache_writeback_flush() {
        let dev = TestBlockDevice {
            block_size: 4,
            data: RefCell::new([0u8; 8]),
        };
        let cache = BlockCache::new(&dev);
        let buf = [7u8, 7, 7, 7];
        cache.write_block(0, &buf).unwrap();

        let mut direct = [0u8; 4];
        dev.read_block(0, &mut direct).unwrap();
        assert_ne!(direct, buf);

        cache.flush().unwrap();
        dev.read_block(0, &mut direct).unwrap();
        assert_eq!(direct, buf);
    }
}
