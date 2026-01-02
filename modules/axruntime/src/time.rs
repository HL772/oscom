#![allow(dead_code)]
//! Timebase and tick accounting helpers.

use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(target_arch = "riscv64")]
use core::arch::asm;

// Time helpers provide tick-based scheduling and rdtime-based monotonic clocks.

static TIMEBASE_HZ: AtomicU64 = AtomicU64::new(0);
static TIMEBASE_START: AtomicU64 = AtomicU64::new(0);
static TICK_HZ: AtomicU64 = AtomicU64::new(0);
static TICK_INTERVAL: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);

/// Initialize timebase frequency and tick interval.
pub fn init(timebase_hz: u64, tick_hz: u64) -> u64 {
    TIMEBASE_HZ.store(timebase_hz, Ordering::Relaxed);
    TIMEBASE_START.store(read_timebase(), Ordering::Relaxed);
    TICK_HZ.store(tick_hz, Ordering::Relaxed);
    let interval = if tick_hz == 0 { 0 } else { timebase_hz / tick_hz };
    TICK_INTERVAL.store(interval, Ordering::Relaxed);
    interval
}

/// Increment the tick counter and return the new value.
pub fn tick() -> u64 {
    TICKS.fetch_add(1, Ordering::Relaxed) + 1
}

/// Return the current tick count.
pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

/// Return the configured timebase frequency.
pub fn timebase_hz() -> u64 {
    TIMEBASE_HZ.load(Ordering::Relaxed)
}

/// Return the configured tick frequency.
pub fn tick_hz() -> u64 {
    TICK_HZ.load(Ordering::Relaxed)
}

/// Return the configured tick interval in timer ticks.
pub fn interval_ticks() -> u64 {
    TICK_INTERVAL.load(Ordering::Relaxed)
}

/// Return uptime in milliseconds.
pub fn uptime_ms() -> u64 {
    monotonic_ns().saturating_div(1_000_000)
}

/// Return monotonic time in nanoseconds.
pub fn monotonic_ns() -> u64 {
    let hz = timebase_hz();
    if hz == 0 {
        return ticks_to_ns();
    }
    let base = TIMEBASE_START.load(Ordering::Relaxed);
    let now = read_timebase();
    let delta = now.saturating_sub(base);
    ((delta as u128).saturating_mul(1_000_000_000u128) / hz as u128) as u64
}

fn ticks_to_ns() -> u64 {
    let hz = tick_hz();
    if hz == 0 {
        0
    } else {
        ticks()
            .saturating_mul(1_000_000_000)
            .saturating_div(hz)
    }
}

#[cfg(target_arch = "riscv64")]
#[inline]
fn read_timebase() -> u64 {
    let value: u64;
    // Safety: rdtime reads the monotonically increasing time CSR.
    unsafe { asm!("rdtime {0}", out(reg) value) };
    value
}

#[cfg(not(target_arch = "riscv64"))]
#[inline]
fn read_timebase() -> u64 {
    0
}
