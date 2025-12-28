#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};

// Time helpers are scaffolded for upcoming scheduler/timeout work.

static TIMEBASE_HZ: AtomicU64 = AtomicU64::new(0);
static TICK_HZ: AtomicU64 = AtomicU64::new(0);
static TICK_INTERVAL: AtomicU64 = AtomicU64::new(0);
static TICKS: AtomicU64 = AtomicU64::new(0);

pub fn init(timebase_hz: u64, tick_hz: u64) -> u64 {
    TIMEBASE_HZ.store(timebase_hz, Ordering::Relaxed);
    TICK_HZ.store(tick_hz, Ordering::Relaxed);
    let interval = if tick_hz == 0 { 0 } else { timebase_hz / tick_hz };
    TICK_INTERVAL.store(interval, Ordering::Relaxed);
    interval
}

pub fn tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn timebase_hz() -> u64 {
    TIMEBASE_HZ.load(Ordering::Relaxed)
}

pub fn tick_hz() -> u64 {
    TICK_HZ.load(Ordering::Relaxed)
}

pub fn interval_ticks() -> u64 {
    TICK_INTERVAL.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    let hz = tick_hz();
    if hz == 0 {
        0
    } else {
        ticks().saturating_mul(1000) / hz
    }
}
