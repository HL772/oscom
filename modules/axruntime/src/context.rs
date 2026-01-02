#![allow(dead_code)]
//! CPU context saved across task switches.

#[repr(C)]
#[derive(Clone, Copy, Default)]
/// Callee-saved register context used by context_switch.
pub struct Context {
    /// Return address.
    pub ra: usize,
    /// Stack pointer.
    pub sp: usize,
    /// Saved register s0/fp.
    pub s0: usize,
    /// Saved register s1.
    pub s1: usize,
    /// Saved register s2.
    pub s2: usize,
    /// Saved register s3.
    pub s3: usize,
    /// Saved register s4.
    pub s4: usize,
    /// Saved register s5.
    pub s5: usize,
    /// Saved register s6.
    pub s6: usize,
    /// Saved register s7.
    pub s7: usize,
    /// Saved register s8.
    pub s8: usize,
    /// Saved register s9.
    pub s9: usize,
    /// Saved register s10.
    pub s10: usize,
    /// Saved register s11.
    pub s11: usize,
}

impl Context {
    /// Construct a zeroed context.
    pub const fn zero() -> Self {
        Self {
            ra: 0,
            sp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }
}
