#![allow(dead_code)]
//! Wait result types used by the runtime.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Result of a wait operation.
pub enum WaitResult {
    Timeout,
    Notified,
}
