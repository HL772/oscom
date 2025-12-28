#![allow(dead_code)]

/// Result of a wait operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitResult {
    Timeout,
    Notified,
}
