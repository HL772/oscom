#![no_std]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    NotReady,
    WouldBlock,
    BufferTooSmall,
    Unsupported,
    Invalid,
}

/// Minimal net device interface for raw frame I/O.
pub trait NetDevice {
    fn mac_address(&self) -> [u8; 6];
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    fn send(&self, buf: &[u8]) -> Result<(), NetError>;
    fn poll(&self) -> bool;
}
