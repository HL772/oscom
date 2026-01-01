#![no_std]

mod smoltcp_impl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    NotReady,
    WouldBlock,
    BufferTooSmall,
    Unsupported,
    Invalid,
    NoMem,
}

/// Minimal net device interface for raw frame I/O.
pub trait NetDevice {
    fn mac_address(&self) -> [u8; 6];
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    fn send(&self, buf: &[u8]) -> Result<(), NetError>;
    fn poll(&self) -> bool;
}

pub use smoltcp_impl::{
    arp_probe_gateway_once, init, notify_irq, ping_gateway_once, poll, socket_accept, socket_bind,
    socket_close,
    socket_connect, socket_create, socket_listen, socket_poll, socket_recv, socket_send, tcp_loopback_test_once, NetEvent, SocketId,
};
pub use smoltcp::wire::{IpAddress, Ipv4Address};

#[allow(dead_code)]
pub enum AxSocket<'a> {
    Tcp(smoltcp::socket::tcp::Socket<'a>),
    Udp(smoltcp::socket::udp::Socket<'a>),
}
