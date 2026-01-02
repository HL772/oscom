#![no_std]
//! Network stack facade and NetDevice abstraction.

mod smoltcp_impl;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Socket-layer errors surfaced to the kernel.
pub enum NetError {
    NotReady,
    WouldBlock,
    BufferTooSmall,
    Unsupported,
    Invalid,
    NoMem,
    InProgress,
    IsConnected,
    Unreachable,
    ConnRefused,
}

/// Minimal net device interface for raw frame I/O.
pub trait NetDevice {
    /// Return the device MAC address.
    fn mac_address(&self) -> [u8; 6];
    /// Receive a frame into the provided buffer.
    fn recv(&self, buf: &mut [u8]) -> Result<usize, NetError>;
    /// Send a frame from the provided buffer.
    fn send(&self, buf: &[u8]) -> Result<(), NetError>;
    /// Return true if RX data is pending.
    fn poll(&self) -> bool;
}

pub use smoltcp_impl::{
    arp_probe_gateway_once, init, notify_irq, ping_gateway_once, poll, request_poll,
    socket_accept, socket_bind, socket_close, socket_connect, socket_connecting, socket_create,
    socket_listen, socket_local_endpoint, socket_poll, socket_recv, socket_recv_window_event,
    socket_remote_endpoint, socket_send, socket_shutdown, socket_take_error, tcp_loopback_test_once,
    NetEvent, SocketId, TcpRecvWindow,
};
pub use smoltcp::wire::{IpAddress, Ipv4Address};

#[allow(dead_code)]
/// Socket wrapper for TCP/UDP sockets managed by the stack.
pub enum AxSocket<'a> {
    Tcp(smoltcp::socket::tcp::Socket<'a>),
    Udp(smoltcp::socket::udp::Socket<'a>),
}
