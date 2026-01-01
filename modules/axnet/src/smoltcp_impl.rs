#![allow(dead_code)]

use core::mem::MaybeUninit;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::icmp::{
    Endpoint as IcmpEndpoint, PacketBuffer as IcmpPacketBuffer, PacketMetadata as IcmpPacketMetadata,
    Socket as IcmpSocket,
};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::socket::udp::{PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket};
use smoltcp::time::Instant;
use smoltcp::wire::{
    ArpOperation, ArpPacket, ArpRepr, EthernetAddress, EthernetFrame, EthernetProtocol, Icmpv4Packet,
    Icmpv4Repr, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address,
};

use crate::{NetDevice, NetError};

const NET_MTU: usize = 1500;
const NET_BUF_SIZE: usize = 2048;
const MAX_SOCKETS: usize = 8;
const SOCKET_STORAGE_LEN: usize = MAX_SOCKETS + 1;
const ICMP_META_LEN: usize = 4;
const ICMP_BUF_LEN: usize = 256;
const TCP_BUF_LEN: usize = 2048;
const UDP_BUF_LEN: usize = 2048;
const UDP_META_LEN: usize = 4;
const ARP_POLL_RETRY: u16 = 8;

const NET_IPV4_ADDR: [u8; 4] = [10, 0, 2, 15];
const NET_IPV4_GATEWAY: [u8; 4] = [10, 0, 2, 2];
const NET_IPV4_PREFIX: u8 = 24;
// poll/ppoll 事件位与 syscall 侧保持一致。
const NET_POLLIN: u16 = 0x001;
const NET_POLLOUT: u16 = 0x004;
const NET_POLLERR: u16 = 0x008;
const NET_POLLHUP: u16 = 0x010;
const LOOPBACK_PORT: u16 = 40000;

static NET_READY: AtomicBool = AtomicBool::new(false);
static NET_NEED_POLL: AtomicBool = AtomicBool::new(false);
static NET_PING_REQUESTED: AtomicBool = AtomicBool::new(false);
static NET_ARP_REQUESTED: AtomicBool = AtomicBool::new(false);
static NET_ARP_PENDING: AtomicU16 = AtomicU16::new(0);
static NET_ARP_REPLY_IP: AtomicU32 = AtomicU32::new(0);
static NET_ARP_SENT_IP: AtomicU32 = AtomicU32::new(0);
static NET_RX_SEEN: AtomicBool = AtomicBool::new(false);
static NEXT_EPHEMERAL_PORT: AtomicU16 = AtomicU16::new(49152);

static mut RX_BUF: [u8; NET_BUF_SIZE] = [0; NET_BUF_SIZE];
static mut TX_BUF: [u8; NET_BUF_SIZE] = [0; NET_BUF_SIZE];
static mut LOOPBACK_QUEUE: LoopbackQueue = LoopbackQueue::new();
static mut ICMP_RX_META: [IcmpPacketMetadata; ICMP_META_LEN] = [IcmpPacketMetadata::EMPTY; ICMP_META_LEN];
static mut ICMP_RX_BUF: [u8; ICMP_BUF_LEN] = [0; ICMP_BUF_LEN];
static mut ICMP_TX_META: [IcmpPacketMetadata; ICMP_META_LEN] = [IcmpPacketMetadata::EMPTY; ICMP_META_LEN];
static mut ICMP_TX_BUF: [u8; ICMP_BUF_LEN] = [0; ICMP_BUF_LEN];
static mut TCP_RX_BUF: [[u8; TCP_BUF_LEN]; MAX_SOCKETS] = [[0; TCP_BUF_LEN]; MAX_SOCKETS];
static mut TCP_TX_BUF: [[u8; TCP_BUF_LEN]; MAX_SOCKETS] = [[0; TCP_BUF_LEN]; MAX_SOCKETS];
static mut UDP_RX_META: [[UdpPacketMetadata; UDP_META_LEN]; MAX_SOCKETS] =
    [[UdpPacketMetadata::EMPTY; UDP_META_LEN]; MAX_SOCKETS];
static mut UDP_RX_BUF: [[u8; UDP_BUF_LEN]; MAX_SOCKETS] = [[0; UDP_BUF_LEN]; MAX_SOCKETS];
static mut UDP_TX_META: [[UdpPacketMetadata; UDP_META_LEN]; MAX_SOCKETS] =
    [[UdpPacketMetadata::EMPTY; UDP_META_LEN]; MAX_SOCKETS];
static mut UDP_TX_BUF: [[u8; UDP_BUF_LEN]; MAX_SOCKETS] = [[0; UDP_BUF_LEN]; MAX_SOCKETS];
static mut ARP_TX_BUF: [u8; 64] = [0; 64];
const ARP_FRAME_LEN: usize = 42;

struct SmolDevice {
    dev: &'static dyn NetDevice,
}

struct SmolRxToken {
    len: usize,
}

struct SmolTxToken<'a> {
    dev: &'a dyn NetDevice,
}

pub type SocketId = usize;

impl Device for SmolDevice {
    type RxToken<'a> = SmolRxToken where Self: 'a;
    type TxToken<'a> = SmolTxToken<'a> where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = NET_MTU;
        caps.medium = Medium::Ethernet;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Loopback frames take priority to wake local TCP listeners.
        let loopback_len = unsafe { LOOPBACK_QUEUE.pop(&mut RX_BUF) };
        if let Some(len) = loopback_len {
            let _ = NET_RX_SEEN.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
            return Some((SmolRxToken { len }, SmolTxToken { dev: self.dev }));
        }
        if !self.dev.poll() {
            return None;
        }
        // SAFETY: single-token receive; buffer is reused once token is consumed.
        let len = unsafe { self.dev.recv(&mut RX_BUF).ok()? };
        let _ = NET_RX_SEEN.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire);
        record_arp_reply(unsafe { &RX_BUF[..len] });
        Some((SmolRxToken { len }, SmolTxToken { dev: self.dev }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(SmolTxToken { dev: self.dev })
    }
}

impl RxToken for SmolRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // SAFETY: the RX buffer remains valid until the token is dropped.
        let slice = unsafe { &mut RX_BUF[..self.len] };
        f(slice)
    }
}

impl TxToken for SmolTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len > NET_BUF_SIZE {
            return f(&mut []);
        }
        // SAFETY: TX buffer is used by a single token at a time.
        let buf = unsafe { &mut TX_BUF[..len] };
        let result = f(buf);
        let mac = EthernetAddress(self.dev.mac_address());
        if try_loopback_arp(buf, mac) {
            return result;
        }
        if should_loopback(buf) {
            // SAFETY: single-hart; loopback queue is only touched here and in receive.
            unsafe {
                LOOPBACK_QUEUE.push(buf);
            }
            NET_NEED_POLL.store(true, Ordering::Release);
            return result;
        }
        let _ = self.dev.send(buf);
        result
    }
}

struct NetState {
    iface: Interface,
    sockets: SocketSet<'static>,
    device: SmolDevice,
    icmp_handle: SocketHandle,
    ping_ident: u16,
    ping_seq: u16,
}

// SAFETY: global net state is serialized by single-hart boot and idle loop.
static mut NET_STATE: Option<NetState> = None;

pub fn init(dev: &'static dyn NetDevice) -> Result<(), NetError> {
    if NET_READY.load(Ordering::Acquire) {
        return Ok(());
    }

    let mac = dev.mac_address();
    let hw_addr = EthernetAddress(mac);
    let ip = IpCidr::new(IpAddress::v4(NET_IPV4_ADDR[0], NET_IPV4_ADDR[1], NET_IPV4_ADDR[2], NET_IPV4_ADDR[3]), NET_IPV4_PREFIX);

    let mut device = SmolDevice { dev };
    let mut sockets = unsafe { SocketSet::new(&mut SOCKET_STORAGE[..]) };
    let icmp_rx = unsafe { IcmpPacketBuffer::new(&mut ICMP_RX_META[..], &mut ICMP_RX_BUF[..]) };
    let icmp_tx = unsafe { IcmpPacketBuffer::new(&mut ICMP_TX_META[..], &mut ICMP_TX_BUF[..]) };
    let icmp_socket = IcmpSocket::new(icmp_rx, icmp_tx);
    let icmp_handle = sockets.add(icmp_socket);

    let mut config = Config::new(hw_addr.into());
    config.random_seed = 0x1234_5678;
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(ip);
    });
    let gateway = Ipv4Address::new(
        NET_IPV4_GATEWAY[0],
        NET_IPV4_GATEWAY[1],
        NET_IPV4_GATEWAY[2],
        NET_IPV4_GATEWAY[3],
    );
    let _ = iface.routes_mut().add_default_ipv4_route(gateway);

    let ping_ident = u16::from_le_bytes([mac[4], mac[5]]);
    let state = NetState {
        iface,
        sockets,
        device,
        icmp_handle,
        ping_ident,
        ping_seq: 1,
    };

    unsafe {
        NET_STATE = Some(state);
    }
    NET_READY.store(true, Ordering::Release);
    NET_NEED_POLL.store(true, Ordering::Release);
    Ok(())
}

pub fn notify_irq() {
    NET_NEED_POLL.store(true, Ordering::Release);
}

pub enum NetEvent {
    IcmpEchoReply { seq: u16, from: IpAddress },
    ArpReply { from: Ipv4Address },
    ArpProbeSent { target: Ipv4Address },
    RxFrameSeen,
    Activity,
}

pub fn poll(now_ms: u64) -> Option<NetEvent> {
    if !NET_READY.load(Ordering::Acquire) {
        return None;
    }
    if !NET_NEED_POLL.swap(false, Ordering::AcqRel) {
        return None;
    }
    let timestamp = Instant::from_millis(now_ms as i64);
    // SAFETY: NET_STATE is only mutated here after init.
    let Some(state) = (unsafe { NET_STATE.as_mut() }) else {
        return None;
    };
    if NET_PING_REQUESTED.swap(false, Ordering::AcqRel) {
        let gateway = IpAddress::Ipv4(Ipv4Address::new(
            NET_IPV4_GATEWAY[0],
            NET_IPV4_GATEWAY[1],
            NET_IPV4_GATEWAY[2],
            NET_IPV4_GATEWAY[3],
        ));
        let socket = state.sockets.get_mut::<IcmpSocket>(state.icmp_handle);
        if !socket.is_open() {
            let _ = socket.bind(IcmpEndpoint::Ident(state.ping_ident));
        }
        if socket.can_send() {
            let payload = b"aurora";
            let repr = Icmpv4Repr::EchoRequest {
                ident: state.ping_ident,
                seq_no: state.ping_seq,
                data: payload,
            };
            let caps = state.device.capabilities();
            let _ = socket.send_with(repr.buffer_len(), gateway, |buf| {
                let mut pkt = Icmpv4Packet::new_unchecked(buf);
                repr.emit(&mut pkt, &caps.checksum);
                repr.buffer_len()
            });
            state.ping_seq = state.ping_seq.wrapping_add(1);
            NET_NEED_POLL.store(true, Ordering::Release);
        }
    }
    if NET_ARP_REQUESTED.swap(false, Ordering::AcqRel) {
        send_arp_probe(state);
        NET_ARP_PENDING.store(ARP_POLL_RETRY, Ordering::Release);
        NET_NEED_POLL.store(true, Ordering::Release);
    }
    let activity = state
        .iface
        .poll(timestamp, &mut state.device, &mut state.sockets);
    let pending_tcp = has_pending_tcp(state);
    if pending_tcp {
        NET_NEED_POLL.store(true, Ordering::Release);
    }

    if let Some(target) = take_arp_sent() {
        return Some(NetEvent::ArpProbeSent { target });
    }
    if let Some(reply) = take_arp_reply() {
        NET_ARP_PENDING.store(0, Ordering::Release);
        return Some(NetEvent::ArpReply { from: reply });
    }
    if take_rx_seen() {
        return Some(NetEvent::RxFrameSeen);
    }

    let socket = state.sockets.get_mut::<IcmpSocket>(state.icmp_handle);
    if socket.can_recv() {
        if let Ok((payload, from)) = socket.recv() {
            if let Ok(pkt) = Icmpv4Packet::new_checked(payload) {
                if let Ok(repr) = Icmpv4Repr::parse(&pkt, &state.device.capabilities().checksum) {
                    if let Icmpv4Repr::EchoReply { ident, seq_no, .. } = repr {
                        if ident == state.ping_ident {
                            return Some(NetEvent::IcmpEchoReply { seq: seq_no, from });
                        }
                    }
                }
            }
        }
    }
    if pending_tcp {
        return Some(NetEvent::Activity);
    }
    if activity {
        return Some(NetEvent::Activity);
    }
    let pending = NET_ARP_PENDING.load(Ordering::Acquire);
    if pending > 0 {
        NET_ARP_PENDING.store(pending.saturating_sub(1), Ordering::Release);
        NET_NEED_POLL.store(true, Ordering::Release);
    }
    None
}

fn has_pending_tcp(state: &mut NetState) -> bool {
    // SAFETY: socket table access is serialized by the single-hart runtime.
    unsafe {
        for slot in SOCKET_TABLE.iter() {
            if !slot.used || slot.kind != AxSocketKind::Tcp {
                continue;
            }
            let handle = ptr::read(slot.handle.as_ptr());
            let socket = state.sockets.get::<TcpSocket>(handle);
            match socket.state() {
                TcpState::SynSent | TcpState::SynReceived => return true,
                _ => {}
            }
        }
    }
    false
}

pub fn tcp_loopback_test_once() -> Result<(), NetError> {
    if !NET_READY.load(Ordering::Acquire) {
        return Err(NetError::NotReady);
    }
    run_tcp_loopback()
}

struct LoopbackQueue {
    frames: [[u8; NET_BUF_SIZE]; 8],
    lens: [usize; 8],
    head: usize,
    tail: usize,
}

impl LoopbackQueue {
    const fn new() -> Self {
        Self {
            frames: [[0; NET_BUF_SIZE]; 8],
            lens: [0; 8],
            head: 0,
            tail: 0,
        }
    }

    fn push(&mut self, data: &[u8]) {
        let next = (self.head + 1) % self.frames.len();
        if next == self.tail {
            return;
        }
        let len = core::cmp::min(data.len(), NET_BUF_SIZE);
        self.frames[self.head][..len].copy_from_slice(&data[..len]);
        self.lens[self.head] = len;
        self.head = next;
    }

    fn pop(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.tail == self.head {
            return None;
        }
        let len = self.lens[self.tail];
        let copy_len = core::cmp::min(len, buf.len());
        buf[..copy_len].copy_from_slice(&self.frames[self.tail][..copy_len]);
        self.tail = (self.tail + 1) % self.frames.len();
        Some(copy_len)
    }
}

struct LoopbackDevice {
    queue: LoopbackQueue,
    rx_buf: [u8; NET_BUF_SIZE],
}

impl LoopbackDevice {
    fn new() -> Self {
        Self {
            queue: LoopbackQueue::new(),
            rx_buf: [0; NET_BUF_SIZE],
        }
    }
}

struct LoopRxToken<'a> {
    buf: &'a mut [u8],
    len: usize,
}

struct LoopTxToken<'a> {
    queue: &'a mut LoopbackQueue,
}

impl Device for LoopbackDevice {
    type RxToken<'a> = LoopRxToken<'a> where Self: 'a;
    type TxToken<'a> = LoopTxToken<'a> where Self: 'a;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = NET_MTU;
        caps.medium = Medium::Ethernet;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let len = self.queue.pop(&mut self.rx_buf)?;
        let rx = LoopRxToken {
            buf: &mut self.rx_buf,
            len,
        };
        let tx = LoopTxToken {
            queue: &mut self.queue,
        };
        Some((rx, tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LoopTxToken {
            queue: &mut self.queue,
        })
    }
}

impl RxToken for LoopRxToken<'_> {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buf[..self.len])
    }
}

impl TxToken for LoopTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        if len > NET_BUF_SIZE {
            return f(&mut []);
        }
        let mut buf = [0u8; NET_BUF_SIZE];
        let result = f(&mut buf[..len]);
        self.queue.push(&buf[..len]);
        result
    }
}

fn run_tcp_loopback() -> Result<(), NetError> {
    let mut device = LoopbackDevice::new();
    let mut config = Config::new(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).into());
    config.random_seed = 0x1234_5678;
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
    });

    static mut LOOPBACK_STORAGE: [SocketStorage<'static>; 2] =
        [SocketStorage::EMPTY; 2];
    static mut SERVER_RX_BUF: [u8; 1024] = [0; 1024];
    static mut SERVER_TX_BUF: [u8; 1024] = [0; 1024];
    static mut CLIENT_RX_BUF: [u8; 1024] = [0; 1024];
    static mut CLIENT_TX_BUF: [u8; 1024] = [0; 1024];

    // SAFETY: loopback buffers are static and only used by this self-test.
    let server_rx = unsafe { TcpSocketBuffer::new(&mut SERVER_RX_BUF[..]) };
    // SAFETY: loopback buffers are static and only used by this self-test.
    let server_tx = unsafe { TcpSocketBuffer::new(&mut SERVER_TX_BUF[..]) };
    // SAFETY: loopback buffers are static and only used by this self-test.
    let client_rx = unsafe { TcpSocketBuffer::new(&mut CLIENT_RX_BUF[..]) };
    // SAFETY: loopback buffers are static and only used by this self-test.
    let client_tx = unsafe { TcpSocketBuffer::new(&mut CLIENT_TX_BUF[..]) };

    let server_socket = TcpSocket::new(server_rx, server_tx);
    let client_socket = TcpSocket::new(client_rx, client_tx);
    // SAFETY: loopback storage is static and only used by this self-test.
    let mut sockets = unsafe { SocketSet::new(&mut LOOPBACK_STORAGE[..]) };
    let server_handle = sockets.add(server_socket);
    let client_handle = sockets.add(client_socket);

    let mut did_listen = false;
    let mut did_connect = false;
    let mut client_sent = false;
    let mut server_received = false;
    let mut server_sent = false;
    let mut client_received = false;
    let payload = b"aurora loopback";
    let reply = b"ok";

    let mut now_ms: i64 = 0;
    for _ in 0..500 {
        let now = Instant::from_millis(now_ms);
        iface.poll(now, &mut device, &mut sockets);

        {
            let server = sockets.get_mut::<TcpSocket>(server_handle);
            if !server.is_active() && !server.is_listening() && !did_listen {
                server.listen(LOOPBACK_PORT).map_err(|_| NetError::Invalid)?;
                did_listen = true;
            }
            if !server_received && server.can_recv() {
                let mut buf = [0u8; 64];
                let read = server.recv_slice(&mut buf).map_err(|_| NetError::Invalid)?;
                if read == payload.len() && buf[..read] == payload[..] {
                    server_received = true;
                } else {
                    return Err(NetError::Invalid);
                }
            }
            if server_received && !server_sent && server.can_send() {
                server.send_slice(reply).map_err(|_| NetError::Invalid)?;
                server_sent = true;
            }
        }

        {
            let client = sockets.get_mut::<TcpSocket>(client_handle);
            if !client.is_open() && !did_connect {
                let cx = iface.context();
                client
                    .connect(cx, (IpAddress::v4(127, 0, 0, 1), LOOPBACK_PORT), 65000)
                    .map_err(|_| NetError::Invalid)?;
                did_connect = true;
            }
            if !client_sent && client.can_send() {
                client.send_slice(payload).map_err(|_| NetError::Invalid)?;
                client_sent = true;
            }
            if !client_received && client.can_recv() {
                let mut buf = [0u8; 16];
                let read = client.recv_slice(&mut buf).map_err(|_| NetError::Invalid)?;
                if read == reply.len() && buf[..read] == reply[..] {
                    client_received = true;
                } else {
                    return Err(NetError::Invalid);
                }
            }
        }

        if server_received && client_received {
            return Ok(());
        }
        now_ms = now_ms.saturating_add(10);
    }
    Err(NetError::Invalid)
}

pub fn ping_gateway_once() -> Result<(), NetError> {
    if !NET_READY.load(Ordering::Acquire) {
        return Err(NetError::NotReady);
    }
    NET_PING_REQUESTED.store(true, Ordering::Release);
    NET_NEED_POLL.store(true, Ordering::Release);
    Ok(())
}

pub fn arp_probe_gateway_once() -> Result<(), NetError> {
    if !NET_READY.load(Ordering::Acquire) {
        return Err(NetError::NotReady);
    }
    NET_ARP_REQUESTED.store(true, Ordering::Release);
    NET_NEED_POLL.store(true, Ordering::Release);
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AxSocketKind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy)]
struct SocketSlot {
    used: bool,
    kind: AxSocketKind,
    local_port: u16,
    listening: bool,
    connecting: bool,
    last_error: Option<NetError>,
    handle: MaybeUninit<SocketHandle>,
}

const EMPTY_SOCKET_SLOT: SocketSlot = SocketSlot {
    used: false,
    kind: AxSocketKind::Tcp,
    local_port: 0,
    listening: false,
    connecting: false,
    last_error: None,
    handle: MaybeUninit::uninit(),
};

static mut SOCKET_TABLE: [SocketSlot; MAX_SOCKETS] = [EMPTY_SOCKET_SLOT; MAX_SOCKETS];

pub fn socket_create(domain: i32, sock_type: i32, _protocol: i32) -> Result<SocketId, NetError> {
    if !NET_READY.load(Ordering::Acquire) {
        return Err(NetError::NotReady);
    }
    if domain != 2 {
        return Err(NetError::Unsupported);
    }
    let kind = match sock_type & 0xf {
        1 => AxSocketKind::Tcp,
        2 => AxSocketKind::Udp,
        _ => return Err(NetError::Unsupported),
    };
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let slot = reserve_socket_slot(kind).ok_or(NetError::NoMem)?;
    let handle = match kind {
        AxSocketKind::Tcp => {
            let rx = unsafe { TcpSocketBuffer::new(&mut TCP_RX_BUF[slot][..]) };
            let tx = unsafe { TcpSocketBuffer::new(&mut TCP_TX_BUF[slot][..]) };
            state.sockets.add(TcpSocket::new(rx, tx))
        }
        AxSocketKind::Udp => {
            let rx = unsafe {
                UdpPacketBuffer::new(&mut UDP_RX_META[slot][..], &mut UDP_RX_BUF[slot][..])
            };
            let tx = unsafe {
                UdpPacketBuffer::new(&mut UDP_TX_META[slot][..], &mut UDP_TX_BUF[slot][..])
            };
            state.sockets.add(UdpSocket::new(rx, tx))
        }
    };
    set_socket_handle(slot, handle);
    Ok(slot)
}

pub fn socket_bind(id: SocketId, addr: IpAddress, port: u16) -> Result<(), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            set_socket_local_port(id, port)?;
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            if socket.is_open() {
                return Err(NetError::Invalid);
            }
            if port == 0 {
                return Err(NetError::Invalid);
            }
            Ok(())
        }
        AxSocketKind::Udp => {
            let socket = state.sockets.get_mut::<UdpSocket>(handle);
            socket.bind((addr, port)).map_err(|_| NetError::Invalid)?;
            Ok(())
        }
    }
}

pub fn socket_connect(id: SocketId, addr: IpAddress, port: u16) -> Result<(), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            set_socket_listening(id, false)?;
            let local_port = socket_local_port(id)?;
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            let tcp_state = socket.state();
            match tcp_state {
                TcpState::SynSent | TcpState::SynReceived => {
                    let _ = set_socket_connecting(id, true);
                    return Err(NetError::InProgress);
                }
                TcpState::Listen => return Err(NetError::Invalid),
                TcpState::Closed => {}
                _ => return Err(NetError::IsConnected),
            }
            set_socket_connecting(id, true)?;
            set_socket_error(id, None)?;
            let local = IpListenEndpoint {
                addr: None,
                port: local_port,
            };
            socket
                .connect(state.iface.context(), (addr, port), local)
                .map_err(|err| match err {
                    smoltcp::socket::tcp::ConnectError::InvalidState => NetError::Invalid,
                    smoltcp::socket::tcp::ConnectError::Unaddressable => NetError::Unreachable,
                })?;
            NET_NEED_POLL.store(true, Ordering::Release);
            Ok(())
        }
        AxSocketKind::Udp => Err(NetError::Unsupported),
    }
}

pub fn socket_listen(id: SocketId, _backlog: usize) -> Result<(), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            let local_port = socket_local_port(id)?;
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            socket
                .listen(IpListenEndpoint { addr: None, port: local_port })
                .map_err(|_| NetError::Invalid)?;
            set_socket_listening(id, true)?;
            NET_NEED_POLL.store(true, Ordering::Release);
            Ok(())
        }
        AxSocketKind::Udp => Err(NetError::Unsupported),
    }
}

pub fn socket_accept(id: SocketId) -> Result<(SocketId, SocketId, Option<(IpAddress, u16)>), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    let AxSocketKind::Tcp = kind else {
        return Err(NetError::Unsupported);
    };
    if !socket_is_listening(id)? {
        return Err(NetError::Invalid);
    }
    let socket = state.sockets.get_mut::<TcpSocket>(handle);
    let tcp_state = socket.state();
    if socket.is_listening() || tcp_state == TcpState::SynReceived {
        NET_NEED_POLL.store(true, Ordering::Release);
        return Err(NetError::WouldBlock);
    }
    if tcp_state != TcpState::Established && tcp_state != TcpState::CloseWait
    {
        return Err(NetError::Invalid);
    }
    let remote = socket.remote_endpoint().map(|ep| (ep.addr, ep.port));
    let local_port = socket_local_port(id)?;
    let listener_id = reserve_socket_slot(AxSocketKind::Tcp).ok_or(NetError::NoMem)?;
    let rx = unsafe { TcpSocketBuffer::new(&mut TCP_RX_BUF[listener_id][..]) };
    let tx = unsafe { TcpSocketBuffer::new(&mut TCP_TX_BUF[listener_id][..]) };
    let listener_handle = state.sockets.add(TcpSocket::new(rx, tx));
    set_socket_handle(listener_id, listener_handle);
    set_socket_local_port(listener_id, local_port)?;
    let listener = state.sockets.get_mut::<TcpSocket>(listener_handle);
    listener
        .listen(IpListenEndpoint { addr: None, port: local_port })
        .map_err(|_| NetError::Invalid)?;
    set_socket_listening(id, false)?;
    set_socket_listening(listener_id, true)?;
    NET_NEED_POLL.store(true, Ordering::Release);
    Ok((id, listener_id, remote))
}

pub fn socket_send(id: SocketId, buf: &[u8], addr: Option<(IpAddress, u16)>) -> Result<usize, NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    let sent = match kind {
        AxSocketKind::Tcp => {
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            let tcp_state = socket.state();
            if matches!(tcp_state, TcpState::Listen | TcpState::Closed) {
                return Err(NetError::Invalid);
            }
            if matches!(tcp_state, TcpState::SynSent | TcpState::SynReceived) {
                NET_NEED_POLL.store(true, Ordering::Release);
                return Err(NetError::WouldBlock);
            }
            if !socket.can_send() {
                NET_NEED_POLL.store(true, Ordering::Release);
                return Err(NetError::WouldBlock);
            }
            match socket.send_slice(buf) {
                Ok(0) => return Err(NetError::WouldBlock),
                Ok(size) => size,
                Err(smoltcp::socket::tcp::SendError::InvalidState) => return Err(NetError::Invalid),
            }
        }
        AxSocketKind::Udp => {
            let socket = state.sockets.get_mut::<UdpSocket>(handle);
            let Some((addr, port)) = addr else {
                return Err(NetError::Invalid);
            };
            match socket.send_slice(buf, IpEndpoint::new(addr, port)) {
                Ok(()) => {}
                Err(smoltcp::socket::udp::SendError::BufferFull) => return Err(NetError::WouldBlock),
                Err(smoltcp::socket::udp::SendError::Unaddressable) => return Err(NetError::Invalid),
            }
            buf.len()
        }
    };
    NET_NEED_POLL.store(true, Ordering::Release);
    Ok(sent)
}

pub fn socket_recv(
    id: SocketId,
    buf: &mut [u8],
) -> Result<(usize, Option<(IpAddress, u16)>), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            let tcp_state = socket.state();
            if matches!(tcp_state, TcpState::Listen | TcpState::Closed) {
                return Err(NetError::Invalid);
            }
            if matches!(tcp_state, TcpState::SynSent | TcpState::SynReceived) {
                NET_NEED_POLL.store(true, Ordering::Release);
                return Err(NetError::WouldBlock);
            }
            let size = match socket.recv_slice(buf) {
                Ok(0) => return Err(NetError::WouldBlock),
                Ok(size) => size,
                Err(smoltcp::socket::tcp::RecvError::Finished) => return Ok((0, None)),
                Err(smoltcp::socket::tcp::RecvError::InvalidState) => return Err(NetError::Invalid),
            };
            Ok((size, None))
        }
        AxSocketKind::Udp => {
            let socket = state.sockets.get_mut::<UdpSocket>(handle);
            let (size, endpoint) = match socket.recv_slice(buf) {
                Ok((size, endpoint)) => {
                    if size == 0 {
                        return Err(NetError::WouldBlock);
                    }
                    (size, endpoint)
                }
                Err(smoltcp::socket::udp::RecvError::Exhausted) => return Err(NetError::WouldBlock),
            };
            Ok((size, Some((endpoint.endpoint.addr, endpoint.endpoint.port))))
        }
    }
}

pub fn socket_poll(id: SocketId, events: u16) -> Result<u16, NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    let mut revents = 0u16;
    match kind {
        AxSocketKind::Tcp => {
            let listening = socket_is_listening(id)?;
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            let tcp_state = socket.state();
            if matches!(tcp_state, TcpState::SynSent | TcpState::SynReceived) {
                NET_NEED_POLL.store(true, Ordering::Release);
            }
            if matches!(tcp_state, TcpState::Established | TcpState::CloseWait) {
                let _ = set_socket_connecting(id, false);
                let _ = set_socket_error(id, None);
            }
            if (events & NET_POLLIN) != 0 {
                if listening {
                    // 监听 socket 就绪：连接完成后转为 Established/CloseWait。
                    if matches!(tcp_state, TcpState::Established | TcpState::CloseWait) {
                        revents |= NET_POLLIN;
                    }
                } else {
                    if socket.can_recv() {
                        revents |= NET_POLLIN;
                    } else if tcp_state == TcpState::CloseWait {
                        revents |= NET_POLLIN | NET_POLLHUP;
                    }
                }
            }
            if (events & NET_POLLOUT) != 0 {
                if !listening && tcp_state == TcpState::Established && socket.can_send() {
                    revents |= NET_POLLOUT;
                }
            }
            if tcp_state == TcpState::Closed {
                if socket_connecting(id)? {
                    let _ = set_socket_connecting(id, false);
                    let _ = set_socket_error(id, Some(NetError::ConnRefused));
                }
                revents |= NET_POLLHUP;
            }
        }
        AxSocketKind::Udp => {
            let socket = state.sockets.get_mut::<UdpSocket>(handle);
            if (events & NET_POLLIN) != 0 && socket.can_recv() {
                revents |= NET_POLLIN;
            }
            if (events & NET_POLLOUT) != 0 && socket.can_send() {
                revents |= NET_POLLOUT;
            }
        }
    }
    Ok(revents)
}

pub fn socket_close(id: SocketId) -> Result<(), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    let _ = state.sockets.remove(handle);
    release_socket_slot(id);
    NET_NEED_POLL.store(true, Ordering::Release);
    match kind {
        AxSocketKind::Tcp | AxSocketKind::Udp => Ok(()),
    }
}

pub fn socket_shutdown(id: SocketId, how: usize) -> Result<(), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            match how {
                0 | 1 | 2 => {
                    socket.close();
                    NET_NEED_POLL.store(true, Ordering::Release);
                    Ok(())
                }
                _ => Err(NetError::Invalid),
            }
        }
        AxSocketKind::Udp => match how {
            0 | 1 | 2 => Ok(()),
            _ => Err(NetError::Invalid),
        },
    }
}

pub fn socket_local_endpoint(id: SocketId) -> Result<(IpAddress, u16), NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            let port = socket_local_port(id)?;
            let ip = IpAddress::Ipv4(local_ipv4());
            Ok((ip, port))
        }
        AxSocketKind::Udp => {
            let socket = state.sockets.get_mut::<UdpSocket>(handle);
            let endpoint = socket.endpoint();
            let ip = endpoint.addr.unwrap_or(IpAddress::Ipv4(Ipv4Address::UNSPECIFIED));
            Ok((ip, endpoint.port))
        }
    }
}

pub fn socket_remote_endpoint(id: SocketId) -> Result<Option<(IpAddress, u16)>, NetError> {
    let state = unsafe { NET_STATE.as_mut() }.ok_or(NetError::NotReady)?;
    let (kind, handle) = socket_handle(id).ok_or(NetError::Invalid)?;
    match kind {
        AxSocketKind::Tcp => {
            let socket = state.sockets.get_mut::<TcpSocket>(handle);
            let tcp_state = socket.state();
            if !matches!(tcp_state, TcpState::Established | TcpState::CloseWait) {
                return Ok(None);
            }
            Ok(socket.remote_endpoint().map(|ep| (ep.addr, ep.port)))
        }
        AxSocketKind::Udp => Ok(None),
    }
}

pub fn socket_connecting(id: SocketId) -> Result<bool, NetError> {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        let slot = SOCKET_TABLE.get(id).ok_or(NetError::Invalid)?;
        if !slot.used {
            return Err(NetError::Invalid);
        }
        Ok(slot.connecting)
    }
}

pub fn socket_take_error(id: SocketId) -> Result<Option<NetError>, NetError> {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        let slot = SOCKET_TABLE.get_mut(id).ok_or(NetError::Invalid)?;
        if !slot.used {
            return Err(NetError::Invalid);
        }
        let err = slot.last_error.take();
        Ok(err)
    }
}

fn reserve_socket_slot(kind: AxSocketKind) -> Option<SocketId> {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        for (idx, slot) in SOCKET_TABLE.iter_mut().enumerate() {
            if !slot.used {
                slot.used = true;
                slot.kind = kind;
                slot.local_port = 0;
                slot.listening = false;
                slot.connecting = false;
                slot.last_error = None;
                return Some(idx);
            }
        }
    }
    None
}

fn set_socket_handle(id: SocketId, handle: SocketHandle) {
    // SAFETY: socket slot is reserved and unique for this id.
    unsafe {
        if let Some(slot) = SOCKET_TABLE.get_mut(id) {
            slot.handle.write(handle);
        }
    }
}

fn set_socket_local_port(id: SocketId, port: u16) -> Result<(), NetError> {
    unsafe {
        let Some(slot) = SOCKET_TABLE.get_mut(id) else {
            return Err(NetError::Invalid);
        };
        if !slot.used {
            return Err(NetError::Invalid);
        }
        slot.local_port = port;
        Ok(())
    }
}

fn set_socket_listening(id: SocketId, listening: bool) -> Result<(), NetError> {
    unsafe {
        let Some(slot) = SOCKET_TABLE.get_mut(id) else {
            return Err(NetError::Invalid);
        };
        if !slot.used {
            return Err(NetError::Invalid);
        }
        slot.listening = listening;
        Ok(())
    }
}

fn socket_is_listening(id: SocketId) -> Result<bool, NetError> {
    unsafe {
        let Some(slot) = SOCKET_TABLE.get(id) else {
            return Err(NetError::Invalid);
        };
        if !slot.used {
            return Err(NetError::Invalid);
        }
        Ok(slot.listening)
    }
}

fn socket_local_port(id: SocketId) -> Result<u16, NetError> {
    unsafe {
        let Some(slot) = SOCKET_TABLE.get(id) else {
            return Err(NetError::Invalid);
        };
        if !slot.used {
            return Err(NetError::Invalid);
        }
        if slot.local_port != 0 {
            return Ok(slot.local_port);
        }
    }
    let port = NEXT_EPHEMERAL_PORT.fetch_add(1, Ordering::Relaxed);
    let _ = set_socket_local_port(id, port);
    Ok(port)
}

fn socket_handle(id: SocketId) -> Option<(AxSocketKind, SocketHandle)> {
    // SAFETY: SocketHandle is a plain index and can be copied by value.
    unsafe {
        let slot = SOCKET_TABLE.get(id)?;
        if !slot.used {
            return None;
        }
        let handle = ptr::read(slot.handle.as_ptr());
        Some((slot.kind, handle))
    }
}

fn release_socket_slot(id: SocketId) {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        if let Some(slot) = SOCKET_TABLE.get_mut(id) {
            slot.used = false;
            slot.local_port = 0;
            slot.listening = false;
            slot.connecting = false;
            slot.last_error = None;
        }
    }
}

fn set_socket_connecting(id: SocketId, connecting: bool) -> Result<(), NetError> {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        let slot = SOCKET_TABLE.get_mut(id).ok_or(NetError::Invalid)?;
        if !slot.used {
            return Err(NetError::Invalid);
        }
        slot.connecting = connecting;
    }
    Ok(())
}

fn set_socket_error(id: SocketId, err: Option<NetError>) -> Result<(), NetError> {
    // SAFETY: single-hart early stage, socket table is serialized.
    unsafe {
        let slot = SOCKET_TABLE.get_mut(id).ok_or(NetError::Invalid)?;
        if !slot.used {
            return Err(NetError::Invalid);
        }
        slot.last_error = err;
    }
    Ok(())
}

static mut SOCKET_STORAGE: [SocketStorage<'static>; SOCKET_STORAGE_LEN] =
    [SocketStorage::EMPTY; SOCKET_STORAGE_LEN];

fn should_loopback(frame: &[u8]) -> bool {
    const ETH_HDR_LEN: usize = 14;
    const ETH_TYPE_IPV4: u16 = 0x0800;
    if frame.len() < ETH_HDR_LEN + 20 {
        return false;
    }
    let eth_type = u16::from_be_bytes([frame[12], frame[13]]);
    if eth_type != ETH_TYPE_IPV4 {
        return false;
    }
    let ip = &frame[ETH_HDR_LEN..];
    let dst = [ip[16], ip[17], ip[18], ip[19]];
    dst == NET_IPV4_ADDR
}

fn try_loopback_arp(frame: &[u8], mac: EthernetAddress) -> bool {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return false;
    };
    if eth.ethertype() != EthernetProtocol::Arp {
        return false;
    }
    let Ok(arp_pkt) = ArpPacket::new_checked(eth.payload()) else {
        return false;
    };
    let Ok(repr) = ArpRepr::parse(&arp_pkt) else {
        return false;
    };
    let ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr,
        source_protocol_addr,
        target_protocol_addr,
        ..
    } = repr
    else {
        return false;
    };
    if target_protocol_addr != local_ipv4() {
        return false;
    }
    let reply = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_hardware_addr: mac,
        source_protocol_addr: local_ipv4(),
        target_hardware_addr: source_hardware_addr,
        target_protocol_addr: source_protocol_addr,
    };
    // SAFETY: single-hart; buffer reused for loopback replies.
    let buf = unsafe { &mut ARP_TX_BUF[..] };
    {
        let mut eth = EthernetFrame::new_unchecked(&mut buf[..]);
        eth.set_dst_addr(source_hardware_addr);
        eth.set_src_addr(mac);
        eth.set_ethertype(EthernetProtocol::Arp);
        let mut arp = ArpPacket::new_unchecked(eth.payload_mut());
        reply.emit(&mut arp);
    }
    unsafe {
        LOOPBACK_QUEUE.push(&buf[..ARP_FRAME_LEN]);
    }
    NET_NEED_POLL.store(true, Ordering::Release);
    true
}

fn local_ipv4() -> Ipv4Address {
    Ipv4Address::new(
        NET_IPV4_ADDR[0],
        NET_IPV4_ADDR[1],
        NET_IPV4_ADDR[2],
        NET_IPV4_ADDR[3],
    )
}

fn gateway_ipv4() -> Ipv4Address {
    Ipv4Address::new(
        NET_IPV4_GATEWAY[0],
        NET_IPV4_GATEWAY[1],
        NET_IPV4_GATEWAY[2],
        NET_IPV4_GATEWAY[3],
    )
}

fn ipv4_to_u32(addr: Ipv4Address) -> u32 {
    u32::from_be_bytes(addr.0)
}

fn take_arp_reply() -> Option<Ipv4Address> {
    let ip = NET_ARP_REPLY_IP.swap(0, Ordering::AcqRel);
    if ip == 0 {
        return None;
    }
    Some(Ipv4Address::from_bytes(&ip.to_be_bytes()))
}

fn take_arp_sent() -> Option<Ipv4Address> {
    let ip = NET_ARP_SENT_IP.swap(0, Ordering::AcqRel);
    if ip == 0 {
        return None;
    }
    Some(Ipv4Address::from_bytes(&ip.to_be_bytes()))
}

fn take_rx_seen() -> bool {
    NET_RX_SEEN.swap(false, Ordering::AcqRel)
}

fn record_arp_reply(frame: &[u8]) {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return;
    };
    if eth.ethertype() != EthernetProtocol::Arp {
        return;
    }
    let Ok(arp_pkt) = ArpPacket::new_checked(eth.payload()) else {
        return;
    };
    let Ok(repr) = ArpRepr::parse(&arp_pkt) else {
        return;
    };
    let ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Reply,
        source_protocol_addr,
        target_protocol_addr,
        ..
    } = repr
    else {
        return;
    };
    if target_protocol_addr != local_ipv4() {
        return;
    }
    if source_protocol_addr != gateway_ipv4() {
        return;
    }
    let _ = NET_ARP_REPLY_IP.compare_exchange(
        0,
        ipv4_to_u32(source_protocol_addr),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}

fn send_arp_probe(state: &mut NetState) {
    let src_mac = EthernetAddress(state.device.dev.mac_address());
    let src_ip = local_ipv4();
    let target_ip = gateway_ipv4();
    let arp = ArpRepr::EthernetIpv4 {
        operation: ArpOperation::Request,
        source_hardware_addr: src_mac,
        source_protocol_addr: src_ip,
        target_hardware_addr: EthernetAddress([0; 6]),
        target_protocol_addr: target_ip,
    };
    let eth = smoltcp::wire::EthernetRepr {
        src_addr: src_mac,
        dst_addr: EthernetAddress::BROADCAST,
        ethertype: EthernetProtocol::Arp,
    };
    let frame_len = eth.buffer_len() + arp.buffer_len();
    let total_len = core::cmp::max(frame_len, 60);
    // SAFETY: single-hart early use; ARP probe is one-shot and reuses a static buffer.
    let buf = unsafe { &mut ARP_TX_BUF[..total_len] };
    buf.fill(0);
    {
        let mut frame = EthernetFrame::new_unchecked(&mut buf[..frame_len]);
        eth.emit(&mut frame);
        let mut pkt = ArpPacket::new_unchecked(frame.payload_mut());
        arp.emit(&mut pkt);
    }
    let _ = state.device.dev.send(buf);
    let _ = NET_ARP_SENT_IP.compare_exchange(
        0,
        ipv4_to_u32(target_ip),
        Ordering::AcqRel,
        Ordering::Acquire,
    );
}
