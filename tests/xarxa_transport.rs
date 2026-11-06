//! Owned packet handoff through public xarxa and Embassy driver/socket APIs.
#![cfg(any(feature = "xarxa", feature = "embassy-net-xarxa"))]
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use mai_coap::transport::{
    DatagramReceiver, DatagramSender, OwnedDatagramSender, ReceivedPacket, SendOutcome,
    xarxa::XarxaError,
};
#[cfg(feature = "xarxa")]
use std::cell::Cell;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use xarxa::{
    Pool, StaticPool,
    driver::{
        Capabilities, ChecksumCapabilities, Driver, HardwareAddress, Medium, NotSupported,
        PacketBuf,
    },
    iface::IfaceHandle,
    wire::IpCidr,
};

trait Attempt: DatagramSender {
    async fn send(
        &mut self,
        r: SocketAddr,
        s: Option<IpAddr>,
        i: Option<u32>,
        bytes: &[u8],
    ) -> Result<SendOutcome, Self::Error> {
        core::future::poll_fn(|cx| self.poll_send(r, s, i, bytes, cx)).await
    }
    async fn send_owned<B>(
        &mut self,
        r: SocketAddr,
        s: Option<IpAddr>,
        i: Option<u32>,
        packet: &mut Option<B>,
    ) -> Result<SendOutcome, Self::Error>
    where
        Self: OwnedDatagramSender<B>,
    {
        core::future::poll_fn(|cx| self.poll_send_owned(r, s, i, packet, cx)).await
    }
}
impl<T: DatagramSender> Attempt for T {}

#[derive(Default)]
struct Link {
    rx: VecDeque<PacketBuf>,
    tx: VecDeque<PacketBuf>,
    blocked: bool,
    waker: Option<Waker>,
}
struct Device(Rc<RefCell<Link>>);
impl Driver for Device {
    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps.checksum = ChecksumCapabilities::all_offloaded();
        caps
    }
    fn hardware_address(&self) -> HardwareAddress {
        HardwareAddress::Ip
    }
    fn register_waker(&mut self, waker: &Waker) -> Result<(), NotSupported> {
        self.0.borrow_mut().waker = Some(waker.clone());
        Ok(())
    }
    fn rx_wanted(&mut self) -> usize {
        0
    }
    fn rx_give(&mut self, _: PacketBuf) {
        panic!("test driver never requests empty buffers");
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        self.0.borrow_mut().rx.pop_front()
    }
    fn can_transmit(&mut self) -> bool {
        !self.0.borrow().blocked
    }
    fn transmit(&mut self, packet: PacketBuf) -> Result<(), PacketBuf> {
        let mut link = self.0.borrow_mut();
        if link.blocked {
            Err(packet)
        } else {
            link.tx.push_back(packet);
            Ok(())
        }
    }
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: F) -> F::Output {
    match poll(core::pin::pin!(future)) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("unexpected pending operation"),
    }
}
fn addresses(ipv6: bool) -> (IpAddr, IpAddr, u8) {
    if ipv6 {
        ("fe80::1".parse().unwrap(), "fe80::2".parse().unwrap(), 64)
    } else {
        (
            "192.0.2.1".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            24,
        )
    }
}
fn remote(ipv6: bool) -> SocketAddr {
    let mut remote = SocketAddr::new(addresses(ipv6).0, 5683);
    if let SocketAddr::V6(address) = &mut remote {
        address.set_scope_id(7);
    }
    remote
}
fn wire_ip(ip: IpAddr) -> xarxa::wire::IpAddr {
    match ip {
        #[cfg(any(feature = "xarxa-ipv4", feature = "embassy-net-xarxa-ipv4"))]
        IpAddr::V4(ip) => ip.into(),
        #[cfg(any(feature = "xarxa-ipv6", feature = "embassy-net-xarxa-ipv6"))]
        IpAddr::V6(ip) => ip.into(),
        #[allow(unreachable_patterns)]
        _ => panic!("disabled address family"),
    }
}
fn incoming(
    pool: &'static StaticPool<1536, 8>,
    bytes: &[u8],
    ipv6: bool,
) -> (PacketBuf, *const u8) {
    let (source, local, _) = addresses(ipv6);
    let header = if source.is_ipv4() { 20 } else { 40 };
    let mut packet = pool.alloc().unwrap();
    packet.set_len(header + 8 + bytes.len());
    packet.fill(0);
    match (source, local) {
        (IpAddr::V4(source), IpAddr::V4(local)) => {
            let length = packet.len() as u16;
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&length.to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&local.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(local)) => {
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
            packet[6] = 17;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source.octets());
            packet[24..40].copy_from_slice(&local.octets());
        }
        _ => unreachable!(),
    }
    packet[header..header + 2].copy_from_slice(&5683u16.to_be_bytes());
    packet[header + 2..header + 4].copy_from_slice(&5683u16.to_be_bytes());
    packet[header + 4..header + 6].copy_from_slice(&((8 + bytes.len()) as u16).to_be_bytes());
    packet[header + 6..header + 8].copy_from_slice(&0xffffu16.to_be_bytes());
    packet[header + 8..].copy_from_slice(bytes);
    let payload = packet[header + 8..].as_ptr();
    (packet, payload)
}
fn assert_tx_source(frame: &[u8], expected: IpAddr) {
    match expected {
        IpAddr::V4(ip) => assert_eq!(&frame[12..16], &ip.octets()),
        IpAddr::V6(ip) => assert_eq!(&frame[8..24], &ip.octets()),
    }
}
fn buffer(pool: &'static impl Pool) -> PacketBuf {
    let mut packet = pool.alloc().unwrap();
    packet.reserve(128);
    packet.set_len(5);
    packet.copy_from_slice(b"reply");
    packet
}
fn assert_packet(packet: &impl ReceivedPacket, identity: *const u8, bytes: &[u8], ipv6: bool) {
    assert_eq!(packet.bytes().as_ptr(), identity);
    assert_eq!(packet.bytes(), bytes);
    assert_eq!(packet.metadata().remote, remote(ipv6));
    assert_eq!(packet.metadata().local, addresses(ipv6).1);
    assert_eq!(packet.metadata().interface, Some(7));
    assert_eq!(packet.metadata().original_len, bytes.len());
}

#[cfg(feature = "xarxa")]
mod native {
    use super::*;
    fn addresses() -> (IpAddr, IpAddr, u8) {
        super::addresses(cfg!(feature = "xarxa-ipv6"))
    }
    fn remote() -> SocketAddr {
        super::remote(cfg!(feature = "xarxa-ipv6"))
    }
    fn incoming(pool: &'static StaticPool<1536, 8>, bytes: &[u8]) -> (PacketBuf, *const u8) {
        super::incoming(pool, bytes, cfg!(feature = "xarxa-ipv6"))
    }
    fn assert_packet(packet: &impl ReceivedPacket, identity: *const u8, bytes: &[u8]) {
        super::assert_packet(packet, identity, bytes, cfg!(feature = "xarxa-ipv6"))
    }

    use mai_coap::transport::xarxa::{StackAccess, XarxaTransport};
    #[derive(Clone)]
    struct Access {
        stack: Rc<RefCell<xarxa::Stack<'static>>>,
        wakes: Rc<Cell<usize>>,
    }
    impl StackAccess<'static> for Access {
        fn with_stack<R>(&self, operation: impl FnOnce(&mut xarxa::Stack<'static>) -> R) -> R {
            operation(&mut self.stack.borrow_mut())
        }
        fn wake_runner(&self) {
            self.wakes.set(self.wakes.get() + 1);
        }
    }
    struct Fixture {
        pool: &'static StaticPool<1536, 8>,
        link: Rc<RefCell<Link>>,
        access: Access,
        iface: IfaceHandle,
        handle: xarxa::udp::UdpHandle,
    }
    impl Fixture {
        fn new() -> Self {
            let pool = Box::leak(Box::new(StaticPool::new()));
            let link = Rc::new(RefCell::new(Link::default()));
            let driver = Box::leak(Box::new(Device(link.clone())));
            let mut stack = xarxa::Stack::new(pool, 1);
            let iface = stack.add_iface_borrowed(driver).unwrap();
            for (ipv6, enabled) in [
                (false, cfg!(feature = "xarxa-ipv4")),
                (true, cfg!(feature = "xarxa-ipv6")),
            ] {
                if enabled {
                    let (_, local, prefix) = super::addresses(ipv6);
                    stack
                        .iface(iface)
                        .add_ip_addr(IpCidr::new(wire_ip(local), prefix))
                        .unwrap();
                }
            }
            let handle = stack.add_udp_socket().unwrap();
            stack.udp_socket(handle).bind_to_iface(Some(iface)).unwrap();
            stack.udp_socket(handle).bind(5683, 0).unwrap();
            let access = Access {
                stack: Rc::new(RefCell::new(stack)),
                wakes: Rc::new(Cell::new(0)),
            };
            Self {
                pool,
                link,
                access,
                iface,
                handle,
            }
        }
        fn transport(&self) -> XarxaTransport<'static, Access> {
            XarxaTransport::new(self.access.clone(), self.handle, self.iface, 7).unwrap()
        }
        fn tick(&self) {
            self.access.with_stack(|stack| {
                stack.poll(xarxa::time::Instant::from_millis(0));
            });
        }
    }
    #[test]
    fn tr_7_native_receive_retains_identity_metadata_and_cancellation() {
        let fixture = Fixture::new();
        let transport = fixture.transport();
        let mut transport = &transport;
        let mut scratch = [];
        let mut pending = Box::pin(transport.receive(&mut scratch));
        assert!(poll(pending.as_mut()).is_pending());
        drop(pending);
        let bytes = vec![0x42; 1153];
        let (packet, identity) = incoming(fixture.pool, &bytes);
        fixture.link.borrow_mut().rx.push_back(packet);
        fixture.tick();
        let packet = ready(transport.receive(&mut scratch)).unwrap();
        assert_packet(&packet, identity, &bytes);
        let wakes = fixture.access.wakes.get();
        drop(packet);
        assert!(fixture.access.wakes.get() > wakes);
        let mut reclaimed = Vec::new();
        while let Some(packet) = fixture.pool.alloc() {
            reclaimed.push(packet);
        }
        assert_eq!(reclaimed.len(), 8);
        assert_eq!(
            core::mem::size_of_val(&<&XarxaTransport<'static, Access>>::receive_buffer::<1152>()),
            0
        );
    }
    #[test]
    fn tr_7_native_owned_send_retains_buffer_on_error_and_transfers_identity() {
        let fixture = Fixture::new();
        let transport = fixture.transport();
        let mut transport = &transport;
        let mut packet = Some(buffer(fixture.pool));
        let identity = packet.as_ref().unwrap().as_ptr();
        assert_eq!(
            ready(transport.send_owned(remote(), None, Some(8), &mut packet)),
            Err(XarxaError::InterfaceMismatch)
        );
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        fixture.link.borrow_mut().blocked = true;
        let mut send = Box::pin(transport.send_owned(remote(), None, Some(7), &mut packet));
        assert!(poll(send.as_mut()).is_pending());
        drop(send);
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        fixture.link.borrow_mut().blocked = false;
        fixture.tick();
        ready(transport.send_owned(remote(), Some(addresses().1), Some(7), &mut packet)).unwrap();
        assert!(packet.is_none());
        let frame = fixture.link.borrow_mut().tx.pop_back().unwrap();
        assert_eq!(frame[frame.len() - 5..].as_ptr(), identity);
        assert_eq!(&frame[frame.len() - 5..], b"reply");
        assert_tx_source(&frame, addresses().1);
    }
    #[test]
    fn tr_7_native_one_buffer_cache_cannot_deadlock_copy_send() {
        let pool = Box::leak(Box::new(StaticPool::<1536, 1>::new()));
        let driver = Box::leak(Box::new(Device(Rc::new(RefCell::new(Link::default())))));
        let mut stack = xarxa::Stack::new(pool, 1);
        let iface = stack.add_iface_borrowed(driver).unwrap();
        stack
            .iface(iface)
            .add_ip_addr(IpCidr::new(wire_ip(addresses().1), addresses().2))
            .unwrap();
        let handle = stack.add_udp_socket().unwrap();
        stack.udp_socket(handle).bind_to_iface(Some(iface)).unwrap();
        stack.udp_socket(handle).bind(5683, 0).unwrap();
        let access = Access {
            stack: Rc::new(RefCell::new(stack)),
            wakes: Rc::new(Cell::new(0)),
        };
        let transport = XarxaTransport::new(access, handle, iface, 7).unwrap();
        let mut transport = &transport;
        let retained = buffer(pool);
        let identity = retained.as_ptr();
        assert_eq!(
            ready(transport.send(remote(), None, None, &retained)),
            Ok(SendOutcome::RetryLater)
        );
        assert_eq!(retained.as_ptr(), identity);
        assert_eq!(retained.as_ref(), b"reply");
    }

    #[test]
    fn tr_5_native_permanent_errors_preserve_owned_bytes() {
        let fixture = Fixture::new();
        let transport = fixture.transport();
        let mut transport = &transport;
        let mut packet = Some(buffer(fixture.pool));
        let identity = packet.as_ref().unwrap().as_ptr();
        let mut unavailable = remote();
        unavailable.set_port(0);
        assert_eq!(
            ready(transport.send_owned(unavailable, None, None, &mut packet)),
            Err(XarxaError::Unaddressable)
        );
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        fixture
            .access
            .with_stack(|stack| stack.udp_socket(fixture.handle).close());
        assert_eq!(
            ready(transport.send_owned(remote(), None, None, &mut packet)),
            Err(XarxaError::InvalidState)
        );
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        assert!(!<&XarxaTransport<'static, Access>>::discard_send_error(
            &XarxaError::InvalidState
        ));
    }
    #[test]
    fn tr_6_native_family_selection_is_independent_of_embassy() {
        let fixture = Fixture::new();
        let transport = fixture.transport();
        let mut transport = &transport;
        for (family, enabled) in [
            (false, cfg!(feature = "xarxa-ipv4")),
            (true, cfg!(feature = "xarxa-ipv6")),
        ] {
            let result = ready(transport.send(super::remote(family), None, None, b"reply"));
            if enabled {
                assert_eq!(result, Ok(SendOutcome::Accepted));
            } else {
                assert_eq!(result, Err(XarxaError::UnsupportedAddressFamily));
            }
            let mut packet = Some(buffer(fixture.pool));
            let identity = packet.as_ref().unwrap().as_ptr();
            let result =
                ready(transport.send_owned(super::remote(family), None, None, &mut packet));
            if enabled {
                assert_eq!(result, Ok(SendOutcome::Accepted));
            } else {
                assert_eq!(result, Err(XarxaError::UnsupportedAddressFamily));
                assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
                assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
            }
        }
    }

    #[test]
    fn tr_7_native_buffer_exhaustion_returns_to_driver() {
        let fixture = Fixture::new();
        let transport = fixture.transport();
        let mut transport = &transport;
        let mut retained = Vec::new();
        while let Some(packet) = fixture.pool.alloc() {
            retained.push(packet);
        }
        let mut send = Box::pin(transport.send(remote(), None, None, b"reply"));
        assert_eq!(
            poll(send.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(send);
        assert!(fixture.link.borrow().tx.is_empty());
        drop(retained);
        ready(transport.send(remote(), None, None, b"reply")).unwrap();
    }
}

#[cfg(feature = "embassy-net-xarxa")]
mod embassy {
    use super::*;
    fn addresses() -> (IpAddr, IpAddr, u8) {
        super::addresses(cfg!(feature = "embassy-net-xarxa-ipv6"))
    }
    fn remote() -> SocketAddr {
        super::remote(cfg!(feature = "embassy-net-xarxa-ipv6"))
    }
    fn incoming(pool: &'static StaticPool<1536, 8>, bytes: &[u8]) -> (PacketBuf, *const u8) {
        super::incoming(pool, bytes, cfg!(feature = "embassy-net-xarxa-ipv6"))
    }
    fn assert_packet(packet: &impl ReceivedPacket, identity: *const u8, bytes: &[u8]) {
        super::assert_packet(
            packet,
            identity,
            bytes,
            cfg!(feature = "embassy-net-xarxa-ipv6"),
        )
    }

    use mai_coap::transport::embassy_xarxa::EmbassyXarxaTransport;
    fn setup<const COUNT: usize>() -> (
        embassy_net_xarxa::Stack<'static>,
        embassy_net_xarxa::Runner<'static>,
        &'static StaticPool<1536, COUNT>,
        Rc<RefCell<Link>>,
        IfaceHandle,
    ) {
        let pool = Box::leak(Box::new(StaticPool::new()));
        let storage = Box::leak(Box::new(embassy_net_xarxa::StackStorage::new()));
        let (stack, runner) = embassy_net_xarxa::Stack::new(storage, pool, 1);
        let link = Rc::new(RefCell::new(Link::default()));
        let driver = Box::leak(Box::new(Device(link.clone())));
        let iface = stack.add_iface_borrowed(driver).unwrap();
        for (ipv6, enabled) in [
            (false, cfg!(feature = "embassy-net-xarxa-ipv4")),
            (true, cfg!(feature = "embassy-net-xarxa-ipv6")),
        ] {
            if enabled {
                let (_, local, prefix) = super::addresses(ipv6);
                iface
                    .add_ip_addr(IpCidr::new(wire_ip(local), prefix))
                    .unwrap();
            }
        }
        (stack, runner, pool, link, iface.handle())
    }
    fn socket(
        stack: embassy_net_xarxa::Stack<'static>,
        iface: IfaceHandle,
    ) -> embassy_net_xarxa::udp::UdpSocket<'static> {
        let mut socket = embassy_net_xarxa::udp::UdpSocket::new(stack).unwrap();
        socket.bind_to_iface(Some(iface)).unwrap();
        socket.bind(5683, 0).unwrap();
        socket
    }
    #[test]
    fn tr_7_embassy_receive_retains_identity_and_large_datagram_length() {
        let (stack, mut runner, pool, link, iface) = setup::<8>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        let mut scratch = [];
        let mut receive = Box::pin(transport.receive(&mut scratch));
        assert!(poll(receive.as_mut()).is_pending());
        drop(receive);
        let bytes = vec![0x42; 1153];
        let (packet, identity) = incoming(pool, &bytes);
        link.borrow_mut().rx.push_back(packet);
        assert!(poll(core::pin::pin!(runner.run())).is_pending());
        let packet = ready(transport.receive(&mut scratch)).unwrap();
        assert_packet(&packet, identity, &bytes);
        drop(packet);
        assert_eq!(
            core::mem::size_of_val(&<&EmbassyXarxaTransport<'_, '_>>::receive_buffer::<1152>()),
            0
        );
    }
    #[test]
    fn tr_7_embassy_owned_send_restores_packet_before_cancel_and_transfers_identity() {
        let (stack, _, pool, link, iface) = setup::<8>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        let mut packet = Some(buffer(pool));
        let identity = packet.as_ref().unwrap().as_ptr();
        assert_eq!(
            ready(transport.send_owned(remote(), None, Some(8), &mut packet)),
            Err(XarxaError::InterfaceMismatch)
        );
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        link.borrow_mut().blocked = true;
        let mut send = Box::pin(transport.send_owned(remote(), None, None, &mut packet));
        assert_eq!(
            poll(send.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(send);
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        let mut retry =
            Box::pin(transport.send_owned(remote(), Some(addresses().1), None, &mut packet));
        assert_eq!(
            poll(retry.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(retry);
        link.borrow_mut().blocked = false;
        let mut retry =
            Box::pin(transport.send_owned(remote(), Some(addresses().1), None, &mut packet));
        assert_eq!(poll(retry.as_mut()), Poll::Ready(Ok(SendOutcome::Accepted)));
        drop(retry);
        assert!(packet.is_none());
        let frame = link.borrow_mut().tx.pop_back().unwrap();
        assert_eq!(frame[frame.len() - 5..].as_ptr(), identity);
        assert_eq!(&frame[frame.len() - 5..], b"reply");
        assert_tx_source(&frame, addresses().1);
    }
    #[test]
    fn tr_6_embassy_family_selection_is_independent_of_native() {
        let (stack, _, pool, _, iface) = setup::<8>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        for (family, enabled) in [
            (false, cfg!(feature = "embassy-net-xarxa-ipv4")),
            (true, cfg!(feature = "embassy-net-xarxa-ipv6")),
        ] {
            let result = ready(transport.send(super::remote(family), None, None, b"reply"));
            if enabled {
                assert_eq!(result, Ok(SendOutcome::Accepted));
            } else {
                assert_eq!(result, Err(XarxaError::UnsupportedAddressFamily));
            }
            let mut packet = Some(buffer(pool));
            let identity = packet.as_ref().unwrap().as_ptr();
            let result =
                ready(transport.send_owned(super::remote(family), None, None, &mut packet));
            if enabled {
                assert_eq!(result, Ok(SendOutcome::Accepted));
            } else {
                assert_eq!(result, Err(XarxaError::UnsupportedAddressFamily));
                assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
                assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
            }
        }
    }

    #[test]
    fn tr_5_embassy_persistent_device_backpressure_returns_to_driver() {
        let (stack, _, pool, link, iface) = setup::<8>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        let mut packet = Some(buffer(pool));
        let identity = packet.as_ref().unwrap().as_ptr();
        link.borrow_mut().blocked = true;
        let mut send = Box::pin(transport.send_owned(remote(), None, None, &mut packet));
        assert_eq!(
            poll(send.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(send);
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        assert!(link.borrow().tx.is_empty());
        drop(packet);

        let mut send = Box::pin(transport.send(remote(), None, None, b"reply"));
        assert_eq!(
            poll(send.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(send);
        let mut reclaimed = Vec::new();
        while let Some(packet) = pool.alloc() {
            reclaimed.push(packet);
        }
        assert_eq!(reclaimed.len(), 8);
    }
    #[test]
    fn tr_5_embassy_permanent_error_restores_packet_and_no_buffer_returns() {
        let (stack, _, pool, link, iface) = setup::<8>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        let mut packet = Some(buffer(pool));
        let identity = packet.as_ref().unwrap().as_ptr();
        let mut unavailable = remote();
        unavailable.set_port(0);
        assert_eq!(
            ready(transport.send_owned(unavailable, None, None, &mut packet)),
            Err(XarxaError::Unaddressable)
        );
        assert_eq!(packet.as_ref().unwrap().as_ptr(), identity);
        assert_eq!(packet.as_ref().unwrap().as_ref(), b"reply");
        drop(packet);
        let mut retained = Vec::new();
        while let Some(packet) = pool.alloc() {
            retained.push(packet);
        }
        let mut send = Box::pin(transport.send(remote(), None, None, b"reply"));
        assert_eq!(
            poll(send.as_mut()),
            Poll::Ready(Ok(SendOutcome::RetryLater))
        );
        drop(send);
        assert!(link.borrow().tx.is_empty());
        drop(retained);
        ready(transport.send(remote(), None, None, b"reply")).unwrap();
    }
    #[test]
    fn tr_7_embassy_one_buffer_cache_cannot_deadlock_copy_send() {
        let (stack, _, pool, _, iface) = setup::<1>();
        let socket = socket(stack, iface);
        let transport = EmbassyXarxaTransport::new(&socket, iface, 7).unwrap();
        let mut transport = &transport;
        let retained = buffer(pool);
        let identity = retained.as_ptr();
        assert_eq!(
            ready(transport.send(remote(), None, None, &retained)),
            Ok(SendOutcome::RetryLater)
        );
        assert_eq!(retained.as_ptr(), identity);
        assert_eq!(retained.as_ref(), b"reply");
    }
}
