//! Real UDP/IP owned-buffer driver workload with deterministic loss and time.
use super::TestRng;
use core::{
    cell::{Cell, RefCell},
    future::Future,
    mem::{MaybeUninit, size_of, size_of_val},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use mai_coap::{
    XarxaStorage,
    codec::{Code, MessageType, MessageView},
    crypto::SoftwareCrypto,
    edhoc::{Identity, TrustedPeer, TrustedPeers, endpoint::Edhoc},
    endpoint::{Disposition, Endpoint, Protection, Request, ResponseWriter, Shared, Unsecured},
    security::{PeerId, Policy, ProtectedOnly, PublicPaths},
    time::{Clock, Instant},
    transport::{
        DatagramSender, OwnedDatagramSender, SendOutcome, Transport,
        xarxa::{StackAccess, XarxaTransport},
    },
};
use xarxa::{
    Pool, Stack, StaticPool,
    driver::{
        Capabilities, ChecksumCapabilities, Driver, HardwareAddress, Medium, NotSupported,
        PacketBuf,
    },
    iface::IfaceHandle,
    udp::UdpHandle,
    wire::IpCidr,
};

const D: usize = 1152;
const BUFFERS: usize = 16;
const BODY: [u8; 1024] = [0x5a; 1024];
type Store = XarxaStorage<fn() -> Option<PacketBuf>, 3>;
const ID_CONTEXT_BYTES: usize = 0;
type Secure = Edhoc<SoftwareCrypto<TestRng>, 1, 1, TrustedPeers<1>, ID_CONTEXT_BYTES>;
type EndpointType<P> = Endpoint<'static, P, D, 1, 4, 1, 2, 2, 1, 1, 1, 3, Store>;
static NETWORK: StaticPool<1536, BUFFERS> = StaticPool::new();
static CLIENT_SHARED: Shared<D, 1> = Shared::new();
static SERVER_SHARED: Shared<D, 1> = Shared::new();
static mut LINK: MaybeUninit<RefCell<Link>> = MaybeUninit::uninit();
static mut DEVICES: [MaybeUninit<Device>; 2] = [const { MaybeUninit::uninit() }; 2];
static mut SIDES: [MaybeUninit<Side>; 2] = [const { MaybeUninit::uninit() }; 2];
static mut SECURE_ENDPOINTS: [MaybeUninit<EndpointType<Secure>>; 2] =
    [const { MaybeUninit::uninit() }; 2];

struct Link {
    packets: [heapless::Deque<PacketBuf, 4>; 2],
    drop_reply: bool,
    saved: [u8; D],
    saved_len: usize,
    retried: bool,
    non_replies: usize,
}
impl Link {
    fn new() -> Self {
        Self {
            packets: [const { heapless::Deque::new() }; 2],
            drop_reply: false,
            saved: [0; D],
            saved_len: 0,
            retried: false,
            non_replies: 0,
        }
    }
}
struct Device {
    link: &'static RefCell<Link>,
    side: usize,
}
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
    fn register_waker(&mut self, _: &Waker) -> Result<(), NotSupported> {
        Ok(())
    }
    fn rx_wanted(&mut self) -> usize {
        0
    }
    fn rx_give(&mut self, _: PacketBuf) {
        panic!("driver never requests empty buffers")
    }
    fn receive(&mut self) -> Option<PacketBuf> {
        self.link.borrow_mut().packets[self.side].pop_front()
    }
    fn can_transmit(&mut self) -> bool {
        !self.link.borrow().packets[1 - self.side].is_full()
    }
    fn transmit(&mut self, packet: PacketBuf) -> Result<(), PacketBuf> {
        let mut link = self.link.borrow_mut();
        if self.side == 1 {
            let payload = packet.get(28..).expect("IPv4 UDP datagram");
            let view = MessageView::parse(payload).unwrap();
            if view.message_type() == MessageType::NonConfirmable {
                link.non_replies += 1;
            }
            if link.drop_reply {
                assert!(view.message_type() == MessageType::Acknowledgement);
                link.saved[..payload.len()].copy_from_slice(payload);
                link.saved_len = payload.len();
                link.drop_reply = false;
                return Ok(());
            }
            if link.saved_len != 0 && !link.retried {
                assert_eq!(payload, &link.saved[..link.saved_len]);
                link.retried = true;
            }
        }
        link.packets[1 - self.side].push_back(packet)
    }
}
struct Side {
    stack: RefCell<Stack<'static>>,
    iface: IfaceHandle,
    socket: UdpHandle,
}
#[derive(Clone, Copy)]
struct Access(&'static Side);
impl StackAccess<'static> for Access {
    fn with_stack<R>(&self, operation: impl FnOnce(&mut Stack<'static>) -> R) -> R {
        operation(&mut self.0.stack.borrow_mut())
    }
    fn wake_runner(&self) { /* The deterministic executor polls both runners every turn. */
    }
}
fn side(index: usize) -> &'static Side {
    // SAFETY: run initializes the static slots before any allocator or driver runs.
    unsafe { (&*((&raw const SIDES).cast::<MaybeUninit<Side>>().add(index))).assume_init_ref() }
}
fn allocate(index: usize) -> Option<PacketBuf> {
    let side = side(index);
    side.stack.borrow_mut().udp_socket(side.socket).alloc()
}
fn allocate_client() -> Option<PacketBuf> {
    allocate(0)
}
fn allocate_server() -> Option<PacketBuf> {
    allocate(1)
}
#[derive(Clone, Copy)]
struct Timer<'a>(&'a Cell<u64>);
impl Clock for Timer<'_> {
    fn now(&self) -> Instant {
        Instant(self.0.get())
    }
    async fn sleep_until(&self, deadline: Instant) {
        core::future::poll_fn(|_| {
            if self.0.get() >= deadline.0 {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
struct Socket<T> {
    inner: T,
    owned: Cell<usize>,
    copied: Cell<usize>,
}
struct SocketSender<'a, T> {
    inner: T,
    owned: &'a Cell<usize>,
    copied: &'a Cell<usize>,
}
impl<T: Transport> Transport for Socket<T> {
    type Error = T::Error;
    type Receiver<'a>
        = T::Receiver<'a>
    where
        Self: 'a;
    type Sender<'a>
        = SocketSender<'a, T::Sender<'a>>
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
        let (r, t) = self.inner.split();
        (
            r,
            SocketSender {
                inner: t,
                owned: &self.owned,
                copied: &self.copied,
            },
        )
    }
}
impl<T: DatagramSender> DatagramSender for SocketSender<'_, T> {
    type Error = T::Error;
    fn discard_send_error(e: &Self::Error) -> bool {
        T::discard_send_error(e)
    }
    fn poll_send(
        &mut self,
        r: core::net::SocketAddr,
        s: Option<core::net::IpAddr>,
        i: Option<u32>,
        bytes: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        let result = self.inner.poll_send(r, s, i, bytes, cx);
        if matches!(result, Poll::Ready(Ok(SendOutcome::Accepted))) {
            self.copied.set(self.copied.get() + 1);
        }
        result
    }
}
impl<T: OwnedDatagramSender<PacketBuf>> OwnedDatagramSender<PacketBuf> for SocketSender<'_, T> {
    fn poll_send_owned(
        &mut self,
        r: core::net::SocketAddr,
        s: Option<core::net::IpAddr>,
        i: Option<u32>,
        packet: &mut Option<PacketBuf>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        let result = self.inner.poll_send_owned(r, s, i, packet, cx);
        if matches!(result, Poll::Ready(Ok(SendOutcome::Accepted))) {
            assert!(packet.is_none());
            self.owned.set(self.owned.get() + 1);
        }
        result
    }
}
unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
}
const PAINT: u32 = 0xcccc_cccc;
#[inline(never)]
fn begin() {
    let low = &raw const _stack_end as usize;
    let sp = cortex_m::register::msp::read() as usize;
    assert!(sp > low + 256);
    for address in (low..sp).step_by(4) {
        // SAFETY: this single-threaded fixture paints only unused linker-bounded stack.
        unsafe { (address as *mut u32).write_volatile(PAINT) };
    }
}
#[inline(never)]
fn peak() -> (usize, usize) {
    let low = &raw const _stack_end as usize;
    let top = &raw const _stack_start as usize;
    let mut first = low;
    while first < top {
        // SAFETY: each aligned address lies within the linker-defined stack.
        if unsafe { (first as *const u32).read_volatile() } != PAINT {
            break;
        }
        first += 4;
    }
    assert!(first >= low + 256);
    (top - first, top - low)
}
#[inline(never)]
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[inline(never)]
fn secure(initiator: bool) -> Secure {
    let (credential, other, private) = if initiator {
        (
            include_bytes!("../../tests/fixtures/i.ccs").as_slice(),
            include_bytes!("../../tests/fixtures/r.ccs").as_slice(),
            b"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b",
        )
    } else {
        (
            include_bytes!("../../tests/fixtures/r.ccs").as_slice(),
            include_bytes!("../../tests/fixtures/i.ccs").as_slice(),
            b"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac",
        )
    };
    let mut key = [0; 32];
    fn digit(c: u8) -> u8 {
        if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
    }
    for (index, pair) in private.as_chunks::<2>().0.iter().enumerate() {
        key[index] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    let mut crypto = SoftwareCrypto::new(TestRng(if initiator { 3 } else { 4 }));
    let identity = Identity::new(credential, key, &mut crypto).unwrap();
    let mut protection = Edhoc::with_store(crypto, identity, TrustedPeers::<1>::new()).unwrap();
    protection
        .trust(TrustedPeer::new(PeerId(1), other).unwrap())
        .unwrap();
    protection
}

#[inline(never)]
fn network() {
    // SAFETY: fixture initialization is single-threaded and each previous run was dropped.
    unsafe {
        let link = (&raw mut LINK).cast::<RefCell<Link>>();
        link.write(RefCell::new(Link::new()));
        for index in 0..2 {
            let device = (&raw mut DEVICES)
                .cast::<MaybeUninit<Device>>()
                .add(index)
                .cast::<Device>();
            device.write(Device {
                link: &*link,
                side: index,
            });
            let mut stack = Stack::new(&NETWORK, index as u64 + 1);
            let iface = stack.add_iface_borrowed(&mut *device).unwrap();
            let ip: core::net::Ipv4Addr = if index == 0 { "192.0.2.1" } else { "192.0.2.2" }
                .parse()
                .unwrap();
            stack
                .iface(iface)
                .add_ip_addr(IpCidr::new(ip.into(), 24))
                .unwrap();
            let socket = stack.add_udp_socket().unwrap();
            stack.udp_socket(socket).bind_to_iface(Some(iface)).unwrap();
            stack.udp_socket(socket).bind(5683, 0).unwrap();
            (&raw mut SIDES)
                .cast::<MaybeUninit<Side>>()
                .add(index)
                .cast::<Side>()
                .write(Side {
                    stack: RefCell::new(stack),
                    iface,
                    socket,
                });
        }
    }
}

#[inline(never)]
fn scenario<P: Protection>(
    client: &mut EndpointType<P>,
    server: &mut EndpointType<P>,
    mode: &str,
    policy: &impl Policy,
) {
    let now = Cell::new(0u64);
    let timer = Timer(&now);
    let mut client_socket = Socket {
        inner: XarxaTransport::new(Access(side(0)), side(0).socket, side(0).iface, 1).unwrap(),
        owned: Cell::new(0),
        copied: Cell::new(0),
    };
    let mut server_socket = Socket {
        inner: XarxaTransport::new(Access(side(1)), side(1).socket, side(1).iface, 1).unwrap(),
        owned: Cell::new(0),
        copied: Cell::new(0),
    };
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
    let calls = Cell::new(0);
    let mut application = |request: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        if mode != "plain" {
            assert!(matches!(
                request.security,
                mai_coap::security::SecurityState::Protected { .. }
            ));
        }
        calls.set(calls.get() + 1);
        response.set_payload(&BODY).unwrap();
        Ok(Disposition::Complete)
    };
    let mut peaks = [(0, 0); 3];
    let (client_bytes, server_bytes);
    {
        let mut client_driver =
            pin!(client.run_owned(&mut client_socket, &timer, &mut unused, policy));
        let mut server_driver =
            pin!(server.run_owned(&mut server_socket, &timer, &mut application, policy));
        client_bytes = size_of_val(client_driver.as_ref().get_ref());
        server_bytes = size_of_val(server_driver.as_ref().get_ref());
        for (phase, measurement) in peaks.iter_mut().enumerate() {
            if phase == 1 {
                unsafe {
                    (&*(&raw const LINK).cast::<RefCell<Link>>())
                        .borrow_mut()
                        .drop_reply = true;
                }
            }
            let remote: core::net::SocketAddr = "192.0.2.2:5683".parse().unwrap();
            let client = CLIENT_SHARED.handle().client(remote);
            let client = if mode == "plain" {
                client
            } else {
                client.peer(PeerId(1))
            };
            let operation = client
                .combined_edhoc(mode != "sequential")
                .request(Code::GET, "/x")
                .unwrap()
                .confirmable(phase != 2)
                .send()
                .unwrap();
            let mut operation = pin!(operation);
            begin();
            let mut complete = false;
            for _ in 0..1000 {
                if let Poll::Ready(reply) = poll(operation.as_mut()) {
                    let reply = reply.unwrap();
                    assert!(reply.message().unwrap().payload() == BODY);
                    complete = true;
                    break;
                }
                assert!(poll(client_driver.as_mut()).is_pending());
                assert!(poll(server_driver.as_mut()).is_pending());
                for index in 0..2 {
                    side(index)
                        .stack
                        .borrow_mut()
                        .poll(xarxa::time::Instant::from_millis(now.get() as u32));
                }
                now.set(now.get() + 100);
            }
            assert!(complete);
            *measurement = peak();
        }
    }
    assert_eq!(calls.get(), 3);
    assert!(server_socket.owned.get() > 0);
    // SAFETY: Link remains initialized until after the drivers and network stacks drop.
    let link = unsafe { &*(&raw const LINK).cast::<RefCell<Link>>() }.borrow();
    assert!(link.retried);
    assert!(link.non_replies > 0);
    for (phase, (painted, capacity)) in peaks.iter().enumerate() {
        semihosting::println!(
            "xarxa: mode={} phase={} D={} painted={} capacity={} client_future={} server_future={} endpoint={} shared={} network_pool={} network_state={} owned={} copied={}",
            mode,
            ["handshake", "traffic", "non"][phase],
            D,
            painted,
            capacity,
            client_bytes,
            server_bytes,
            size_of::<EndpointType<Secure>>() * 2,
            size_of::<Shared<D, 1>>() * 2,
            size_of::<StaticPool<1536, BUFFERS>>(),
            size_of::<Side>() * 2 + size_of::<Device>() * 2 + size_of::<RefCell<Link>>(),
            client_socket.owned.get() + server_socket.owned.get(),
            client_socket.copied.get() + server_socket.copied.get()
        );
    }
}
fn cleanup() {
    // SAFETY: run has already dropped both endpoints and their driver futures.
    unsafe {
        for index in 0..2 {
            core::ptr::drop_in_place(
                (&raw mut SIDES)
                    .cast::<MaybeUninit<Side>>()
                    .add(index)
                    .cast::<Side>(),
            );
        }
        core::ptr::drop_in_place((&raw mut LINK).cast::<RefCell<Link>>());
    }
    let mut reclaimed = [const { None }; BUFFERS];
    for slot in &mut reclaimed {
        *slot = Some(NETWORK.alloc().expect("network buffer leaked"));
    }
    assert!(NETWORK.alloc().is_none());
    semihosting::println!("xarxa pool: free={} buffers={}", reclaimed.len(), BUFFERS);
}
// Keep configuration formatting out of the measured driver frame.
#[inline(never)]
fn report_configuration() {
    semihosting::println!("xarxa config: id_context_bytes={}", ID_CONTEXT_BYTES);
}

pub fn run() {
    report_configuration();
    const {
        assert!(size_of::<EndpointType<Unsecured<TestRng>>>() <= size_of::<EndpointType<Secure>>());
        assert!(
            core::mem::align_of::<EndpointType<Unsecured<TestRng>>>()
                <= core::mem::align_of::<EndpointType<Secure>>()
        );
    }
    network();
    // SAFETY: single fixture entrypoint exclusively initializes, accesses and drops slots.
    unsafe {
        let endpoints = (&raw mut SECURE_ENDPOINTS)
            .cast::<MaybeUninit<EndpointType<Unsecured<TestRng>>>>()
            .cast::<EndpointType<Unsecured<TestRng>>>();
        endpoints.write(
            EndpointType::with_storage(
                &CLIENT_SHARED,
                Unsecured(TestRng(7)),
                Store::new(allocate_client),
            )
            .unwrap(),
        );
        endpoints.add(1).write(
            EndpointType::with_storage(
                &SERVER_SHARED,
                Unsecured(TestRng(8)),
                Store::new(allocate_server),
            )
            .unwrap(),
        );
        scenario(
            &mut *endpoints,
            &mut *endpoints.add(1),
            "plain",
            &PublicPaths(&[(Code::GET, "/x")]),
        );
        core::ptr::drop_in_place(endpoints);
        core::ptr::drop_in_place(endpoints.add(1));
    }
    cleanup();
    for combined in [true, false] {
        network();
        // SAFETY: these static slots have no other owner, and are dropped before reuse.
        unsafe {
            let endpoints = (&raw mut SECURE_ENDPOINTS)
                .cast::<MaybeUninit<EndpointType<Secure>>>()
                .cast::<EndpointType<Secure>>();
            endpoints.write(
                EndpointType::with_storage(
                    &CLIENT_SHARED,
                    secure(true),
                    Store::new(allocate_client),
                )
                .unwrap(),
            );
            endpoints.add(1).write(
                EndpointType::with_storage(
                    &SERVER_SHARED,
                    secure(false),
                    Store::new(allocate_server),
                )
                .unwrap(),
            );
            scenario(
                &mut *endpoints,
                &mut *endpoints.add(1),
                if combined { "combined" } else { "sequential" },
                &ProtectedOnly,
            );
            assert!((*endpoints).protection_mut().contexts() == 1);
            assert!((*endpoints.add(1)).protection_mut().contexts() == 1);
            core::ptr::drop_in_place(endpoints);
            core::ptr::drop_in_place(endpoints.add(1));
        }
        cleanup();
    }
}
