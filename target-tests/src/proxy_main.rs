#![no_std]
#![no_main]

use cortex_m as _;
use cortex_m_rt::entry;
include!("rng.rs");
#[allow(dead_code)]
mod stack;

use core::{
    cell::{Cell, RefCell},
    future::{Future, poll_fn},
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    crypto::SoftwareCrypto,
    edhoc::{TrustedPeers, endpoint::Edhoc},
    endpoint::{
        Application, Disposition, Endpoint, Protection, Request, ResponseWriter, Shared, Unsecured,
    },
    proxy::{ForwardProxy, Routing},
    security::PublicPaths,
    time::{Clock, Instant},
    transport::{Datagram, Metadata, SendOutcome, Transport},
};

const D: usize = 1152;
const F: usize = 2;
const PAYLOAD: [u8; 1024] = [0xa5; 1024];
type Secure = Edhoc<SoftwareCrypto<TestRng>, 1, 1, TrustedPeers<1>, 0>;
#[cfg(feature = "proxy-roles")]
type Incoming<P> = Endpoint<
    'static,
    P,
    D,
    4,
    8,
    0,
    2,
    2,
    4,
    4,
    2,
    2,
    mai_coap::InlineStorage<D, 2>,
    mai_coap::endpoint::role::Server,
>;
#[cfg(not(feature = "proxy-roles"))]
type Incoming<P> = Endpoint<'static, P, D, 4, 8, 0, 2, 2, 4, 4, 2, 2>;
#[cfg(feature = "proxy-roles")]
type Outgoing = Endpoint<
    'static,
    Unsecured<TestRng>,
    D,
    F,
    1,
    0,
    1,
    2,
    F,
    0,
    0,
    F,
    mai_coap::InlineStorage<D, F>,
    mai_coap::endpoint::role::Client,
>;
#[cfg(not(feature = "proxy-roles"))]
type Outgoing = Endpoint<'static, Unsecured<TestRng>, D, F, 1, 0, 1, 2, F, 0, 0, F>;

fn make_incoming<P: Protection>(protection: P) -> Incoming<P> {
    #[cfg(feature = "proxy-roles")]
    {
        Incoming::new_with_role(&INCOMING_SHARED, protection).unwrap()
    }
    #[cfg(not(feature = "proxy-roles"))]
    {
        Incoming::new(&INCOMING_SHARED, protection).unwrap()
    }
}
fn make_outgoing(seed: u64) -> Outgoing {
    #[cfg(feature = "proxy-roles")]
    {
        Outgoing::new_with_role(&OUTGOING_SHARED, Unsecured(TestRng(seed))).unwrap()
    }
    #[cfg(not(feature = "proxy-roles"))]
    {
        Outgoing::new(&OUTGOING_SHARED, Unsecured(TestRng(seed))).unwrap()
    }
}

static INCOMING_SHARED: Shared<D, 4> = Shared::new();
static OUTGOING_SHARED: Shared<D, F> = Shared::new();
// Only main accesses these slots, and every initialized value is dropped before
// reuse. Keep endpoint storage outside the stack paint's measurement boundary.
static mut PLAIN: MaybeUninit<Incoming<Unsecured<TestRng>>> = MaybeUninit::uninit();
static mut SECURED: MaybeUninit<Incoming<Secure>> = MaybeUninit::uninit();
static mut OUTGOING: MaybeUninit<Outgoing> = MaybeUninit::uninit();

fn address(last: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(192, 0, 2, last).into(), 5683)
}

struct Mailbox {
    bytes: [u8; D],
    length: usize,
    waker: Option<Waker>,
}
impl Mailbox {
    const fn new() -> Self {
        Self {
            bytes: [0; D],
            length: 0,
            waker: None,
        }
    }
}
struct Link {
    incoming: [RefCell<Mailbox>; 2],
    allow_origin: Cell<bool>,
    empty_acks: Cell<usize>,
    relays: Cell<usize>,
    relayed_tokens: Cell<u8>,
    local_replies: Cell<usize>,
}
impl Link {
    fn request(&self, token: u8, proxy: bool) {
        let mut packet = self.incoming[0].borrow_mut();
        assert_eq!(packet.length, 0);
        let mut builder = MessageBuilder::new(
            &mut packet.bytes,
            MessageType::Confirmable,
            Code::GET,
            u16::from(token),
            &[token],
        )
        .unwrap();
        if proxy {
            builder
                .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
                .unwrap();
        } else {
            builder.option(OptionNumber::URI_PATH, b"local").unwrap();
        }
        packet.length = builder.finish(&[]).unwrap();
        if let Some(waker) = packet.waker.take() {
            waker.wake();
        }
    }
}
struct Socket<'a>(&'a Link, usize);
impl Transport for Socket<'_> {
    type Error = core::convert::Infallible;
    type Receiver<'a>
        = &'a Self
    where
        Self: 'a;
    type Sender<'a>
        = &'a Self
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
        (self, self)
    }
}
impl mai_coap::transport::DatagramReceiver for &Socket<'_> {
    type Error = core::convert::Infallible;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;
    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
        let n = poll_fn(|cx| {
            let mut packet = self.0.incoming[self.1].borrow_mut();
            if packet.length == 0 || self.1 == 1 && !self.0.allow_origin.get() {
                packet.waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = packet.length;
            scratch[..n].copy_from_slice(&packet.bytes[..n]);
            packet.length = 0;
            Poll::Ready(n)
        })
        .await;
        Ok(Datagram {
            bytes: core::hint::black_box(&scratch[..n]),
            metadata: Metadata::new(
                address(if self.1 == 0 { 1 } else { 9 }),
                address(if self.1 == 0 { 2 } else { 3 }).ip(),
                n,
            ),
        })
    }
}
impl mai_coap::transport::DatagramSender for &Socket<'_> {
    type Error = core::convert::Infallible;
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        _: Option<IpAddr>,
        _: Option<u32>,
        bytes: &[u8],
        _: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        let message = MessageView::parse(bytes).unwrap();
        if self.1 == 1 {
            assert_eq!(remote, address(9));
            assert_eq!(message.code(), Code::GET);
            let mut packet = self.0.incoming[1].borrow_mut();
            if packet.length != 0 {
                return Poll::Pending;
            }
            packet.length = MessageBuilder::new(
                &mut packet.bytes,
                MessageType::Acknowledgement,
                Code::CONTENT,
                message.message_id(),
                message.token(),
            )
            .unwrap()
            .finish(&PAYLOAD)
            .unwrap();
            if let Some(waker) = packet.waker.take() {
                waker.wake();
            }
        } else {
            assert_eq!(remote, address(1));
            if message.code() == Code::EMPTY {
                self.0.empty_acks.set(self.0.empty_acks.get() + 1);
            } else {
                assert_eq!(message.code(), Code::CONTENT);
                if message.token() == [3] {
                    assert_eq!(message.payload(), b"local");
                    self.0.local_replies.set(self.0.local_replies.get() + 1);
                } else {
                    assert!(message.token() == [1] || message.token() == [2]);
                    assert_eq!(message.payload(), &PAYLOAD);
                    let token = if message.token() == [1] { 1 } else { 2 };
                    assert_eq!(self.0.relayed_tokens.get() & token, 0);
                    self.0
                        .relayed_tokens
                        .set(self.0.relayed_tokens.get() | token);
                    self.0.relays.set(self.0.relays.get() + 1);
                    if message.message_type() == MessageType::Confirmable {
                        let mut packet = self.0.incoming[0].borrow_mut();
                        assert_eq!(packet.length, 0);
                        packet.length = MessageBuilder::new(
                            &mut packet.bytes,
                            MessageType::Acknowledgement,
                            Code::EMPTY,
                            message.message_id(),
                            &[],
                        )
                        .unwrap()
                        .finish(&[])
                        .unwrap();
                        if let Some(waker) = packet.waker.take() {
                            waker.wake();
                        }
                    }
                }
            }
        }
        Poll::Ready(Ok(SendOutcome::Accepted))
    }
}
struct Timer;
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant(0)
    }
    async fn sleep_until(&self, _: Instant) {
        core::future::pending::<()>().await;
    }
}
struct Route;
impl Routing for Route {
    fn allow(&self, _: SocketAddr, host: &str, port: u16) -> bool {
        host == "192.0.2.9" && port == 5683
    }
}
struct Local;
impl Application<D> for Local {
    fn recognizes(&self, _: OptionNumber) -> bool {
        false
    }
    fn handle(
        &mut self,
        _: Request<'_>,
        response: &mut ResponseWriter<'_, D>,
    ) -> Result<Disposition, Code> {
        response.set_payload(b"local")?;
        Ok(Disposition::Complete)
    }
}
#[inline(never)]
fn poll_driver<Fut: Future>(future: Pin<&mut Fut>) {
    assert!(
        future
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

#[inline(never)]
fn scenario<P: Protection>(security: &str, incoming: &mut Incoming<P>, outgoing: &mut Outgoing) {
    let link = Link {
        incoming: [const { RefCell::new(Mailbox::new()) }; 2],
        allow_origin: Cell::new(false),
        empty_acks: Cell::new(0),
        relays: Cell::new(0),
        relayed_tokens: Cell::new(0),
        local_replies: Cell::new(0),
    };
    let mut a = Socket(&link, 0);
    let mut b = Socket(&link, 1);
    let mut proxy = ForwardProxy::<_, _, D, 4, F, F>::with_outbound(
        Local,
        Route,
        INCOMING_SHARED.handle(),
        OUTGOING_SHARED.handle(),
    )
    .unwrap();
    let mut unused = Local;
    let policy = PublicPaths(&[(Code::GET, "/local")]);
    link.request(1, true);
    stack::begin();
    let incoming_future = incoming.run(&mut a, &Timer, &mut proxy, &policy);
    let outgoing_future = outgoing.run(&mut b, &Timer, &mut unused, &policy);
    let incoming_size = core::mem::size_of_val(&incoming_future);
    let outgoing_size = core::mem::size_of_val(&outgoing_future);
    {
        let mut incoming_future = pin!(incoming_future);
        let mut outgoing_future = pin!(outgoing_future);
        let mut second = false;
        let mut local = false;
        for _ in 0..100 {
            poll_driver(incoming_future.as_mut());
            poll_driver(outgoing_future.as_mut());
            if link.empty_acks.get() == 1 && !second {
                link.request(2, true);
                second = true;
            }
            if link.empty_acks.get() == F {
                link.allow_origin.set(true);
            }
            if link.relays.get() == F && !local && link.incoming[0].borrow().length == 0 {
                link.request(3, false);
                local = true;
            }
            if link.local_replies.get() == 1 {
                break;
            }
        }
        assert_eq!(link.empty_acks.get(), F);
        assert_eq!(link.relays.get(), F);
        assert_eq!(link.relayed_tokens.get(), 3);
        assert_eq!(link.local_replies.get(), 1);
    }
    let peak = stack::finish();
    semihosting::println!(
        "proxy: security={} D={} forwards={} payload={} incoming_future={} outgoing_future={} painted={} capacity={}",
        security,
        D,
        F,
        PAYLOAD.len(),
        incoming_size,
        outgoing_size,
        peak.painted,
        peak.capacity
    );
}

#[entry]
fn main() -> ! {
    // SAFETY: there are no interrupts, main is the only caller, and each slot is
    // initialized before its exclusive borrow and dropped before reuse.
    unsafe {
        let outgoing = &raw mut OUTGOING;
        let outgoing = &mut *outgoing;
        let plain = &raw mut PLAIN;
        let plain = &mut *plain;
        plain.write(make_incoming(Unsecured(TestRng(7))));
        outgoing.write(make_outgoing(8));
        scenario("plain", plain.assume_init_mut(), outgoing.assume_init_mut());
        plain.assume_init_drop();
        outgoing.assume_init_drop();
        let secured = &raw mut SECURED;
        let secured = &mut *secured;
        secured.write(make_incoming(stack::protection_with_context::<0>(false)));
        outgoing.write(make_outgoing(11));
        scenario(
            "secure",
            secured.assume_init_mut(),
            outgoing.assume_init_mut(),
        );
        secured.assume_init_drop();
        outgoing.assume_init_drop();
    }
    semihosting::println!("mai-coap proxy runtime: PASS");
    semihosting::process::exit(0)
}
