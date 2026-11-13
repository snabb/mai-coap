//! Single-threaded Cortex-M stack regression fixture; no interrupts are enabled.
use super::TestRng;
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use mai_coap::{
    codec::Code,
    crypto::SoftwareCrypto,
    edhoc::{Identity, TrustedPeer, TrustedPeers, endpoint::Edhoc},
    endpoint::{Disposition, Endpoint, Reply, Request, ResponseWriter, Shared},
    security::{PeerId, ProtectedOnly},
    time::{Clock, Instant},
    transport::{Datagram, Metadata, Transport},
};

const D: usize = 1152;
// Keep runtime coverage of the public default; the xarxa fixture covers zero.
const ID_CONTEXT_BYTES: usize = 255;
type Secure = Edhoc<SoftwareCrypto<TestRng>, 1, 1, TrustedPeers<1>, ID_CONTEXT_BYTES>;
type Driver = Endpoint<'static, Secure, D, 1, 4, 1, 2, 2, 1, 1, 1, 3>;
static CLIENT_SHARED: Shared<D, 1> = Shared::new();
static SERVER_SHARED: Shared<D, 1> = Shared::new();
// Retained endpoint storage must not consume the stack being measured. Only run()
// accesses these slots, and drops each initialized value before the next scenario.
static mut CLIENT: MaybeUninit<Driver> = MaybeUninit::uninit();
static mut SERVER: MaybeUninit<Driver> = MaybeUninit::uninit();
unsafe extern "C" {
    static _stack_start: u32;
    static _stack_end: u32;
}
const PAINT: u32 = 0xcccc_cccc;

// Paint only unused stack, never the live future storage above MSP. Volatile
// word writes keep this loop independent of memset and its stack requirements.
#[inline(never)]
pub(super) fn begin() {
    let low = &raw const _stack_end as usize;
    let sp = cortex_m::register::msp::read() as usize;
    assert!(sp > low + 256);
    for address in (low..sp).step_by(4) {
        // SAFETY: the linker bounds this unused stack below the current frame;
        // this fixture enables no interrupt sources and the loop makes no calls.
        unsafe { (address as *mut u32).write_volatile(PAINT) };
    }
}

pub(super) struct Peak {
    pub(super) painted: usize,
    pub(super) capacity: usize,
}
#[inline(never)]
pub(super) fn finish() -> Peak {
    let low = &raw const _stack_end as usize;
    let top = &raw const _stack_start as usize;
    let mut first = low;
    while first < top {
        // SAFETY: word-aligned addresses lie inside the linker-defined stack.
        if unsafe { (first as *const u32).read_volatile() } != PAINT {
            break;
        }
        first += 4;
    }
    // A guard makes touching the bottom of the painted region a hard failure.
    assert!(first >= low + 256);
    Peak {
        painted: top - first,
        capacity: top - low,
    }
}

struct Mailbox {
    bytes: [u8; D],
    length: usize,
}
impl Mailbox {
    const fn new() -> Self {
        Self {
            bytes: [0; D],
            length: 0,
        }
    }
}
struct Link([RefCell<Mailbox>; 2]);
struct Socket<'a> {
    link: &'a Link,
    side: usize,
    local: SocketAddr,
    remote: SocketAddr,
}
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
        let n = poll_fn(|_| {
            let mut packet = self.link.0[self.side].borrow_mut();
            if packet.length == 0 {
                return Poll::Pending;
            }
            let n = packet.length;
            scratch[..n].copy_from_slice(&packet.bytes[..n]);
            packet.length = 0;
            Poll::Ready(n)
        })
        .await;
        Ok(Datagram {
            bytes: &scratch[..n],
            metadata: Metadata::new(self.remote, self.local.ip(), n),
        })
    }
}
impl mai_coap::transport::DatagramSender for &Socket<'_> {
    type Error = core::convert::Infallible;
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        _: Option<u32>,
        bytes: &[u8],
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        assert!(remote == self.remote);
        assert!(source.is_none_or(|ip| ip == self.local.ip()));
        (|| {
            let mut packet = self.link.0[1 - self.side].borrow_mut();
            if packet.length != 0 {
                return Poll::Pending;
            }
            packet.bytes[..bytes.len()].copy_from_slice(bytes);
            packet.length = bytes.len();
            Poll::Ready(Ok(()))
        })()
        .map(|result| result.map(|()| mai_coap::transport::SendOutcome::Accepted))
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

// Keep the application/executor boundary stable while allowing run() and its
// callees to inline into this actual poll, as they do in application tasks.
#[inline(never)]
fn poll_driver<F: Future>(future: Pin<&mut F>) {
    assert!(
        future
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}
#[inline(never)]
fn poll_operation<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[inline(never)]
pub(super) fn protection(initiator: bool) -> Secure {
    protection_with_context(initiator)
}

pub(super) fn protection_with_context<const N: usize>(
    initiator: bool,
) -> Edhoc<SoftwareCrypto<TestRng>, 1, 1, TrustedPeers<1>, N> {
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
    for (i, pair) in private.as_chunks::<2>().0.iter().enumerate() {
        key[i] = digit(pair[0]) * 16 + digit(pair[1]);
    }
    let mut crypto = SoftwareCrypto::new(TestRng(if initiator { 3 } else { 4 }));
    let identity = Identity::new(credential, key, &mut crypto).unwrap();
    let mut secure = Edhoc::with_store(crypto, identity, TrustedPeers::<1>::new()).unwrap();
    secure
        .trust(TrustedPeer::new(PeerId(1), other).unwrap())
        .unwrap();
    secure
}

#[inline(never)]
fn scenario(client: &mut Driver, server: &mut Driver, combined: bool) {
    let link = Link([RefCell::new(Mailbox::new()), RefCell::new(Mailbox::new())]);
    let a = "192.0.2.1:5683".parse().unwrap();
    let b = "192.0.2.2:5683".parse().unwrap();
    let mut client_socket = Socket {
        link: &link,
        side: 0,
        local: a,
        remote: b,
    };
    let mut server_socket = Socket {
        link: &link,
        side: 1,
        local: b,
        remote: a,
    };
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
    let mut application = |request: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        assert!(matches!(
            request.security,
            mai_coap::security::SecurityState::Protected { .. }
        ));
        response.set_payload(b"ok").unwrap();
        Ok(Disposition::Complete)
    };
    let mut client_driver =
        pin!(client.run(&mut client_socket, &Timer, &mut unused, &ProtectedOnly));
    let mut server_driver =
        pin!(server.run(&mut server_socket, &Timer, &mut application, &ProtectedOnly));
    let driver_bytes = core::mem::size_of_val(client_driver.as_ref().get_ref());
    let server_driver_bytes = core::mem::size_of_val(server_driver.as_ref().get_ref());
    let mut peaks = [
        Peak {
            painted: 0,
            capacity: 0,
        },
        Peak {
            painted: 0,
            capacity: 0,
        },
    ];
    for peak in &mut peaks {
        let operation = CLIENT_SHARED
            .handle()
            .client(b)
            .peer(PeerId(1))
            .combined_edhoc(combined)
            .get("/x");
        let mut operation = pin!(operation);
        begin();
        let mut complete = false;
        for _ in 0..100 {
            // Submit first, then allow both real driver futures to make progress.
            if let Poll::Ready(reply) = poll_operation(operation.as_mut()) {
                let reply: Reply<D> = reply.unwrap();
                assert!(reply.message().unwrap().code() == Code::CONTENT);
                assert!(reply.message().unwrap().payload() == b"ok");
                complete = true;
                break;
            }
            poll_driver(client_driver.as_mut());
            poll_driver(server_driver.as_mut());
        }
        assert!(complete);
        *peak = finish();
    }
    // Reporting happens after both measurements so formatting cannot set their peaks.
    for (phase, peak) in peaks.iter().enumerate() {
        semihosting::println!(
            "stack: mode={} phase={} D={} painted={} capacity={} client_future={} server_future={}",
            if combined { "combined" } else { "sequential" },
            if phase == 0 { "handshake" } else { "traffic" },
            D,
            peak.painted,
            peak.capacity,
            driver_bytes,
            server_driver_bytes
        );
    }
}

#[inline(never)]
fn initialize(client: *mut Driver, server: *mut Driver) {
    // SAFETY: run supplies the exclusive, uninitialized slots; both return initialized.
    unsafe {
        client.write(Driver::new(&CLIENT_SHARED, protection(true)).unwrap());
        server.write(Driver::new(&SERVER_SHARED, protection(false)).unwrap());
    }
}

// Keep configuration formatting out of the measured driver frame.
#[inline(never)]
fn report_configuration() {
    semihosting::println!("stack config: id_context_bytes={}", ID_CONTEXT_BYTES);
}

pub fn run() {
    report_configuration();
    for combined in [true, false] {
        // SAFETY: this single-threaded fixture is the sole owner. Each slot is
        // initialized before use and dropped once, after both drivers are dropped.
        unsafe {
            let client = (&raw mut CLIENT).cast::<Driver>();
            let server = (&raw mut SERVER).cast::<Driver>();
            initialize(client, server);
            scenario(&mut *client, &mut *server, combined);
            assert!((*client).protection_mut().contexts() == 1);
            assert!((*server).protection_mut().contexts() == 1);
            assert!((*client).protection_mut().runs() == 1);
            core::ptr::drop_in_place(client);
            core::ptr::drop_in_place(server);
        }
    }
}
