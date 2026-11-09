#![no_std]
#![no_main]

#[cfg(target_arch = "arm")]
use cortex_m as _;
#[cfg(target_arch = "arm")]
use cortex_m_rt::entry;
#[cfg(target_arch = "riscv32")]
use riscv as _;
#[cfg(target_arch = "riscv32")]
use riscv_rt::entry;

#[cfg(any(feature = "memory-layout", feature = "proxy", feature = "oscore"))]
use mai_coap::endpoint::Response;
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Request, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
};

#[cfg(any(
    not(feature = "get-server"),
    feature = "memory-layout",
    feature = "proxy",
    feature = "discovery"
))]
use mai_coap::endpoint::Endpoint;

// Keep the RNG at crate root for concrete names in the storage-layout report.
include!("rng.rs");

#[entry]
fn main() -> ! {
    #[cfg(feature = "memory-layout")]
    memory_profile();
    codec_and_endpoint();
    #[cfg(all(feature = "block1", not(feature = "get-server")))]
    blocks();
    #[cfg(feature = "block")]
    block2();
    #[cfg(feature = "observe")]
    observe();
    #[cfg(feature = "proxy")]
    proxy();
    #[cfg(feature = "discovery")]
    discovery();
    #[cfg(feature = "oscore")]
    oscore();
    #[cfg(feature = "edhoc")]
    edhoc();
    semihosting::println!("mai-coap target runtime: PASS");
    semihosting::process::exit(0)
}

#[cfg(feature = "memory-layout")]
#[inline(never)]
fn retain_layout<T>() {
    // Keep the concrete pointee in DWARF without allocating another endpoint.
    core::hint::black_box((core::ptr::null::<T>(), core::mem::size_of::<T>()));
}

#[cfg(feature = "memory-layout")]
// Keep the layout probe's temporary endpoint off later runtime-test frames.
#[inline(never)]
fn memory_profile() {
    use core::mem::{size_of, size_of_val};
    use mai_coap::{
        __test_support::{Deduplication, PacketPool},
        crypto::SoftwareCrypto,
        edhoc::endpoint::Edhoc,
        endpoint::{
            DefaultEndpoint, DefaultShared, ServerEndpoint, ServerShared, SmallEndpoint,
            SmallShared,
        },
        time::Clock,
        transport::{Datagram, Transport},
    };
    type Secure = Edhoc<SoftwareCrypto<TestRng>, 4, 4>;
    type DefaultSecureEndpoint<'a> = DefaultEndpoint<'a, Secure>;
    type SmallSecureEndpoint<'a> = SmallEndpoint<'a, Secure>;
    type ServerSecureEndpoint<'a> = ServerEndpoint<'a, Secure>;
    retain_layout::<DefaultSecureEndpoint<'_>>();
    retain_layout::<DefaultShared>();
    retain_layout::<SmallSecureEndpoint<'_>>();
    retain_layout::<SmallShared>();
    retain_layout::<ServerSecureEndpoint<'_>>();
    retain_layout::<ServerShared<1152>>();
    retain_layout::<PacketPool<1152, 40>>();
    retain_layout::<PacketPool<1152, 16>>();
    retain_layout::<PacketPool<1152, 2>>();
    retain_layout::<Response<1152>>();
    struct Socket;
    impl Transport for Socket {
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
    impl mai_coap::transport::DatagramReceiver for &Socket {
        type Error = core::convert::Infallible;
        type Packet<'a>
            = Datagram<'a>
        where
            Self: 'a;
        async fn receive<'a>(&'a mut self, _: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
            core::future::pending().await
        }
    }
    impl mai_coap::transport::DatagramSender for &Socket {
        type Error = core::convert::Infallible;
        fn poll_send(
            &mut self,
            _: core::net::SocketAddr,
            _: Option<core::net::IpAddr>,
            _: Option<u32>,
            _: &[u8],
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
            core::task::Poll::Pending
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
    static STORAGE: Shared<1152, 4> = Shared::new();
    let mut endpoint =
        Endpoint::<_, 1152, 4, 16, 4, 2, 16>::new(&STORAGE, Unsecured(TestRng(321))).unwrap();
    let mut socket = Socket;
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 1152>| Err(Code::NOT_FOUND);
    let policy = PublicPaths(&[]);
    let driver = endpoint.run(&mut socket, &Timer, &mut app, &policy);
    let client = STORAGE
        .handle()
        .client("192.0.2.1:5683".parse::<core::net::SocketAddr>().unwrap());
    let get = client.get("/x");
    let mut output = [0; 4096];
    let download = client.get_blocks("/x", 6, &mut output);
    let upload = client.upload(
        Code::PUT,
        "/image",
        mai_coap::codec::ContentFormat::OCTET_STREAM,
        b"body",
        6,
    );
    semihosting::println!(
        "memory layout: D=1152 multicast={} shared_counters={} observe={}",
        cfg!(feature = "multicast"),
        cfg!(feature = "shared-counters"),
        cfg!(feature = "observe")
    );
    semihosting::println!(
        "memory profile: name=default OUTBOUND=8 DEDUP=32 OBS=8 CACHED=8 SEND=16 COMMANDS=8 DEFERRED=8 BODY_CONTEXTS=8 PACKETS=40"
    );
    semihosting::println!(
        "memory profile: name=small OUTBOUND=4 DEDUP=16 OBS=4 CACHED=4 SEND=4 COMMANDS=4 DEFERRED=4 BODY_CONTEXTS=4 PACKETS=16"
    );
    semihosting::println!(
        "memory profile: name=server OUTBOUND=0 DEDUP=8 OBS=0 CACHED=2 SEND=2 COMMANDS=0 DEFERRED=0 BODY_CONTEXTS=0 PACKETS=2"
    );
    semihosting::println!(
        "memory sizes: name=default endpoint={} shared={} dedup={} pool={} response={} security={}",
        size_of::<DefaultSecureEndpoint<'_>>(),
        size_of::<DefaultShared>(),
        size_of::<Deduplication<32, 8>>(),
        size_of::<PacketPool<1152, 40>>(),
        size_of::<Response<1152>>(),
        size_of::<Secure>()
    );
    semihosting::println!(
        "memory sizes: name=small endpoint={} shared={} dedup={} pool={} response={} security={}",
        size_of::<SmallSecureEndpoint<'_>>(),
        size_of::<SmallShared>(),
        size_of::<Deduplication<16, 4>>(),
        size_of::<PacketPool<1152, 16>>(),
        size_of::<Response<1152>>(),
        size_of::<Secure>()
    );
    semihosting::println!(
        "memory sizes: name=server endpoint={} shared={} dedup={} pool={} response={} security={}",
        size_of::<ServerSecureEndpoint<'_>>(),
        size_of::<ServerShared<1152>>(),
        size_of::<Deduplication<8, 2>>(),
        size_of::<PacketPool<1152, 2>>(),
        size_of::<Response<1152>>(),
        size_of::<Secure>()
    );
    semihosting::println!(
        "unsecured futures: driver={} get={} download={} upload={}",
        size_of_val(&driver),
        size_of_val(&get),
        size_of_val(&download),
        size_of_val(&upload)
    );
}

#[inline(never)]
fn codec_and_endpoint() {
    #[cfg(not(feature = "get-server"))]
    static SHARED: Shared<128, 1> = Shared::new();
    #[cfg(feature = "get-server")]
    static SHARED: mai_coap::endpoint::ServerShared<128> = Shared::new();
    let shared = &SHARED;
    // Keep the live endpoint's packet pool small enough for the 16 KiB M0 fixture.
    #[cfg(not(feature = "get-server"))]
    let mut endpoint =
        Endpoint::<_, 128, 1, 2, 8, 8, 2, 1, 1, 8, 2>::new(shared, Unsecured(TestRng(123)))
            .unwrap();
    #[cfg(feature = "get-server")]
    let mut endpoint =
        mai_coap::endpoint::ServerEndpoint::new(shared, Unsecured(TestRng(123))).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        #[cfg(all(feature = "get-server", feature = "shared-counters"))]
        assert_eq!(shared.counters().requests, calls.get() as u64 - 1);
        response.set_payload(b"embedded").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    #[cfg(feature = "get-server")]
    let mut application = mai_coap::server::Router::<128, 1, 0, 0>::new(&policy);
    #[cfg(feature = "get-server")]
    application.route("/x", &[Code::GET], &mut handler).unwrap();
    #[cfg(not(feature = "get-server"))]
    let mut application = &mut handler;
    let mut bytes = [0; 128];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 99, b"t").unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    endpoint
        .receive(&bytes[..n], metadata, Instant(0), &mut application, &policy)
        .unwrap();
    let first = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(first.packet.as_slice())
            .unwrap()
            .payload(),
        b"embedded"
    );
    endpoint
        .receive(&bytes[..n], metadata, Instant(1), &mut application, &policy)
        .unwrap();
    assert_eq!(first.packet, endpoint.pop_outgoing().unwrap().packet);
    assert_eq!(calls.get(), 1);
    assert_eq!(
        TransmissionParameters::default().exchange_lifetime(),
        247000
    );
    #[cfg(feature = "get-server")]
    {
        use core::{
            future::Future,
            task::{Context, Poll, Waker},
        };
        use mai_coap::{
            time::Clock,
            transport::{Datagram, Transport},
        };
        struct Socket<'a> {
            request: &'a [u8],
            receives: core::cell::Cell<u16>,
            sends: core::cell::Cell<usize>,
        }
        impl Transport for Socket<'_> {
            type Error = ();
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
            type Error = ();
            type Packet<'a>
                = Datagram<'a>
            where
                Self: 'a;
            async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, ()> {
                // Keep the fixture bounded if the scripted send sequence changes.
                if self.receives.get() == 2 {
                    return Err(());
                }
                let request = self.request;
                scratch[..request.len()].copy_from_slice(request);
                scratch[2..4].copy_from_slice(&(100 + self.receives.get()).to_be_bytes());
                self.receives.set(self.receives.get() + 1);
                Ok(Datagram {
                    bytes: &scratch[..request.len()],
                    metadata: Metadata::new(
                        "192.0.2.1:5683".parse().unwrap(),
                        "192.0.2.2".parse().unwrap(),
                        request.len(),
                    ),
                })
            }
        }
        impl mai_coap::transport::DatagramSender for &Socket<'_> {
            type Error = ();
            fn poll_send(
                &mut self,
                _: core::net::SocketAddr,
                _: Option<core::net::IpAddr>,
                _: Option<u32>,
                bytes: &[u8],
                _cx: &mut core::task::Context<'_>,
            ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>>
            {
                core::task::Poll::Ready(
                    (|| -> Result<(), ()> {
                        let message = MessageView::parse(bytes).unwrap();
                        assert_eq!(message.payload(), b"embedded");
                        self.sends.set(self.sends.get() + 1);
                        // Avoid linking a formatter used only by this fixture.
                        assert!(message.message_id() == 99 + self.sends.get() as u16);
                        if self.sends.get() == 1 {
                            Ok(())
                        } else {
                            Err(())
                        }
                    })()
                    .map(|()| mai_coap::transport::SendOutcome::Accepted),
                )
            }
        }
        struct Timer;
        impl Clock for Timer {
            fn now(&self) -> Instant {
                Instant(2)
            }
            async fn sleep_until(&self, _: Instant) {
                core::future::pending::<()>().await;
            }
        }
        let mut socket = Socket {
            request: &bytes[..n],
            receives: core::cell::Cell::new(0),
            sends: core::cell::Cell::new(0),
        };
        {
            let mut driver = core::pin::pin!(application.run(&mut endpoint, &mut socket, &Timer));
            assert!(matches!(
                driver
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Err(mai_coap::endpoint::RunError::Transport(())))
            ));
        }
        assert!(socket.receives.get() == 2);
        assert_eq!(socket.sends.get(), 2);
        assert_eq!(calls.get(), 3);
        #[cfg(feature = "shared-counters")]
        {
            // Debug formatting would dominate the snapshot's measured flash cost.
            assert!(shared.counters() == endpoint.counters());
            assert_eq!(shared.handle().counters().requests, 3);
            assert_eq!(shared.counters().send_failures, 1);
        }
    }
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    let handle = shared.handle();
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    let operation = handle
        .client(metadata.remote)
        .parameters(TransmissionParameters::default())
        .unwrap()
        .request_raw(&bytes[..n])
        .unwrap()
        .token_length(8)
        .unwrap()
        .wait_for_nstart(false)
        .send()
        .unwrap();
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    endpoint.poll(Instant(2)).unwrap();
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    let sent = endpoint.pop_outgoing().unwrap();
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    endpoint.poll(Instant(3002)).unwrap();
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    assert_eq!(sent.packet, endpoint.pop_outgoing().unwrap().packet);
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    drop(operation);
    #[cfg(all(feature = "client", not(feature = "get-server")))]
    endpoint.poll(Instant(3003)).unwrap();
}

#[cfg(feature = "block")]
#[inline(never)]
fn block2() {
    use mai_coap::{block::Block, server::BodyWindow};
    let mut output = [0; 8];
    let mut window = BodyWindow::new(4, &mut output);
    window.write(b"block-two").unwrap();
    let chunk = window
        .finish(mai_coap::codec::ContentFormat::TEXT, 60)
        .unwrap();
    assert_eq!(&output[..chunk.written], b"k-two");
    assert_eq!(chunk.total, Some(9));
    assert_eq!(Block::new(0, false, 0).unwrap().offset(), Ok(0));
}

#[inline(never)]
#[cfg(all(feature = "block1", not(feature = "get-server")))]
fn blocks() {
    use mai_coap::block::{Block, BufferedUpload, Progress};
    let mut upload = BufferedUpload::<32>::new(Instant(1000));
    assert_eq!(
        upload.push(
            Block::new(0, true, 0).unwrap(),
            &[7; 16],
            Some(18),
            Instant(0),
            Instant(1000)
        ),
        Ok(Progress::Continue)
    );
    assert_eq!(
        upload.push(
            Block::new(1, false, 0).unwrap(),
            &[9; 2],
            Some(18),
            Instant(1),
            Instant(1000)
        ),
        Ok(Progress::Complete)
    );
    assert_eq!(upload.complete_body().unwrap().len(), 18);
    assert!(Block::decode(7).is_err());
}
#[cfg(feature = "observe")]
#[inline(never)]
fn observe() {
    let mut ordering = mai_coap::__test_support::Ordering::default();
    assert!(ordering.accept(0xffffff, Instant(0)));
    assert!(ordering.accept(0, Instant(1)));
    assert!(!ordering.accept(0xffffff, Instant(2)));
    assert!(ordering.accept(0xffffff, Instant(128003)));
}

#[cfg(feature = "proxy")]
#[inline(never)]
fn proxy() {
    use mai_coap::{
        endpoint::Application,
        proxy::{ForwardProxy, Routing},
    };
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
            true
        }
    }
    static SHARED: Shared<256, 4> = Shared::new();
    let mut endpoint = Endpoint::<_, 256, 4, 4, 1>::new(&SHARED, Unsecured(TestRng(4))).unwrap();
    let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    let mut app = ForwardProxy::<_, _, 256, 4, 1>::new(local, Route, SHARED.handle()).unwrap();
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 5, b"t").unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://192.0.2.3/x")
        .unwrap();
    let n = b.finish(&[]).unwrap();
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    endpoint
        .receive(
            &bytes[..n],
            metadata,
            Instant(0),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .code(),
        Code::EMPTY
    );
    endpoint.poll(Instant(0)).unwrap();
    let sent = endpoint.pop_outgoing().unwrap();
    let request = MessageView::parse(sent.packet.as_slice()).unwrap();
    let n = Response::<256>::new(Code::CONTENT)
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            request.message_id(),
            request.token(),
        )
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(sent.remote, metadata.local, n).with_interface(metadata.interface),
            Instant(1),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    app.poll(
        Instant(1),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    endpoint.poll(Instant(1)).unwrap();
    app.poll(
        Instant(1),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    assert!(endpoint.pop_outgoing().is_some());
}

#[cfg(feature = "discovery")]
#[inline(never)]
fn discovery() {
    use mai_coap::server::Router;
    let policy = PublicPaths(&[(Code::GET, "/.well-known/core"), (Code::GET, "/x")]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    let mut router = Router::<128, 1, 1, 32>::new(&policy);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 2, 1>::new(&shared, Unsecured(TestRng(4))).unwrap();
    let mut bytes = [0; 128];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"d").unwrap();
    mai_coap::uri::path_options("/.well-known/core", &mut b).unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let packet = endpoint.pop_outgoing().unwrap().packet;
    let message = MessageView::parse(packet.as_slice()).unwrap();
    assert_eq!(
        mai_coap::link_format::Links::new(message.payload())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .href(),
        "/x"
    );
}

#[cfg(feature = "oscore")]
#[inline(never)]
fn oscore() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        oscore::{Context, ResponseNonce},
        security::PeerId,
    };
    let mut crypto = SoftwareCrypto::new(TestRng(7));
    let mut client = Context::derive(
        &mut crypto,
        &[1; 16],
        Some(&[2; 8]),
        &[0],
        &[1],
        None,
        PeerId(1),
    )
    .unwrap();
    let mut server = Context::derive(
        &mut crypto,
        &[1; 16],
        Some(&[2; 8]),
        &[1],
        &[0],
        None,
        PeerId(2),
    )
    .unwrap();
    let mut plain = [0; 128];
    let mut b =
        MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    let mut wire = [0; 128];
    let (used, mut cb) = client
        .protect_request::<128>(
            &mut crypto,
            MessageView::parse(&plain[..n]).unwrap(),
            &mut wire,
        )
        .unwrap();
    let mut decoded = [0; 128];
    let (n, mut sb) = server
        .unprotect_request::<128>(
            &mut crypto,
            MessageView::parse(&wire[..used]).unwrap(),
            &mut decoded,
        )
        .unwrap();
    assert_eq!(MessageView::parse(&decoded[..n]).unwrap().code(), Code::GET);
    assert!(
        server
            .unprotect_request::<128>(
                &mut crypto,
                MessageView::parse(&wire[..used]).unwrap(),
                &mut decoded
            )
            .is_err()
    );
    let n = Response::<128>::new(Code::CONTENT)
        .encode(&mut plain, MessageType::Acknowledgement, 1, b"t")
        .unwrap();
    let n = server
        .protect_response::<128>(
            &mut crypto,
            MessageView::parse(&plain[..n]).unwrap(),
            &mut sb,
            ResponseNonce::Fresh,
            &mut wire,
        )
        .unwrap();
    let n = client
        .unprotect_response::<128>(
            &mut crypto,
            MessageView::parse(&wire[..n]).unwrap(),
            &mut cb,
            &mut decoded,
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(&decoded[..n]).unwrap().code(),
        Code::CONTENT
    );
    assert_eq!(client.next_sequence(), 1);
}

// QEMU's micro:bit has 16 KiB RAM; the full two-role fixture runs on larger machines.
#[cfg(all(feature = "edhoc", small_ram))]
#[inline(never)]
fn edhoc() {
    let mut crypto = mai_coap::crypto::SoftwareCrypto::new(TestRng(3));
    let (initiator, message) =
        mai_coap::edhoc::Initiator::start::<64>(&mut crypto, &[1], &[2]).unwrap();
    assert_eq!(initiator.connection_id(), &[1]);
    assert!(message.as_slice().starts_with(&[3, 2, 0x58, 0x20]));
}

#[cfg(all(feature = "edhoc", not(small_ram)))]
#[inline(never)]
fn edhoc() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        edhoc::{Identity, Initiator, Responder, TrustedPeer},
        security::PeerId,
    };
    fn key(value: &[u8; 64]) -> [u8; 32] {
        fn digit(c: u8) -> u8 {
            if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
        }
        let mut result = [0; 32];
        for (i, pair) in value.as_chunks::<2>().0.iter().enumerate() {
            result[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        result
    }
    let mut identity_crypto = SoftwareCrypto::new(TestRng(5));
    let own_i = Identity::new(
        include_bytes!("../../tests/fixtures/i.ccs"),
        key(b"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"),
        &mut identity_crypto,
    )
    .unwrap();
    let own_r = Identity::new(
        include_bytes!("../../tests/fixtures/r.ccs"),
        key(b"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"),
        &mut identity_crypto,
    )
    .unwrap();
    let trust_i =
        TrustedPeer::new(PeerId(1), include_bytes!("../../tests/fixtures/i.ccs")).unwrap();
    let trust_r =
        TrustedPeer::new(PeerId(2), include_bytes!("../../tests/fixtures/r.ccs")).unwrap();
    let mut crypto = SoftwareCrypto::new(TestRng(3));
    let mut responder_crypto = SoftwareCrypto::new(TestRng(4));
    let (initiator, m1) = Initiator::start::<256>(&mut crypto, &[1], &[2]).unwrap();
    assert_eq!(initiator.connection_id(), &[1]);
    assert!(m1.as_slice().starts_with(&[3, 2, 0x58, 0x20]));
    let (responder, m2) =
        Responder::start::<256>(&mut responder_crypto, &own_r, &[2], m1.as_slice(), false).unwrap();
    let (m3, initiator_keys) = initiator
        .finish::<256>(&mut crypto, &own_i, &trust_r, m2.as_slice(), false)
        .unwrap();
    let responder_keys = responder
        .finish(&mut responder_crypto, &[trust_i], m3.as_slice())
        .unwrap();
    let mut client = initiator_keys.into_context(&mut crypto).unwrap();
    let mut server = responder_keys.into_context(&mut responder_crypto).unwrap();
    let mut plain = [0; 128];
    let mut wire = [0; 128];
    let mut decoded = [0; 128];
    let n = MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    let (used, _) = client
        .protect_request::<128>(
            &mut crypto,
            MessageView::parse(&plain[..n]).unwrap(),
            &mut wire,
        )
        .unwrap();
    let (used, _) = server
        .unprotect_request::<128>(
            &mut responder_crypto,
            MessageView::parse(&wire[..used]).unwrap(),
            &mut decoded,
        )
        .unwrap();
    assert_eq!(&plain[..n], &decoded[..used]);
    assert!(mai_coap::__test_support::combined_message_3_length(&[0x58, 0x12, 0]).is_err());
}
#[path = "../../tests/support/outgoing.rs"]
mod outgoing;
use outgoing::PopOutgoing;
