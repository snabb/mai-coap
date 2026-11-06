//! Routing, peer identity, profiles and worker-side storage.
#![cfg(all(feature = "server", feature = "client"))]
mod support;
use futures_lite::future::block_on;
#[cfg(any(
    feature = "block1",
    all(feature = "edhoc", feature = "software-crypto", feature = "proxy")
))]
use futures_lite::future::poll_once;
#[cfg(any(feature = "block1", feature = "software-crypto"))]
use mai_coap::Error;
use mai_coap::{
    codec::{Code, MessageType, MessageView, OptionNumber},
    endpoint::{Application, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    security::PublicPaths,
    time::Instant,
};
use support::PopOutgoing;

#[test]
fn api_4_builder_orders_options_and_snapshots_route_and_profile() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let profile = TransmissionParameters::default().with_ack_timeout_ms(10000);
    let mut target = mai_coap::endpoint::Target::new(remote);
    target.source = Some("192.0.2.2".parse().unwrap());
    target.interface = Some(7);
    let client = shared
        .handle()
        .client(target)
        .parameters(profile)
        .unwrap()
        .through_proxy();
    let _operation = client
        .request(Code::PUT, "coap://node.example/x?q=1")
        .unwrap()
        .option(OptionNumber::LOCATION_PATH, b"a")
        .unwrap()
        .option(OptionNumber::IF_MATCH, b"tag")
        .unwrap()
        .option(OptionNumber::LOCATION_PATH, b"b")
        .unwrap()
        .payload(b"body")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let first = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        (first.remote, first.source, first.interface),
        (remote, Some("192.0.2.2".parse().unwrap()), Some(7))
    );
    let message = MessageView::parse(first.packet.as_slice()).unwrap();
    assert_eq!(
        message.option(OptionNumber::URI_HOST).unwrap().value,
        b"node.example"
    );
    assert_eq!(
        message
            .values(OptionNumber::LOCATION_PATH)
            .collect::<Vec<_>>(),
        [b"a", b"b"]
    );
    assert_eq!(
        message.option(OptionNumber::PROXY_SCHEME).unwrap().value,
        b"coap"
    );
    assert_eq!(message.payload(), b"body");
    endpoint.poll(Instant(9999)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    endpoint.poll(Instant(15000)).unwrap();
    let retry = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        (retry.source, retry.interface, retry.packet),
        (first.source, first.interface, first.packet)
    );
}

#[test]
fn api_1_owned_response_keeps_independent_option_and_payload_bounds() {
    for payload_first in [false, true] {
        let mut response = Response::<8>::new(Code::CONTENT);
        if payload_first {
            response.set_payload(&[0xa5; 8]).unwrap();
        }
        response.option(OptionNumber::ETAG, &[0x5a; 8]).unwrap();
        response.set_payload(&[0xa5; 8]).unwrap();
        assert_eq!(
            response.set_payload(&[0; 9]),
            Err(mai_coap::endpoint::ResponseError::Capacity)
        );
        let mut output = [0; 32];
        let len = response
            .encode(&mut output, MessageType::Acknowledgement, 7, &[1; 8])
            .unwrap();
        assert_eq!(len, 30);
        let message = MessageView::parse(&output[..len]).unwrap();
        assert_eq!(
            message.option(OptionNumber::ETAG).unwrap().value,
            &[0x5a; 8]
        );
        assert_eq!(message.payload(), &[0xa5; 8]);
        assert_eq!(message.token(), &[1; 8]);
    }
}

#[test]
fn api_1_ordered_add_and_replace_preserve_repeats_and_failure_atomicity() {
    let mut response = Response::<32>::new(Code::CONTENT);
    response.option(OptionNumber::LOCATION_PATH, b"a").unwrap();
    response.option(OptionNumber::IF_MATCH, b"").unwrap();
    response.option(OptionNumber::LOCATION_PATH, b"b").unwrap();
    response.option(OptionNumber::ETAG, b"old").unwrap();
    response.set_option(OptionNumber::ETAG, b"new").unwrap();
    response.set_option(OptionNumber::IF_MATCH, b"").unwrap();
    let before = response.clone();
    assert_eq!(
        response.set_option(OptionNumber::ETAG, &[0; 33]),
        Err(mai_coap::endpoint::ResponseError::Capacity)
    );
    let mut a = [0; 64];
    let mut b = [0; 64];
    let n = response
        .encode(&mut a, MessageType::Acknowledgement, 1, &[])
        .unwrap();
    assert_eq!(
        n,
        before
            .encode(&mut b, MessageType::Acknowledgement, 1, &[])
            .unwrap()
    );
    assert_eq!(a, b);
    let message = MessageView::parse(&a[..n]).unwrap();
    assert_eq!(
        message
            .values(OptionNumber::LOCATION_PATH)
            .collect::<Vec<_>>(),
        [b"a", b"b"]
    );
    assert_eq!(message.option(OptionNumber::ETAG).unwrap().value, b"new");
}

struct Wrapped<A>(A);
impl<A: Application<D>, const D: usize> Application<D> for Wrapped<A> {
    mai_coap::delegate_application!(0, D; except [handle]);
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, D>,
    ) -> Result<mai_coap::endpoint::Disposition, Code> {
        self.0.handle(request, response)
    }
}

#[test]
fn tr_4_receive_metadata_failure_is_counted_and_socket_failure_still_stops_driver() {
    use mai_coap::{
        endpoint::RunError,
        transport::{Datagram, Transport},
    };
    #[derive(Debug, Eq, PartialEq)]
    enum Failure {
        Metadata,
        Socket,
    }
    struct Socket(core::cell::Cell<bool>);
    impl Transport for Socket {
        type Error = Failure;
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
        type Error = Failure;
        type Packet<'a>
            = Datagram<'a>
        where
            Self: 'a;
        fn discard_receive_error(error: &Failure) -> bool {
            *error == Failure::Metadata
        }
        async fn receive<'a>(&'a mut self, _: &'a mut [u8]) -> Result<Datagram<'a>, Failure> {
            if self.0.replace(false) {
                Err(Failure::Metadata)
            } else {
                Err(Failure::Socket)
            }
        }
    }
    impl mai_coap::transport::DatagramSender for &Socket {
        type Error = Failure;
        fn poll_send(
            &mut self,
            _: core::net::SocketAddr,
            _: Option<core::net::IpAddr>,
            _: Option<u32>,
            _: &[u8],
            _cx: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
            core::task::Poll::Ready(Ok(()).map(|()| mai_coap::transport::SendOutcome::Accepted))
        }
    }
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = Wrapped(|_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND));
    let result = block_on(endpoint.run(
        &mut Socket(core::cell::Cell::new(true)),
        &support::Network::default(),
        &mut app,
        &PublicPaths(&[]),
    ));
    assert!(matches!(result, Err(RunError::Transport(Failure::Socket))));
    assert_eq!(endpoint.counters().dropped_messages, 1);
}

#[cfg(feature = "proxy")]
#[test]
fn api_4_proxy_uses_separate_endpoints_and_wakes_the_incoming_driver() {
    use mai_coap::{
        codec::MessageBuilder,
        proxy::{ForwardProxy, Routing},
        security::ProtectedOnly,
        transport::Metadata,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Wake(AtomicUsize);
    impl std::task::Wake for Wake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
            true
        }
    }
    let incoming = Shared::<256, 2>::new();
    let outgoing = Shared::<256, 3>::new();
    let mut inbound = Endpoint::<_, 256, 2, 4>::new(&incoming, Unsecured(rand::rng())).unwrap();
    let mut outbound = Endpoint::<_, 256, 3, 4>::new(&outgoing, Unsecured(rand::rng())).unwrap();
    let mut proxy = ForwardProxy::<_, _, 256, 2, 2, 3>::with_outbound(
        Wrapped(|_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND)),
        Route,
        incoming.handle(),
        outgoing.handle(),
    )
    .unwrap();
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a").unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = b.finish(&[]).unwrap();
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    )
    .with_interface(Some(1));
    inbound
        .receive(
            &bytes[..n],
            metadata,
            Instant(0),
            &mut proxy,
            &ProtectedOnly,
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(inbound.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .code(),
        Code::EMPTY
    );
    outbound.poll(Instant(0)).unwrap();
    let upstream = outbound.pop_outgoing().unwrap();
    let wake = Arc::new(Wake(AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wake.clone());
    let mut cx = core::task::Context::from_waker(&waker);
    inbound
        .poll_resources(Instant(0), &mut proxy, &ProtectedOnly, &mut cx)
        .unwrap();
    let request = MessageView::parse(upstream.packet.as_slice()).unwrap();
    let n = Response::<256>::new(Code::CONTENT)
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            request.message_id(),
            request.token(),
        )
        .unwrap();
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    outbound
        .receive(
            &bytes[..n],
            Metadata::new(upstream.remote, metadata.local, n).with_interface(metadata.interface),
            Instant(1),
            &mut unused,
            &ProtectedOnly,
        )
        .unwrap();
    assert!(
        wake.0.load(Ordering::SeqCst) > 0,
        "upstream completion must wake the receiving driver"
    );
    inbound
        .poll_resources(Instant(1), &mut proxy, &ProtectedOnly, &mut cx)
        .unwrap();
    inbound.poll(Instant(1)).unwrap();
    let response = inbound.pop_outgoing().unwrap();
    assert_eq!(response.remote, metadata.remote);
    assert_eq!(
        MessageView::parse(response.packet.as_slice())
            .unwrap()
            .code(),
        Code::CONTENT
    );
}

#[cfg(feature = "block1")]
#[test]
fn rel_2_all_block_continuations_use_the_configured_slow_link_profile() {
    use futures_lite::future::race;
    use mai_coap::endpoint::Disposition;
    use mai_coap::{
        codec::ContentFormat,
        server::{Router, SliceBody},
    };
    block_on(async {
        let network = support::Network::default();
        network.configure(4000, &[]);
        let cs = Shared::<256, 2>::new();
        let ss = Shared::<256, 2>::new();
        let mut client = Endpoint::<_, 256, 2, 8>::new(&cs, Unsecured(rand::rng())).unwrap();
        let mut server = Endpoint::<_, 256, 2, 8>::new(&ss, Unsecured(rand::rng())).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let remote = b.local;
        let body = [7; 80];
        let mut source = {
            let mut body = SliceBody::new(&body, ContentFormat::OCTET_STREAM);
            body.etag = b"one";
            body.max_age = 60;
            body
        };
        let mut upload = |request: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            assert_eq!(request.payload(), body);
            response.set_code(Code::CHANGED);
            Ok(Disposition::Complete)
        };
        let policy = PublicPaths(&[(Code::GET, "/data"), (Code::PUT, "/image")]);
        let mut router = Router::<256, 2, 1, 128>::new(&policy);
        router.representation("/data", &mut source).unwrap();
        router
            .buffered_upload("/image", &[Code::PUT], &mut upload)
            .unwrap();
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let drivers = race(
            client.run(&mut a, &network, &mut unused, &policy),
            router.run(&mut server, &mut b, &network),
        );
        let mut drivers = core::pin::pin!(drivers);
        let configured = cs
            .handle()
            .client(remote)
            .parameters(
                TransmissionParameters::default()
                    .with_ack_timeout_ms(10000)
                    .with_ack_random_factor(1000),
            )
            .unwrap();
        let operations = async {
            let mut output = [0; 80];
            assert_eq!(
                configured
                    .get_blocks("/data", 0, &mut output)
                    .await
                    .unwrap(),
                80
            );
            assert_eq!(output, body);
            assert_eq!(
                configured
                    .upload(Code::PUT, "/image", ContentFormat::OCTET_STREAM, &body, 0)
                    .await
                    .unwrap()
                    .message()
                    .unwrap()
                    .code(),
                Code::CHANGED
            );
        };
        let mut operations = core::pin::pin!(operations);
        let mut done = false;
        for _ in 0..2000 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            if poll_once(operations.as_mut()).await.is_some() {
                done = true;
                break;
            }
            network.advance(250);
        }
        assert!(done);
        for code in [Code::GET, Code::PUT] {
            let sent = network.sent();
            let count = sent
                .iter()
                .filter(|p| {
                    p.from == "192.0.2.1:5683".parse().unwrap()
                        && MessageView::parse(&p.bytes).unwrap().code() == code
                })
                .count();
            assert_eq!(
                count, 5,
                "each of the five blocks must use the long timeout without retries"
            );
        }
    });
}

#[cfg(feature = "block1")]
#[test]
fn api_7_async_upload_worker_preserves_transactions_duplicates_and_cancellation() {
    use mai_coap::{
        block::{Block, BodyKey},
        codec::MessageBuilder,
        server::{
            Router,
            work::{
                WorkQueue,
                upload::{AsyncUploadSink, UploadWorker},
            },
        },
        time::Clock,
        transport::Metadata,
    };
    use std::{cell::RefCell, rc::Rc};
    #[derive(Default)]
    struct State {
        writes: usize,
        commits: usize,
        aborts: usize,
        stall: bool,
        fail: bool,
    }
    struct Sink(Rc<RefCell<State>>);
    impl AsyncUploadSink for Sink {
        async fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            Ok(())
        }
        async fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
            let stall = self.0.borrow().stall;
            if stall {
                core::future::pending::<()>().await;
            }
            if self.0.borrow().fail {
                return Err(Error::Capacity);
            }
            self.0.borrow_mut().writes += 1;
            Ok(())
        }
        async fn commit(&mut self) -> Result<(), Error> {
            self.0.borrow_mut().commits += 1;
            Ok(())
        }
        fn abort(&mut self) {
            self.0.borrow_mut().aborts += 1;
        }
    }
    let clock = support::Network::default();
    let queue = WorkQueue::<256, 2>::new();
    let mut handler = queue.handler(1000).unwrap();
    let policy = PublicPaths(&[(Code::PUT, "/image")]);
    let mut router = Router::<256, 1>::new(&policy);
    router.route("/image", &[Code::PUT], &mut handler).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut mid = 0;
    let mut previous = None;
    let mut enqueue = |remote: &str, number, more| {
        if let Some(ticket) = previous.take() {
            let operation = shared
                .handle()
                .respond(ticket, &Response::new(Code::CHANGED))
                .unwrap();
            endpoint.poll(clock.now()).unwrap();
            match block_on(poll_once(operation))
                .expect("response submission must complete in this poll")
            {
                Ok(_) => assert!(endpoint.pop_outgoing().is_some()),
                Err(Error::Cancelled) => assert!(endpoint.pop_outgoing().is_none()),
                Err(error) => panic!("unexpected ticket result: {error}"),
            }
        }
        mid += 1;
        endpoint
            .poll_resources(
                clock.now(),
                &mut router,
                &policy,
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            )
            .unwrap();
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::PUT,
            mid,
            b"x",
        )
        .unwrap();
        b.option(OptionNumber::URI_PATH, b"image").unwrap();
        b.uint_option(
            OptionNumber::BLOCK1,
            Block::new(number, more, 0).unwrap().encode().unwrap(),
        )
        .unwrap();
        let n = b.finish(&[7; 16]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                Metadata::new(remote.parse().unwrap(), "192.0.2.2".parse().unwrap(), n),
                clock.now(),
                &mut router,
                &policy,
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_none());
        let job = block_on(poll_once(queue.next())).expect("request must reach the worker");
        previous = Some(job.ticket());
        job
    };
    let state = Rc::new(RefCell::new(State::default()));
    let mut worker = UploadWorker::new(&queue, Sink(state.clone()), 1024, 1000).unwrap();
    let first = enqueue("192.0.2.1:5683", 0, true);
    assert_eq!(
        block_on(worker.process(&first, &clock)).code(),
        Code::CONTINUE
    );
    let repeat = enqueue("192.0.2.1:5683", 0, true);
    assert_eq!(
        block_on(worker.process(&repeat, &clock)).code(),
        Code::CONTINUE
    );
    assert_eq!(state.borrow().writes, 1);
    let other = enqueue("192.0.2.3:5683", 0, true);
    assert_eq!(
        block_on(worker.process(&other, &clock)).code(),
        Code::UNAVAILABLE
    );
    let final_block = enqueue("192.0.2.1:5683", 1, false);
    assert_eq!(
        block_on(worker.process(&final_block, &clock)).code(),
        Code::CHANGED
    );
    let repeat = enqueue("192.0.2.1:5683", 1, false);
    assert_eq!(
        block_on(worker.process(&repeat, &clock)).code(),
        Code::CHANGED
    );
    assert_eq!((state.borrow().writes, state.borrow().commits), (2, 1));
    state.borrow_mut().stall = true;
    let restart = enqueue("192.0.2.1:5683", 0, true);
    let before = state.borrow().aborts;
    assert!(block_on(poll_once(worker.process(&restart, &clock))).is_none());
    assert!(
        state.borrow().aborts > before,
        "cancelled writes must invalidate staging"
    );
    state.borrow_mut().stall = false;
    let continuation = enqueue("192.0.2.1:5683", 1, false);
    assert_eq!(
        block_on(worker.process(&continuation, &clock)).code(),
        Code::INCOMPLETE
    );
    assert_eq!(state.borrow().commits, 1);
    state.borrow_mut().fail = true;
    let failed = enqueue("192.0.2.1:5683", 0, false);
    assert_eq!(
        block_on(worker.process(&failed, &clock)).code(),
        Code::INTERNAL_ERROR
    );
    assert_eq!(state.borrow().commits, 1);
    state.borrow_mut().fail = false;
    let restarted = enqueue("192.0.2.1:5683", 0, true);
    assert_eq!(
        block_on(worker.process(&restarted, &clock)).code(),
        Code::CONTINUE
    );
    let before = state.borrow().aborts;
    clock.advance(1100);
    worker.expire(clock.now());
    assert!(state.borrow().aborts > before);
    let late = enqueue("192.0.2.1:5683", 1, false);
    assert_eq!(
        block_on(worker.process(&late, &clock)).code(),
        Code::INCOMPLETE
    );
    assert_eq!(state.borrow().commits, 1);
    let restarted = enqueue("192.0.2.1:5683", 0, true);
    assert_eq!(
        block_on(worker.process(&restarted, &clock)).code(),
        Code::CONTINUE
    );
    let before = state.borrow().aborts;
    drop(worker);
    assert!(
        state.borrow().aborts > before,
        "dropping an incomplete worker must abort staging"
    );
}

#[cfg(feature = "software-crypto")]
#[test]
#[cfg(feature = "block1")]
fn api_7_cancelling_async_begin_aborts_staging_and_releases_the_body_epoch() {
    use mai_coap::{
        block::BodyKey,
        codec::MessageBuilder,
        crypto::SoftwareCrypto,
        oscore::{Context, Oscore},
        security::{PeerId, ProtectedOnly},
        server::{
            Router,
            work::{
                WorkQueue,
                upload::{AsyncUploadSink, UploadWorker},
            },
        },
        transport::Metadata,
    };
    use std::{cell::Cell, rc::Rc};
    struct Sink(Rc<Cell<usize>>);
    impl AsyncUploadSink for Sink {
        async fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            core::future::pending().await
        }
        async fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        async fn commit(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn abort(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let mut provider = SoftwareCrypto::new(rand::rng());
    let mut client =
        Context::derive(&mut provider, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
    let mut protection = Oscore::<_, 1>::new(SoftwareCrypto::new(rand::rng()));
    let context = Context::derive(
        &mut SoftwareCrypto::new(rand::rng()),
        &[1; 16],
        None,
        &[1],
        &[0],
        None,
        PeerId(1),
    )
    .unwrap();
    protection.install_fresh(context).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, protection).unwrap();
    let queue = WorkQueue::<256, 2>::new();
    let mut handler = queue.handler(1000).unwrap();
    let mut router = Router::<256, 1>::new(&ProtectedOnly);
    router.route("/image", &[Code::PUT], &mut handler).unwrap();
    let mut plain = [0; 256];
    let mut b =
        MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::PUT, 1, b"x").unwrap();
    b.option(OptionNumber::URI_PATH, b"image").unwrap();
    b.uint_option(OptionNumber::BLOCK1, 8).unwrap();
    let n = b.finish(&[7; 16]).unwrap();
    let mut wire = [0; 256];
    let (n, _) = client
        .protect_request::<256>(
            &mut provider,
            MessageView::parse(&plain[..n]).unwrap(),
            &mut wire,
        )
        .unwrap();
    endpoint
        .receive(
            &wire[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut router,
            &ProtectedOnly,
        )
        .unwrap();
    let job = block_on(poll_once(queue.next())).unwrap();
    let epoch = job.request().unwrap().context.unwrap();
    assert!(queue.contains_context(epoch));
    let aborts = Rc::new(Cell::new(0));
    let mut worker = UploadWorker::new(&queue, Sink(aborts.clone()), 1024, 1000).unwrap();
    assert!(
        block_on(poll_once(
            worker.process(&job, &support::Network::default())
        ))
        .is_none()
    );
    assert!(aborts.get() > 0);
    assert!(
        !queue.contains_context(epoch),
        "cancelled begin must not retain the epoch until timeout"
    );
}

#[cfg(feature = "software-crypto")]
#[test]
fn api_2_peer_selection_survives_route_changes_and_transparent_protection_wrapper() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        endpoint::{Protection, Target},
        oscore::{Context, Oscore},
        security::{PeerId, SecurityState},
        transport::Metadata,
    };
    struct WrappedProtection<P>(P);
    impl<P: Protection> Protection for WrappedProtection<P> {
        mai_coap::delegate_protection!(0, P::Binding; except [outgoing]);
        fn outgoing<const N: usize>(
            &mut self,
            target: Target,
            request: MessageView<'_>,
            output: &mut [u8],
        ) -> Result<mai_coap::endpoint::Prepared<Self::Binding>, Error> {
            self.0.outgoing::<N>(target, request, output)
        }
    }
    let original: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let mut oscore = Oscore::<_, 2>::new(SoftwareCrypto::new(rand::rng()));
    let mut receivers = Vec::new();
    for peer in [1, 2] {
        let context = Context::derive(
            &mut SoftwareCrypto::new(rand::rng()),
            &[peer; 16],
            None,
            &[0],
            &[peer],
            None,
            PeerId(peer.into()),
        )
        .unwrap();
        oscore.install_fresh(context).unwrap();
        let mut receiver = Oscore::<_, 2>::new(SoftwareCrypto::new(rand::rng()));
        let context = Context::derive(
            &mut SoftwareCrypto::new(rand::rng()),
            &[peer; 16],
            None,
            &[peer],
            &[0],
            None,
            PeerId(peer.into()),
        )
        .unwrap();
        receiver.install_fresh(context).unwrap();
        receivers.push(receiver);
    }
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, WrappedProtection(oscore)).unwrap();
    for (index, peer) in [1, 2].into_iter().enumerate() {
        let remote = "192.0.2.99:5683".parse().unwrap();
        let operation = shared
            .handle()
            .client(remote)
            .peer(PeerId(peer))
            .request(Code::GET, "coap://node.example/x")
            .unwrap()
            .send()
            .unwrap();
        endpoint.poll(Instant(index as u64)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(outgoing.remote, remote);
        let mut plain = [0; 256];
        let (_, security, binding) = receivers[index]
            .incoming::<256>(
                MessageView::parse(outgoing.packet.as_slice()).unwrap(),
                Metadata::new(remote, remote.ip(), outgoing.packet.as_slice().len()),
                &mut plain,
            )
            .unwrap();
        assert_eq!(security, SecurityState::Protected { peer: PeerId(peer) });
        receivers[index].release(binding.unwrap());
        drop(operation);
        endpoint.poll(Instant(index as u64 + 1)).unwrap();
    }
    let mut target = Target::new(original);
    target.peer = Some(PeerId(3));
    let operation = shared
        .handle()
        .client(target)
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(10)).unwrap();
    assert_eq!(block_on(operation).unwrap_err(), Error::ContextNotFound);
    assert!(endpoint.pop_outgoing().is_none());
}

#[cfg(all(feature = "edhoc", feature = "software-crypto", feature = "proxy"))]
#[test]
fn api_2_edh_4_two_peers_through_one_proxy_with_empty_and_single_byte_kids() {
    use core::net::SocketAddr;
    use futures_lite::future::race;
    use mai_coap::endpoint::Disposition;
    use mai_coap::{
        crypto::SoftwareCrypto,
        edhoc::{Identity, TrustedPeer, TrustedPeers, endpoint::Edhoc},
        proxy::{ForwardProxy, Routing},
        security::{PeerId, ProtectedOnly, SecurityState},
    };
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: SocketAddr, host: &str, _: u16) -> bool {
            matches!(host, "one.example" | "two.example")
        }
        fn resolve(&self, host: &str, _: u16) -> Option<SocketAddr> {
            match host {
                "one.example" => Some("192.0.2.3:5683".parse().unwrap()),
                "two.example" => Some("192.0.2.4:5683".parse().unwrap()),
                _ => None,
            }
        }
    }
    let initiator = include_bytes!("fixtures/client-kid-01.ccs");
    let responder = include_bytes!("fixtures/node-empty-kid.ccs");
    let mut trusted = TrustedPeers::<2>::new();
    for peer in [1, 2] {
        trusted
            .insert(TrustedPeer::new(PeerId(peer), responder).unwrap())
            .unwrap();
    }
    let mut identity_crypto = SoftwareCrypto::new(rand::rng());
    let protection = Edhoc::<_, 4, 2, _>::with_store(
        SoftwareCrypto::new(rand::rng()),
        Identity::new(
            initiator,
            support::hex("fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"),
            &mut identity_crypto,
        )
        .unwrap(),
        trusted,
    )
    .unwrap();
    let server = || {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let identity = Identity::new(
            responder,
            support::hex("72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"),
            &mut crypto,
        )
        .unwrap();
        let mut p = Edhoc::<_, 4, 2>::new(crypto, identity).unwrap();
        p.trust(TrustedPeer::new(PeerId(9), initiator).unwrap())
            .unwrap();
        p
    };
    block_on(async {
        let network = support::Network::default();
        let cs = Shared::<512, 4>::new();
        let ps = Shared::<512, 4>::new();
        let s1 = Shared::<512, 2>::new();
        let s2 = Shared::<512, 2>::new();
        let mut client = Endpoint::<_, 512, 4, 8>::new(&cs, protection).unwrap();
        let mut proxy = Endpoint::<_, 512, 4, 8>::new(&ps, Unsecured(rand::rng())).unwrap();
        let mut one = Endpoint::<_, 512, 2, 8>::new(&s1, server()).unwrap();
        let mut two = Endpoint::<_, 512, 2, 8>::new(&s2, server()).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let mut c = network.socket("192.0.2.3:5683");
        let mut d = network.socket("192.0.2.4:5683");
        let mut unused =
            Wrapped(|_: Request<'_>, _: &mut ResponseWriter<'_, 512>| Err(Code::NOT_FOUND));
        let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| Err(Code::NOT_FOUND);
        let mut forward = ForwardProxy::<_, _, 512, 4>::new(local, Route, ps.handle()).unwrap();
        let app = || {
            |request: Request<'_>, response: &mut ResponseWriter<'_, 512>| {
                assert_eq!(
                    request.security,
                    SecurityState::Protected { peer: PeerId(9) }
                );
                response.set_payload(b"ok").unwrap();
                Ok(Disposition::Complete)
            }
        };
        let mut app1 = app();
        let mut app2 = app();
        let drivers = race(
            race(
                client.run(&mut a, &network, &mut unused, &ProtectedOnly),
                proxy.run(&mut b, &network, &mut forward, &ProtectedOnly),
            ),
            race(
                one.run(&mut c, &network, &mut app1, &ProtectedOnly),
                two.run(&mut d, &network, &mut app2, &ProtectedOnly),
            ),
        );
        let mut drivers = core::pin::pin!(drivers);
        let base = cs
            .handle()
            .client("192.0.2.2:5683".parse::<core::net::SocketAddr>().unwrap())
            .parameters(
                TransmissionParameters::default()
                    .with_nstart(2)
                    .with_ack_timeout_ms(10000),
            )
            .unwrap()
            .through_proxy();
        let mut first = core::pin::pin!(
            base.peer(PeerId(1))
                .combined_edhoc(false)
                .get("coap://one.example/x")
        );
        let mut second = core::pin::pin!(base.peer(PeerId(2)).get("coap://two.example/x"));
        let (mut done1, mut done2) = (false, false);
        for _ in 0..1000 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            if !done1 && let Some(reply) = poll_once(first.as_mut()).await {
                assert_eq!(reply.unwrap().message().unwrap().payload(), b"ok");
                done1 = true;
            }
            if !done2 && let Some(reply) = poll_once(second.as_mut()).await {
                assert_eq!(reply.unwrap().message().unwrap().payload(), b"ok");
                done2 = true;
            }
            if done1 && done2 {
                break;
            }
            network.advance(1);
        }
        assert!(
            done1 && done2,
            "both logical peers must complete through one next hop"
        );
    });
}
