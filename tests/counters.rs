//! Shared counter snapshots while the socket driver owns the endpoint.
#![cfg(all(feature = "server", feature = "shared-counters"))]

mod support;

use core::{
    cell::{Cell, RefCell},
    net::{IpAddr, SocketAddr},
    task::Context,
};
#[cfg(feature = "observe")]
use mai_coap::{Error, transport::Metadata};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Application, Counters, Disposition, Endpoint, Protection, Request, ResponseWriter,
        RunError, ServerShared, Shared, Unsecured,
    },
    security::AllowAll,
    time::Instant,
    transport::{Datagram, Transport},
};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Wake, Waker},
};

struct RecoverableReceive(support::Socket);
impl Transport for RecoverableReceive {
    type Error = support::Unreachable;
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
impl mai_coap::transport::DatagramReceiver for &RecoverableReceive {
    type Error = support::Unreachable;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;

    fn discard_receive_error(_: &Self::Error) -> bool {
        true
    }

    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
        let (length, metadata) = {
            let mut inner = &self.0;
            let packet = inner.receive(scratch).await?;
            (packet.bytes.len(), packet.metadata)
        };
        Ok(Datagram {
            bytes: &scratch[..length],
            metadata,
        })
    }
}
impl mai_coap::transport::DatagramSender for &RecoverableReceive {
    type Error = support::Unreachable;
    fn discard_send_error(error: &Self::Error) -> bool {
        <&support::Socket>::discard_send_error(error)
    }
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        (&self.0).poll_send(remote, source, interface, bytes, cx)
    }
}

struct ReportingProtection<'a, const COMMANDS: usize> {
    inner: Unsecured<rand::rngs::ThreadRng>,
    shared: &'a Shared<128, COMMANDS>,
    handshakes: &'a Cell<u64>,
    evictions: &'a Cell<u64>,
}
impl<const COMMANDS: usize> Protection for ReportingProtection<'_, COMMANDS> {
    mai_coap::delegate_protection!(inner, (); except [handshake_runs, context_evictions]);

    fn handshake_runs(&self) -> u64 {
        let _ = self.shared.counters();
        self.handshakes.get()
    }
    fn context_evictions(&self) -> u64 {
        let _ = self.shared.handle().counters();
        self.evictions.get()
    }
}

struct Status<'a, const COMMANDS: usize> {
    shared: &'a Shared<128, COMMANDS>,
    handled: &'a RefCell<Vec<Counters>>,
    polled: &'a Cell<Counters>,
    polls: &'a Cell<usize>,
}
impl<const COMMANDS: usize> Application<128> for Status<'_, COMMANDS> {
    fn handle(
        &mut self,
        _: Request<'_>,
        response: &mut ResponseWriter<'_, 128>,
    ) -> Result<Disposition, Code> {
        let counters = self.shared.handle().counters();
        assert_eq!(counters, self.shared.counters());
        self.handled.borrow_mut().push(counters);
        response.set_payload(&[
            counters.requests as u8,
            counters.dedup_reply_drops as u8,
            counters.dropped_messages as u8,
        ])?;
        Ok(Disposition::Complete)
    }
    fn recognizes(&self, _: OptionNumber) -> bool {
        false
    }
    fn poll(&mut self, _: Instant, _: &mut Context<'_>) {
        self.polls.set(self.polls.get() + 1);
        self.polled.set(self.shared.counters());
    }
}

#[derive(Default)]
struct CountWake(AtomicUsize);
impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn api_8_snapshots_are_readable_from_handlers_poll_and_other_tasks_without_command_slots() {
    fn check<const COMMANDS: usize>(shared: &Shared<128, COMMANDS>) {
        assert_eq!(shared.counters(), Counters::default());
        assert_eq!(shared.handle().counters(), Counters::default());
        let network = support::Network::default();
        network.configure(0, &[support::Action::Unreachable]);
        let socket = network.socket("192.0.2.2:5683");
        let local = socket.local;
        let peer = "192.0.2.1:5683".parse().unwrap();
        let mut socket = RecoverableReceive(socket);
        let handshakes = Cell::new(7);
        let evictions = Cell::new(3);
        let protection = ReportingProtection {
            inner: Unsecured(rand::rng()),
            shared,
            handshakes: &handshakes,
            evictions: &evictions,
        };
        let mut endpoint =
            Endpoint::<_, 128, 0, 8, 0, 1, 2, COMMANDS, 0, 0, 2>::new(shared, protection).unwrap();
        let handled = RefCell::new(Vec::new());
        let polled = Cell::new(Counters::default());
        let polls = Cell::new(0);
        let mut app = Status {
            shared,
            handled: &handled,
            polled: &polled,
            polls: &polls,
        };
        let wake = Arc::new(CountWake::default());
        let waker = Waker::from(wake.clone());
        let mut cx = Context::from_waker(&waker);
        {
            let mut driver =
                core::pin::pin!(endpoint.run(&mut socket, &network, &mut app, &AllowAll));
            assert!(driver.as_mut().poll(&mut cx).is_pending());
            assert_eq!(shared.counters().edhoc_runs, 7);
            assert_eq!(shared.counters().context_evictions, 3);
            for mid in 1..=3 {
                if mid == 3 {
                    handshakes.set(9);
                    evictions.set(5);
                }
                let mut bytes = [0; 128];
                let n =
                    MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, mid, &[1])
                        .unwrap()
                        .finish(&[])
                        .unwrap();
                network.inject(peer, local, &bytes[..n]);
                assert!(driver.as_mut().poll(&mut cx).is_pending());
                let counters = shared.counters();
                assert_eq!(counters, shared.handle().counters());
                assert_eq!(counters.requests, u64::from(mid));
                assert_eq!(counters.dropped_messages, 1);
                assert_eq!(counters.dedup_reply_drops, u64::from(mid - 1));
                assert_eq!(polled.get(), counters);
            }
            assert_eq!(shared.counters().edhoc_runs, 9);
            assert_eq!(shared.counters().context_evictions, 5);
            let wakes = wake.0.load(Ordering::Relaxed);
            let before = polls.get();
            for _ in 0..4 {
                assert_eq!(shared.counters(), shared.handle().counters());
            }
            assert_eq!(wake.0.load(Ordering::Relaxed), wakes);
            assert!(driver.as_mut().poll(&mut cx).is_pending());
            assert_eq!(
                polls.get(),
                before,
                "reading counters must not schedule another pass"
            );
        }
        assert_eq!(shared.counters(), endpoint.counters());
        assert_eq!(handled.borrow().len(), 3);
        assert_eq!(handled.borrow()[0].requests, 0);
        assert_eq!(handled.borrow()[2].dedup_reply_drops, 1);
        assert_eq!(handled.borrow()[2].dropped_messages, 1);
        let sent = network.sent();
        assert_eq!(
            MessageView::parse(&sent[2].bytes).unwrap().payload(),
            &[2, 1, 1]
        );
    }
    let server = const { ServerShared::<128>::new() };
    check(&server);
    check(&Shared::<128, 2>::new());
}

#[test]
fn api_8_rate_rejections_are_published_while_the_driver_owns_the_endpoint() {
    let shared = ServerShared::<128>::new();
    let mut endpoint =
        mai_coap::endpoint::ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    endpoint
        .set_rate_limits(mai_coap::rate::Limits::default().with_source_burst(1))
        .unwrap();
    let calls = Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(b"cached")?;
        Ok(Disposition::Complete)
    };
    let network = support::Network::default();
    let mut socket = network.socket("192.0.2.2:5683");
    let local = socket.local;
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    assert_eq!(shared.counters().rate_limited, 0);
    {
        let mut driver = core::pin::pin!(endpoint.run(&mut socket, &network, &mut app, &AllowAll));
        let mut cx = Context::from_waker(Waker::noop());
        for rate_limited in 0..=2 {
            network.inject(peer, local, &bytes[..n]);
            assert!(driver.as_mut().poll(&mut cx).is_pending());
            assert_eq!(shared.counters().rate_limited, rate_limited);
            assert_eq!(shared.handle().counters(), shared.counters());
            assert_eq!(shared.counters().requests, 1);
            assert_eq!(shared.counters().duplicates, 0);
            assert_eq!(shared.counters().dropped_messages, 0);
        }
        network.advance(1000);
        network.inject(peer, local, &bytes[..n]);
        assert!(driver.as_mut().poll(&mut cx).is_pending());
        assert_eq!(shared.counters().rate_limited, 2);
        assert_eq!(shared.counters().duplicates, 1);
    }
    assert_eq!(calls.get(), 1);
    let sent = network.sent();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].bytes, sent[1].bytes);
    assert_eq!(shared.counters(), endpoint.counters());
}

struct FatalSend(support::Socket);
impl Transport for FatalSend {
    type Error = support::Unreachable;
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
impl mai_coap::transport::DatagramReceiver for &FatalSend {
    type Error = support::Unreachable;
    type Packet<'a>
        = Datagram<'a>
    where
        Self: 'a;

    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
        let (length, metadata) = {
            let mut inner = &self.0;
            let packet = inner.receive(scratch).await?;
            (packet.bytes.len(), packet.metadata)
        };
        Ok(Datagram {
            bytes: &scratch[..length],
            metadata,
        })
    }
}
impl mai_coap::transport::DatagramSender for &FatalSend {
    type Error = support::Unreachable;
    fn poll_send(
        &mut self,
        _: SocketAddr,
        _: Option<IpAddr>,
        _: Option<u32>,
        _: &[u8],
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        core::task::Poll::Ready(
            Err(support::Unreachable).map(|()| mai_coap::transport::SendOutcome::Accepted),
        )
    }
}

#[test]
fn api_8_final_snapshot_includes_the_fatal_send_failure() {
    let shared = const { ServerShared::<128>::new() };
    let mut endpoint =
        mai_coap::endpoint::ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let network = support::Network::default();
    let mut socket = FatalSend(network.socket("192.0.2.2:5683"));
    let mut bytes = [0; 4];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[])
        .unwrap()
        .finish(&[])
        .unwrap();
    network.inject(
        "192.0.2.1:5683".parse().unwrap(),
        socket.0.local,
        &bytes[..n],
    );
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    {
        let mut driver = core::pin::pin!(endpoint.run(&mut socket, &network, &mut app, &AllowAll));
        assert!(matches!(
            driver
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            core::task::Poll::Ready(Err(RunError::Transport(support::Unreachable)))
        ));
    }
    let counters = shared.counters();
    assert_eq!(counters.requests, 1);
    assert_eq!(counters.send_failures, 1);
    assert_eq!(counters, endpoint.counters());
    assert_eq!(shared.handle().counters(), counters);
}

#[cfg(feature = "observe")]
#[test]
fn api_8_idle_snapshot_includes_a_notification_dropped_during_resource_polling() {
    struct FailingNotification<'a> {
        inner: Unsecured<rand::rngs::ThreadRng>,
        fail: &'a Cell<bool>,
    }
    impl Protection for FailingNotification<'_> {
        mai_coap::delegate_protection!(inner, (); except [incoming, response]);

        fn incoming<const D: usize>(
            &mut self,
            request: MessageView<'_>,
            metadata: Metadata,
            output: &mut [u8],
        ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
            let (n, security, _) = self.inner.incoming::<D>(request, metadata, output)?;
            Ok((n, security, Some(())))
        }
        fn response<const D: usize>(
            &mut self,
            response: MessageView<'_>,
            binding: &mut (),
            output: &mut [u8],
        ) -> Result<usize, Error> {
            if self.fail.get() {
                return Err(Error::SequenceExhausted);
            }
            self.inner.response::<D>(response, binding, output)
        }
    }
    let shared = const { ServerShared::<128>::new() };
    let fail = Cell::new(false);
    let mut endpoint = Endpoint::<_, 128, 1, 4, 1, 1, 2, 0, 0, 0, 2>::new(
        &shared,
        FailingNotification {
            inner: Unsecured(rand::rng()),
            fail: &fail,
        },
    )
    .unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.set_payload(b"value")?;
        Ok(Disposition::Complete)
    };
    let mut router = mai_coap::server::Router::<128, 1, 0, 0>::new(&AllowAll);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    let resource = mai_coap::server::Router::observable(
        &mut router,
        "/x",
        mai_coap::observe::Settings::new(7),
    )
    .unwrap();
    let mut bytes = [0; 128];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[1]).unwrap();
    builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    builder.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = builder.finish(&[]).unwrap();
    let network = support::Network::default();
    let mut socket = network.socket("192.0.2.2:5683");
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new("192.0.2.1:5683".parse().unwrap(), socket.local.ip(), n),
            Instant(0),
            &mut router,
            &AllowAll,
        )
        .unwrap();
    assert!(endpoint.front_outgoing().is_some());
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    fail.set(true);
    shared.handle().notify(resource).unwrap();
    {
        let mut driver =
            core::pin::pin!(endpoint.run(&mut socket, &network, &mut router, &AllowAll));
        assert!(
            driver
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let counters = shared.counters();
        assert_eq!(counters.requests, 1);
        assert_eq!(counters.dropped_messages, 1);
        assert_eq!(counters.protection_failures, 1);
        assert!(network.sent().is_empty());
    }
    assert_eq!(shared.counters(), endpoint.counters());
}
