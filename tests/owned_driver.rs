//! Ownership and cancellation invariants at the endpoint/socket handoff (TR-7).
#![cfg(all(feature = "server", feature = "client", feature = "_xarxa"))]
use core::{
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    XarxaStorage,
    codec::{Code, MessageBuilder, MessageType},
    endpoint::{
        Disposition, Endpoint, Request, Response, ResponseWriter, RunError, ServerEndpoint,
        ServerShared, Shared, Unsecured,
    },
    security::AllowAll,
    time::{Clock, Instant},
    transport::{
        DatagramReceiver, DatagramSender, Metadata, OwnedDatagramSender, ReceivedPacket, Transport,
    },
};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};
use xarxa::{Pool, StaticPool, driver::PacketBuf};

const D: usize = 128;
type Driver<'a, S> =
    Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 1, 8, 0, 2, 4, 1, 0, 0, 4, S>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Failure {
    Datagram,
    Socket,
}
#[derive(Default)]
struct State {
    incoming: VecDeque<(Vec<u8>, Metadata)>,
    sent: Vec<(Vec<u8>, Option<usize>)>,
    send_metadata: Vec<(SocketAddr, Option<IpAddr>, Option<u32>)>,
    allocations: Vec<usize>,
    allocation_attempts: Vec<u64>,
    copy_pool: Option<&'static dyn Pool>,
    copy_attempts: usize,
    sleep_deadlines: Vec<Instant>,
    blocked: bool,
    retry_until: Option<u64>,
    send_attempts: Vec<u64>,
    send_waker: Option<Waker>,
    error: Option<Failure>,
    now: u64,
}
struct Incoming(Vec<u8>, Metadata);
impl ReceivedPacket for Incoming {
    fn bytes(&self) -> &[u8] {
        &self.0
    }
    fn metadata(&self) -> Metadata {
        self.1
    }
}
#[derive(Clone)]
struct Socket(Rc<RefCell<State>>);
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
        = Incoming
    where
        Self: 'a;
    fn receive_buffer<const N: usize>() -> impl AsMut<[u8]> {
        []
    }

    async fn receive<'a>(&'a mut self, scratch: &'a mut [u8]) -> Result<Incoming, Failure> {
        assert!(scratch.is_empty());
        poll_fn(|_| {
            self.0
                .borrow_mut()
                .incoming
                .pop_front()
                .map_or(Poll::Pending, |(bytes, meta)| {
                    Poll::Ready(Ok(Incoming(bytes, meta)))
                })
        })
        .await
    }
}
impl mai_coap::transport::DatagramSender for &Socket {
    type Error = Failure;
    fn discard_send_error(error: &Failure) -> bool {
        matches!(error, Failure::Datagram)
    }
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        (|| {
            let mut state = self.0.borrow_mut();
            let now = state.now;
            state.send_attempts.push(now);
            state.send_metadata.push((remote, source, interface));
            if state.retry_until.is_some_and(|until| now < until) {
                return Poll::Ready(Ok(mai_coap::transport::SendOutcome::RetryLater));
            }
            if state.blocked {
                state.send_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            if let Some(error) = state.error.take() {
                return Poll::Ready(Err(error));
            }
            if let Some(pool) = state.copy_pool {
                state.copy_attempts += 1;
                let Some(mut packet) = pool.alloc() else {
                    return Poll::Ready(Ok(mai_coap::transport::SendOutcome::RetryLater));
                };
                packet.set_len(bytes.len());
                packet.copy_from_slice(bytes);
            }
            state.sent.push((bytes.to_vec(), None));
            Poll::Ready(Ok(mai_coap::transport::SendOutcome::Accepted))
        })()
    }
}
impl OwnedDatagramSender<PacketBuf> for &Socket {
    fn poll_send_owned(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        packet: &mut Option<PacketBuf>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<mai_coap::transport::SendOutcome, Failure>> {
        let mut state = self.0.borrow_mut();
        let now = state.now;
        state.send_attempts.push(now);
        state.send_metadata.push((remote, source, interface));
        if state.retry_until.is_some_and(|until| now < until) {
            return Poll::Ready(Ok(mai_coap::transport::SendOutcome::RetryLater));
        }
        if state.blocked {
            state.send_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if let Some(error) = state.error.take() {
            return Poll::Ready(Err(error));
        }
        let packet = packet.take().expect("live queue buffer");
        state
            .sent
            .push((packet.to_vec(), Some(packet.as_ptr() as usize)));
        Poll::Ready(Ok(mai_coap::transport::SendOutcome::Accepted))
    }
}
// Exercise the default hook through a wrapper: forgetting to delegate restores D bytes.
struct Wrapped<T>(T);
impl<T: Transport> Transport for Wrapped<T> {
    type Error = T::Error;
    type Receiver<'a>
        = Wrapped<T::Receiver<'a>>
    where
        Self: 'a;
    type Sender<'a>
        = Wrapped<T::Sender<'a>>
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
        let (r, t) = self.0.split();
        (Wrapped(r), Wrapped(t))
    }
}
impl<T: DatagramReceiver> DatagramReceiver for Wrapped<T> {
    type Error = T::Error;
    type Packet<'a>
        = T::Packet<'a>
    where
        Self: 'a;
    fn receive_buffer<const N: usize>() -> impl AsMut<[u8]> {
        T::receive_buffer::<N>()
    }
    fn discard_receive_error(e: &Self::Error) -> bool {
        T::discard_receive_error(e)
    }
    async fn receive<'a>(
        &'a mut self,
        scratch: &'a mut [u8],
    ) -> Result<Self::Packet<'a>, Self::Error> {
        self.0.receive(scratch).await
    }
}
impl<T: DatagramSender> DatagramSender for Wrapped<T> {
    type Error = T::Error;
    fn discard_send_error(e: &Self::Error) -> bool {
        T::discard_send_error(e)
    }
    fn poll_send(
        &mut self,
        r: SocketAddr,
        s: Option<IpAddr>,
        i: Option<u32>,
        bytes: &[u8],
        cx: &mut Context<'_>,
    ) -> Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        self.0.poll_send(r, s, i, bytes, cx)
    }
}
impl<B, T: OwnedDatagramSender<B>> OwnedDatagramSender<B> for Wrapped<T> {
    fn poll_send_owned(
        &mut self,
        r: SocketAddr,
        s: Option<IpAddr>,
        i: Option<u32>,
        p: &mut Option<B>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
        self.0.poll_send_owned(r, s, i, p, cx)
    }
}
#[derive(Clone)]
struct Timer(Rc<RefCell<State>>);
impl Clock for Timer {
    fn now(&self) -> Instant {
        Instant(self.0.borrow().now)
    }
    async fn sleep_until(&self, deadline: Instant) {
        self.0.borrow_mut().sleep_deadlines.push(deadline);
        poll_fn(|_| {
            if self.now() >= deadline {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await
    }
}
fn poll<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn request(ty: MessageType, mid: u16) -> (Vec<u8>, Metadata) {
    let mut wire = [0; D];
    let length = MessageBuilder::new(&mut wire, ty, Code::GET, mid, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    (
        wire[..length].to_vec(),
        Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            length,
        )
        .with_interface(Some(7)),
    )
}
fn storage<const N: usize>(
    pool: &'static StaticPool<D, N>,
    state: &Rc<RefCell<State>>,
) -> XarxaStorage<impl FnMut() -> Option<PacketBuf>, 4> {
    let state = state.clone();
    XarxaStorage::new(move || {
        let now = state.borrow().now;
        state.borrow_mut().allocation_attempts.push(now);
        let packet = pool.alloc()?;
        state
            .borrow_mut()
            .allocations
            .push(packet.as_ptr() as usize);
        Some(packet)
    })
}
fn reply(_: Request<'_>, response: &mut ResponseWriter<'_, D>) -> Result<Disposition, Code> {
    response.set_payload(b"reply")?;
    Ok(Disposition::Complete)
}

#[test]
fn slow_handler_starts_new_reply_budget_after_processing_without_refreshing_old_packets() {
    static POOL: StaticPool<D, 8> = StaticPool::new();
    for owned in [false, true] {
        for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
            for old_packet in [false, true] {
                for wait_ms in [0, 999, 1000] {
                    let shared = Shared::<D, 1>::new();
                    let state = Rc::new(RefCell::new(State {
                        now: 500,
                        blocked: wait_ms != 0,
                        ..Default::default()
                    }));
                    let mut endpoint = Driver::with_storage(
                        &shared,
                        Unsecured(rand::rng()),
                        storage(&POOL, &state),
                    )
                    .unwrap();
                    if old_packet {
                        let (bytes, metadata) = request(ty, 1);
                        endpoint
                            .receive(&bytes, metadata, Instant(0), &mut reply, &AllowAll)
                            .unwrap();
                    }
                    state.borrow_mut().incoming.push_back(request(ty, 2));
                    let mut socket = Socket(state.clone());
                    let clock = Timer(state.clone());
                    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
                        state.borrow_mut().now = 2500;
                        response.set_payload(b"slow")?;
                        Ok(Disposition::Complete)
                    };
                    let mut driver: Pin<Box<dyn Future<Output = _>>> = if owned {
                        Box::pin(endpoint.run_owned(&mut socket, &clock, &mut app, &AllowAll))
                    } else {
                        Box::pin(endpoint.run(&mut socket, &clock, &mut app, &AllowAll))
                    };
                    assert!(poll(driver.as_mut()).is_pending());
                    drop(driver);
                    if wait_ms != 0 {
                        assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2500));
                        state.borrow_mut().now = 2500 + wait_ms;
                        state.borrow_mut().blocked = false;
                        let mut driver: Pin<Box<dyn Future<Output = _>>> = if owned {
                            Box::pin(endpoint.run_owned(&mut socket, &clock, &mut app, &AllowAll))
                        } else {
                            Box::pin(endpoint.run(&mut socket, &clock, &mut app, &AllowAll))
                        };
                        assert!(poll(driver.as_mut()).is_pending());
                        drop(driver);
                    }
                    let expired = wait_ms == 1000;
                    assert_eq!(state.borrow().sent.len(), usize::from(!expired));
                    if !expired {
                        assert_eq!(
                            state.borrow().send_attempts.last().copied(),
                            Some(2500 + wait_ms)
                        );
                        assert_eq!(
                            mai_coap::codec::MessageView::parse(&state.borrow().sent[0].0)
                                .unwrap()
                                .payload(),
                            b"slow"
                        );
                    }
                    assert_eq!(
                        endpoint.counters().local_send_timeouts,
                        u64::from(old_packet) + u64::from(expired)
                    );
                    assert_eq!(endpoint.counters().send_failures, 0);
                }
            }
        }
    }
}

#[test]
fn older_reply_keeps_only_its_remaining_budget_after_another_handler_runs() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State {
        now: 2000,
        blocked: true,
        ..Default::default()
    }));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let (bytes, metadata) = request(MessageType::Confirmable, 1);
    endpoint
        .receive(&bytes, metadata, Instant(2000), &mut reply, &AllowAll)
        .unwrap();
    state
        .borrow_mut()
        .incoming
        .push_back(request(MessageType::Confirmable, 2));
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        state.borrow_mut().now = 2500;
        response.set_payload(b"new")?;
        Ok(Disposition::Complete)
    };
    for now in [2000, 3000, 3499] {
        state.borrow_mut().now = now;
        state.borrow_mut().blocked = now != 3499;
        assert!(
            poll(core::pin::pin!(endpoint.run_owned(
                &mut socket,
                &clock,
                &mut app,
                &AllowAll
            )))
            .is_pending()
        );
        if now == 2000 {
            assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2000));
        } else if now == 3000 {
            assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2500));
            assert_eq!(endpoint.deadline(Instant(now)), Instant(3500));
            assert_eq!(endpoint.counters().local_send_timeouts, 1);
        }
    }
    assert_eq!(state.borrow().sent.len(), 1);
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    assert_eq!(
        mai_coap::codec::MessageView::parse(&state.borrow().sent[0].0)
            .unwrap()
            .payload(),
        b"new"
    );
}

#[test]
fn resuming_driver_does_not_restart_an_existing_send_budget() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State {
        now: 900,
        blocked: true,
        ..Default::default()
    }));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let (bytes, metadata) = request(MessageType::NonConfirmable, 1);
    endpoint
        .receive(&bytes, metadata, Instant(0), &mut reply, &AllowAll)
        .unwrap();
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(0));
    state.borrow_mut().now = 1000;
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    assert!(state.borrow().sent.is_empty());
}

#[test]
fn sole_owner_transfers_original_serialization_buffer_through_wrapper() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    state
        .borrow_mut()
        .incoming
        .push_back(request(MessageType::NonConfirmable, 1));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let mut socket = Wrapped(Socket(state.clone()));
    let clock = Timer(state.clone());
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    let state = state.borrow();
    assert_eq!(state.sent.len(), 1);
    assert_eq!(state.sent[0].1, Some(state.allocations[0]));
    assert!(endpoint.front_outgoing().is_none());
}

#[test]
fn cached_confirmable_reply_uses_borrowed_bytes_and_dispatches_once() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    state.borrow_mut().incoming.extend([
        request(MessageType::Confirmable, 1),
        request(MessageType::Confirmable, 1),
    ]);
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    let mut calls = 0;
    let mut application = |request: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        calls += 1;
        reply(request, response)
    };
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(calls, 1);
    let state = state.borrow();
    assert_eq!(state.sent.len(), 2);
    assert_eq!(state.sent[0], state.sent[1]);
    assert_eq!(state.sent[0].1, None);
}

#[test]
fn two_packet_server_retains_cached_reply_during_copy_pool_shortage() {
    use mai_coap::codec::MessageView;

    static POOL: StaticPool<D, 2> = StaticPool::new();
    let shared = ServerShared::<D>::new();
    let state = Rc::new(RefCell::new(State {
        copy_pool: Some(&POOL),
        ..Default::default()
    }));
    let storage = XarxaStorage::<_, 2>::new(|| POOL.alloc());
    let mut endpoint =
        ServerEndpoint::<_, D, _>::with_storage(&shared, Unsecured(rand::rng()), storage).unwrap();
    let mut calls = 0;
    let mut application = |request: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        calls += 1;
        reply(request, response)
    };
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    state.borrow_mut().incoming.extend([
        request(MessageType::Confirmable, 1),
        request(MessageType::Confirmable, 2),
    ]);
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(state.borrow().sent.len(), 1);
    assert_eq!(state.borrow().sent[0].1, None);
    assert_eq!(state.borrow().copy_attempts, 2);
    assert!(POOL.alloc().is_none());
    assert!(endpoint.front_outgoing().is_some());
    assert_eq!(endpoint.counters().send_failures, 0);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    state.borrow_mut().now = 1000;
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    assert_eq!(endpoint.counters().dropped_messages, 1);
    assert_eq!(endpoint.counters().dedup_reply_drops, 0);

    // A NON response reclaims the oldest cached reply and transfers its sole buffer.
    state
        .borrow_mut()
        .incoming
        .push_back(request(MessageType::NonConfirmable, 3));
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    assert_eq!(state.borrow().sent.len(), 2);
    assert!(state.borrow().sent[1].1.is_some());
    state
        .borrow_mut()
        .incoming
        .push_back(request(MessageType::Confirmable, 2));
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(calls, 3, "discarding a send must preserve the cached reply");
    let state = state.borrow();
    assert_eq!(state.copy_attempts, 3);
    assert_eq!(state.sent.len(), 3);
    assert_eq!(state.sent[2].1, None);
    assert_eq!(
        MessageView::parse(&state.sent[2].0).unwrap().message_id(),
        2
    );
}

#[test]
fn cancelled_and_failed_owned_sends_leave_exact_queue_bytes_for_restart() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State {
        blocked: true,
        ..Default::default()
    }));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let (wire, meta) = request(MessageType::NonConfirmable, 1);
    endpoint
        .receive(&wire, meta, Instant(0), &mut reply, &AllowAll)
        .unwrap();
    let before = endpoint.front_outgoing().unwrap().bytes.to_vec();
    let pointer = endpoint.front_outgoing().unwrap().bytes.as_ptr() as usize;
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, before);
    state.borrow_mut().blocked = false;
    state.borrow_mut().error = Some(Failure::Socket);
    assert!(matches!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        ))),
        Poll::Ready(Err(RunError::Transport(Failure::Socket)))
    ));
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, before);
    assert_eq!(
        endpoint.front_outgoing().unwrap().bytes.as_ptr() as usize,
        pointer
    );
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(state.borrow().sent[0], (before, Some(pointer)));
}

#[test]
fn recoverable_owned_error_discards_one_packet_and_continues() {
    static POOL: StaticPool<D, 4> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State {
        error: Some(Failure::Datagram),
        ..Default::default()
    }));
    state.borrow_mut().incoming.extend([
        request(MessageType::NonConfirmable, 1),
        request(MessageType::NonConfirmable, 2),
    ]);
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut reply,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(state.borrow().sent.len(), 1);
    assert_eq!(endpoint.counters().send_failures, 1);
    assert_eq!(endpoint.counters().dropped_messages, 1);
}

#[test]
fn network_exhaustion_reclaims_cache_even_with_free_logical_slots() {
    static POOL: StaticPool<D, 1> = StaticPool::new();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    for mid in 1..=2 {
        let (wire, meta) = request(MessageType::Confirmable, mid);
        endpoint
            .receive(&wire, meta, Instant(0), &mut reply, &AllowAll)
            .unwrap();
        assert!(endpoint.front_outgoing().is_some());
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    let (wire, meta) = request(MessageType::Confirmable, 1);
    let mut calls = 0;
    let mut application = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| {
        calls += 1;
        Ok(Disposition::Complete)
    };
    endpoint
        .receive(&wire, meta, Instant(0), &mut application, &AllowAll)
        .unwrap();
    assert_eq!(calls, 0);
}

#[test]
fn only_confirmable_client_wire_is_kept_for_retransmission() {
    for confirmable in [false, true] {
        static POOL: StaticPool<D, 8> = StaticPool::new();
        let shared = Shared::<D, 1>::new();
        let state = Rc::new(RefCell::new(State::default()));
        let mut endpoint =
            Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
        let operation = shared
            .handle()
            .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
            .request(Code::GET, "/")
            .unwrap()
            .confirmable(confirmable)
            .send()
            .unwrap();
        let mut socket = Socket(state.clone());
        let clock = Timer(state.clone());
        assert!(
            poll(core::pin::pin!(endpoint.run_owned(
                &mut socket,
                &clock,
                &mut reply,
                &AllowAll
            )))
            .is_pending()
        );
        assert_eq!(state.borrow().sent.len(), 1);
        assert_eq!(state.borrow().sent[0].1.is_some(), !confirmable);
        if confirmable {
            state.borrow_mut().now = 4000;
            assert!(
                poll(core::pin::pin!(endpoint.run_owned(
                    &mut socket,
                    &clock,
                    &mut reply,
                    &AllowAll
                )))
                .is_pending()
            );
            let state = state.borrow();
            assert_eq!(state.sent.len(), 2);
            assert_eq!(state.sent[0], state.sent[1]);
        }
        drop(operation);
    }
}

#[test]
fn waiting_request_survives_backing_exhaustion_with_free_logical_slots() {
    static POOL: StaticPool<D, 1> = StaticPool::new();
    let held = POOL.alloc().unwrap();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let operation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/")
        .unwrap()
        .wait_for_nstart(true)
        .send()
        .unwrap();
    let mut operation = core::pin::pin!(operation);
    endpoint.poll(Instant(0)).unwrap();
    assert!(poll(operation.as_mut()).is_pending());
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.deadline(Instant(0)), Instant(1));
    drop(held);
    endpoint.poll(Instant(1)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    assert!(poll(operation.as_mut()).is_pending());
}

#[cfg(feature = "observe")]
#[test]
fn observation_admission_releases_partial_reservations_before_waiting() {
    static POOL: StaticPool<D, 2> = StaticPool::new();
    let held = POOL.alloc().unwrap();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let mut observation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .observe("/")
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert!(poll(core::pin::pin!(observation.next())).is_pending());
    assert!(endpoint.front_outgoing().is_none());
    // The successful first reservation must not leak when the second fails.
    assert!(POOL.alloc().is_some());
    drop(held);
    endpoint.poll(Instant(1)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    assert!(poll(core::pin::pin!(observation.next())).is_pending());
}

#[cfg(feature = "observe")]
#[test]
fn live_observation_refresh_and_cancellation_wait_for_backing_storage() {
    use mai_coap::codec::{MessageView, OptionNumber};
    for cancel in [false, true] {
        static POOL: StaticPool<D, 3> = StaticPool::new();
        let shared = Shared::<D, 1>::new();
        let state = Rc::new(RefCell::new(State::default()));
        let mut endpoint =
            Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
        let mut observation = Some(
            shared
                .handle()
                .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
                .observe("/")
                .unwrap(),
        );
        endpoint.poll(Instant(0)).unwrap();
        let sent = endpoint.front_outgoing().unwrap().bytes.to_vec();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        let sent = MessageView::parse(&sent).unwrap();
        let original_mid = sent.message_id();
        let mut response = [0; D];
        let mut b = MessageBuilder::new(
            &mut response,
            MessageType::Acknowledgement,
            Code::CONTENT,
            sent.message_id(),
            sent.token(),
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.uint_option(OptionNumber::MAX_AGE, 1).unwrap();
        let n = b.finish(b"initial").unwrap();
        let (_, mut meta) = request(MessageType::Confirmable, 0);
        meta.original_len = n;
        endpoint
            .receive(&response[..n], meta, Instant(0), &mut reply, &AllowAll)
            .unwrap();
        assert!(matches!(
            poll(core::pin::pin!(observation.as_mut().unwrap().next())),
            Poll::Ready(Some(Ok(_)))
        ));
        if cancel {
            drop(observation.take());
        }
        let held = [POOL.alloc().unwrap(), POOL.alloc().unwrap()];
        assert!(POOL.alloc().is_none());
        endpoint.poll(Instant(3000)).unwrap();
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.deadline(Instant(3000)), Instant(3001));
        if let Some(observation) = observation.as_mut() {
            assert!(poll(core::pin::pin!(observation.next())).is_pending());
        }
        drop(held);
        endpoint.poll(Instant(3001)).unwrap();
        let sent = endpoint
            .front_outgoing()
            .expect("observation remains live")
            .bytes;
        let refreshed = MessageView::parse(sent).unwrap();
        assert_eq!(
            refreshed.option(OptionNumber::OBSERVE).unwrap().uint(),
            Ok(u64::from(cancel))
        );
        assert_ne!(refreshed.message_id(), original_mid);
        let expected = sent.to_vec();
        state.borrow_mut().now = 3001;
        let mut socket = Socket(state.clone());
        let clock = Timer(state.clone());
        assert!(
            poll(core::pin::pin!(endpoint.run_owned(
                &mut socket,
                &clock,
                &mut reply,
                &AllowAll
            )))
            .is_pending()
        );
        assert_eq!(state.borrow().sent, [(expected, None)]);
    }
}

#[test]
fn persistent_allocator_failure_preserves_other_cached_replies() {
    use core::cell::Cell;
    use mai_coap::Error;
    for undersized in [false, true] {
        static POOL: StaticPool<D, 4> = StaticPool::new();
        static SMALL: StaticPool<D, 1> = StaticPool::new();
        let failing = Cell::new(false);
        let shared = Shared::<D, 1>::new();
        let storage = XarxaStorage::<_, 4>::new(|| {
            if failing.get() {
                if undersized {
                    let mut packet = SMALL.alloc()?;
                    packet.reserve(1);
                    Some(packet)
                } else {
                    None
                }
            } else {
                POOL.alloc()
            }
        });
        let mut endpoint = Driver::with_storage(&shared, Unsecured(rand::rng()), storage).unwrap();
        for mid in 1..=2 {
            let (bytes, meta) = request(MessageType::Confirmable, mid);
            endpoint
                .receive(&bytes, meta, Instant(0), &mut reply, &AllowAll)
                .unwrap();
            endpoint.complete_outgoing(
                endpoint
                    .front_outgoing()
                    .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
            );
        }
        failing.set(true);
        for mid in 3..20 {
            let (bytes, meta) = request(MessageType::Confirmable, mid);
            endpoint
                .receive(&bytes, meta, Instant(0), &mut reply, &AllowAll)
                .unwrap();
            assert!(endpoint.front_outgoing().is_none());
            assert_eq!(
                endpoint.counters().dedup_reply_drops,
                u64::from(!undersized)
            );
        }
        // The newest reply survives even an allocator that never recovers.
        let (bytes, meta) = request(MessageType::Confirmable, 2);
        endpoint
            .receive(
                &bytes,
                meta,
                Instant(0),
                &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| {
                    panic!("cached request redispatched")
                },
                &AllowAll,
            )
            .unwrap();
        assert!(endpoint.front_outgoing().is_some());
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        if !undersized {
            failing.set(false);
            let (bytes, meta) = request(MessageType::Confirmable, 20);
            endpoint
                .receive(&bytes, meta, Instant(0), &mut reply, &AllowAll)
                .unwrap();
            assert!(endpoint.front_outgoing().is_some());
            endpoint.complete_outgoing(
                endpoint
                    .front_outgoing()
                    .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
            );
            failing.set(true);
            for mid in 21..30 {
                let (bytes, meta) = request(MessageType::Confirmable, mid);
                endpoint
                    .receive(&bytes, meta, Instant(0), &mut reply, &AllowAll)
                    .unwrap();
                assert_eq!(endpoint.counters().dedup_reply_drops, 2);
            }
            let (bytes, meta) = request(MessageType::Confirmable, 20);
            endpoint
                .receive(
                    &bytes,
                    meta,
                    Instant(0),
                    &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| {
                        panic!("cached reply lost after recovery")
                    },
                    &AllowAll,
                )
                .unwrap();
            assert!(endpoint.front_outgoing().is_some());
            endpoint.complete_outgoing(
                endpoint
                    .front_outgoing()
                    .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
            );
        }
        if undersized {
            let operation = shared
                .handle()
                .client("192.0.2.9:5683".parse::<SocketAddr>().unwrap())
                .request(Code::GET, "/")
                .unwrap()
                .send()
                .unwrap();
            endpoint.poll(Instant(1)).unwrap();
            assert!(matches!(
                poll(core::pin::pin!(operation)),
                Poll::Ready(Err(Error::InvalidStorage))
            ));
            assert_eq!(endpoint.counters().dedup_reply_drops, 0);
        }
    }
}

#[test]
fn deferred_response_waits_for_network_pool_without_consuming_the_ticket() {
    for expire in [false, true] {
        static POOL: StaticPool<D, 1> = StaticPool::new();
        let shared = Shared::<D, 1>::new();
        type DeferredDriver<'a, S> =
            Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 1, 8, 0, 2, 4, 1, 1, 0, 4, S>;
        let state = Rc::new(RefCell::new(State::default()));
        let mut endpoint =
            DeferredDriver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state))
                .unwrap();
        let ticket = core::cell::Cell::new(None);
        let (bytes, meta) = request(MessageType::Confirmable, 1);
        endpoint
            .receive(
                &bytes,
                meta,
                Instant(0),
                &mut |request: Request<'_>, _: &mut ResponseWriter<'_, D>| {
                    ticket.set(request.deferred_ticket());
                    Ok(Disposition::Deferred)
                },
                &AllowAll,
            )
            .unwrap();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        let held = POOL.alloc().unwrap();
        let operation = shared
            .handle()
            .respond(ticket.get().unwrap(), &Response::new(Code::CONTENT))
            .unwrap();
        let mut operation = core::pin::pin!(operation);
        endpoint.poll(Instant(1)).unwrap();
        assert!(poll(operation.as_mut()).is_pending());
        if expire {
            endpoint.poll(Instant(1_000_000)).unwrap();
            assert!(matches!(
                poll(operation.as_mut()),
                Poll::Ready(Err(mai_coap::Error::Cancelled))
            ));
            assert!(endpoint.front_outgoing().is_none());
            drop(held);
            continue;
        }
        drop(held);
        endpoint.poll(Instant(2)).unwrap();
        assert!(matches!(poll(operation.as_mut()), Poll::Ready(Ok(_))));
        assert!(endpoint.front_outgoing().is_some());
    }
}

#[cfg(feature = "observe")]
#[test]
fn changed_server_notification_retries_without_an_unrelated_wakeup() {
    use core::cell::Cell;
    use mai_coap::{
        codec::{MessageView, OptionNumber},
        observe::Settings,
        server::Router,
    };
    static POOL: StaticPool<D, 1> = StaticPool::new();
    type NotificationDriver<'a, S> =
        Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 1, 8, 1, 2, 4, 1, 0, 0, 4, S>;
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    let calls = Cell::new(0);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        calls.set(calls.get() + 1);
        response.set_payload(b"notification")?;
        Ok(Disposition::Complete)
    };
    let mut application = Router::<D, 1>::new(&AllowAll);
    application.route("/", &[Code::GET], &mut handler).unwrap();
    let resource = application
        .observable("/", Settings::new(7).with_confirmable_ms(86_400_000))
        .unwrap();
    let mut endpoint =
        NotificationDriver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state))
            .unwrap();
    let mut bytes = [0; D];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::NonConfirmable, Code::GET, 1, b"t").unwrap();
    b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    let n = b.finish(&[]).unwrap();
    let (_, mut meta) = request(MessageType::NonConfirmable, 1);
    meta.original_len = n;
    state
        .borrow_mut()
        .incoming
        .push_back((bytes[..n].to_vec(), meta));
    let mut socket = Socket(state.clone());
    let clock = Timer(state.clone());
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(calls.get(), 1);
    let held = POOL.alloc().unwrap();
    shared.handle().notify(resource).unwrap();
    assert!(
        poll(core::pin::pin!(endpoint.run_owned(
            &mut socket,
            &clock,
            &mut application,
            &AllowAll
        )))
        .is_pending()
    );
    assert_eq!(calls.get(), 1, "failed reservation must not dispatch");
    assert_eq!(state.borrow().allocation_attempts, [0, 0]);
    assert_eq!(endpoint.deadline(Instant(0)), Instant(1));
    assert!(endpoint.deadline(Instant(0)) > clock.now());
    let mut driver =
        core::pin::pin!(endpoint.run_owned(&mut socket, &clock, &mut application, &AllowAll));
    assert!(poll(driver.as_mut()).is_pending());
    assert_eq!(state.borrow().allocation_attempts, [0, 0]);
    state.borrow_mut().now = 1;
    assert!(poll(driver.as_mut()).is_pending());
    assert_eq!(state.borrow().allocation_attempts, [0, 0, 1]);
    assert_eq!(state.borrow().sleep_deadlines.last(), Some(&Instant(3)));
    shared.handle().notify(resource).unwrap();
    assert!(poll(driver.as_mut()).is_pending());
    state.borrow_mut().now = 2;
    assert!(poll(driver.as_mut()).is_pending());
    assert_eq!(state.borrow().allocation_attempts, [0, 0, 1]);
    assert_eq!(calls.get(), 1);
    drop(held);
    // Keep the same driver future: restarting it would hide a missing deadline.
    state.borrow_mut().now = 3;
    assert!(poll(driver.as_mut()).is_pending());
    assert_eq!(state.borrow().allocation_attempts, [0, 0, 1, 3]);
    assert_eq!(calls.get(), 2);
    let state = state.borrow();
    assert_eq!(state.sent.len(), 2);
    let message = MessageView::parse(&state.sent[1].0).unwrap();
    assert_eq!(message.option(OptionNumber::OBSERVE).unwrap().uint(), Ok(1));
    assert_eq!(message.payload(), b"notification");
}

#[cfg(feature = "observe")]
#[test]
fn pool_shortage_backoff_caps_and_resets_after_complete_admission() {
    use core::cell::Cell;
    use mai_coap::codec::OptionNumber;
    type RetryDriver<'a, S> =
        Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 2, 8, 0, 2, 4, 2, 0, 0, 4, S>;
    for retained in [false, true] {
        static POOL: StaticPool<D, 2> = StaticPool::new();
        let held: Vec<_> = (0..if retained { 1 } else { 2 })
            .map(|_| POOL.alloc().unwrap())
            .collect();
        let shared = Shared::<D, 2>::new();
        let now = Cell::new(0);
        let attempts = RefCell::new(Vec::new());
        let storage = XarxaStorage::<_, 4>::new(|| {
            attempts.borrow_mut().push(now.get());
            POOL.alloc()
        });
        let mut endpoint =
            RetryDriver::with_storage(&shared, Unsecured(rand::rng()), storage).unwrap();
        let client = shared
            .handle()
            .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap());
        let mut request = client.request(Code::GET, "/").unwrap();
        if retained {
            request = request.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        }
        let operation = request.send().unwrap();
        let mut operation = core::pin::pin!(operation);
        for time in 0..10_000 {
            now.set(time);
            endpoint.poll(Instant(time)).unwrap();
        }
        assert!(poll(operation.as_mut()).is_pending());
        let expected = [
            0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4047, 6047, 8047,
        ];
        let expected: Vec<_> = expected
            .into_iter()
            .flat_map(|time| core::iter::repeat_n(time, if retained { 2 } else { 1 }))
            .collect();
        assert_eq!(*attempts.borrow(), expected);
        assert_eq!(endpoint.deadline(Instant(9999)), Instant(10047));
        drop(held);
        now.set(10047);
        endpoint.poll(Instant(10047)).unwrap();
        assert!(endpoint.front_outgoing().is_some());
        // The first exchange keeps the pool full after recovery; a new shortage
        // must start at 1 ms rather than inherit the old 2-second delay.
        let second = shared
            .handle()
            .client("192.0.2.9:5683".parse::<SocketAddr>().unwrap())
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        let extra = if retained {
            None
        } else {
            Some(POOL.alloc().unwrap())
        };
        now.set(10048);
        endpoint.poll(Instant(10048)).unwrap();
        assert_eq!(endpoint.deadline(Instant(10048)), Instant(10049));
        drop(extra);
        drop(second);
    }
}

#[test]
fn cancelling_a_waiting_command_clears_its_due_storage_wakeup() {
    static POOL: StaticPool<D, 1> = StaticPool::new();
    let held = POOL.alloc().unwrap();
    let shared = Shared::<D, 1>::new();
    let state = Rc::new(RefCell::new(State::default()));
    let mut endpoint =
        Driver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state)).unwrap();
    let operation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert_eq!(endpoint.deadline(Instant(0)), Instant(1));
    assert_eq!(endpoint.deadline(Instant(2)), Instant(2));
    drop(operation);
    endpoint.poll(Instant(2)).unwrap();
    assert!(endpoint.deadline(Instant(2)) > Instant(2));
    drop(held);
}

#[test]
fn driver_processes_rx_commands_and_cancellation_while_tx_waits() {
    for timed in [false, true] {
        let pool = Box::leak(Box::new(StaticPool::<D, 8>::new()));
        let shared = Shared::<D, 1>::new();
        let state = Rc::new(RefCell::new(State {
            blocked: !timed,
            retry_until: timed.then_some(100),
            ..Default::default()
        }));
        let mut endpoint =
            Driver::with_storage(&shared, Unsecured(rand::rng()), storage(pool, &state)).unwrap();
        let mut socket = Socket(state.clone());
        let clock = Timer(state.clone());
        let calls = core::cell::Cell::new(0);
        let mut app = |request: Request<'_>, response: &mut ResponseWriter<'_, D>| {
            calls.set(calls.get() + 1);
            reply(request, response)
        };
        state
            .borrow_mut()
            .incoming
            .push_back(request(MessageType::NonConfirmable, 1));
        let mut driver = Box::pin(endpoint.run_owned(&mut socket, &clock, &mut app, &AllowAll));
        assert!(poll(driver.as_mut()).is_pending());
        assert_eq!(calls.get(), 1);
        let attempts = state.borrow().send_attempts.len();
        state
            .borrow_mut()
            .incoming
            .push_back(request(MessageType::NonConfirmable, 2));
        let operation = shared
            .handle()
            .client("192.0.2.3:5683".parse::<SocketAddr>().unwrap())
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        assert!(poll(driver.as_mut()).is_pending());
        assert_eq!(calls.get(), 2);
        if timed {
            assert_eq!(
                state.borrow().send_attempts.len(),
                attempts,
                "unrelated work cannot bypass timed backoff"
            );
        }
        drop(operation);
        assert!(poll(driver.as_mut()).is_pending());
        assert!(state.borrow().sent.is_empty());
        state.borrow_mut().blocked = false;
        for now in 1..=164 {
            state.borrow_mut().now = now;
            assert!(poll(driver.as_mut()).is_pending());
            if state.borrow().sent.len() == 2 {
                break;
            }
        }
        assert_eq!(state.borrow().sent.len(), 2);
        assert!(
            state
                .borrow()
                .sent
                .iter()
                .all(|(_, marker)| marker.is_some())
        );
        drop(driver);
        assert_eq!(endpoint.counters().local_send_timeouts, 0);
    }
}

#[test]
fn deferred_delivery_waits_for_owned_and_copying_acceptance() {
    use mai_coap::codec::MessageView;
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        static POOL: StaticPool<D, 2> = StaticPool::new();
        let shared = Shared::<D, 1>::new();
        type DeferredDriver<'a, S> =
            Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 1, 8, 0, 2, 4, 1, 1, 0, 4, S>;
        let state = Rc::new(RefCell::new(State::default()));
        let mut endpoint =
            DeferredDriver::with_storage(&shared, Unsecured(rand::rng()), storage(&POOL, &state))
                .unwrap();
        let ticket = core::cell::Cell::new(None);
        let (bytes, meta) = request(ty, 1);
        let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, D>| {
            ticket.set(request.deferred_ticket());
            Ok(Disposition::Deferred)
        };
        endpoint
            .receive(&bytes, meta, Instant(0), &mut app, &AllowAll)
            .unwrap();
        if ty == MessageType::Confirmable {
            endpoint.complete_outgoing(Instant(0));
        }
        let operation = shared
            .handle()
            .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
            .unwrap();
        let mut operation = core::pin::pin!(operation);
        endpoint.poll(Instant(1)).unwrap();
        let mid = MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .message_id();
        state.borrow_mut().blocked = true;
        let socket = Socket(state.clone());
        let mut sender = &socket;
        assert!(
            endpoint
                .poll_transmit_owned(
                    &mut sender,
                    Instant(1),
                    &mut Context::from_waker(Waker::noop())
                )
                .is_pending()
        );
        assert!(poll(operation.as_mut()).is_pending());
        state.borrow_mut().blocked = false;
        assert!(matches!(
            endpoint.poll_transmit_owned(
                &mut sender,
                Instant(2),
                &mut Context::from_waker(Waker::noop())
            ),
            Poll::Ready(Ok(()))
        ));
        let marker = state.borrow().sent[0].1;
        assert_eq!(marker.is_some(), ty == MessageType::NonConfirmable);
        if ty == MessageType::Confirmable {
            assert!(poll(operation.as_mut()).is_pending());
            let mut ack = [0; 4];
            let n = MessageBuilder::new(
                &mut ack,
                MessageType::Acknowledgement,
                Code::EMPTY,
                mid,
                &[],
            )
            .unwrap()
            .finish(&[])
            .unwrap();
            let mut meta = meta;
            meta.original_len = n;
            endpoint
                .receive(&ack[..n], meta, Instant(3), &mut app, &AllowAll)
                .unwrap();
        }
        assert!(matches!(poll(operation.as_mut()), Poll::Ready(Ok(()))));
    }
}

#[test]
fn queued_metadata_survives_manual_views_and_both_send_paths_after_backpressure() {
    static POOL: StaticPool<D, 8> = StaticPool::new();
    let peers = [
        (
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
        ),
        (
            SocketAddr::V6(core::net::SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                5683,
                0x12345,
                u32::MAX,
            )),
            "fe80::2".parse().unwrap(),
        ),
    ];
    for owned in [false, true] {
        for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
            for (remote, local) in peers {
                for interface in [None, Some(0), Some(u32::MAX)] {
                    let shared = Shared::<D, 1>::new();
                    let state = Rc::new(RefCell::new(State {
                        blocked: true,
                        ..Default::default()
                    }));
                    let mut endpoint = Driver::with_storage(
                        &shared,
                        Unsecured(rand::rng()),
                        storage(&POOL, &state),
                    )
                    .unwrap();
                    let (bytes, _) = request(ty, 1);
                    let metadata =
                        Metadata::new(remote, local, bytes.len()).with_interface(interface);
                    endpoint
                        .receive(&bytes, metadata, Instant(0), &mut reply, &AllowAll)
                        .unwrap();
                    let outgoing = endpoint.front_outgoing().unwrap();
                    assert_eq!(
                        (outgoing.remote, outgoing.source, outgoing.interface),
                        (remote, Some(local), interface)
                    );
                    let expected = outgoing.bytes.to_vec();
                    let socket = Socket(state.clone());
                    let mut sender = &socket;
                    let mut context = Context::from_waker(Waker::noop());
                    let result = if owned {
                        endpoint.poll_transmit_owned(&mut sender, Instant(0), &mut context)
                    } else {
                        endpoint.poll_transmit(&mut sender, Instant(0), &mut context)
                    };
                    assert!(result.is_pending());
                    assert_eq!(endpoint.front_outgoing().unwrap().bytes, expected);
                    state.borrow_mut().blocked = false;
                    let result = if owned {
                        endpoint.poll_transmit_owned(&mut sender, Instant(1), &mut context)
                    } else {
                        endpoint.poll_transmit(&mut sender, Instant(1), &mut context)
                    };
                    assert!(matches!(result, Poll::Ready(Ok(()))));
                    let state = state.borrow();
                    assert_eq!(state.send_metadata, [(remote, Some(local), interface); 2]);
                    assert_eq!(state.sent.len(), 1);
                    assert_eq!(state.sent[0].0, expected);
                    assert_eq!(
                        state.sent[0].1.is_some(),
                        owned && ty == MessageType::NonConfirmable
                    );
                    assert!(endpoint.front_outgoing().is_none());
                }
            }
        }
    }
}
