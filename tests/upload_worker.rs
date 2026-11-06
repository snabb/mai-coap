//! A failed deferred reply must not stop the asynchronous upload worker.
#![cfg(all(feature = "server", feature = "client", feature = "block1"))]
mod support;
use support::PopOutgoing;

use futures_lite::future::{block_on, poll_once};
use mai_coap::{
    Error,
    block::{Block, BodyKey},
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Application, Endpoint, Protection, Shared, Unsecured},
    messaging::TransmissionParameters,
    security::PublicPaths,
    server::work::{
        Handler, WorkQueue,
        upload::{AsyncUploadSink, UploadWorker},
    },
    time::{Clock, Instant},
    transport::Metadata,
};
use std::{
    cell::Cell,
    rc::Rc,
    task::{Context, Waker},
};

#[derive(Default)]
struct State {
    failure: Cell<Option<Error>>,
    responses: Cell<usize>,
    writes: Cell<usize>,
    commits: Cell<usize>,
    aborts: Cell<usize>,
}
struct Sink(Rc<State>);
impl AsyncUploadSink for Sink {
    async fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
        Ok(())
    }
    async fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
        self.0.writes.set(self.0.writes.get() + 1);
        Ok(())
    }
    async fn commit(&mut self) -> Result<(), Error> {
        self.0.commits.set(self.0.commits.get() + 1);
        Ok(())
    }
    fn abort(&mut self) {
        self.0.aborts.set(self.0.aborts.get() + 1);
    }
}

struct CheckedClock<'a> {
    inner: &'a support::Network,
    sleeps: std::cell::RefCell<Vec<Instant>>,
}
impl Clock for CheckedClock<'_> {
    fn now(&self) -> Instant {
        self.inner.now()
    }
    async fn sleep_until(&self, deadline: Instant) {
        assert_ne!(deadline, Instant(u64::MAX));
        self.sleeps.borrow_mut().push(deadline);
        self.inner.sleep_until(deadline).await;
    }
}

#[test]
fn api_7_upload_worker_arms_only_live_transaction_timers() {
    for more in [false, true] {
        let network = support::Network::default();
        let clock = CheckedClock {
            inner: &network,
            sleeps: Default::default(),
        };
        let shared = Shared::new();
        let queue = WorkQueue::new();
        let mut f = Fixture::new(&network, &shared, &queue, 1000);
        let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
        let run = worker.run(shared.handle(), &clock);
        fn indefinitely_running(_: &impl Future<Output = core::convert::Infallible>) {}
        indefinitely_running(&run);
        let mut run = core::pin::pin!(run);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        assert!(
            clock.sleeps.borrow().is_empty(),
            "idle worker must only await its queue"
        );
        f.receive_block(1, MessageType::NonConfirmable, 0, more);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.poll();
        f.endpoint.pop_outgoing().unwrap();
        clock.sleeps.borrow_mut().clear();
        assert!(block_on(poll_once(run.as_mut())).is_none());
        let aborts = f.state.aborts.get();
        if more {
            assert_eq!(*clock.sleeps.borrow(), [Instant(1000)]);
            network.advance(1000);
            assert!(block_on(poll_once(run.as_mut())).is_none());
            assert_eq!(f.state.aborts.get(), aborts + 1);
        } else {
            assert!(
                clock.sleeps.borrow().is_empty(),
                "completed body needs no idle timer"
            );
        }
    }
}

#[test]
fn blk_4_plt_7_worker_refusals_include_contextual_options() {
    for too_large in [false, true] {
        let clock = support::Network::default();
        let shared = Shared::new();
        let queue = WorkQueue::new();
        let mut f = Fixture::new(&clock, &shared, &queue, 1000);
        f.enqueue(1);
        let job = block_on(queue.next());
        if !too_large {
            clock.advance(1000);
        }
        let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 4, 1000).unwrap();
        let response = block_on(worker.process(&job, &clock));
        let mut bytes = [0; 128];
        let n = response
            .encode(&mut bytes, MessageType::NonConfirmable, 1, b"x")
            .unwrap();
        let reply = MessageView::parse(&bytes[..n]).unwrap();
        if too_large {
            assert_eq!(reply.code(), Code::TOO_LARGE);
            assert_eq!(reply.option(OptionNumber::SIZE1).unwrap().uint(), Ok(4));
            assert!(reply.option(OptionNumber::MAX_AGE).is_none());
        } else {
            assert_eq!(reply.code(), Code::UNAVAILABLE);
            assert_eq!(reply.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(1));
        }
    }
}
struct FailingResponse<P> {
    inner: P,
    state: Rc<State>,
}
impl<P: Protection<Binding = ()>> Protection for FailingResponse<P> {
    mai_coap::delegate_protection!(inner, (); except [incoming, response]);
    fn incoming<const D: usize>(
        &mut self,
        request: MessageView<'_>,
        metadata: Metadata,
        output: &mut [u8],
    ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
        let (length, security, _) = self.inner.incoming::<D>(request, metadata, output)?;
        Ok((length, security, Some(())))
    }
    fn response<const D: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut (),
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.state.responses.set(self.state.responses.get() + 1);
        if let Some(error) = self.state.failure.get() {
            return Err(error);
        }
        self.inner.response::<D>(response, binding, output)
    }
}

type TestEndpoint<'a> = Endpoint<'a, FailingResponse<Unsecured<rand::rngs::ThreadRng>>, 128, 2, 8>;
struct Fixture<'a> {
    clock: &'a support::Network,
    handler: Handler<'a, 128, 2, 1152>,
    endpoint: TestEndpoint<'a>,
    state: Rc<State>,
}
impl<'a> Fixture<'a> {
    fn new(
        clock: &'a support::Network,
        shared: &'a Shared<128, 2>,
        queue: &'a WorkQueue<128, 2>,
        timeout: u64,
    ) -> Self {
        let state = Rc::new(State::default());
        let protection = FailingResponse {
            inner: Unsecured(rand::rng()),
            state: state.clone(),
        };
        Self {
            clock,
            handler: queue.handler(timeout).unwrap(),
            endpoint: Endpoint::new(shared, protection).unwrap(),
            state,
        }
    }
    fn enqueue(&mut self, mid: u16) {
        self.handler
            .poll(self.clock.now(), &mut Context::from_waker(Waker::noop()));
        self.receive(mid);
    }
    fn receive(&mut self, mid: u16) {
        self.receive_block(mid, MessageType::NonConfirmable, 0, false);
    }
    fn receive_block(&mut self, mid: u16, ty: MessageType, number: u32, more: bool) {
        let mut bytes = [0; 128];
        let mut builder = MessageBuilder::new(&mut bytes, ty, Code::PUT, mid, b"x").unwrap();
        builder
            .uint_option(
                OptionNumber::BLOCK1,
                Block::new(number, more, 0).unwrap().encode().unwrap(),
            )
            .unwrap();
        let payload = [mid as u8; 16];
        let n = builder
            .finish(&payload[..if more { 16 } else { 5 }])
            .unwrap();
        self.endpoint
            .receive(
                &bytes[..n],
                Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    n,
                ),
                self.clock.now(),
                &mut self.handler,
                &PublicPaths(&[(Code::PUT, "/")]),
            )
            .unwrap();
    }
    fn poll(&mut self) {
        self.endpoint.poll(self.clock.now()).unwrap();
    }
    fn changed(&mut self) {
        let outgoing = self.endpoint.pop_outgoing().expect("reply must be queued");
        let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(response.code(), Code::CHANGED);
        assert_eq!(response.option(OptionNumber::BLOCK1).unwrap().uint(), Ok(0));
        assert!(self.endpoint.pop_outgoing().is_none());
    }
    fn stored(&self, count: usize) {
        assert_eq!(self.state.writes.get(), count);
        assert_eq!(self.state.commits.get(), count);
    }
}

#[test]
fn api_7_upload_reply_survives_a_lost_ack_for_the_previous_block_response() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 1000);
    f.receive_block(1, MessageType::Confirmable, 0, true);
    let ack = f.endpoint.pop_outgoing().unwrap();
    let ack = MessageView::parse(ack.packet.as_slice()).unwrap();
    assert_eq!(
        (ack.message_type(), ack.code(), ack.message_id()),
        (MessageType::Acknowledgement, Code::EMPTY, 1)
    );
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    let first = f.endpoint.pop_outgoing().unwrap().packet;
    let reply = MessageView::parse(first.as_slice()).unwrap();
    assert_eq!(
        (reply.message_type(), reply.code()),
        (MessageType::Confirmable, Code::CONTINUE)
    );
    let first_mid = reply.message_id();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    // The client received block 0's response, but its ACK was lost.
    f.receive_block(2, MessageType::Confirmable, 1, false);
    let ack = f.endpoint.pop_outgoing().unwrap();
    let ack = MessageView::parse(ack.packet.as_slice()).unwrap();
    assert_eq!(
        (ack.message_type(), ack.code(), ack.message_id()),
        (MessageType::Acknowledgement, Code::EMPTY, 2)
    );
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    assert!(
        f.endpoint.pop_outgoing().is_none(),
        "NSTART must hold the final response"
    );
    clock.advance(1001);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    assert!(f.endpoint.pop_outgoing().is_none());
    clock.advance(1999);
    f.poll();
    assert_eq!(f.endpoint.pop_outgoing().unwrap().packet, first);
    let [high, low] = first_mid.to_be_bytes();
    let ack = [0x60, 0, high, low];
    f.endpoint
        .receive(
            &ack,
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                ack.len(),
            ),
            clock.now(),
            &mut f.handler,
            &PublicPaths(&[(Code::PUT, "/")]),
        )
        .unwrap();
    f.poll();
    let final_reply = f
        .endpoint
        .pop_outgoing()
        .expect("the queued final response must survive NSTART waiting");
    let reply = MessageView::parse(final_reply.packet.as_slice()).unwrap();
    assert_eq!(
        (reply.message_type(), reply.code()),
        (MessageType::Confirmable, Code::CHANGED)
    );
    assert_eq!(reply.option(OptionNumber::BLOCK1).unwrap().uint(), Ok(16));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    assert_eq!(f.state.writes.get(), 2);
    assert_eq!(f.state.commits.get(), 1);
    assert_eq!(f.endpoint.counters().retransmissions, 1);
    assert_eq!(f.endpoint.counters().dropped_messages, 0);
}

#[test]
fn api_7_upload_reply_retries_transient_submission_pressure() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 1000);
    f.enqueue(1);
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut blockers = Vec::new();
    for _ in 0..2 {
        blockers.push(
            shared
                .handle()
                .client("192.0.2.3:5683".parse::<core::net::SocketAddr>().unwrap())
                .request(Code::GET, "/")
                .unwrap()
                .send()
                .unwrap(),
        );
    }
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.stored(1);
    for delay in [100, 250, 500] {
        clock.advance(delay);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.stored(1);
    }
    drop(blockers);
    f.poll();
    clock.advance(499);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    assert!(f.endpoint.pop_outgoing().is_none());
    clock.advance(1);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    f.changed();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.stored(1);
}

#[test]
fn api_7_upload_reply_uses_delivery_grace_after_processing_deadline() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 10);
    f.enqueue(1);
    f.state.failure.set(Some(Error::Capacity));
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    clock.advance(11);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.state.failure.set(None);
    clock.advance(89);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    f.changed();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    assert_eq!(f.state.responses.get(), 2);
    f.stored(1);
}

#[test]
fn api_7_upload_reply_retries_capacity_until_expiry_and_serves_next_job() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 1000);
    f.endpoint
        .set_parameters(
            TransmissionParameters::default()
                .with_ack_timeout_ms(2000)
                .with_max_retransmit(0)
                .with_max_latency_ms(0),
        )
        .unwrap();
    f.enqueue(1);
    f.state.failure.set(Some(Error::Capacity));
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    for (attempt, delay) in [0, 100, 250, 500, 500, 500, 500, 500]
        .into_iter()
        .enumerate()
    {
        clock.advance(delay);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.poll();
        assert!(block_on(poll_once(run.as_mut())).is_none());
        assert_eq!(f.state.responses.get(), attempt + 1);
        f.stored(1);
    }
    clock.advance(149);
    f.enqueue(2);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.stored(1);
    clock.advance(1);
    f.state.failure.set(None);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    f.changed();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.stored(2);
}

#[test]
fn api_7_upload_reply_stops_at_ticket_delivery_deadline() {
    for pending in [false, true] {
        let clock = support::Network::default();
        let shared = Shared::new();
        let queue = WorkQueue::new();
        let mut f = Fixture::new(&clock, &shared, &queue, 10);
        f.endpoint
            .set_parameters(
                TransmissionParameters::default()
                    .with_ack_timeout_ms(40)
                    .with_max_retransmit(0)
                    .with_max_latency_ms(0),
            )
            .unwrap();
        f.enqueue(1);
        let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
        let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
        assert!(block_on(poll_once(run.as_mut())).is_none());
        if !pending {
            f.state.failure.set(Some(Error::Capacity));
            f.poll();
            assert!(block_on(poll_once(run.as_mut())).is_none());
        }
        clock.advance(49);
        f.state.failure.set(None);
        f.enqueue(2);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.stored(1);
        clock.advance(1);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.poll();
        f.changed();
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.stored(2);
        assert_eq!(f.state.responses.get(), if pending { 1 } else { 2 });
    }
}

#[test]
fn api_7_upload_reply_keeps_pending_command_past_one_second() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 1000);
    f.enqueue(1);
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    clock.advance(3000);
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.stored(1);
    f.poll();
    f.changed();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    assert_eq!(
        f.state.responses.get(),
        1,
        "the pending response must remain deliverable"
    );
}

#[test]
fn api_7_upload_worker_continues_immediately_after_noncapacity_errors() {
    for error in [Error::SequenceExhausted, Error::Cancelled] {
        let clock = support::Network::default();
        let shared = Shared::new();
        let queue = WorkQueue::new();
        let mut f = Fixture::new(&clock, &shared, &queue, 1000);
        f.enqueue(1);
        f.state.failure.set(Some(error));
        let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
        let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.poll();
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.state.failure.set(None);
        f.enqueue(2);
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.poll();
        f.changed();
        assert!(block_on(poll_once(run.as_mut())).is_none());
        f.stored(2);
    }
}

#[test]
fn api_7_upload_worker_future_can_be_cancelled_during_backoff() {
    let clock = support::Network::default();
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 1000);
    f.enqueue(1);
    f.state.failure.set(Some(Error::Capacity));
    let mut worker = UploadWorker::new(&queue, Sink(f.state.clone()), 1024, 1000).unwrap();
    let mut run = Box::pin(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    assert!(block_on(poll_once(run.as_mut())).is_none());
    drop(run);
    clock.advance(1000);
    f.poll();
    assert_eq!(f.state.responses.get(), 1);
    f.state.failure.set(None);
    f.enqueue(2);
    let mut run = core::pin::pin!(worker.run(shared.handle(), &clock));
    assert!(block_on(poll_once(run.as_mut())).is_none());
    f.poll();
    f.changed();
    f.stored(2);
}

#[test]
fn api_7_job_deadlines_use_arrival_time_and_snapshot_endpoint_parameters() {
    let clock = support::Network::default();
    clock.advance(100);
    let shared = Shared::new();
    let queue = WorkQueue::new();
    let mut f = Fixture::new(&clock, &shared, &queue, 10);
    f.endpoint
        .set_parameters(
            TransmissionParameters::default()
                .with_ack_timeout_ms(40)
                .with_max_retransmit(0)
                .with_max_latency_ms(0),
        )
        .unwrap();
    // The last application poll preceded an idle receive wait.
    f.handler
        .poll(Instant(0), &mut Context::from_waker(Waker::noop()));
    f.receive(1);
    f.endpoint
        .set_parameters(TransmissionParameters::default())
        .unwrap();
    let job = block_on(poll_once(queue.next())).unwrap();
    assert_eq!(job.deadline(), Instant(110));
    assert_eq!(job.delivery_deadline(), Instant(150));
}
