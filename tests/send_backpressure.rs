//! Local acceptance budgets and CoAP timers are independent (TR-5, REL-2–5).
#![cfg(all(feature = "server", feature = "client"))]
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    task::{Context, Poll, Waker},
};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, SendWindow, Shared, Unsecured},
    security::AllowAll,
    time::{Clock, Instant},
    transport::{DatagramSender, Metadata, SendOutcome},
};

const D: usize = 128;
type Driver<'a> = Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, 2, 8, 1, 2, 4, 2, 0, 0, 8>;
#[derive(Default)]
struct Sender {
    now: u64,
    busy_until: u64,
    attempts: Vec<u64>,
    sent: Vec<Vec<u8>>,
    pending: bool,
}
impl DatagramSender for Sender {
    type Error = core::convert::Infallible;
    fn poll_send(
        &mut self,
        _: SocketAddr,
        _: Option<IpAddr>,
        _: Option<u32>,
        bytes: &[u8],
        _: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        self.attempts.push(self.now);
        if self.pending {
            return Poll::Pending;
        }
        if self.now < self.busy_until {
            return Poll::Ready(Ok(SendOutcome::RetryLater));
        }
        self.sent.push(bytes.to_vec());
        Poll::Ready(Ok(SendOutcome::Accepted))
    }
}
fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}
struct ManualClock(core::cell::Cell<u64>);
impl Clock for ManualClock {
    fn now(&self) -> Instant {
        Instant(self.0.get())
    }
    fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
        core::future::pending()
    }
}
fn incoming(endpoint: &mut Driver<'_>, now: u64, mid: u16, ty: MessageType) {
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, ty, Code::GET, mid, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    let meta = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    endpoint
        .receive(
            &bytes[..n],
            meta,
            Instant(now),
            &mut |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
                response.set_payload(b"value")?;
                Ok(Disposition::Complete)
            },
            &AllowAll,
        )
        .unwrap();
}
#[test]
fn slow_device_preserves_ack_and_non_bytes_and_honours_timed_backoff() {
    for busy in [5, 100, 500] {
        for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
            let shared = Shared::<D, 2>::new();
            let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
            incoming(&mut endpoint, 0, 1, ty);
            let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
            let mut sender = Sender {
                busy_until: busy,
                ..Default::default()
            };
            for now in 0..busy + 65 {
                sender.now = now;
                endpoint.poll(Instant(now)).unwrap();
                let _ = endpoint.poll_transmit(&mut sender, Instant(now), &mut cx());
                if !sender.sent.is_empty() {
                    break;
                }
            }
            assert_eq!(sender.sent, [original]);
            assert!(sender.attempts.last().copied().unwrap() >= busy);
            assert!(sender.attempts.len() < 18);
            for (i, pair) in sender.attempts.windows(2).enumerate() {
                assert_eq!(pair[1] - pair[0], (1u64 << i.min(6)).min(64));
            }
            assert_eq!(endpoint.counters().send_failures, 0);
            assert_eq!(endpoint.counters().dropped_messages, 0);
        }
    }
}
#[test]
fn exchange_completion_resets_send_backoff_only_when_removing_the_queue_head() {
    for remove_head in [true, false] {
        for ty in [MessageType::Reset, MessageType::Acknowledgement] {
            let shared = Shared::<D, 2>::new();
            let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
            let first = shared
                .handle()
                .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
                .request(Code::GET, "/first")
                .unwrap()
                .send()
                .unwrap();
            let second = shared
                .handle()
                .client("192.0.2.3:5683".parse::<SocketAddr>().unwrap())
                .request(Code::GET, "/second")
                .unwrap()
                .send()
                .unwrap();
            let mut first = core::pin::pin!(first);
            let mut second = core::pin::pin!(second);
            endpoint.poll(Instant(0)).unwrap();
            let mut sender = Sender::default();
            for _ in 0..2 {
                assert!(matches!(
                    endpoint.poll_transmit(&mut sender, Instant(0), &mut cx()),
                    Poll::Ready(Ok(()))
                ));
            }
            let original = sender.sent.clone();
            sender.sent.clear();
            sender.attempts.clear();
            sender.busy_until = u64::MAX;
            // Both accepted originals are due for retransmission by 3 seconds.
            endpoint.poll(Instant(3000)).unwrap();
            for delay in [0, 1, 3, 7, 15, 31, 63] {
                sender.now = 3000 + delay;
                assert!(
                    endpoint
                        .poll_transmit(&mut sender, Instant(3000 + delay), &mut cx())
                        .is_pending()
                );
            }
            assert_eq!(sender.attempts.len(), 7);
            let completed = usize::from(!remove_head);
            let message = MessageView::parse(&original[completed]).unwrap();
            let mut bytes = [0; D];
            let code = if ty == MessageType::Reset {
                Code::EMPTY
            } else {
                Code::CONTENT
            };
            let token = if ty == MessageType::Reset {
                &[][..]
            } else {
                message.token()
            };
            let n = MessageBuilder::new(&mut bytes, ty, code, message.message_id(), token)
                .unwrap()
                .finish(&[])
                .unwrap();
            let remote = if remove_head {
                "192.0.2.1:5683"
            } else {
                "192.0.2.3:5683"
            };
            endpoint
                .receive(
                    &bytes[..n],
                    Metadata::new(remote.parse().unwrap(), "192.0.2.2".parse().unwrap(), n),
                    Instant(3064),
                    &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Ok(Disposition::Complete),
                    &AllowAll,
                )
                .unwrap();
            let result = if remove_head {
                first.as_mut().poll(&mut cx())
            } else {
                second.as_mut().poll(&mut cx())
            };
            if ty == MessageType::Reset {
                assert!(matches!(result, Poll::Ready(Err(Error::Reset))));
            } else {
                assert!(matches!(result, Poll::Ready(Ok(_))));
            }
            assert_eq!(
                endpoint.front_outgoing().unwrap().bytes,
                original[1 - completed]
            );
            sender.now = 3064;
            assert!(
                endpoint
                    .poll_transmit(&mut sender, Instant(3064), &mut cx())
                    .is_pending()
            );
            assert_eq!(sender.attempts.len(), if remove_head { 8 } else { 7 });
            let next = if remove_head { 3065 } else { 3127 };
            sender.busy_until = next;
            sender.now = next - 1;
            assert!(
                endpoint
                    .poll_transmit(&mut sender, Instant(next - 1), &mut cx())
                    .is_pending()
            );
            sender.now = next;
            assert!(matches!(
                endpoint.poll_transmit(&mut sender, Instant(next), &mut cx()),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(sender.sent, [original[1 - completed].clone()]);
        }
    }
}
#[test]
fn queue_time_counts_and_deadline_is_inclusive_for_readiness_waits() {
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    incoming(&mut endpoint, 0, 1, MessageType::NonConfirmable);
    incoming(&mut endpoint, 100, 2, MessageType::NonConfirmable);
    let mut sender = Sender {
        pending: true,
        ..Default::default()
    };
    assert!(
        endpoint
            .poll_transmit(&mut sender, Instant(100), &mut cx())
            .is_pending()
    );
    assert_eq!(endpoint.deadline(Instant(100)), Instant(1000));
    endpoint.poll(Instant(999)).unwrap();
    assert_eq!(endpoint.counters().local_send_timeouts, 0);
    endpoint.poll(Instant(1000)).unwrap();
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(100));
    endpoint.poll(Instant(1099)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    endpoint.poll(Instant(1100)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.counters().local_send_timeouts, 2);
    assert_eq!(endpoint.counters().send_failures, 0);
}
#[test]
fn unsent_initial_request_times_out_locally_and_ack_timer_starts_at_acceptance() {
    for accept in [false, true] {
        let shared = Shared::<D, 2>::new();
        let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
        let operation = shared
            .handle()
            .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        let mut operation = core::pin::pin!(operation);
        endpoint.poll(Instant(0)).unwrap();
        assert_eq!(endpoint.deadline(Instant(0)), Instant(1000));
        if !accept {
            endpoint.poll(Instant(1000)).unwrap();
            assert!(matches!(
                operation.as_mut().poll(&mut cx()),
                Poll::Ready(Err(Error::LocalSendTimeout))
            ));
            assert!(endpoint.front_outgoing().is_none());
            continue;
        }
        let mut sender = Sender {
            now: 500,
            ..Default::default()
        };
        assert!(matches!(
            endpoint.poll_transmit(&mut sender, Instant(500), &mut cx()),
            Poll::Ready(Ok(()))
        ));
        let ack_at = endpoint.deadline(Instant(500));
        assert!((2500..=3500).contains(&ack_at.0));
        endpoint.poll(ack_at).unwrap();
        assert_eq!(endpoint.counters().retransmissions, 0);
        let retry = endpoint.front_outgoing().unwrap().bytes.to_vec();
        assert_eq!(sender.sent[0], retry);
        endpoint.poll(ack_at.after(1000)).unwrap();
        assert_eq!(endpoint.counters().local_send_timeouts, 1);
        assert!(operation.as_mut().poll(&mut cx()).is_pending());
        // An ACK/response still completes the accepted request after a local retry expired.
        let request = MessageView::parse(&retry).unwrap();
        let mut bytes = [0; D];
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            request.message_id(),
            request.token(),
        )
        .unwrap()
        .finish(b"ok")
        .unwrap();
        let meta = Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            n,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta,
                ack_at.after(1001),
                &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Ok(Disposition::Complete),
                &AllowAll,
            )
            .unwrap();
        assert!(matches!(
            operation.as_mut().poll(&mut cx()),
            Poll::Ready(Ok(_))
        ));
    }
}
#[test]
fn cached_ack_survives_local_expiry_and_duplicate_gets_exact_bytes() {
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    incoming(&mut endpoint, 0, 1, MessageType::Confirmable);
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    endpoint.poll(Instant(1000)).unwrap();
    incoming(&mut endpoint, 1001, 1, MessageType::Confirmable);
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
    assert_eq!(endpoint.counters().requests, 1);
    assert_eq!(endpoint.counters().duplicates, 1);
}

#[test]
fn manual_send_window_excludes_slow_preparation_even_on_error_without_refreshing_old_packets() {
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        for fail_step in [false, true] {
            for send_at in [3499, 3500] {
                let shared = Shared::<D, 2>::new();
                let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
                incoming(&mut endpoint, 0, 9, ty);
                let clock = ManualClock(core::cell::Cell::new(0));
                let mut bytes = [0; D];
                let n = MessageBuilder::new(&mut bytes, ty, Code::GET, 1, b"t")
                    .unwrap()
                    .finish(&[])
                    .unwrap();
                let meta = Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    n,
                );
                let result = endpoint.with_send_window(&clock, |window| {
                    window.receive(
                        &bytes[..n],
                        meta,
                        &mut |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
                            clock.0.set(2500);
                            response.set_payload(b"slow")?;
                            Ok(Disposition::Complete)
                        },
                        &AllowAll,
                    )?;
                    if fail_step {
                        Err(Error::Cancelled)
                    } else {
                        Ok(())
                    }
                });
                assert_eq!(
                    result,
                    if fail_step {
                        Err(Error::Cancelled)
                    } else {
                        Ok(())
                    }
                );
                assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(0));
                endpoint.poll(Instant(2500)).unwrap();
                let reply = endpoint.front_outgoing().unwrap();
                assert_eq!(reply.enqueued, Instant(2500));
                assert_eq!(MessageView::parse(reply.bytes).unwrap().payload(), b"slow");
                let mut sender = Sender::default();
                let _ = endpoint.poll_transmit(&mut sender, Instant(send_at), &mut cx());
                assert_eq!(sender.sent.len(), usize::from(send_at == 3499));
                assert_eq!(
                    endpoint.counters().local_send_timeouts,
                    if send_at == 3499 { 1 } else { 2 }
                );
            }
        }
    }
}

fn produce_reply(window: &mut SendWindow<'_, Driver<'_>>, mid: u16, ty: MessageType) {
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, ty, Code::GET, mid, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    window
        .receive(
            &bytes[..n],
            metadata,
            &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Ok(Disposition::Complete),
            &AllowAll,
        )
        .unwrap();
}

#[test]
fn producer_helpers_share_one_timestamp_and_preserve_older_packet_budgets() {
    fn helper(window: &mut SendWindow<'_, Driver<'_>>, clock: &ManualClock, ty: MessageType) {
        assert_eq!(window.now(), Instant(100));
        produce_reply(window, 2, ty);
        clock.0.set(4100);
        window.poll().unwrap();
        assert_eq!(window.now(), Instant(100));
        produce_reply(window, 3, ty);
    }
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        let shared = Shared::<D, 2>::new();
        let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
        incoming(&mut endpoint, 0, 99, ty);
        let clock = ManualClock(core::cell::Cell::new(100));
        endpoint.with_send_window(&clock, |window| {
            produce_reply(window, 1, ty);
            clock.0.set(2100);
            window.poll().unwrap();
            helper(window, &clock, ty);
            clock.0.set(7100);
        });
        assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(0));
        endpoint.poll(Instant(7100)).unwrap();
        assert_eq!(endpoint.counters().local_send_timeouts, 1);
        let mut sender = Sender::default();
        for _ in 0..3 {
            assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(7100));
            assert!(
                endpoint
                    .poll_transmit(&mut sender, Instant(8099), &mut cx())
                    .is_ready()
            );
        }
        assert_eq!(sender.sent.len(), 3);
        assert!(endpoint.front_outgoing().is_none());
        incoming(&mut endpoint, 9000, 4, ty);
        clock.0.set(12000);
        endpoint.with_send_window(&clock, |_| {});
        assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(9000));
        endpoint.poll(Instant(12000)).unwrap();
        assert_eq!(endpoint.counters().local_send_timeouts, 2);
    }
}

#[test]
fn resource_polling_and_helpers_use_the_frozen_producer_timestamp() {
    struct ApplicationTimes(Vec<Instant>);
    impl mai_coap::endpoint::Application<D> for ApplicationTimes {
        fn handle(
            &mut self,
            _: Request<'_>,
            _: &mut ResponseWriter<'_, D>,
        ) -> Result<Disposition, Code> {
            Ok(Disposition::Complete)
        }
        fn recognizes(&self, _: mai_coap::codec::OptionNumber) -> bool {
            false
        }
        fn poll(&mut self, now: Instant, _: &mut Context<'_>) {
            self.0.push(now);
        }
    }
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let clock = ManualClock(core::cell::Cell::new(7));
    let mut app = ApplicationTimes(Vec::new());
    endpoint.with_send_window(&clock, |window| {
        window
            .poll_resources(&mut app, &AllowAll, &mut cx())
            .unwrap();
        clock.0.set(2500);
        window
            .poll_resources(&mut app, &AllowAll, &mut cx())
            .unwrap();
        #[cfg(feature = "observe")]
        window.poll_observations(&mut app, &AllowAll).unwrap();
        assert_eq!(window.now(), Instant(7));
    });
    assert_eq!(app.0, [Instant(7), Instant(7)]);
}

#[test]
fn completed_window_output_uses_current_time_for_transmission_and_retry_wakeups() {
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        for busy in [false, true] {
            let shared = Shared::<D, 2>::new();
            let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
            let clock = ManualClock(core::cell::Cell::new(0));
            endpoint.with_send_window(&clock, |window| {
                produce_reply(window, 1, ty);
                clock.0.set(2500);
                window.poll().unwrap();
            });
            assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2500));
            let mut sender = Sender {
                now: 2500,
                busy_until: if busy { 3000 } else { 0 },
                ..Default::default()
            };
            let result = endpoint.poll_transmit(&mut sender, clock.now(), &mut cx());
            assert_eq!(result.is_pending(), busy);
            if busy {
                clock.0.set(3000);
                assert_eq!(endpoint.deadline(clock.now()), clock.now());
                sender.pending = true;
                assert!(
                    endpoint
                        .poll_transmit(&mut sender, clock.now(), &mut cx())
                        .is_pending()
                );
                assert!(endpoint.deadline(clock.now()) > clock.now());
                sender.pending = false;
                sender.now = 3000;
                assert!(
                    endpoint
                        .poll_transmit(&mut sender, clock.now(), &mut cx())
                        .is_ready()
                );
            }
            assert_eq!(sender.sent.len(), 1);
            assert!(endpoint.front_outgoing().is_none());
            assert_eq!(endpoint.counters().local_send_timeouts, 0);
        }
    }
}

#[test]
#[cfg(feature = "multicast")]
fn producer_window_preserves_fixed_collection_deadlines() {
    for poll_first in [false, true] {
        for at in [999, 1000, 1001] {
            let shared = Shared::<D, 2>::new();
            let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
            let mut collection = shared
                .handle()
                .discover_multicast("224.0.1.187:5683".parse().unwrap(), Instant(1000))
                .unwrap();
            let clock = ManualClock(core::cell::Cell::new(0));
            let mut sender = Sender::default();
            endpoint.with_send_window(&clock, |window| {
                window.poll().unwrap();
                clock.0.set(at);
                window.poll().unwrap();
            });
            assert_eq!(endpoint.deadline(clock.now()), Instant(at.max(1000)));
            if poll_first {
                endpoint.poll(clock.now()).unwrap();
            }
            sender.now = at;
            let _ = endpoint.poll_transmit(&mut sender, clock.now(), &mut cx());
            assert_eq!(sender.sent.len(), usize::from(at < 1000));
            endpoint.poll(Instant(at.max(1000))).unwrap();
            let result = core::pin::pin!(collection.next()).as_mut().poll(&mut cx());
            if at < 1000 {
                assert!(matches!(result, Poll::Ready(None)));
            } else {
                assert!(matches!(
                    result,
                    Poll::Ready(Some(Err(Error::LocalSendTimeout)))
                ));
            }
            assert_eq!(
                endpoint.counters().local_send_timeouts,
                u64::from(at >= 1000)
            );
            assert_eq!(endpoint.counters().dropped_messages, u64::from(at >= 1000));
        }
    }
}

#[test]
#[cfg(feature = "multicast")]
fn unaccepted_collection_expiry_reports_a_local_failure() {
    for until in [500, 1000, 2000] {
        let shared = Shared::<D, 2>::new();
        let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut collection = shared
            .handle()
            .discover_multicast("224.0.1.187:5683".parse().unwrap(), Instant(until))
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        assert_eq!(endpoint.deadline(Instant(0)), Instant(until.min(1000)));
        let mut sender = Sender::default();
        let _ = endpoint.poll_transmit(&mut sender, Instant(3000), &mut cx());
        let result = core::pin::pin!(collection.next()).as_mut().poll(&mut cx());
        assert!(matches!(
            result,
            Poll::Ready(Some(Err(Error::LocalSendTimeout)))
        ));
        assert_eq!(endpoint.counters().local_send_timeouts, 1);
        assert_eq!(endpoint.counters().dropped_messages, 1);
        assert!(sender.sent.is_empty());
    }
}

#[test]
#[cfg(panic = "unwind")]
fn unwinding_send_window_stamps_output_and_allows_endpoint_reuse() {
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let clock = ManualClock(core::cell::Cell::new(0));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        endpoint.with_send_window(&clock, |window| {
            produce_reply(window, 1, MessageType::NonConfirmable);
            clock.0.set(2500);
            panic!("application failure");
        });
    }));
    assert!(result.is_err());
    assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2500));
    incoming(&mut endpoint, 3000, 2, MessageType::NonConfirmable);
    clock.0.set(4000);
    endpoint.with_send_window(&clock, |window| {
        produce_reply(window, 3, MessageType::NonConfirmable);
        clock.0.set(8000);
    });
    endpoint.poll(Instant(8000)).unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(8000));
    assert_eq!(endpoint.counters().local_send_timeouts, 2);
}

#[test]
fn slow_manual_reply_is_replayed_from_cache_with_a_fresh_local_send_budget() {
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let clock = ManualClock(core::cell::Cell::new(0));
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    let meta = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    let mut calls = 0;
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        calls += 1;
        clock.0.set(2500);
        response.set_payload(b"cached slow reply")?;
        Ok(Disposition::Complete)
    };
    endpoint
        .with_send_window(&clock, |window| {
            window.receive(&bytes[..n], meta, &mut handler, &AllowAll)
        })
        .unwrap();
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    endpoint.poll(Instant(3500)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
    clock.0.set(3501);
    endpoint
        .with_send_window(&clock, |window| {
            window.receive(&bytes[..n], meta, &mut handler, &AllowAll)
        })
        .unwrap();
    assert_eq!(calls, 1);
    let replay = endpoint.front_outgoing().unwrap();
    assert_eq!(replay.bytes, original);
    assert_eq!(replay.enqueued, Instant(3501));
    let mut sender = Sender::default();
    let _ = endpoint.poll_transmit(&mut sender, Instant(4500), &mut cx());
    assert_eq!(sender.sent, [original]);
    assert_eq!(endpoint.counters().duplicates, 1);
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
}

#[test]
fn unsent_non_failure_releases_provisional_pacing() {
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let client = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap());
    let first = client
        .request(Code::GET, "/large-unsent")
        .unwrap()
        .confirmable(false)
        .send()
        .unwrap();
    let mut first = core::pin::pin!(first);
    endpoint.poll(Instant(0)).unwrap();
    endpoint.poll(Instant(1000)).unwrap();
    assert!(matches!(
        first.as_mut().poll(&mut cx()),
        Poll::Ready(Err(Error::LocalSendTimeout))
    ));
    let _second = client
        .request(Code::GET, "/next")
        .unwrap()
        .confirmable(false)
        .send()
        .unwrap();
    endpoint.poll(Instant(1000)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
}

#[test]
fn retry_cannot_be_accepted_after_max_transmit_span() {
    for window in [false, true] {
        for (entry, at) in [(44_999, 45_000), (44_999, 45_001), (45_001, 45_001)] {
            let shared = Shared::<D, 2>::new();
            let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
            let _operation = shared
                .handle()
                .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
                .request(Code::GET, "/")
                .unwrap()
                .send()
                .unwrap();
            endpoint.poll(Instant(0)).unwrap();
            let mut sender = Sender::default();
            assert!(
                endpoint
                    .poll_transmit(&mut sender, Instant(0), &mut cx())
                    .is_ready()
            );
            // Missed scheduling opportunities cannot shift the last permissible send.
            let clock = ManualClock(core::cell::Cell::new(entry));
            if window {
                endpoint.with_send_window(&clock, |window| {
                    window.poll().unwrap();
                    clock.0.set(at);
                });
            } else {
                endpoint.poll(Instant(entry)).unwrap();
                clock.0.set(at);
            }
            assert_eq!(endpoint.front_outgoing().is_some(), entry <= 45_000);
            if entry <= 45_000 {
                assert_eq!(endpoint.deadline(Instant(entry)), Instant(45_001));
            }
            sender.now = at;
            let _ = endpoint.poll_transmit(&mut sender, clock.now(), &mut cx());
            assert_eq!(sender.sent.len(), if at == 45_000 { 2 } else { 1 });
            let expired_queued_retry = u64::from(entry <= 45_000 && at > 45_000);
            assert_eq!(
                endpoint.counters().local_send_timeouts,
                expired_queued_retry
            );
            assert_eq!(endpoint.counters().dropped_messages, expired_queued_retry);
        }
    }
}

// Peer and local MIDs are independent spaces (RFC 7252 section 4.4), so a reply
// reusing a notification's number must not count as a lost notification.
#[cfg(feature = "observe")]
#[test]
fn expired_ack_reusing_a_notification_mid_leaves_the_schedule_alone() {
    use mai_coap::{codec::OptionNumber, observe::Settings, server::Router};
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        response.set_payload(b"latest")?;
        Ok(Disposition::Complete)
    };
    let mut app = Router::<D, 1, 0, 0>::new(&AllowAll);
    app.route("/", &[Code::GET], &mut handler).unwrap();
    app.observable(
        "/",
        Settings::new(1)
            .with_maximum_ms(5_000)
            .with_confirmable_ms(10),
    )
    .unwrap();
    let remote = "192.0.2.1:5683".parse().unwrap();
    let local = "192.0.2.2".parse().unwrap();
    let mut bytes = [0; D];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(remote, local, n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    endpoint.complete_outgoing(Instant(0));

    endpoint
        .poll_resources(Instant(5_000), &mut app, &AllowAll, &mut cx())
        .unwrap();
    let mid = MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
        .unwrap()
        .message_id();
    endpoint.complete_outgoing(Instant(5_000));
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        mid,
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(remote, local, n),
            Instant(5_000),
            &mut app,
            &AllowAll,
        )
        .unwrap();

    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, mid, b"p")
        .unwrap()
        .finish(&[])
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(remote, local, n),
            Instant(5_010),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(reply.message_type(), MessageType::Acknowledgement);
    assert_eq!(reply.message_id(), mid);
    endpoint.poll(Instant(6_010)).unwrap();
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    assert!(endpoint.front_outgoing().is_none());

    // A treated-as-lost notification would retry here, one retry delay later.
    endpoint
        .poll_resources(Instant(6_074), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert!(endpoint.front_outgoing().is_none());
    endpoint
        .poll_resources(Instant(9_999), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert!(endpoint.front_outgoing().is_none());

    endpoint
        .poll_resources(Instant(10_000), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert!(endpoint.front_outgoing().is_some());
}

#[cfg(feature = "observe")]
#[test]
fn expired_notification_preserves_subscription_and_confirmation_due_time() {
    use mai_coap::{codec::OptionNumber, observe::Settings, server::Router};
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, D>| {
        response.set_payload(b"latest")?;
        Ok(Disposition::Complete)
    };
    let mut app = Router::<D, 1, 0, 0>::new(&AllowAll);
    app.route("/", &[Code::GET], &mut handler).unwrap();
    app.observable(
        "/",
        Settings::new(1).with_maximum_ms(1).with_confirmable_ms(10),
    )
    .unwrap();
    let remote = "192.0.2.1:5683".parse().unwrap();
    let local = "192.0.2.2".parse().unwrap();
    let mut bytes = [0; D];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(remote, local, n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    endpoint.complete_outgoing(Instant(0));
    endpoint
        .poll_resources(Instant(10), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .message_type(),
        MessageType::Confirmable
    );
    endpoint.poll(Instant(1010)).unwrap();
    assert_eq!(endpoint.counters().local_send_timeouts, 1);
    endpoint
        .poll_resources(Instant(1074), &mut app, &AllowAll, &mut cx())
        .unwrap();
    let notification = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(notification.message_type(), MessageType::Confirmable);
    let mid = notification.message_id();
    endpoint.complete_outgoing(Instant(1075));
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        mid,
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(remote, local, n),
            Instant(1075),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    endpoint
        .poll_resources(Instant(1075), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .message_type(),
        MessageType::NonConfirmable
    );
    endpoint.discard_outgoing(Instant(1075));
    assert_eq!(endpoint.deadline(Instant(1075)), Instant(1139));
    endpoint
        .poll_resources(Instant(1138), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert!(endpoint.front_outgoing().is_none());
    endpoint
        .poll_resources(Instant(1139), &mut app, &AllowAll, &mut cx())
        .unwrap();
    assert!(
        endpoint.front_outgoing().is_some(),
        "permanent datagram errors retain a bounded fresh-state opportunity"
    );
}

#[test]
fn fatal_send_retains_initial_request_and_datagram_rejection_completes_it() {
    use mai_coap::endpoint::RunError;
    struct Reject(bool);
    impl DatagramSender for Reject {
        type Error = bool;
        fn discard_send_error(error: &bool) -> bool {
            *error
        }
        fn poll_send(
            &mut self,
            _: SocketAddr,
            _: Option<IpAddr>,
            _: Option<u32>,
            _: &[u8],
            _: &mut Context<'_>,
        ) -> Poll<Result<SendOutcome, bool>> {
            Poll::Ready(Err(self.0))
        }
    }
    let shared = Shared::<D, 2>::new();
    let mut endpoint = Driver::new(&shared, Unsecured(rand::rng())).unwrap();
    let operation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    let mut operation = core::pin::pin!(operation);
    endpoint.poll(Instant(0)).unwrap();
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    assert!(matches!(
        endpoint.poll_transmit(&mut Reject(false), Instant(0), &mut cx()),
        Poll::Ready(Err(RunError::Transport(false)))
    ));
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
    assert!(operation.as_mut().poll(&mut cx()).is_pending());
    assert!(matches!(
        endpoint.poll_transmit(&mut Reject(true), Instant(0), &mut cx()),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        operation.as_mut().poll(&mut cx()),
        Poll::Ready(Err(Error::LocalSendFailed))
    ));
    assert_eq!(endpoint.counters().send_failures, 2);
    assert_eq!(endpoint.counters().local_send_timeouts, 0);
}

// TR-5 / RFC 7252 section 4.2: producer latency is not local transport waiting.
fn assert_slow_producer(delay: u16, confirmable: bool) {
    use core::{
        cell::{Cell, RefCell},
        convert::Infallible,
        future::{Future, poll_fn},
        net::{IpAddr, SocketAddr},
        task::{Context, Poll, Waker},
    };
    use mai_coap::{
        codec::{Code, MessageType},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::AllowAll,
        time::Clock,
        transport::{
            DatagramReceiver, DatagramSender, Metadata, ReceivedPacket, SendOutcome, Transport,
        },
    };
    use rand::SeedableRng;
    struct Input(Vec<u8>, Metadata);
    impl ReceivedPacket for Input {
        fn bytes(&self) -> &[u8] {
            &self.0
        }
        fn metadata(&self) -> Metadata {
            self.1
        }
    }
    struct Link<'a> {
        now: &'a Cell<u64>,
        input: RefCell<Option<Input>>,
        sent: RefCell<Option<(u64, Vec<u8>)>>,
    }
    impl Transport for Link<'_> {
        type Error = Infallible;
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
    impl DatagramReceiver for &Link<'_> {
        type Error = Infallible;
        type Packet<'a>
            = Input
        where
            Self: 'a;
        async fn receive<'a>(&'a mut self, _: &'a mut [u8]) -> Result<Input, Infallible> {
            Ok(poll_fn(|_| {
                self.input
                    .borrow_mut()
                    .take()
                    .map_or(Poll::Pending, Poll::Ready)
            })
            .await)
        }
    }
    impl DatagramSender for &Link<'_> {
        type Error = Infallible;
        fn poll_send(
            &mut self,
            _: SocketAddr,
            _: Option<IpAddr>,
            _: Option<u32>,
            bytes: &[u8],
            _: &mut Context<'_>,
        ) -> Poll<Result<SendOutcome, Infallible>> {
            assert!(
                self.sent
                    .borrow_mut()
                    .replace((self.now.get(), bytes.to_vec()))
                    .is_none()
            );
            Poll::Ready(Ok(SendOutcome::Accepted))
        }
    }
    struct Timer<'a>(&'a Cell<u64>);
    impl Clock for Timer<'_> {
        fn now(&self) -> Instant {
            Instant(self.0.get())
        }
        async fn sleep_until(&self, deadline: Instant) {
            poll_fn(|_| {
                if self.now() >= deadline {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
    }
    let delay = u64::from(delay);
    let ty = if confirmable {
        MessageType::Confirmable
    } else {
        MessageType::NonConfirmable
    };
    let mut bytes = [0; 64];
    let n = MessageBuilder::new(&mut bytes, ty, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    let now = Cell::new(0);
    let mut link = Link {
        now: &now,
        input: RefCell::new(Some(Input(
            bytes[..n].to_vec(),
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
        ))),
        sent: RefCell::new(None),
    };
    let clock = Timer(&now);
    let shared = Shared::<64, 1>::new();
    let mut endpoint = Endpoint::<_, 64, 1, 2, 0, 1, 2, 1, 0, 0, 2>::new(
        &shared,
        Unsecured(rand::rngs::StdRng::from_seed([3; 32])),
    )
    .unwrap();
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 64>| {
        now.set(delay);
        response.set_payload(b"reply")?;
        Ok(Disposition::Complete)
    };
    {
        let mut driver = core::pin::pin!(endpoint.run(&mut link, &clock, &mut app, &AllowAll));
        assert!(
            driver
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
    }
    let sent = link.sent.borrow();
    let (accepted, bytes) = sent
        .as_ref()
        .expect("prepared response was never offered to transport");
    assert_eq!(*accepted, delay);
    assert_eq!(MessageView::parse(bytes).unwrap().payload(), b"reply");
    assert_eq!(endpoint.counters().local_send_timeouts, 0);
}

proptest::proptest! {
    #[test]
    fn synchronous_producer_delay_preserves_the_send_budget(
        delay in proptest::prelude::any::<u16>(),
        confirmable in proptest::prelude::any::<bool>(),
    ) {
        assert_slow_producer(delay, confirmable);
    }
}
