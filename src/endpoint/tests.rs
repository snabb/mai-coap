#[cfg(feature = "client")]
use super::*;

#[cfg(feature = "client")]
struct FixedClock(u64);
#[cfg(feature = "client")]
impl Clock for FixedClock {
    fn now(&self) -> Instant {
        Instant(self.0)
    }
    fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
        core::future::pending()
    }
}

#[cfg(feature = "client")]
mod client_regressions {
    use super::*;
    use crate::codec::MessageBuilder;
    #[cfg(any(feature = "server", feature = "observe"))]
    use core::{cell::Cell, net::IpAddr};
    use core::{
        future::{Future, poll_fn},
        net::SocketAddr,
        pin::Pin,
        task::Poll,
    };
    use std::boxed::Box;
    #[cfg(any(feature = "server", feature = "observe"))]
    use std::rc::Rc;

    fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Option<F::Output> {
        futures_lite::future::block_on(poll_fn(|cx| {
            Poll::Ready(match future.as_mut().poll(cx) {
                Poll::Ready(output) => Some(output),
                Poll::Pending => None,
            })
        }))
    }

    type TestEndpoint<'a, const OUTBOUND: usize, const COMMANDS: usize, const PACKETS: usize> =
        Endpoint<
            'a,
            Unsecured<rand::rngs::ThreadRng>,
            128,
            OUTBOUND,
            2,
            0,
            1,
            2,
            COMMANDS,
            0,
            0,
            PACKETS,
        >;

    #[cfg(any(feature = "server", feature = "observe"))]
    struct ReleaseCounter {
        inner: Unsecured<rand::rngs::ThreadRng>,
        releases: Rc<Cell<usize>>,
    }

    #[cfg(any(feature = "server", feature = "observe"))]
    impl Protection for ReleaseCounter {
        mai_coap::delegate_protection!(inner, (); except [release]);

        fn release(&mut self, _: ()) {
            self.releases.set(self.releases.get() + 1);
        }
    }

    fn exchange(remote: SocketAddr, mid: u16) -> Exchange<()> {
        Exchange {
            slot: None,
            target: remote.into(),
            mid,
            token: heapless::Vec::from_slice(b"old").unwrap(),
            packet: None,
            retry: None,
            deadline: Instant(1_000),
            binding: None,
            original: None,
            handshaking: false,
            recovered: false,
            raw: false,
            credit: true,
            accepted: true,
            #[cfg(feature = "observe")]
            refresh: None,
            #[cfg(feature = "multicast")]
            collection: None,
            #[cfg(feature = "observe")]
            observation: None,
            #[cfg(feature = "observe")]
            observer: None,
        }
    }

    #[test]
    fn slow_command_preparation_keeps_the_mid_reserved_for_the_fresh_send_window() {
        struct Timer(core::cell::Cell<u64>);
        impl Clock for Timer {
            fn now(&self) -> Instant {
                Instant(self.0.get())
            }
            fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
                core::future::pending()
            }
        }
        let shared = Shared::<128, 1>::new();
        let mut endpoint = TestEndpoint::<1, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let parameters = TransmissionParameters::default()
            .with_ack_timeout_ms(1)
            .with_ack_random_factor(1000)
            .with_max_retransmit(0)
            .with_max_latency_ms(0);
        let operation = shared
            .handle()
            .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
            .parameters(parameters)
            .unwrap()
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        let clock = Timer(core::cell::Cell::new(0));
        endpoint.with_send_window(&clock, |window| {
            let now = window.now();
            let endpoint = &mut *window.endpoint;
            endpoint.poll(now).unwrap();
            assert!(endpoint.exchanges[0].deadline > now);
            clock.0.set(2000);
            endpoint.poll(now).unwrap();
            assert!(endpoint.front_outgoing().is_some());
            assert!(endpoint.deadline(now) > now);
        });
        assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(2000));
        assert_eq!(
            endpoint.exchanges[0].deadline,
            endpoint
                .send_policy
                .unsent_deadline(Instant(2000), parameters)
        );
        endpoint.poll(Instant(2000)).unwrap();
        assert!(endpoint.front_outgoing().is_some());
        let lifetime = parameters.exchange_lifetime() + endpoint.send_policy.max_wait_ms;
        for _ in 1..65536 {
            endpoint.ids.allocate(Instant(0), lifetime).unwrap();
        }
        assert!(!endpoint.ids.available(Instant(lifetime + 1999)));
        assert!(endpoint.ids.available(Instant(lifetime + 2000)));
        endpoint.poll(Instant(3000)).unwrap();
        assert!(matches!(
            poll_once(Box::pin(operation).as_mut()),
            Some(Err(Error::LocalSendTimeout))
        ));
    }

    // Private access observes the queued MID without exposing it through SendWindow;
    // preserve coverage of ACK removal before producer completion.
    #[test]
    fn acknowledgement_during_preparation_preserves_response_timeout_and_releases_slots() {
        let shared = Shared::<128, 1>::new();
        let mut endpoint = TestEndpoint::<1, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let remote = "192.0.2.1:5683".parse::<SocketAddr>().unwrap();
        let mut operation = Box::pin(
            shared
                .handle()
                .client(remote)
                .request(Code::GET, "/")
                .unwrap()
                .send()
                .unwrap(),
        );
        let clock = FixedClock(0);
        let response_deadline = endpoint.with_send_window(&clock, |window| {
            let now = window.now();
            let endpoint = &mut *window.endpoint;
            endpoint.poll(now).unwrap();
            let request = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
            let mid = request.message_id();
            let response_deadline = endpoint.exchanges[0].deadline;
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
            endpoint
                .receive(
                    &ack[..n],
                    Metadata::new(remote, "192.0.2.2".parse().unwrap(), n),
                    now,
                    &mut |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
                        Ok(Disposition::Complete)
                    },
                    &crate::security::AllowAll,
                )
                .unwrap();
            assert!(endpoint.front_outgoing().is_none());
            assert_eq!(endpoint.exchanges[0].deadline, response_deadline);
            assert_eq!(endpoint.deadline(now), response_deadline);
            response_deadline
        });
        assert_eq!(endpoint.deadline(Instant(0)), response_deadline);
        endpoint.poll(Instant(response_deadline.0 - 1)).unwrap();
        assert!(poll_once(operation.as_mut()).is_none());
        endpoint.poll(response_deadline).unwrap();
        assert!(matches!(
            poll_once(operation.as_mut()),
            Some(Err(Error::Timeout))
        ));
        assert!(endpoint.exchanges.is_empty());
        assert_eq!(endpoint.pool.available(), 4);
        assert_eq!(endpoint.counters().local_send_timeouts, 0);
        assert_eq!(endpoint.counters().dropped_messages, 0);
        let next = shared
            .handle()
            .client(remote)
            .request(Code::GET, "/next")
            .unwrap()
            .send()
            .unwrap();
        endpoint.poll(response_deadline).unwrap();
        assert_eq!(endpoint.exchanges.len(), 1);
        assert!(endpoint.front_outgoing().is_some());
        drop(next);
        endpoint.poll(response_deadline).unwrap();
        assert!(endpoint.exchanges.is_empty());
        assert_eq!(endpoint.pool.available(), 4);
    }

    #[test]
    fn send_window_never_shortens_an_exchange_deadline() {
        struct Timer;
        impl Clock for Timer {
            fn now(&self) -> Instant {
                Instant(2000)
            }
            fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
                core::future::pending()
            }
        }
        for accepted in [false, true] {
            let shared = Shared::<128, 1>::new();
            let mut endpoint =
                TestEndpoint::<1, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
            let remote = "192.0.2.1:5683".parse().unwrap();
            let mut exchange = exchange(remote, 77);
            exchange.accepted = accepted;
            let deadline = if accepted {
                Instant(1000)
            } else {
                Instant(u64::MAX)
            };
            exchange.deadline = deadline;
            endpoint.exchanges.push(exchange).ok().unwrap();
            endpoint.ids = MessageIds::new(77);
            assert_eq!(endpoint.ids.allocate(Instant(0), 1000), Ok(77));
            endpoint.with_send_window(&Timer, |window| {
                let now = window.now();
                let endpoint = &mut *window.endpoint;
                endpoint
                    .queue_inline(
                        remote,
                        None,
                        None,
                        &[0x40, 0x01, 0, 77],
                        QueuedMid::Owned(77),
                        now,
                    )
                    .unwrap();
            });
            assert_eq!(endpoint.exchanges[0].deadline, deadline);
            for _ in 1..65536 {
                endpoint.ids.allocate(Instant(0), 0).unwrap();
            }
            assert_eq!(endpoint.ids.available(Instant(1000)), accepted);
        }
    }

    #[test]
    fn acceptance_after_preparation_preserves_the_completed_mid_hold() {
        struct Timer(core::cell::Cell<u64>);
        impl Clock for Timer {
            fn now(&self) -> Instant {
                Instant(self.0.get())
            }
            fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
                core::future::pending()
            }
        }
        for (owned, confirmable) in [(false, false), (true, false), (true, true)] {
            let shared = Shared::<128, 1>::new();
            let mut endpoint =
                TestEndpoint::<1, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
            let parameters = TransmissionParameters::default()
                .with_ack_timeout_ms(1)
                .with_ack_random_factor(1000)
                .with_max_retransmit(0)
                .with_max_latency_ms(0);
            endpoint.set_parameters(parameters).unwrap();
            endpoint.ids = MessageIds::new(100);
            assert_eq!(
                endpoint
                    .ids
                    .allocate(Instant(0), endpoint.send_policy.unsent_lifetime(parameters)),
                Ok(100)
            );
            let remote = "192.0.2.1:5683".parse().unwrap();
            if owned {
                let mut exchange = exchange(remote, 100);
                exchange.accepted = false;
                exchange.target.parameters = parameters;
                exchange.deadline = endpoint.send_policy.unsent_deadline(Instant(0), parameters);
                exchange.retry = confirmable.then(|| Retransmission::pending(parameters, 0));
                endpoint.exchanges.push(exchange).ok().unwrap();
            }
            let clock = Timer(core::cell::Cell::new(0));
            endpoint.with_send_window(&clock, |window| {
                let now = window.now();
                let endpoint = &mut *window.endpoint;
                let mid = if owned {
                    QueuedMid::Owned(100)
                } else {
                    QueuedMid::Local(100)
                };
                endpoint
                    .queue_inline(
                        remote,
                        None,
                        None,
                        &[if confirmable { 0x40 } else { 0x50 }, 0x45, 0, 100],
                        mid,
                        now,
                    )
                    .unwrap();
                clock.0.set(2500);
            });
            endpoint.complete_outgoing(clock.now());
            if owned {
                let exchange = &endpoint.exchanges[0];
                assert!(exchange.accepted);
                assert_eq!(
                    exchange.deadline,
                    Instant(2500).after(parameters.exchange_lifetime())
                );
                if let Some(retry) = exchange.retry {
                    assert_eq!(retry.deadline(), Instant(2501));
                }
            }
            clock.0.set(5000);
            endpoint.with_send_window(&clock, |_| {});
            assert!(endpoint.front_outgoing().is_none());
            for _ in 1..65536 {
                endpoint.ids.allocate(Instant(0), 0).unwrap();
            }
            let until = endpoint
                .send_policy
                .unsent_deadline(Instant(2500), parameters);
            assert!(!endpoint.ids.available(Instant(until.0 - 1)));
            assert!(endpoint.ids.available(until));
        }
    }

    #[test]
    fn continuation_id_exhaustion_preserves_exchange_until_rollover_is_safe() {
        struct CountingProtection {
            inner: Unsecured<rand::rngs::ThreadRng>,
            calls: usize,
            releases: usize,
        }
        impl Protection for CountingProtection {
            mai_coap::delegate_protection!(inner, (); except [
                handshake_response,
                recover,
                release
            ]);

            fn handshake_response<const N: usize>(
                &mut self,
                target: Target,
                _: MessageView<'_>,
                original: MessageView<'_>,
                now: Instant,
                output: &mut [u8],
            ) -> Result<Prepared<()>, Error> {
                self.recover::<N>(target, original, now, output)
            }

            fn recover<const N: usize>(
                &mut self,
                _: Target,
                original: MessageView<'_>,
                _: Instant,
                output: &mut [u8],
            ) -> Result<Prepared<()>, Error> {
                self.calls += 1;
                Ok(Prepared::Request {
                    length: copy(original.as_bytes(), output)?,
                    binding: Some(()),
                })
            }

            fn release(&mut self, _: ()) {
                self.releases += 1;
            }
        }

        for handshaking in [false, true] {
            for ty in [MessageType::Acknowledgement, MessageType::Confirmable] {
                let shared = Shared::<128, 0>::new();
                let mut endpoint = Endpoint::<_, 128, 1, 2, 0, 1, 2, 0, 0, 0, 2>::new(
                    &shared,
                    CountingProtection {
                        inner: Unsecured(rand::rng()),
                        calls: 0,
                        releases: 0,
                    },
                )
                .unwrap();
                let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
                let mut active = exchange(remote, 300);
                active.handshaking = handshaking;
                active.target.recover = true;
                active.binding = (!handshaking).then_some(());
                active.retry = Some(Retransmission::new(Instant(0), active.target.parameters, 0));
                let retry_at = active.retry.unwrap().deadline();
                let mut original = [0; 128];
                let length = MessageBuilder::new(
                    &mut original,
                    MessageType::Confirmable,
                    Code::GET,
                    active.mid,
                    &active.token,
                )
                .unwrap()
                .finish(&[])
                .unwrap();
                for slot in [&mut active.original, &mut active.packet] {
                    let packet = endpoint.pool.reserve().unwrap();
                    endpoint.pool.write(&packet, &original[..length]).unwrap();
                    *slot = Some(packet);
                }
                assert!(endpoint.exchanges.push(active).is_ok());
                endpoint.ids = MessageIds::new(1);
                for _ in 0..=u16::MAX {
                    endpoint.ids.allocate(Instant(0), 100).unwrap();
                }
                let mut response = [0; 128];
                let code = if handshaking {
                    Code::CONTENT
                } else {
                    Code::UNAUTHORIZED
                };
                let n = MessageBuilder::new(&mut response, ty, code, 300, b"old")
                    .unwrap()
                    .finish(&[])
                    .unwrap();
                let message = MessageView::parse(&response[..n]).unwrap();
                let metadata = Metadata::new(remote, "192.0.2.2".parse().unwrap(), n);
                let mut app =
                    |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);

                for now in [Instant(1), Instant(99)] {
                    assert_eq!(
                        endpoint.receive_response(message, metadata, now, &mut app),
                        Err(Error::Capacity)
                    );
                    assert_eq!(endpoint.protection.calls, 0);
                    assert_eq!(endpoint.protection.releases, 0);
                    assert!(endpoint.front_outgoing().is_none());
                    assert_eq!(endpoint.pool.available(), 0);
                    assert_eq!(endpoint.exchanges.len(), 1);
                    let active = &endpoint.exchanges[0];
                    assert_eq!(active.mid, 300);
                    assert_eq!(active.token.as_slice(), b"old");
                    assert_eq!(active.retry.unwrap().deadline(), retry_at);
                    assert_eq!(active.handshaking, handshaking);
                    assert_eq!(active.binding.is_some(), !handshaking);
                    assert!(!active.recovered);
                    for packet in [&active.original, &active.packet] {
                        assert_eq!(
                            endpoint.pool.get(packet.as_ref().unwrap()).unwrap(),
                            &original[..length]
                        );
                    }
                }
                assert_eq!(endpoint.deadline(Instant(99)), Instant(100));

                endpoint.with_send_window(&FixedClock(100), |window| {
                    let now = window.now();
                    let endpoint = &mut *window.endpoint;
                    endpoint
                        .receive_response(message, metadata, now, &mut app)
                        .unwrap();
                    assert!(!endpoint.exchanges[0].accepted);
                    assert!(endpoint.exchanges[0].deadline > now);
                });
                assert!(!endpoint.exchanges[0].accepted);
                assert_eq!(endpoint.protection.calls, 1);
                assert_eq!(endpoint.protection.releases, usize::from(!handshaking));
                if ty == MessageType::Confirmable {
                    let ack = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
                    assert_eq!(ack.code(), Code::EMPTY);
                    assert_eq!(ack.message_type(), MessageType::Acknowledgement);
                    endpoint.complete_outgoing(
                        endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued),
                    );
                }
                let next = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
                assert_eq!(next.code(), Code::GET);
                assert_eq!(next.message_id(), 1);
                endpoint.complete_outgoing(
                    endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued),
                );
                assert_eq!(endpoint.exchanges.len(), 1);
                assert!(endpoint.exchanges[0].accepted);
                endpoint.finish(0, Err(Error::Timeout));
                assert_eq!(endpoint.pool.available(), 2);
                assert_eq!(endpoint.protection.releases, 1 + usize::from(!handshaking));
            }
        }
    }

    #[cfg(all(feature = "server", feature = "_xarxa"))]
    #[test]
    fn inbound_allocation_releases_waiting_commands_before_the_backoff_deadline() {
        use xarxa::{Pool, StaticPool};
        static NETWORK: StaticPool<128, 2> = StaticPool::new();
        let blocked = Cell::new(true);
        let storage =
            crate::XarxaStorage::<_, 4>::new(|| if blocked.get() { None } else { NETWORK.alloc() });
        let shared = Shared::<128, 1>::new();
        let mut endpoint = Endpoint::<_, 128, 1, 2, 0, 1, 4, 1, 0, 0, 4, _>::with_storage(
            &shared,
            Unsecured(rand::rng()),
            storage,
        )
        .unwrap();
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let operation = shared
            .handle()
            .client(remote)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        let mut operation = Box::pin(operation);
        for now in [0, 1, 3, 7, 15, 31, 63, 127, 255, 511] {
            endpoint.poll(Instant(now)).unwrap();
        }
        assert!(poll_once(operation.as_mut()).is_none());
        assert_eq!(endpoint.deadline(Instant(512)), Instant(1023));
        blocked.set(false);
        let mut bytes = [0; 128];
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::POST,
            42,
            b"s",
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        let metadata = Metadata::new(remote, "192.0.2.2".parse().unwrap(), n);
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        endpoint
            .receive(
                &bytes[..n],
                metadata,
                Instant(512),
                &mut app,
                &crate::security::AllowAll,
            )
            .unwrap();
        assert_eq!(endpoint.storage_deadline(), None);
        assert_eq!(endpoint.storage_backoff_ms, 1);
        endpoint.poll(Instant(512)).unwrap();
        let first = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        assert!(first.code().is_response());
        assert!(matches!(
            endpoint.reserve_packet(None, Instant(512)),
            Err(Error::Capacity)
        ));
        assert_eq!(endpoint.storage_deadline(), Some(Instant(513)));
        endpoint.complete_outgoing(endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued));
        assert_eq!(endpoint.storage_deadline(), None);
        let held = NETWORK.alloc().unwrap();
        assert!(matches!(
            endpoint.reserve_packet(None, Instant(512)),
            Err(Error::Capacity)
        ));
        let next = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        assert_eq!(next.code(), Code::GET);
        endpoint.complete_outgoing(endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued));
        assert_eq!(endpoint.storage_deadline(), Some(Instant(513)));
        drop(operation);
        endpoint.poll(Instant(512)).unwrap();
        assert_eq!(endpoint.storage_deadline(), None);
        assert_eq!(endpoint.storage_backoff_ms, 1);
        assert_eq!(endpoint.pool.available(), 4);
        drop(held);
    }

    #[test]
    fn full_logical_pool_does_not_start_backing_allocation_backoff() {
        let shared = Shared::<128, 0>::new();
        let mut endpoint = TestEndpoint::<0, 0, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
        let first = endpoint.reserve_packet(None, Instant(0)).unwrap();
        let second = endpoint.reserve_packet(None, Instant(0)).unwrap();
        for now in [0, 1, 10, 2000] {
            assert!(matches!(
                endpoint.reserve_packet(None, Instant(now)),
                Err(Error::Capacity)
            ));
            assert_eq!(endpoint.storage_deadline(), None);
            assert_eq!(endpoint.storage_backoff_ms, 1);
        }
        endpoint.pool.release(first);
        endpoint.pool.release(second);
    }

    #[test]
    #[cfg(feature = "shared-counters")]
    fn counter_publication_preserves_command_revision_and_driver_waker() {
        use std::{sync::Arc, task::Wake};

        struct UnexpectedWake;
        impl Wake for UnexpectedWake {
            fn wake(self: Arc<Self>) {
                panic!("counter publication must not wake the driver");
            }
        }

        let shared = Shared::<128, 0>::new();
        let mut endpoint = TestEndpoint::<0, 0, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
        shared.lock(|state| {
            state.revision = 17;
            state.driver = Some(Waker::from(Arc::new(UnexpectedWake)));
        });
        endpoint.counters.requests = 3;
        endpoint.publish_counters();
        assert_eq!(shared.counters().requests, 3);
        shared.lock(|state| {
            assert_eq!(state.revision, 17);
            assert!(state.driver.is_some());
        });
    }

    #[test]
    fn malformed_pending_request_completes_and_frees_command_slot() {
        let shared = Shared::<128, 1>::new();
        let mut endpoint = TestEndpoint::<1, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let local: IpAddr = "192.0.2.2".parse().unwrap();
        for _ in 0..2 {
            endpoint
                .queue_inline(
                    remote,
                    Some(local),
                    None,
                    &[1, 2, 3, 4],
                    QueuedMid::Peer,
                    Instant(0),
                )
                .unwrap();
        }
        let operation = shared
            .submit(Command::Request {
                target: Target::new(remote),
                packet: Packet::copy_from(&[0]).unwrap(),
                token_len: 1,
                wait: false,
                raw: false,
                #[cfg(feature = "multicast")]
                collect_until: None,
            })
            .unwrap();
        let mut operation = Box::pin(operation);

        endpoint.poll(Instant(0)).unwrap();
        assert!(matches!(
            poll_once(operation.as_mut()),
            Some(Err(Error::Malformed))
        ));
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, [1, 2, 3, 4]);
        drop(operation);
        endpoint.complete_outgoing(endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued));
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, [1, 2, 3, 4]);
        endpoint.complete_outgoing(endpoint.front_outgoing().map_or(Instant(0), |p| p.enqueued));

        let fresh = shared
            .handle()
            .client(remote)
            .request(Code::GET, "/fresh")
            .unwrap()
            .send()
            .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        assert!(endpoint.front_outgoing().is_some());
        drop(fresh);
        endpoint.poll(Instant(1)).unwrap();
    }

    #[test]
    fn rejected_nonconfirmable_exchange_releases_queued_packet_only() {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = TestEndpoint::<1, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let existing_peer: SocketAddr = "192.0.2.3:5683".parse().unwrap();
        assert!(endpoint.exchanges.push(exchange(existing_peer, 91)).is_ok());

        let mut request = [0; 128];
        let length = MessageBuilder::new(
            &mut request,
            MessageType::NonConfirmable,
            Code::GET,
            7,
            b"t",
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        let reservation = endpoint.reserve_packet(None, Instant(0)).unwrap();
        let result = endpoint.command_reserved(
            (0, 1),
            Command::Request {
                target: Target::new(peer),
                packet: Packet::copy_from(&request[..length]).unwrap(),
                token_len: 1,
                wait: false,
                raw: false,
                #[cfg(feature = "multicast")]
                collect_until: None,
            },
            Instant(0),
            &reservation,
            None,
        );
        assert_eq!(result, Err(Error::Capacity));
        endpoint.pool.release(reservation);

        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.pool.available(), 4);
        assert_eq!(endpoint.exchanges.len(), 1);
        assert_eq!(endpoint.exchanges[0].target.remote, existing_peer);
        assert_eq!(endpoint.exchanges[0].mid, 91);
    }

    #[cfg(feature = "server")]
    #[test]
    fn deferred_ack_queue_failure_releases_incoming_binding_once() {
        type DeferredEndpoint<'a> = Endpoint<'a, ReleaseCounter, 32, 1, 2, 0, 1, 1, 1, 1, 0, 3>;
        let shared = Shared::<32, 1>::new();
        let releases = Rc::new(Cell::new(0));
        let mut endpoint = DeferredEndpoint::new(
            &shared,
            ReleaseCounter {
                inner: Unsecured(rand::rng()),
                releases: releases.clone(),
            },
        )
        .unwrap();
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let local: IpAddr = "192.0.2.2".parse().unwrap();
        endpoint
            .queue_inline(
                remote,
                Some(local),
                None,
                &[0; 4],
                QueuedMid::Peer,
                Instant(0),
            )
            .unwrap();
        let mut bytes = [0; 32];
        let length = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 3, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        let message = MessageView::parse(&bytes[..length]).unwrap();
        let metadata = Metadata::new(remote, local, length);
        let reservation = endpoint.reserve_packet(None, Instant(0)).unwrap();

        let result = endpoint.defer_request(
            message,
            metadata,
            (
                Ticket(1),
                ResponseWriter::new(&mut [0; 32], Code::CONTENT, message.token()).unwrap(),
            ),
            Some(()),
            Instant(0),
            &reservation,
        );
        assert_eq!(result, Err(Error::Capacity));
        endpoint.pool.release(reservation);
        assert_eq!(releases.get(), 1);
        assert_eq!(endpoint.deferred.len(), 0);
        assert!(endpoint.front_outgoing().is_some());
    }

    #[cfg(feature = "observe")]
    #[test]
    fn oversized_observer_snapshot_releases_incoming_binding_once() {
        type ObserveEndpoint<'a> = Endpoint<'a, ReleaseCounter, 32, 1, 2, 1, 1, 2, 1, 0, 0, 3>;
        let shared = Shared::<32, 1>::new();
        let releases = Rc::new(Cell::new(0));
        let mut endpoint = ObserveEndpoint::new(
            &shared,
            ReleaseCounter {
                inner: Unsecured(rand::rng()),
                releases: releases.clone(),
            },
        )
        .unwrap();
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let local: IpAddr = "192.0.2.2".parse().unwrap();
        let mut bytes = [0; 128];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 4, b"t").unwrap();
        builder.option(OptionNumber::OBSERVE, &[0]).unwrap();
        let length = builder.finish(&[0; 64]).unwrap();
        let message = MessageView::parse(&bytes[..length]).unwrap();
        let metadata = Metadata::new(remote, local, length);
        let request = Request {
            message,
            metadata,
            security: SecurityState::Unprotected,
            ticket: Ticket(1),
            deferred_available: false,
            body: message.payload(),
            context: None,
            #[cfg(feature = "server")]
            response_grace_ms: 10_000,
        };
        let mut arena = [0; 32];
        let response = ResponseWriter::new(&mut arena, Code::CONTENT, message.token()).unwrap();
        let reservation = endpoint
            .reserve_packet(Some((remote, local)), Instant(0))
            .unwrap();

        let result = endpoint.register_observer(
            request,
            message,
            response,
            Some(()),
            crate::observe::Settings::new(1),
            (Instant(0), &reservation),
        );
        assert_eq!(result, Err(Error::Capacity));
        endpoint.pool.release(reservation);
        assert_eq!(releases.get(), 1);
        assert_eq!(endpoint.observers.len(), 0);
        assert!(endpoint.front_outgoing().is_none());
    }
}

#[cfg(all(feature = "server", feature = "multicast"))]
mod server_multicast_regressions {
    use super::super::*;
    use crate::codec::MessageBuilder;
    use core::{cell::Cell, future::Future};

    #[test]
    fn leisure_promotion_explicitly_starts_the_send_window_and_extends_the_mid_hold() {
        struct Timer(Cell<u64>);
        impl Clock for Timer {
            fn now(&self) -> Instant {
                Instant(self.0.get())
            }
            fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
                core::future::pending()
            }
        }
        let shared = Shared::<128, 1>::new();
        let mut endpoint =
            Endpoint::<_, 128, 1, 2, 0, 1, 2, 1, 0, 0, 4>::new(&shared, Unsecured(rand::rng()))
                .unwrap();
        endpoint.ids = MessageIds::new(100);
        endpoint
            .set_parameters(TransmissionParameters::default().with_leisure_ms(0))
            .unwrap();
        let clock = Timer(Cell::new(0));
        let mut bytes = [0; 128];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::NonConfirmable, Code::GET, 1, b"t")
                .unwrap();
        crate::uri::path_options("/.well-known/core", &mut builder).unwrap();
        let n = builder.finish(&[]).unwrap();
        let metadata = crate::transport::Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "224.0.1.187".parse().unwrap(),
            n,
        );
        endpoint
            .with_send_window(&clock, |window| {
                let now = window.now();
                let endpoint = &mut *window.endpoint;
                endpoint.receive(
                    &bytes[..n],
                    metadata,
                    now,
                    &mut |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
                        clock.0.set(2000);
                        response.set_payload(b"reply")?;
                        Ok(Disposition::Complete)
                    },
                    &crate::security::AllowAll,
                )
            })
            .unwrap();
        assert!(endpoint.outgoing.is_empty());
        assert_eq!(endpoint.leisure.len(), 1);
        assert!(!endpoint.leisure[0].outgoing.pending_timestamp);
        endpoint
            .with_send_window(&clock, |window| {
                let now = window.now();
                let endpoint = &mut *window.endpoint;
                endpoint.poll_multicast(now)?;
                assert!(endpoint.outgoing.front().unwrap().pending_timestamp);
                clock.0.set(3000);
                Ok::<_, Error>(())
            })
            .unwrap();
        assert_eq!(endpoint.front_outgoing().unwrap().enqueued, Instant(3000));
        assert!(!endpoint.outgoing.front().unwrap().pending_timestamp);
        let until = clock
            .now()
            .after(endpoint.parameters.exchange_lifetime() + endpoint.send_policy.max_wait_ms);
        for _ in 1..65536 {
            endpoint.ids.allocate(Instant(0), 0).unwrap();
        }
        assert!(!endpoint.ids.available(Instant(until.0 - 1)));
        assert!(endpoint.ids.available(until));
    }
}

#[cfg(all(feature = "client", feature = "observe"))]
mod local_observe {
    use super::*;
    #[test]
    fn unsent_refresh_preserves_binding_and_order_until_acceptance_or_abort() {
        for (accept, cancel) in [(true, false), (true, true), (false, false), (false, true)] {
            let shared = Shared::<128, 0>::new();
            let mut endpoint =
                Endpoint::<_, 128, 1, 4, 1, 2, 4, 0, 0, 0, 4>::new(&shared, Unsecured(rand::rng()))
                    .unwrap();
            let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
            let mut original = [0; 128];
            let n = {
                let mut b = MessageBuilder::new(
                    &mut original,
                    MessageType::Confirmable,
                    Code::GET,
                    77,
                    b"t",
                )
                .unwrap();
                b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
                b.finish(&[]).unwrap()
            };
            let packet = endpoint.pool.reserve().unwrap();
            endpoint.pool.write(&packet, &original[..n]).unwrap();
            let mut ordering = crate::observe::Ordering::default();
            assert!(ordering.accept(10, Instant(0)));
            let exchange = Exchange {
                slot: None,
                target: remote.into(),
                mid: 77,
                token: heapless::Vec::from_slice(b"t").unwrap(),
                packet: None,
                retry: None,
                deadline: Instant(10),
                binding: Some(()),
                original: Some(packet),
                handshaking: false,
                recovered: false,
                raw: false,
                credit: false,
                accepted: true,
                #[cfg(feature = "multicast")]
                collection: None,
                observation: Some(ordering),
                observer: None,
                refresh: None,
            };
            assert!(endpoint.exchanges.push(exchange).is_ok());
            endpoint.with_send_window(&FixedClock(10), |window| {
                let now = window.now();
                let endpoint = &mut *window.endpoint;
                endpoint.refresh_observation(0, cancel, now).unwrap();
                assert!(endpoint.exchanges[0].accepted);
                assert_eq!(endpoint.exchanges[0].deadline, Instant(10));
            });
            assert!(endpoint.exchanges[0].accepted);
            let candidate = endpoint.exchanges[0].refresh.as_ref().unwrap().mid;
            assert_ne!(candidate, 77);
            assert_eq!(endpoint.exchanges[0].mid, 77);
            assert_eq!(endpoint.exchanges[0].binding, Some(()));
            assert!(
                !endpoint.exchanges[0]
                    .observation
                    .unwrap()
                    .accept(9, Instant(11))
            );
            assert_eq!(
                endpoint
                    .pool
                    .get(endpoint.exchanges[0].original.as_ref().unwrap())
                    .unwrap(),
                &original[..n]
            );
            if accept {
                endpoint.complete_outgoing(Instant(20));
                assert_eq!(endpoint.exchanges[0].mid, candidate);
                assert!(endpoint.exchanges[0].refresh.is_none());
                if cancel {
                    assert!(endpoint.exchanges[0].observation.is_none());
                } else {
                    assert!(!endpoint.exchanges[0].observation.unwrap().established());
                }
                let original = MessageView::parse(
                    endpoint
                        .pool
                        .get(endpoint.exchanges[0].original.as_ref().unwrap())
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(original.message_id(), candidate);
                assert_eq!(
                    original.option(OptionNumber::OBSERVE).unwrap().uint(),
                    Ok(u64::from(cancel))
                );
                assert!(endpoint.exchanges[0].retry.unwrap().deadline() >= Instant(2020));
            } else {
                endpoint.poll(Instant(1010)).unwrap();
                if cancel {
                    assert!(endpoint.exchanges.is_empty());
                    assert_eq!(endpoint.pool.available(), 4);
                } else {
                    assert_eq!(
                        endpoint
                            .pool
                            .get(endpoint.exchanges[0].original.as_ref().unwrap())
                            .unwrap(),
                        &original[..n]
                    );
                    assert_eq!(endpoint.exchanges[0].mid, 77);
                    assert_eq!(endpoint.exchanges[0].binding, Some(()));
                    assert!(endpoint.exchanges[0].observation.unwrap().established());
                    assert!(endpoint.exchanges[0].refresh.is_none());
                    assert_eq!(endpoint.deadline(Instant(1010)), Instant(1074));
                }
            }
        }
    }
}

mod queue_metadata {
    use super::super::{Queued, QueuedMid, SendPacket};
    use crate::time::Instant;
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    #[test]
    fn queued_routes_preserve_every_address_field_and_optional_interface() {
        let remotes = [
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, u16::MAX)),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 5683)),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
            SocketAddr::V6(SocketAddrV6::new(
                Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped(),
                u16::MAX,
                u32::MAX,
                u32::MAX,
            )),
            SocketAddr::V6(SocketAddrV6::new(
                "fe80::1".parse().unwrap(),
                5683,
                0x12345,
                7,
            )),
        ];
        for remote in remotes {
            for source in [
                None,
                Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ] {
                for interface in [None, Some(0), Some(1), Some(u32::MAX)] {
                    let queued = Queued::new(
                        remote,
                        source,
                        interface,
                        SendPacket::Inline {
                            bytes: [0; 4],
                            length: 4,
                        },
                        QueuedMid::Peer,
                        Instant(0),
                        false,
                    );
                    let restored = queued.remote;
                    assert_eq!(restored, remote);
                    if let (SocketAddr::V6(actual), SocketAddr::V6(expected)) = (restored, remote) {
                        assert_eq!(actual.flowinfo(), expected.flowinfo());
                        assert_eq!(actual.scope_id(), expected.scope_id());
                    }
                    assert_eq!(queued.source, source);
                    assert_eq!(queued.interface(), interface);
                }
            }
        }
    }
}
