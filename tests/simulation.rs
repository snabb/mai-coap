//! Deterministic transport faults, congestion and Observe lifecycle tests.
#![cfg(all(
    feature = "server",
    feature = "client",
    feature = "observe",
    feature = "block"
))]
mod support;
use futures_lite::future::{block_on, poll_once, race};
use mai_coap::{
    codec::{Code, MessageType, MessageView},
    endpoint::{Disposition, Endpoint, Protection, Request, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    observe::Settings,
    security::PublicPaths,
    server::Router,
    transport::{DatagramReceiver, DatagramSender},
};
use support::{Action, Network};

#[test]
fn tst_4_rel_3_lost_evicted_reply_finishes_with_unavailable_instead_of_timeout() {
    fn check<P: Protection>(client_protection: P, server_protection: P, protected: bool) {
        use mai_coap::{
            Error,
            codec::{MessageBuilder, OptionNumber},
            security::PeerId,
            time::{Clock, Instant},
        };
        block_on(async {
            let network = Network::default();
            network.configure(0, &[Action::Deliver, Action::Drop]);
            let cs = Shared::<256, 2>::new();
            let ss = Shared::<256, 2>::new();
            let mut client = Endpoint::<_, 256, 2, 8>::new(&cs, client_protection).unwrap();
            let mut server = Endpoint::<_, 256, 2, 8, 0, 1>::new(&ss, server_protection).unwrap();
            let mut a = network.socket("192.0.2.1:5683");
            let mut b = network.socket("192.0.2.2:5683");
            let server_addr = b.local;
            let pressure_addr = "192.0.2.3:5683".parse().unwrap();
            let calls = core::cell::Cell::new(0);
            let mut application = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
                calls.set(calls.get() + 1);
                response.set_code(Code::CHANGED);
                response.set_payload(b"done")?;
                Ok(Disposition::Complete)
            };
            let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
            let policy = PublicPaths(&[(Code::POST, "/x"), (Code::POST, "/pressure")]);
            let mut destination = cs
                .handle()
                .client(server_addr)
                .parameters(TransmissionParameters::default().with_ack_random_factor(1000))
                .unwrap();
            if protected {
                destination = destination.peer(PeerId(1)).recovery(true);
            }
            {
                let drivers = race(
                    client.run(&mut a, &network, &mut unused, &policy),
                    server.run(&mut b, &network, &mut application, &policy),
                );
                let mut drivers = core::pin::pin!(drivers);
                let mut operation = core::pin::pin!(
                    destination
                        .request(Code::POST, "/x")
                        .unwrap()
                        .send()
                        .unwrap()
                );
                for _ in 0..20 {
                    assert!(poll_once(drivers.as_mut()).await.is_none());
                    if network.sent().len() == 2 {
                        break;
                    }
                    network.advance(1);
                }
                assert_eq!(
                    network.sent().len(),
                    2,
                    "the initial reply was sent and lost"
                );
                assert_eq!(calls.get(), 1);
                assert!(poll_once(operation.as_mut()).await.is_none());

                let mut pressure = [0; 64];
                let mut builder = MessageBuilder::new(
                    &mut pressure,
                    MessageType::Confirmable,
                    Code::POST,
                    123,
                    b"pressure",
                )
                .unwrap();
                builder.option(OptionNumber::URI_PATH, b"pressure").unwrap();
                let n = builder.finish(&[]).unwrap();
                network.inject(pressure_addr, server_addr, &pressure[..n]);
                let mut completed = false;
                for _ in 0..500 {
                    assert!(poll_once(drivers.as_mut()).await.is_none());
                    if let Some(result) = poll_once(operation.as_mut()).await {
                        if protected {
                            assert_eq!(
                                result.unwrap_err(),
                                Error::UnprotectedResponse(Code::UNAVAILABLE)
                            );
                        } else {
                            assert_eq!(
                                result.unwrap().message().unwrap().code(),
                                Code::UNAVAILABLE
                            );
                        }
                        completed = true;
                        break;
                    }
                    network.advance(10);
                }
                assert!(
                    completed,
                    "must fail at the first retransmission, not exchange expiry"
                );
                assert!(network.now() < Instant(5000));
                assert_eq!(calls.get(), 2, "the duplicate must not reach the handler");

                let mut fresh = core::pin::pin!(
                    destination
                        .request(Code::POST, "/x")
                        .unwrap()
                        .send()
                        .unwrap()
                );
                let mut completed = false;
                for _ in 0..20 {
                    assert!(poll_once(drivers.as_mut()).await.is_none());
                    if let Some(result) = poll_once(fresh.as_mut()).await {
                        assert_eq!(result.unwrap().message().unwrap().code(), Code::CHANGED);
                        completed = true;
                        break;
                    }
                    network.advance(1);
                }
                assert!(completed, "a fresh request must still succeed immediately");
            }
            assert_eq!(calls.get(), 3);
            assert_eq!(server.counters().dedup_reply_misses, 1);
            assert_eq!(server.counters().duplicates, 1);
            assert_eq!(server.counters().protection_failures, 0);
            assert_eq!(
                client.counters().unprotected_responses,
                u64::from(protected)
            );
            let sent = network.sent();
            let retries: Vec<_> = sent.iter().filter(|p| p.from == a.local).collect();
            assert_eq!(retries.len(), 3);
            assert_eq!(retries[0].bytes, retries[1].bytes);
            assert_ne!(retries[1].bytes, retries[2].bytes);
            let refusals: Vec<_> = sent
                .iter()
                .filter(|p| MessageView::parse(&p.bytes).unwrap().code() == Code::UNAVAILABLE)
                .collect();
            assert_eq!(refusals.len(), 1);
            let refusal = MessageView::parse(&refusals[0].bytes).unwrap();
            let original = MessageView::parse(&retries[0].bytes).unwrap();
            assert_eq!(refusal.message_type(), MessageType::Acknowledgement);
            assert_eq!(refusal.message_id(), original.message_id());
            assert_eq!(refusal.token(), original.token());
            assert_eq!(refusal.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(0));
            assert!(refusal.option(OptionNumber::OSCORE).is_none());
        });
    }
    check(Unsecured(rand::rng()), Unsecured(rand::rng()), false);
    #[cfg(feature = "software-crypto")]
    {
        use mai_coap::{
            crypto::SoftwareCrypto,
            oscore::{Context, Oscore},
            security::PeerId,
        };
        let mut cp = SoftwareCrypto::new(rand::rng());
        let cc = Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
        let mut sp = SoftwareCrypto::new(rand::rng());
        let sc = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let mut cp = Oscore::<_, 1>::new(cp);
        cp.install_fresh(cc).unwrap();
        let mut sp = Oscore::<_, 1>::new(sp);
        sp.install_fresh(sc).unwrap();
        check(cp, sp, true);
    }
}

#[test]
fn tst_4_rel_3_4_slow_lossy_link_reuses_exact_bytes_and_dispatches_once() {
    block_on(async {
        let network = Network::default();
        network.configure(
            1500,
            &[Action::Duplicate, Action::Drop, Action::Delay(1000)],
        );
        let client_shared = Shared::<256, 2>::new();
        let server_shared = Shared::<256, 2>::new();
        let mut client =
            Endpoint::<_, 256, 2, 8>::new(&client_shared, Unsecured(rand::rng())).unwrap();
        let mut server =
            Endpoint::<_, 256, 2, 8>::new(&server_shared, Unsecured(rand::rng())).unwrap();
        let mut client_socket = network.socket("192.0.2.1:5683");
        let mut server_socket = network.socket("192.0.2.2:5683");
        let peer = server_socket.local;
        let mut calls = 0;
        let mut application = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            calls += 1;
            response.set_payload(b"one").unwrap();
            Ok(Disposition::Complete)
        };
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let policy = PublicPaths(&[(Code::GET, "/x")]);
        {
            let drivers = race(
                client.run(&mut client_socket, &network, &mut unused, &policy),
                server.run(&mut server_socket, &network, &mut application, &policy),
            );
            let mut drivers = core::pin::pin!(drivers);
            let handle = client_shared.handle();
            let mut operation = core::pin::pin!(handle.client(peer).get("/x"));
            let mut complete = false;
            for _ in 0..2000 {
                assert!(poll_once(drivers.as_mut()).await.is_none());
                if let Some(response) = poll_once(operation.as_mut()).await {
                    assert_eq!(response.unwrap().message().unwrap().payload(), b"one");
                    complete = true;
                    break;
                }
                network.advance(10);
            }
            assert!(complete, "simulated response deadline");
        }
        assert_eq!(calls, 1);
        let sent = network.sent();
        let requests: Vec<_> = sent
            .iter()
            .filter(|p| {
                p.from.ip() == "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
                    && MessageView::parse(&p.bytes).unwrap().code().is_request()
            })
            .collect();
        assert!(requests.len() >= 2);
        assert!(requests.iter().all(|p| p.bytes == requests[0].bytes));
    });
}

#[test]
fn obs_1_2_3_4_5_8_change_coalescing_confirmable_ack_refresh_and_cancel() {
    block_on(async {
        let network = Network::default();
        let cs = Shared::<256, 4>::new();
        let ss = Shared::<256, 4>::new();
        let mut client = Endpoint::<_, 256, 4, 16>::new(&cs, Unsecured(rand::rng())).unwrap();
        let mut server = Endpoint::<_, 256, 4, 16>::new(&ss, Unsecured(rand::rng())).unwrap();
        let mut client_socket = network.socket("192.0.2.1:5683");
        let mut server_socket = network.socket("192.0.2.2:5683");
        let peer = server_socket.local;
        let policy = PublicPaths(&[(Code::GET, "/x")]);
        let mut value = 0u8;
        let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            value += 1;
            response.set_payload(&[value]).unwrap();
            Ok(Disposition::Complete)
        };
        let mut router = Router::<256>::new(&policy);
        router.route("/x", &[Code::GET], &mut handler).unwrap();
        router
            .observable(
                "/x",
                Settings::new(7)
                    .with_minimum_ms(100)
                    .with_maximum_ms(500)
                    .with_confirmable_ms(1000),
            )
            .unwrap();
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let drivers = race(
            client.run(&mut client_socket, &network, &mut unused, &policy),
            server.run(&mut server_socket, &network, &mut router, &policy),
        );
        let mut drivers = core::pin::pin!(drivers);
        let handle = cs.handle();
        let mut stream = handle
            .client(peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .observe("/x")
            .unwrap();
        let mut values = Vec::new();
        for i in 0..160 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            if let Some(Some(reply)) = poll_once(stream.next()).await {
                values.push(reply.unwrap().message().unwrap().payload()[0]);
            }
            if i < 5 {
                ss.handle().notify(7).unwrap();
            }
            network.advance(10);
        }
        assert!(values.len() >= 4 && values.len() <= 6, "{values:?}");
        assert!(values.windows(2).all(|v| v[0] < v[1]));
        let sent = network.sent();
        assert!(sent.iter().any(|p| {
            let m = MessageView::parse(&p.bytes).unwrap();
            m.code().is_response() && m.message_type() == MessageType::Confirmable
        }));
        stream.cancel();
        for _ in 0..5 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            network.advance(1);
        }
        let before = network.sent().len();
        network.advance(5000);
        for _ in 0..5 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            network.advance(1);
        }
        assert_eq!(
            network.sent().len(),
            before,
            "cancelled server must stop notifications"
        );
    });
}

#[test]
fn tr_5_simulator_reports_icmp_and_reorders_delayed_packets() {
    block_on(async {
        let network = Network::default();
        network.configure(
            0,
            &[Action::Delay(20), Action::Deliver, Action::Unreachable],
        );
        let a = network.socket("192.0.2.1:1");
        let b = network.socket("192.0.2.2:2");
        core::future::poll_fn(|cx| (&a).poll_send(b.local, None, None, b"first", cx))
            .await
            .unwrap();
        core::future::poll_fn(|cx| (&a).poll_send(b.local, None, None, b"second", cx))
            .await
            .unwrap();
        let mut scratch = [0; 32];
        assert_eq!((&b).receive(&mut scratch).await.unwrap().bytes, b"second");
        network.advance(20);
        assert_eq!((&b).receive(&mut scratch).await.unwrap().bytes, b"first");
        core::future::poll_fn(|cx| (&a).poll_send(b.local, None, None, b"icmp", cx))
            .await
            .unwrap();
        assert!((&a).receive(&mut scratch).await.is_err());
    });
}

#[cfg(all(feature = "software-crypto", feature = "proxy"))]
#[test]
fn tst_4_osc_14_prx_4_slow_proxy_preserves_protected_retries_and_dispatches_once() {
    use core::net::SocketAddr;
    use mai_coap::{
        crypto::SoftwareCrypto,
        oscore::{Context, Oscore},
        proxy::{ForwardProxy, Routing},
        security::{PeerId, ProtectedOnly},
    };
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: SocketAddr, host: &str, _: u16) -> bool {
            host == "192.0.2.3"
        }
    }
    block_on(async {
        let network = Network::default();
        network.configure(1500, &[Action::Deliver, Action::Duplicate, Action::Drop]);
        let cs = Shared::<256, 4>::new();
        let ps = Shared::<256, 4>::new();
        let ss = Shared::<256, 4>::new();
        let proxy_addr: core::net::SocketAddr = "192.0.2.2:5683".parse().unwrap();
        let mut cp = SoftwareCrypto::new(rand::rng());
        let cc = Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
        let mut sp = SoftwareCrypto::new(rand::rng());
        let sc = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let mut cp = Oscore::<_, 2>::new(cp);
        cp.install_fresh(cc).unwrap();
        let mut sp = Oscore::<_, 2>::new(sp);
        sp.install_fresh(sc).unwrap();
        let mut client = Endpoint::<_, 256, 4, 16>::new(&cs, cp).unwrap();
        let mut proxy = Endpoint::<_, 256, 4, 16>::new(&ps, Unsecured(rand::rng())).unwrap();
        let mut server = Endpoint::<_, 256, 4, 16>::new(&ss, sp).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let mut c = network.socket("192.0.2.3:5683");
        let mut calls = 0;
        let mut handler = |request: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            assert!(matches!(
                request.security,
                mai_coap::security::SecurityState::Protected { .. }
            ));
            calls += 1;
            response.set_payload(b"protected through proxy").unwrap();
            Ok(Disposition::Complete)
        };
        let mut empty = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let mut forwarding =
            ForwardProxy::<_, _, 256, 4, 4>::new(local, Route, ps.handle()).unwrap();
        {
            let drivers = race(
                client.run(&mut a, &network, &mut empty, &ProtectedOnly),
                race(
                    proxy.run(&mut b, &network, &mut forwarding, &ProtectedOnly),
                    server.run(&mut c, &network, &mut handler, &ProtectedOnly),
                ),
            );
            let mut drivers = core::pin::pin!(drivers);
            let handle = cs.handle();
            let mut output = [0; 256];
            let mut operation = core::pin::pin!(
                handle
                    .client(proxy_addr)
                    .peer(PeerId(1))
                    // The proxy's empty ACK arrives at 3010 ms; a jittered first
                    // timeout near 3000 ms would race it and skip the retry.
                    .parameters(TransmissionParameters::default().with_ack_random_factor(1000))
                    .unwrap()
                    .through_proxy()
                    .get_blocks("coap://192.0.2.3/x", 0, &mut output)
            );
            let mut completed = false;
            for _ in 0..6000 {
                assert!(poll_once(drivers.as_mut()).await.is_none());
                if let Some(result) = poll_once(operation.as_mut()).await {
                    assert_eq!(result.unwrap(), 23);
                    completed = true;
                    break;
                }
                network.advance(10);
            }
            assert!(completed);
        }
        assert_eq!(calls, 1);
        let sent = network.sent();
        let requests: Vec<_> = sent
            .iter()
            .filter(|p| {
                p.from == a.local && MessageView::parse(&p.bytes).unwrap().code().is_request()
            })
            .collect();
        assert!(requests.len() > 1);
        assert!(requests.iter().all(|p| p.bytes == requests[0].bytes));
    });
}

#[cfg(feature = "proxy")]
#[test]
fn tst_4_prx_3_6_separate_ack_then_gateway_timeout_on_silent_target() {
    use core::net::SocketAddr;
    use mai_coap::{
        codec::{MessageBuilder, OptionNumber},
        proxy::{ForwardProxy, Routing},
        security::ProtectedOnly,
    };
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
            true
        }
        fn parameters(&self, _: SocketAddr) -> TransmissionParameters {
            (TransmissionParameters::default())
                .with_ack_timeout_ms(20)
                .with_ack_random_factor(1000)
                .with_max_retransmit(0)
                .with_max_latency_ms(10)
        }
    }
    block_on(async {
        let network = Network::default();
        let cs = Shared::<256, 4>::new();
        let ps = Shared::<256, 4>::new();
        let mut client = Endpoint::<_, 256, 4, 8>::new(&cs, Unsecured(rand::rng())).unwrap();
        let mut proxy = Endpoint::<_, 256, 4, 8>::new(&ps, Unsecured(rand::rng())).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let remote = b.local;
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let mut app = ForwardProxy::<_, _, 256, 4, 4>::new(local, Route, ps.handle()).unwrap();
        let drivers = race(
            client.run(&mut a, &network, &mut unused, &ProtectedOnly),
            proxy.run(&mut b, &network, &mut app, &ProtectedOnly),
        );
        let mut drivers = core::pin::pin!(drivers);
        let mut bytes = [0; 256];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[]).unwrap();
        builder
            .option(OptionNumber::PROXY_URI, b"coap://192.0.2.3/x")
            .unwrap();
        let n = builder.finish(&[]).unwrap();
        let handle = cs.handle();
        let mut request = core::pin::pin!(
            handle
                .client(remote)
                .parameters(TransmissionParameters::default())
                .unwrap()
                .request_raw(&bytes[..n])
                .unwrap()
                .token_length(8)
                .unwrap()
                .wait_for_nstart(true)
                .send()
                .unwrap()
        );
        let mut complete = false;
        for _ in 0..200 {
            assert!(poll_once(drivers.as_mut()).await.is_none());
            if let Some(reply) = poll_once(request.as_mut()).await {
                assert_eq!(
                    reply.unwrap().message().unwrap().code(),
                    Code::GATEWAY_TIMEOUT
                );
                complete = true;
                break;
            }
            network.advance(1);
        }
        assert!(complete);
        assert!(
            network
                .sent()
                .iter()
                .any(|p| MessageView::parse(&p.bytes).unwrap().code() == Code::EMPTY)
        );
    });
}

#[test]
#[cfg(feature = "block1")]
fn tst_4_blk_4b_streaming_upload_with_lost_and_duplicate_datagrams_commits_once() {
    use mai_coap::{
        Error,
        block::{BodyKey, UploadSink},
        codec::ContentFormat,
    };
    #[derive(Default)]
    struct Sink {
        bytes: Vec<u8>,
        writes: usize,
        commits: usize,
    }
    impl UploadSink for Sink {
        fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            self.bytes.clear();
            Ok(())
        }
        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
            assert_eq!(offset, self.bytes.len());
            self.bytes.extend_from_slice(bytes);
            self.writes += 1;
            Ok(())
        }
        fn commit(&mut self) -> Result<(), Error> {
            self.commits += 1;
            Ok(())
        }
        fn abort(&mut self) {
            self.bytes.clear();
        }
    }
    block_on(async {
        let network = Network::default();
        network.configure(0, &[Action::Duplicate, Action::Drop]);
        let cs = Shared::<256, 4>::new();
        let ss = Shared::<256, 4>::new();
        let mut client = Endpoint::<_, 256, 4, 16>::new(&cs, Unsecured(rand::rng())).unwrap();
        let mut server = Endpoint::<_, 256, 4, 16>::new(&ss, Unsecured(rand::rng())).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let remote = b.local;
        let mut sink = Sink::default();
        let policy = PublicPaths(&[(Code::PUT, "/image")]);
        {
            let mut router = Router::<256, 1>::new(&policy);
            router
                .streaming_upload("/image", &[Code::PUT], 1000, &mut sink)
                .unwrap();
            let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
            let drivers = race(
                client.run(&mut a, &network, &mut unused, &policy),
                server.run(&mut b, &network, &mut router, &policy),
            );
            let mut drivers = core::pin::pin!(drivers);
            let handle = cs.handle();
            let mut operation = core::pin::pin!(handle.client(remote).upload(
                Code::PUT,
                "/image",
                ContentFormat::OCTET_STREAM,
                &[7; 95],
                1
            ));
            let mut complete = false;
            for _ in 0..2000 {
                assert!(poll_once(drivers.as_mut()).await.is_none());
                if let Some(reply) = poll_once(operation.as_mut()).await {
                    assert_eq!(reply.unwrap().message().unwrap().code(), Code::CHANGED);
                    complete = true;
                    break;
                }
                network.advance(10);
            }
            assert!(complete);
        }
        assert_eq!(sink.bytes, vec![7; 95]);
        assert_eq!(sink.commits, 1);
        assert_eq!(sink.writes, 3);
    });
}

#[cfg(all(feature = "edhoc", feature = "software-crypto"))]
#[test]
fn tst_4_obs_8_osc_17_reboot_refresh_reestablishes_keys_and_accepts_reset_sequence() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        edhoc::{Identity, TrustedPeer, endpoint::Edhoc},
        security::{PeerId, ProtectedOnly},
        time::{Clock, Instant},
    };
    fn protection(initiator: bool) -> Edhoc<SoftwareCrypto<rand::rngs::ThreadRng>, 4, 2> {
        let (own, other, private) = if initiator {
            (
                include_bytes!("fixtures/i.ccs").as_slice(),
                include_bytes!("fixtures/r.ccs").as_slice(),
                "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b",
            )
        } else {
            (
                include_bytes!("fixtures/r.ccs").as_slice(),
                include_bytes!("fixtures/i.ccs").as_slice(),
                "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac",
            )
        };
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let identity = Identity::new(own, support::hex(private), &mut crypto).unwrap();
        let mut p = Edhoc::new(crypto, identity).unwrap();
        p.trust(TrustedPeer::new(PeerId(1), other).unwrap())
            .unwrap();
        p
    }
    struct RebootClock<'a>(&'a Network, Instant);
    impl Clock for RebootClock<'_> {
        fn now(&self) -> Instant {
            Instant(self.0.now().elapsed_since(self.1))
        }
        async fn sleep_until(&self, t: Instant) {
            self.0.sleep_until(self.1.after(t.0)).await;
        }
    }
    block_on(async {
        let network = Network::default();
        network.advance(100000);
        let cs = Shared::<512, 4>::new();
        let ss = Shared::<512, 4>::new();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let remote = b.local;
        let cp = protection(true);
        let mut client = Endpoint::<_, 512, 4, 16>::new(&cs, cp).unwrap();
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| Err(Code::NOT_FOUND);
        let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 512>| {
            response.set_payload(b"alive").unwrap();
            Ok(Disposition::Complete)
        };
        let mut router = Router::<512, 1>::new(&ProtectedOnly);
        router.route("/x", &[Code::GET], &mut handler).unwrap();
        router
            .observable(
                "/x",
                Settings::new(1)
                    .with_minimum_ms(100)
                    .with_maximum_ms(500)
                    .with_confirmable_ms(1000),
            )
            .unwrap();
        let handle = cs.handle();
        let mut observation = handle.client(remote).peer(PeerId(1)).observe("/x").unwrap();
        for phase in 0..3 {
            let mut server = Endpoint::<_, 512, 4, 16>::new(&ss, protection(false)).unwrap();
            let clock = RebootClock(
                &network,
                if phase == 0 {
                    Instant(0)
                } else {
                    network.now()
                },
            );
            {
                let drivers = race(
                    client.run(&mut a, &network, &mut unused, &ProtectedOnly),
                    server.run(&mut b, &clock, &mut router, &ProtectedOnly),
                );
                let mut drivers = core::pin::pin!(drivers);
                let mut complete = false;
                for _ in 0..2000 {
                    assert!(poll_once(drivers.as_mut()).await.is_none());
                    if let Some(Some(reply)) = poll_once(observation.next()).await {
                        let reply = reply.unwrap();
                        assert_eq!(
                            reply.message().unwrap().code(),
                            Code::CONTENT,
                            "phase {phase}"
                        );
                        assert_eq!(reply.message().unwrap().payload(), b"alive");
                        complete = true;
                        break;
                    }
                    network.advance(10);
                }
                assert!(complete, "phase {phase}");
            }
            if phase == 0 {
                client.protection_mut().pin_epoch(1).unwrap();
            }
        }
        assert_eq!(client.counters().edhoc_runs, 3);
        assert_eq!(client.protection_mut().contexts(), 2);
        client.protection_mut().unpin_epoch(1);
        observation.cancel();
    });
}

#[test]
fn obs_6_client_fetches_complete_notification_with_matching_etag() {
    use mai_coap::{
        codec::{ContentFormat, OptionNumber},
        server::SliceBody,
    };
    block_on(async {
        let network = Network::default();
        let cs = Shared::<256, 4>::new();
        let ss = Shared::<256, 4>::new();
        let mut client = Endpoint::<_, 256, 4, 16>::new(&cs, Unsecured(rand::rng())).unwrap();
        let mut server = Endpoint::<_, 256, 4, 16>::new(&ss, Unsecured(rand::rng())).unwrap();
        let mut a = network.socket("192.0.2.1:5683");
        let mut b = network.socket("192.0.2.2:5683");
        let remote = b.local;
        let client_address = a.local;
        let policy = PublicPaths(&[(Code::GET, "/large")]);
        let body = [0x53; 193];
        let mut source = {
            let mut body = SliceBody::new(&body, ContentFormat::OCTET_STREAM);
            body.etag = b"v1";
            body.max_age = 60;
            body
        };
        let mut router = Router::<256, 1>::new(&policy);
        router.representation("/large", &mut source).unwrap();
        router
            .observable(
                "/large",
                Settings::new(1)
                    .with_minimum_ms(10)
                    .with_maximum_ms(1000)
                    .with_confirmable_ms(2000),
            )
            .unwrap();
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
        let drivers = race(
            client.run(&mut a, &network, &mut unused, &policy),
            server.run(&mut b, &network, &mut router, &policy),
        );
        let mut drivers = core::pin::pin!(drivers);
        let handle = cs.handle();
        let mut observation = handle
            .client(remote)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .observe("/large")
            .unwrap();
        let mut output = [0; 256];
        {
            let mut next = core::pin::pin!(observation.next_blocks(&mut output));
            let mut complete = false;
            for _ in 0..1000 {
                assert!(poll_once(drivers.as_mut()).await.is_none());
                if let Some(result) = poll_once(next.as_mut()).await {
                    assert_eq!(result.unwrap().unwrap(), body.len());
                    complete = true;
                    break;
                }
                network.advance(1);
            }
            assert!(complete);
        }
        assert_eq!(&output[..body.len()], &body);
        let sent = network.sent();
        let followups: Vec<_> = sent
            .iter()
            .filter_map(|p| {
                let m = MessageView::parse(&p.bytes).unwrap();
                (p.from == client_address
                    && m.code() == Code::GET
                    && m.option(OptionNumber::BLOCK2).is_some())
                .then_some(m)
            })
            .collect();
        assert_eq!(followups.len(), 3);
        assert!(
            followups
                .iter()
                .all(|m| m.option(OptionNumber::OBSERVE).is_none())
        );
    });
}
