//! Deferred responses, final upload replies and observation request preservation.
#![cfg(all(feature = "server", feature = "client", feature = "block1"))]
mod support;
use support::PopOutgoing;

use core::{cell::Cell, net::SocketAddr};
use mai_coap::{
    Error,
    block::Block,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Application, Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured,
    },
    security::{ProtectedOnly, PublicPaths},
    server::Router,
    time::Instant,
    transport::Metadata,
};

fn meta(remote: SocketAddr, n: usize) -> Metadata {
    Metadata::new(remote, "192.0.2.10".parse().unwrap(), n)
}

fn short_profile() -> mai_coap::messaging::TransmissionParameters {
    mai_coap::messaging::TransmissionParameters::default()
        .with_ack_timeout_ms(1)
        .with_ack_random_factor(1000)
        .with_max_retransmit(0)
        .with_max_latency_ms(10)
}

#[test]
fn reserved_block_size_is_bad_request_but_oversized_option_is_bad_option() {
    for number in [OptionNumber::BLOCK1, OptionNumber::BLOCK2] {
        for (value, expected) in [
            (vec![7], Code::BAD_REQUEST),
            (vec![0, 0, 0, 7], Code::BAD_OPTION),
        ] {
            let policy = PublicPaths(&[(Code::POST, "/upload"), (Code::GET, "/body")]);
            let mut handler =
                |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
            let mut body = {
                let mut body =
                    mai_coap::server::SliceBody::new(b"data", mai_coap::codec::ContentFormat::TEXT);
                body.etag = b"x";
                body.max_age = 60;
                body
            };
            let mut router = Router::<128, 2, 1, 32>::new(&policy);
            router
                .buffered_upload("/upload", &[Code::POST], &mut handler)
                .unwrap();
            router.representation("/body", &mut body).unwrap();
            let mut bytes = [0; 128];
            let (method, path) = if number == OptionNumber::BLOCK1 {
                (Code::POST, b"upload".as_slice())
            } else {
                (Code::GET, b"body".as_slice())
            };
            let mut b =
                MessageBuilder::new(&mut bytes, MessageType::Confirmable, method, 1, b"t").unwrap();
            b.option(OptionNumber::URI_PATH, path).unwrap();
            b.option(number, &value).unwrap();
            let n = b.finish(&[]).unwrap();
            let message = MessageView::parse(&bytes[..n]).unwrap();
            let shared = Shared::<128, 2>::new();
            let mut endpoint =
                Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
            endpoint
                .receive(
                    message.as_bytes(),
                    meta("192.0.2.1:1".parse().unwrap(), n),
                    Instant(0),
                    &mut router,
                    &policy,
                )
                .unwrap();
            let output = endpoint.pop_outgoing().unwrap();
            assert_eq!(
                MessageView::parse(output.packet.as_slice()).unwrap().code(),
                expected
            );
        }
    }
}

#[test]
fn matching_etag_returns_valid_without_block_continuation_metadata() {
    use mai_coap::{codec::ContentFormat, server::SliceBody};
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let policy = PublicPaths(&[(Code::GET, "/body")]);
    let mut source = {
        let mut body = SliceBody::new(&[1; 128], ContentFormat::TEXT);
        body.etag = b"tag";
        body.max_age = 10;
        body
    };
    let mut router = Router::<128>::new(&policy);
    router.representation("/body", &mut source).unwrap();
    for index in 0..2 {
        let mut bytes = [0; 128];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, index, b"t")
                .unwrap();
        b.option(OptionNumber::ETAG, b"tag").unwrap();
        b.option(OptionNumber::URI_PATH, b"body").unwrap();
        b.uint_option(OptionNumber::BLOCK2, u64::from(index) << 4)
            .unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:1".parse().unwrap(), n),
                Instant(index.into()),
                &mut router,
                &policy,
            )
            .unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        let response = MessageView::parse(output.packet.as_slice()).unwrap();
        assert_eq!(response.code(), Code::VALID);
        assert!(response.payload().is_empty());
        assert_eq!(response.option(OptionNumber::ETAG).unwrap().value, b"tag");
        assert_eq!(
            response.option(OptionNumber::MAX_AGE).unwrap().uint(),
            Ok(10)
        );
        assert!(response.option(OptionNumber::BLOCK2).is_none());
        assert!(response.option(OptionNumber::SIZE2).is_none());
    }
}

#[test]
fn work_queue_timeout_retains_ticket_through_processing_and_delivery_grace() {
    use mai_coap::server::work::WorkQueue;
    for at in [22, 510, 522] {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        endpoint.set_parameters(short_profile()).unwrap();
        let queue = WorkQueue::<128, 1>::new();
        let mut app = queue.handler(500).unwrap();
        assert_eq!(
            ResponseWriter::<128>::new(&mut [0; 128], Code::CONTENT, &[])
                .unwrap()
                .set_deferred_timeout(0),
            Err(mai_coap::endpoint::ResponseError::InvalidTimeout)
        );
        let mut bytes = [0; 128];
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        let peer = "192.0.2.1:1".parse().unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &PublicPaths(&[(Code::GET, "/")]),
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
        let job = futures_lite::future::block_on(queue.next());
        assert_eq!(job.deadline(), Instant(500));
        endpoint.poll(Instant(at)).unwrap();
        let operation = shared
            .handle()
            .respond(job.ticket(), &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(at)).unwrap();
        let result = futures_lite::future::block_on(operation);
        if at < 521 {
            assert!(result.is_ok());
            assert!(endpoint.pop_outgoing().is_some());
        } else {
            assert_eq!(result.unwrap_err(), Error::Cancelled);
            assert!(endpoint.pop_outgoing().is_none());
        }
    }
}

#[cfg(feature = "proxy")]
#[test]
fn proxy_slow_route_outlives_local_profile_and_times_out_queued_work() {
    use mai_coap::{
        messaging::TransmissionParameters,
        proxy::{ForwardProxy, Routing},
    };
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
            true
        }
        fn parameters(&self, _: SocketAddr) -> TransmissionParameters {
            TransmissionParameters::default()
                .with_ack_timeout_ms(100)
                .with_ack_random_factor(1000)
                .with_max_retransmit(0)
                .with_max_latency_ms(1000)
        }
    }
    for blocked in [false, true] {
        let shared = Shared::<128, 3>::new();
        let mut endpoint = Endpoint::<_, 128, 3, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
        endpoint.set_parameters(short_profile()).unwrap();
        let mut app = ForwardProxy::<_, _, 128, 3>::new(
            |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND),
            Route,
            shared.handle(),
        )
        .unwrap();
        let peer = "192.0.2.1:1".parse().unwrap();
        let upstream = "192.0.2.2:5683".parse().unwrap();
        let mut bytes = [0; 128];
        let mut blocker = None;
        if blocked {
            let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[])
                .unwrap()
                .finish(&[])
                .unwrap();
            blocker = Some(
                shared
                    .handle()
                    .client(upstream)
                    .parameters(TransmissionParameters::default())
                    .unwrap()
                    .request_raw(&bytes[..n])
                    .unwrap()
                    .token_length(8)
                    .unwrap()
                    .wait_for_nstart(true)
                    .send()
                    .unwrap(),
            );
            endpoint.poll(Instant(0)).unwrap();
            endpoint.pop_outgoing().unwrap();
        }
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
        b.option(OptionNumber::PROXY_URI, b"coap://192.0.2.2/x")
            .unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
        endpoint.poll(Instant(0)).unwrap();
        if blocked {
            assert!(endpoint.pop_outgoing().is_none());
            assert_eq!(app.deadline(), Some(Instant(2100)));
            app.poll(
                Instant(2100),
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            );
        } else {
            let outgoing = endpoint.pop_outgoing().unwrap();
            let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            endpoint.poll(Instant(22)).unwrap();
            let n = MessageBuilder::new(
                &mut bytes,
                MessageType::Acknowledgement,
                Code::CONTENT,
                request.message_id(),
                request.token(),
            )
            .unwrap()
            .finish(b"late result")
            .unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    meta(upstream, n),
                    Instant(22),
                    &mut app,
                    &ProtectedOnly,
                )
                .unwrap();
            app.poll(
                Instant(22),
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            );
        }
        let now = Instant(if blocked { 2100 } else { 22 });
        for _ in 0..3 {
            endpoint.poll(now).unwrap();
            app.poll(
                now,
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            );
        }
        let replies: Vec<_> = core::iter::from_fn(|| endpoint.pop_outgoing())
            .filter(|out| out.remote == peer)
            .collect();
        assert_eq!(replies.len(), 1);
        let response = MessageView::parse(replies[0].packet.as_slice()).unwrap();
        assert_eq!(
            response.code(),
            if blocked {
                Code::GATEWAY_TIMEOUT
            } else {
                Code::CONTENT
            }
        );
        if !blocked {
            assert_eq!(response.payload(), b"late result");
        }
        drop(blocker);
    }
}

#[test]
fn full_backoff_table_forgets_earliest_expiry_without_blocking_unrelated_peers() {
    use mai_coap::messaging::TransmissionParameters;
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND);
    let peers: [SocketAddr; 3] = [
        "192.0.2.1:1".parse().unwrap(),
        "192.0.2.2:1".parse().unwrap(),
        "192.0.2.3:1".parse().unwrap(),
    ];
    let mut bytes = [0; 128];
    for (index, peer) in peers.iter().enumerate() {
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[])
            .unwrap()
            .finish(&[])
            .unwrap();
        let operation = shared
            .handle()
            .client(*peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .request_raw(&bytes[..n])
            .unwrap()
            .token_length(8)
            .unwrap()
            .wait_for_nstart(true)
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::TOO_MANY_REQUESTS,
            request.message_id(),
            request.token(),
        )
        .unwrap();
        b.uint_option(
            OptionNumber::MAX_AGE,
            if index == 1 { 1 } else { u32::MAX.into() },
        )
        .unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(*peer, n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        futures_lite::future::block_on(operation).unwrap();
    }
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[])
        .unwrap()
        .finish(&[])
        .unwrap();
    let blocked = shared
        .handle()
        .client(peers[0])
        .parameters(TransmissionParameters::default())
        .unwrap()
        .request_raw(&bytes[..n])
        .unwrap()
        .token_length(8)
        .unwrap()
        .wait_for_nstart(true)
        .send()
        .unwrap();
    let unrelated: SocketAddr = "192.0.2.4:1".parse().unwrap();
    let other = shared
        .handle()
        .client(unrelated)
        .parameters(TransmissionParameters::default())
        .unwrap()
        .request_raw(&bytes[..n])
        .unwrap()
        .token_length(8)
        .unwrap()
        .wait_for_nstart(true)
        .send()
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    assert_eq!(endpoint.pop_outgoing().unwrap().remote, unrelated);
    assert!(endpoint.pop_outgoing().is_none());
    drop(other);
    endpoint.poll(Instant(1)).unwrap();
    let evicted = shared
        .handle()
        .client(peers[1])
        .parameters(TransmissionParameters::default())
        .unwrap()
        .request_raw(&bytes[..n])
        .unwrap()
        .token_length(8)
        .unwrap()
        .wait_for_nstart(true)
        .send()
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    assert_eq!(endpoint.pop_outgoing().unwrap().remote, peers[1]);
    assert!(endpoint.pop_outgoing().is_none());
    drop((blocked, evicted));
}

#[cfg(feature = "proxy")]
#[test]
fn local_policy_is_checked_before_proxy_deferred_overload() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Deferred);
    let mut bytes = [0; 128];
    let peer = "192.0.2.1:1".parse().unwrap();
    for (id, expected) in [(0, Code::EMPTY), (1, Code::UNAUTHORIZED)] {
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, id, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        if id == 0 {
            endpoint
                .receive(
                    &bytes[..n],
                    meta(peer, n),
                    Instant(0),
                    &mut app,
                    &PublicPaths(&[(Code::GET, "/")]),
                )
                .unwrap();
        } else {
            endpoint
                .receive(
                    &bytes[..n],
                    meta(peer, n),
                    Instant(1),
                    &mut app,
                    &ProtectedOnly,
                )
                .unwrap();
        }
        let output = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(output.packet.as_slice()).unwrap().code(),
            expected
        );
    }
}

#[cfg(feature = "observe")]
#[test]
fn due_observation_wakes_as_soon_as_nstart_credit_is_released() {
    use mai_coap::messaging::TransmissionParameters;
    for cancel in [false, true] {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let peer = "192.0.2.1:1".parse().unwrap();
        let mut bytes = [0; 128];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[]).unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        let n = b.finish(&[]).unwrap();
        let observation = shared
            .handle()
            .client(peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .request_raw(&bytes[..n])
            .unwrap()
            .token_length(8)
            .unwrap()
            .wait_for_nstart(true)
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(output.packet.as_slice()).unwrap();
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            request.message_id(),
            request.token(),
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.uint_option(OptionNumber::MAX_AGE, 0).unwrap();
        let n = b.finish(&[]).unwrap();
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND);
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[])
            .unwrap()
            .finish(&[])
            .unwrap();
        let blocker = shared
            .handle()
            .client(peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .request_raw(&bytes[..n])
            .unwrap()
            .token_length(8)
            .unwrap()
            .wait_for_nstart(true)
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(output.packet.as_slice()).unwrap();
        if cancel {
            drop(observation);
        }
        endpoint.poll(Instant(2000)).unwrap();
        assert!(
            endpoint.deadline(Instant(2000)) > Instant(2000),
            "blocked refresh must not spin"
        );
        while endpoint.pop_outgoing().is_some() {}
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::EMPTY,
            request.message_id(),
            &[],
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(2000),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        assert_eq!(endpoint.deadline(Instant(2000)), Instant(2000));
        endpoint.poll(Instant(2000)).unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(output.packet.as_slice())
                .unwrap()
                .option(OptionNumber::OBSERVE)
                .unwrap()
                .uint(),
            Ok(u64::from(cancel))
        );
        drop(blocker);
    }
}

#[test]
fn final_block_does_not_replay_continue_after_deferred_or_failed_handler() {
    for deferred in [false, true] {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let calls = Cell::new(0);
        let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
            calls.set(calls.get() + 1);
            if deferred {
                Ok(Disposition::Deferred)
            } else {
                Err(Code::FORBIDDEN)
            }
        };
        let policy = PublicPaths(&[(Code::POST, "/upload")]);
        let mut router = Router::<128, 1, 1, 32>::new(&policy);
        router
            .buffered_upload("/upload", &[Code::POST], &mut handler)
            .unwrap();
        for index in 0..3 {
            let mut bytes = [0; 128];
            let mut b = MessageBuilder::new(
                &mut bytes,
                MessageType::Confirmable,
                Code::POST,
                index,
                b"t",
            )
            .unwrap();
            b.option(OptionNumber::URI_PATH, b"upload").unwrap();
            let block = Block::new(u32::from(index != 0), index == 0, 0).unwrap();
            b.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
                .unwrap();
            let n = b
                .finish(if index == 0 { &[1; 16] } else { b"end" })
                .unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    meta("192.0.2.1:1".parse().unwrap(), n),
                    Instant(index.into()),
                    &mut router,
                    &policy,
                )
                .unwrap();
            let output = endpoint.pop_outgoing().unwrap();
            let reply = MessageView::parse(output.packet.as_slice()).unwrap();
            let expected = match index {
                0 => Code::CONTINUE,
                1 if deferred => Code::EMPTY,
                1 => Code::FORBIDDEN,
                _ => Code::INCOMPLETE,
            };
            assert_eq!(reply.code(), expected);
            if index == 2 {
                assert!(reply.option(OptionNumber::BLOCK1).is_none());
            }
        }
        assert_eq!(calls.get(), 1);
    }
}

#[test]
fn final_block_reply_inserts_block1_before_handler_options() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.uint_option(OptionNumber::SIZE2, 10).unwrap();
        response.option(OptionNumber::ECHO, b"fresh").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<128, 1, 1, 32>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    let mut bytes = [0; 128];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 1, b"t").unwrap();
    b.option(OptionNumber::URI_PATH, b"upload").unwrap();
    b.uint_option(OptionNumber::BLOCK1, 0).unwrap();
    let n = b.finish(b"end").unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("192.0.2.1:1".parse().unwrap(), n),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let output = endpoint.pop_outgoing().unwrap();
    let reply = MessageView::parse(output.packet.as_slice()).unwrap();
    assert_eq!(reply.code(), Code::CHANGED);
    assert_eq!(reply.option(OptionNumber::BLOCK1).unwrap().uint(), Ok(0));
    assert_eq!(reply.option(OptionNumber::SIZE2).unwrap().uint(), Ok(10));
    assert_eq!(reply.option(OptionNumber::ECHO).unwrap().value, b"fresh");
}

#[cfg(feature = "proxy")]
#[test]
fn proxy_retries_a_relay_after_asynchronous_capacity_failure() {
    use mai_coap::proxy::{ForwardProxy, Routing};
    struct Route;
    impl Routing for Route {
        fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
            true
        }
    }
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = Cell::new(None);
    let handler = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        ticket.set(Some(request.deferred_ticket().unwrap()));
        Ok(Disposition::Deferred)
    };
    let handle = shared.handle();
    let mut proxy = ForwardProxy::<_, _, 128, 2>::new(handler, Route, handle).unwrap();
    let requester = "192.0.2.1:1".parse().unwrap();
    let upstream = "192.0.2.2:5683".parse().unwrap();
    let local_peer: SocketAddr = "192.0.2.3:1".parse().unwrap();
    let mut bytes = [0; 128];
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::Confirmable,
        Code::GET,
        1,
        b"original",
    )
    .unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://192.0.2.2/x")
        .unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(requester, n),
            Instant(0),
            &mut proxy,
            &ProtectedOnly,
        )
        .unwrap();
    endpoint.pop_outgoing().unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap()
    .finish(b"relayed")
    .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(upstream, n),
            Instant(1),
            &mut proxy,
            &ProtectedOnly,
        )
        .unwrap();

    let mut separate_ids = Vec::new();
    let mut local_handler = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        ticket.set(Some(request.deferred_ticket().unwrap()));
        Ok(Disposition::Deferred)
    };
    for id in 2..4 {
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            id,
            b"local",
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(SocketAddr::new(local_peer.ip(), id), n),
                Instant(2),
                &mut local_handler,
                &PublicPaths(&[(Code::GET, "/")]),
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
        let operation = shared
            .handle()
            .respond(ticket.get().unwrap(), &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(2)).unwrap();
        futures_lite::future::block_on(operation).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let mid = MessageView::parse(outgoing.packet.as_slice())
            .unwrap()
            .message_id();
        separate_ids.push(mid);
    }
    proxy.poll(
        Instant(3),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    endpoint.poll(Instant(3)).unwrap();
    proxy.poll(
        Instant(3),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    assert!(endpoint.pop_outgoing().is_none());
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        separate_ids[0],
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(SocketAddr::new(local_peer.ip(), 2), n),
            Instant(4),
            &mut proxy,
            &ProtectedOnly,
        )
        .unwrap();
    proxy.poll(
        Instant(4),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    endpoint.poll(Instant(4)).unwrap();
    proxy.poll(
        Instant(4),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    let outgoing = endpoint
        .pop_outgoing()
        .expect("relayed response must survive Capacity");
    assert_eq!(outgoing.remote, requester);
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.token(), b"original");
    assert_eq!(response.payload(), b"relayed");
}

#[cfg(feature = "observe")]
#[test]
fn fetch_observation_refresh_and_cancel_preserve_method_and_body() {
    use mai_coap::messaging::TransmissionParameters;
    for cancel in [false, true] {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let peer = "192.0.2.1:1".parse().unwrap();
        let mut bytes = [0; 128];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::FETCH, 0, &[]).unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        b.uint_option(OptionNumber::CONTENT_FORMAT, 60).unwrap();
        let n = b.finish(b"selector").unwrap();
        let operation = shared
            .handle()
            .client(peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .request_raw(&bytes[..n])
            .unwrap()
            .token_length(8)
            .unwrap()
            .wait_for_nstart(true)
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            request.message_id(),
            request.token(),
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.uint_option(OptionNumber::MAX_AGE, 1).unwrap();
        let n = b.finish(b"result").unwrap();
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        if cancel {
            drop(operation);
        }
        endpoint.poll(Instant(3001)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let refreshed = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(refreshed.code(), Code::FETCH);
        assert_eq!(refreshed.payload(), b"selector");
        assert_eq!(
            refreshed.option(OptionNumber::OBSERVE).unwrap().uint(),
            Ok(u64::from(cancel))
        );
    }
}
