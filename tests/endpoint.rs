//! Endpoint reliability, routing, cancellation and source-address tests (REL, TR).
#![cfg(all(feature = "server", feature = "client"))]
mod support;
use core::net::SocketAddr;
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;
fn meta(remote: SocketAddr, n: usize) -> Metadata {
    Metadata::new(remote, "127.0.0.2".parse().unwrap(), n).with_interface(Some(1))
}
fn request<const N: usize>(bytes: &mut [u8; N], mid: u16, token: &[u8], ty: MessageType) -> usize {
    let mut b = MessageBuilder::new(bytes, ty, Code::GET, mid, token).unwrap();
    b.option(OptionNumber::URI_HOST, b"host").unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    b.finish(&[]).unwrap()
}

#[test]
fn response_payload_replacement_preserves_content_on_overflow() {
    let mut response = Response::<32>::new(Code::CONTENT);
    response.set_payload(&[7; 32]).unwrap();
    assert_eq!(
        response.set_payload(&[9; 33]),
        Err(mai_coap::endpoint::ResponseError::Capacity)
    );
    let mut wire = [0; 64];
    let n = response
        .encode(&mut wire, MessageType::Acknowledgement, 1, &[])
        .unwrap();
    assert_eq!(MessageView::parse(&wire[..n]).unwrap().payload(), &[7; 32]);

    for payload in [b"short".as_slice(), b""] {
        response.set_payload(payload).unwrap();
        let n = response
            .encode(&mut wire, MessageType::Acknowledgement, 1, &[])
            .unwrap();
        assert_eq!(MessageView::parse(&wire[..n]).unwrap().payload(), payload);
    }
    assert_eq!(Response::<0>::new(Code::CONTENT).set_payload(&[]), Ok(()));
}

#[test]
fn server_without_outbound_exchanges_rejects_unsolicited_responses() {
    let shared = Shared::<64, 0>::new();
    let mut endpoint =
        Endpoint::<_, 64, 0, 2, 0, 1, 2, 0, 0, 0, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer = "127.0.0.1:99".parse().unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| -> Result<Disposition, Code> {
        panic!("an unsolicited response must not reach the application")
    };
    let mut wire = [0; 64];
    for ty in [
        MessageType::Confirmable,
        MessageType::NonConfirmable,
        MessageType::Acknowledgement,
    ] {
        let n = Response::<64>::new(Code::CONTENT)
            .encode(&mut wire, ty, 42, b"t")
            .unwrap();
        endpoint
            .receive(
                &wire[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &PublicPaths(&[]),
            )
            .unwrap();
        if ty == MessageType::Confirmable {
            let outgoing = endpoint.pop_outgoing().unwrap();
            let reset = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(reset.message_type(), MessageType::Reset);
            assert_eq!(reset.code(), Code::EMPTY);
            assert_eq!(reset.message_id(), 42);
            assert!(reset.token().is_empty());
        }
        assert!(endpoint.pop_outgoing().is_none());
    }
}

#[test]
fn public_outgoing_front_complete_and_discard_lifecycle() {
    let shared = Shared::<256, 1>::new();
    let mut endpoint = Endpoint::<_, 256, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer = "127.0.0.1:99".parse().unwrap();
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        response.set_payload(b"reply").unwrap();
        Ok(Disposition::Complete)
    };
    let mut bytes = [0; 256];

    let n = request(&mut bytes, 1, b"one", MessageType::Confirmable);
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    let first = endpoint.front_outgoing().unwrap();
    let sent = first.bytes.to_vec();
    assert_eq!(first.remote, peer);
    assert_eq!(first.source, Some("127.0.0.2".parse().unwrap()));
    assert_eq!(first.bytes, endpoint.front_outgoing().unwrap().bytes);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    assert!(endpoint.front_outgoing().is_none());

    let n = request(&mut bytes, 2, b"two", MessageType::Confirmable);
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(1),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    let second = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(second.message_id(), 2);
    assert_eq!(second.token(), b"two");
    assert_eq!(second.payload(), b"reply");
    assert_ne!(endpoint.front_outgoing().unwrap().bytes, sent);
    endpoint.discard_outgoing(mai_coap::time::Instant(0));
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.counters().dropped_messages, 1);
}

#[test]
fn srv_1_4_rel_3_duplicate_is_byte_identical_and_not_dispatched_twice() {
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut count = 0;
    let mut app = |req: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        count += 1;
        assert_eq!(
            req.message.option(OptionNumber::URI_HOST).unwrap().value,
            b"host"
        );
        response.set_payload(&[count]).unwrap();
        Ok(Disposition::Complete)
    };
    let mut bytes = [0; 256];
    let n = request(&mut bytes, 123, b"token", MessageType::Confirmable);
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    let first = endpoint.pop_outgoing().unwrap();
    assert_eq!(first.source, Some("127.0.0.2".parse().unwrap()));
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(10000),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    assert_eq!(first.packet, endpoint.pop_outgoing().unwrap().packet);
    assert_eq!(count, 1);
    assert_eq!(endpoint.counters().duplicates, 1);
}

#[test]
fn srv_5_failed_representation_preconditions_have_no_representation_metadata() {
    use mai_coap::{
        codec::ContentFormat,
        server::{Router, SliceBody},
    };
    for method in [Code::GET, Code::FETCH] {
        for (option, value) in [
            (OptionNumber::IF_MATCH, b"old".as_slice()),
            (OptionNumber::IF_NONE_MATCH, b"".as_slice()),
        ] {
            let shared = Shared::<128, 1>::new();
            let mut endpoint =
                Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
            let policy = PublicPaths(&[(Code::GET, "/body"), (Code::FETCH, "/body")]);
            let mut source = {
                let mut body = SliceBody::new(b"body", ContentFormat::TEXT);
                body.etag = b"tag";
                body.max_age = 10;
                body
            };
            let mut router = Router::<128, 1, 1, 32>::new(&policy);
            router.representation("/body", &mut source).unwrap();
            let mut bytes = [0; 128];
            let mut builder =
                MessageBuilder::new(&mut bytes, MessageType::Confirmable, method, 1, b"t").unwrap();
            builder.option(option, value).unwrap();
            builder.option(OptionNumber::URI_PATH, b"body").unwrap();
            #[cfg(feature = "block")]
            builder.uint_option(OptionNumber::BLOCK2, 0).unwrap();
            let n = builder.finish(&[]).unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    meta("127.0.0.1:99".parse().unwrap(), n),
                    Instant(0),
                    &mut router,
                    &policy,
                )
                .unwrap();
            let outgoing = endpoint.pop_outgoing().unwrap();
            let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(response.code(), Code::PRECONDITION_FAILED);
            assert_eq!(response.options().count(), 0);
            assert!(response.payload().is_empty());
        }
    }
}

#[test]
fn api_8_cache_counters_distinguish_record_loss_from_reply_loss() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Endpoint::<_, 128, 2, 2, 1, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut app = |request: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        if request.message.message_id() != 1 {
            response.set_payload(b"reply").unwrap();
        }
        Ok(Disposition::Complete)
    };
    let peer = "127.0.0.1:99".parse().unwrap();
    for (id, now, responds) in [
        (1, 0, true),
        (2, 1, true),
        (3, 2, true),
        (2, 3, true),
        (4, 247_010, true),
    ] {
        let mut bytes = [0; 128];
        let n = request(&mut bytes, id, b"", MessageType::Confirmable);
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(now),
                &mut app,
                &PublicPaths(&[(Code::GET, "/x")]),
            )
            .unwrap();
        assert_eq!(endpoint.pop_outgoing().is_some(), responds);
    }
    let counters = endpoint.counters();
    assert_eq!(counters.dedup_record_evictions, 1);
    assert_eq!(counters.dedup_reply_drops, 1);
    assert_eq!(counters.dedup_reply_misses, 1);
    assert_eq!(counters.duplicates, 1);
    assert_eq!(counters.dropped_messages, 0);
    assert_eq!(calls.get(), 4);
}
#[test]
fn rel_3_full_reply_pressure_preserves_duplicate_records_and_current_reply() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Endpoint::<_, 128, 2, 4, 1, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(&[calls.get(); 8]).unwrap();
        Ok(Disposition::Complete)
    };
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut previous = None;
    for (step, id) in [1, 2, 2, 1].into_iter().enumerate() {
        let mut bytes = [0; 128];
        let n = request(&mut bytes, id, b"t", MessageType::Confirmable);
        endpoint
            .receive(
                &bytes[..n],
                meta(peer, n),
                Instant(step as u64),
                &mut app,
                &PublicPaths(&[(Code::GET, "/x")]),
            )
            .unwrap();
        if step == 3 {
            let outgoing = endpoint.pop_outgoing().unwrap();
            let refusal = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(refusal.code(), Code::UNAVAILABLE);
            assert_eq!(refusal.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(0));
            continue;
        }
        let outgoing = endpoint.pop_outgoing().unwrap();
        if step == 2 {
            assert_eq!(Some(&outgoing.packet), previous.as_ref());
        }
        previous = Some(outgoing.packet);
    }
    assert_eq!(calls.get(), 2);
    assert_eq!(endpoint.counters().dedup_record_evictions, 0);
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    assert_eq!(endpoint.counters().dedup_reply_misses, 1);
    assert_eq!(endpoint.counters().duplicates, 2);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    assert!(Endpoint::<_, 128, 2, 4, 1, 0>::new(&shared, Unsecured(rand::rng())).is_err());
}
#[test]
fn rel_6_separate_response_and_wrong_peer_token_mid_do_not_complete() {
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 256];
    let n = request(&mut bytes, 0, &[], MessageType::Confirmable);
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
    let sent = endpoint.pop_outgoing().unwrap();
    let outgoing = MessageView::parse(sent.packet.as_slice()).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let wrong = Response::<256>::new(Code::CONTENT);
    let n = wrong
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            outgoing.message_id().wrapping_add(1),
            outgoing.token(),
        )
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(1),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        outgoing.message_id(),
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(2),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    endpoint.poll(Instant(10000)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    let n = wrong
        .encode(&mut bytes, MessageType::Confirmable, 987, outgoing.token())
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("127.0.0.3:99".parse().unwrap(), n),
            Instant(10001),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::Reset
    );
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(10002),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::Acknowledgement
    );
    assert_eq!(
        futures_lite::future::block_on(operation)
            .unwrap()
            .message()
            .unwrap()
            .code(),
        Code::CONTENT
    );
}
#[test]
fn srv_3_rel_7_deferred_work_does_not_hold_the_endpoint() {
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 256];
    let mut ticket = None;
    let mut app = |req: Request<'_>, _: &mut ResponseWriter<'_, 256>| {
        ticket = Some(req.deferred_ticket().unwrap());
        Ok(Disposition::Deferred)
    };
    let n = request(&mut bytes, 100, b"one", MessageType::Confirmable);
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    let ack = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(ack.packet.as_slice()).unwrap().code(),
        Code::EMPTY
    );
    let ticket = ticket.unwrap();
    let response = Response::new(Code::CONTENT);
    let done = shared.handle().respond(ticket, &response).unwrap();
    endpoint.poll(Instant(1)).unwrap();
    let separate = endpoint.pop_outgoing().unwrap();
    let view = MessageView::parse(separate.packet.as_slice()).unwrap();
    assert_eq!(view.token(), b"one");
    assert_eq!(view.message_type(), MessageType::Confirmable);
    assert_ne!(view.message_id(), 100);
    assert!(futures_lite::future::block_on(done).is_ok());
}
#[test]
fn plt_7_client_cancellation_releases_slots() {
    let shared = Shared::<256, 1>::new();
    let mut endpoint = Endpoint::<_, 256, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 256];
    let n = request(&mut bytes, 0, &[], MessageType::Confirmable);
    let future = shared
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
    endpoint.pop_outgoing();
    drop(future);
    endpoint.poll(Instant(1)).unwrap();
    assert!(
        shared
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
            .is_ok()
    );
}
#[test]
fn aut_2_denial_and_msg_2_ping_oversize_and_malformed() {
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 256];
    let n = request(&mut bytes, 1, &[], MessageType::Confirmable);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| {
        panic!("denied requests must not reach handler")
    };
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &mai_coap::security::ProtectedOnly,
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .code(),
        Code::UNAUTHORIZED
    );
    let ping = [0x40, 0, 0, 9];
    endpoint
        .receive(
            &ping,
            meta(peer, 4),
            Instant(1),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::Reset
    );
    endpoint
        .receive(
            &[0x40, 1, 0, 1, 255],
            meta(peer, 5),
            Instant(2),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::Reset
    );
    endpoint
        .receive(
            &[0x50, 1, 0, 1, 255],
            meta(peer, 5),
            Instant(2),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    endpoint
        .receive(
            &[0; 256],
            meta(peer, 257),
            Instant(3),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(endpoint.counters().oversized, 1);
    let _ = Error::Timeout;
}

#[test]
fn rel_5_7_separate_confirmable_responses_share_destination_nstart() {
    let shared = Shared::<128, 4>::new();
    let mut endpoint = Endpoint::<_, 128, 4, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote = "127.0.0.1:99".parse().unwrap();
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let tickets = core::cell::RefCell::new(Vec::new());
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        tickets
            .borrow_mut()
            .push(request.deferred_ticket().unwrap());
        Ok(Disposition::Deferred)
    };
    for id in 0..2 {
        let mut bytes = [0; 128];
        let n = request(&mut bytes, id, &[id as u8], MessageType::Confirmable);
        endpoint
            .receive(&bytes[..n], meta(remote, n), Instant(0), &mut app, &policy)
            .unwrap();
        assert_eq!(
            MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
                .unwrap()
                .code(),
            Code::EMPTY
        );
    }
    let handle = shared.handle();
    let mut first = handle
        .respond_confirmed(tickets.borrow()[0], &Response::new(Code::CONTENT))
        .unwrap();
    let mut second = handle
        .respond_confirmed(tickets.borrow()[1], &Response::new(Code::CONTENT))
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    let packet = endpoint.pop_outgoing().unwrap().packet;
    let message = MessageView::parse(packet.as_slice()).unwrap();
    assert!(futures_lite::future::block_on(futures_lite::future::poll_once(&mut first)).is_none());
    assert!(futures_lite::future::block_on(futures_lite::future::poll_once(&mut second)).is_none());
    assert!(endpoint.pop_outgoing().is_none());
    let mut bytes = [0; 4];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::EMPTY,
        message.message_id(),
        &[],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint
        .receive(&bytes[..n], meta(remote, n), Instant(2), &mut app, &policy)
        .unwrap();
    endpoint.poll(Instant(2)).unwrap();
    assert_eq!(futures_lite::future::block_on(first), Ok(()));
    let packet = endpoint.pop_outgoing().unwrap().packet;
    let mid = MessageView::parse(packet.as_slice()).unwrap().message_id();
    assert!(futures_lite::future::block_on(futures_lite::future::poll_once(&mut second)).is_none());
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
        .receive(&bytes[..n], meta(remote, n), Instant(3), &mut app, &policy)
        .unwrap();
    assert_eq!(futures_lite::future::block_on(second), Ok(()));
}

#[test]
fn rel_5_rfc8516_max_age_defers_subsequent_requests() {
    let shared = Shared::<128, 4>::new();
    let mut endpoint = Endpoint::<_, 128, 4, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 128];
    let n = request(&mut bytes, 0, &[], MessageType::Confirmable);
    let handle = shared.handle();
    let first = handle
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
    let sent = endpoint.pop_outgoing().unwrap().packet;
    let message = MessageView::parse(sent.as_slice()).unwrap();
    let mut response = Response::<128>::new(Code::TOO_MANY_REQUESTS);
    response.uint_option(OptionNumber::MAX_AGE, 1).unwrap();
    let used = response
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            message.message_id(),
            message.token(),
        )
        .unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND);
    endpoint
        .receive(
            &bytes[..used],
            meta(peer, used),
            Instant(0),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        futures_lite::future::block_on(first)
            .unwrap()
            .message()
            .unwrap()
            .code(),
        Code::TOO_MANY_REQUESTS
    );
    let n = request(&mut bytes, 0, &[], MessageType::Confirmable);
    let second = handle
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
    endpoint.poll(Instant(999)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(endpoint.deadline(Instant(999)), Instant(1000));
    endpoint.poll(Instant(1000)).unwrap();
    assert!(endpoint.pop_outgoing().is_some());
    drop(second);
}

#[test]
fn srv_7_response_capacity_failure_returns_internal_error() {
    let shared = Shared::<64, 2>::new();
    let mut endpoint = Endpoint::<_, 64, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 64>| {
        response.set_payload(&[7; 64])?;
        Ok(Disposition::Complete)
    };
    let mut bytes = [0; 64];
    let n = request(&mut bytes, 1, b"token123", MessageType::Confirmable);
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(outgoing.packet.as_slice())
            .unwrap()
            .code(),
        Code::INTERNAL_ERROR
    );
}

#[cfg(feature = "software-crypto")]
#[test]
fn rel_3_reply_misses_exclude_rate_limited_duplicates_with_or_without_oscore() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        oscore::{Context, Oscore},
        rate::Limits,
        security::PeerId,
    };
    for protected in [false, true] {
        let peer = "127.0.0.1:99".parse().unwrap();
        let mut cp = SoftwareCrypto::new(rand::rng());
        let mut client =
            Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
        let mut sp = SoftwareCrypto::new(rand::rng());
        let server = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let mut protection = Oscore::<_, 1>::new(sp);
        protection.install_fresh(server).unwrap();
        let shared = Shared::<128, 0>::new();
        let mut endpoint = Endpoint::<_, 128, 0, 4, 0, 1>::new(&shared, protection).unwrap();
        let calls = core::cell::Cell::new(0);
        let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
            calls.set(calls.get() + 1);
            response.set_payload(b"reply")?;
            Ok(Disposition::Complete)
        };
        let policy = PublicPaths(&[(Code::GET, "/x")]);
        let mut original = Vec::new();
        for mid in 1..=2 {
            let mut plain = [0; 128];
            let n = request(&mut plain, mid, b"x", MessageType::Confirmable);
            let mut wire = [0; 128];
            let bytes = if protected {
                let (n, _) = client
                    .protect_request::<128>(
                        &mut cp,
                        MessageView::parse(&plain[..n]).unwrap(),
                        &mut wire,
                    )
                    .unwrap();
                &wire[..n]
            } else {
                &plain[..n]
            };
            endpoint
                .receive(
                    bytes,
                    meta(peer, bytes.len()),
                    Instant(0),
                    &mut app,
                    &policy,
                )
                .unwrap();
            endpoint.pop_outgoing().unwrap();
            if mid == 1 {
                original.extend_from_slice(bytes);
            }
        }
        endpoint
            .set_rate_limits(
                Limits::default()
                    .with_per_source(1)
                    .with_source_burst(1)
                    .with_overall(1)
                    .with_overall_burst(1),
            )
            .unwrap();
        for (now, responds, misses, rate_limited) in
            [(0, true, 1, 0), (0, false, 1, 1), (1000, true, 2, 1)]
        {
            endpoint
                .receive(
                    &original,
                    meta(peer, original.len()),
                    Instant(now),
                    &mut app,
                    &policy,
                )
                .unwrap();
            let outgoing = endpoint.pop_outgoing();
            assert_eq!(outgoing.is_some(), responds);
            if let Some(outgoing) = outgoing {
                let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
                assert_eq!(response.code(), Code::UNAVAILABLE);
                assert_eq!(
                    response.option(OptionNumber::MAX_AGE).unwrap().uint(),
                    Ok(0)
                );
            }
            assert_eq!(endpoint.counters().dedup_reply_misses, misses);
            assert_eq!(endpoint.counters().rate_limited, rate_limited);
        }
        assert_eq!(calls.get(), 2);
        assert_eq!(endpoint.counters().dropped_messages, 0);
        assert_eq!(endpoint.counters().protection_failures, 0);
    }
}

#[cfg(feature = "software-crypto")]
#[test]
fn rel_3_osc_14_reply_pool_pressure_preserves_ciphertext_and_replay_checks() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        oscore::{Context, Oscore, OscoreOption},
        security::{PeerId, ProtectedOnly},
    };
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut cp = SoftwareCrypto::new(rand::rng());
    let mut client = Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
    let mut sp = SoftwareCrypto::new(rand::rng());
    let server = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
    let mut protection = Oscore::<_, 1>::new(sp);
    protection.install_fresh(server).unwrap();
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 2, 1, 1>::new(&shared, protection).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(&[calls.get(); 8]).unwrap();
        Ok(Disposition::Complete)
    };
    let mut requests = Vec::new();
    for id in 1..=3 {
        let mut plain = [0; 128];
        let n = request(&mut plain, id, &[id as u8], MessageType::Confirmable);
        let mut wire = [0; 128];
        let (n, mut binding) = client
            .protect_request::<128>(&mut cp, MessageView::parse(&plain[..n]).unwrap(), &mut wire)
            .unwrap();
        requests.push(wire[..n].to_vec());
        endpoint
            .receive(
                &wire[..n],
                meta(peer, n),
                Instant(id as u64 * 10),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        let reply = endpoint.pop_outgoing().unwrap().packet;
        let message = MessageView::parse(reply.as_slice()).unwrap();
        assert_eq!(
            OscoreOption::parse(message.option(OptionNumber::OSCORE).unwrap().value)
                .unwrap()
                .partial_iv,
            Some(&[(id - 1) as u8][..])
        );
        let n = client
            .unprotect_response::<128>(&mut cp, message, &mut binding, &mut plain)
            .unwrap();
        assert_eq!(
            MessageView::parse(&plain[..n]).unwrap().payload(),
            &[id as u8; 8]
        );
        if id == 2 {
            for (index, cached) in [(1, true), (0, false)] {
                let wire = &requests[index];
                endpoint
                    .receive(
                        wire,
                        meta(peer, wire.len()),
                        Instant(21),
                        &mut app,
                        &ProtectedOnly,
                    )
                    .unwrap();
                if cached {
                    assert_eq!(endpoint.pop_outgoing().unwrap().packet, reply);
                } else {
                    let outgoing = endpoint.pop_outgoing().unwrap();
                    let refusal = MessageView::parse(outgoing.packet.as_slice()).unwrap();
                    assert_eq!(refusal.code(), Code::UNAVAILABLE);
                    assert_eq!(refusal.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(0));
                    assert!(refusal.option(OptionNumber::OSCORE).is_none());
                }
            }
            assert_eq!(calls.get(), 2);
        }
    }
    // Actual record pressure still falls through to the OSCORE replay check.
    let wire = &requests[0];
    endpoint
        .receive(
            wire,
            meta(peer, wire.len()),
            Instant(31),
            &mut app,
            &ProtectedOnly,
        )
        .unwrap();
    let repeated = endpoint.pop_outgoing().unwrap().packet;
    let message = MessageView::parse(repeated.as_slice()).unwrap();
    assert_eq!(message.code(), Code::UNAUTHORIZED);
    assert!(message.option(OptionNumber::OSCORE).is_none());
    assert_eq!(calls.get(), 3);
    assert_eq!(endpoint.counters().duplicates, 2);
    assert_eq!(endpoint.counters().protection_failures, 1);
    assert_eq!(endpoint.counters().dedup_reply_misses, 1);
    assert_eq!(endpoint.counters().dropped_messages, 0);
}

#[cfg(feature = "software-crypto")]
#[test]
fn srv_7_osc_14_protected_response_capacity_uses_fresh_nonce_for_error_reply() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        oscore::{Context, Oscore},
        security::{PeerId, ProtectedOnly},
    };
    for size in [50, 64] {
        let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
        let mut cp = SoftwareCrypto::new(rand::rng());
        let mut client =
            Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
        let mut sp = SoftwareCrypto::new(rand::rng());
        let server = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let mut protection = Oscore::<_, 1>::new(sp);
        protection.install_fresh(server).unwrap();
        let shared = Shared::<64, 2>::new();
        let mut endpoint = Endpoint::<_, 64, 2, 4>::new(&shared, protection).unwrap();
        let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 64>| {
            response.set_payload(&[7; 64][..size])?;
            Ok(Disposition::Complete)
        };
        let mut bytes = [0; 64];
        let n = request(&mut bytes, 1, b"token123", MessageType::Confirmable);
        let mut wire = [0; 64];
        let (n, mut binding) = client
            .protect_request::<64>(&mut cp, MessageView::parse(&bytes[..n]).unwrap(), &mut wire)
            .unwrap();
        endpoint
            .receive(
                &wire[..n],
                meta(peer, n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let n = client
            .unprotect_response::<64>(
                &mut cp,
                MessageView::parse(outgoing.packet.as_slice()).unwrap(),
                &mut binding,
                &mut bytes,
            )
            .unwrap();
        assert_eq!(
            MessageView::parse(&bytes[..n]).unwrap().code(),
            Code::INTERNAL_ERROR
        );
    }
}

#[test]
fn srv_3_plt_7_deferred_capacity_failure_keeps_ticket_for_retry() {
    let shared = Shared::<64, 2>::new();
    let mut endpoint = Endpoint::<_, 64, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = core::cell::Cell::new(None);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 64>| {
        ticket.set(Some(request.deferred_ticket().unwrap()));
        Ok(Disposition::Deferred)
    };
    let mut bytes = [0; 64];
    let n = request(&mut bytes, 1, b"token123", MessageType::Confirmable);
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    endpoint.pop_outgoing().unwrap();
    let handle = shared.handle();
    let ticket = ticket.get().unwrap();
    let mut response = Response::new(Code::CONTENT);
    response.set_payload(&[7; 57]).unwrap();
    let operation = handle.respond_confirmed(ticket, &response).unwrap();
    endpoint.poll(Instant(1)).unwrap();
    assert_eq!(
        futures_lite::future::block_on(operation).unwrap_err(),
        Error::Capacity
    );
    let operation = handle
        .respond_confirmed(ticket, &Response::new(Code::CONTENT))
        .unwrap();
    endpoint.poll(Instant(2)).unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(outgoing.packet.as_slice())
            .unwrap()
            .code(),
        Code::CONTENT
    );
    let mid = MessageView::parse(outgoing.packet.as_slice())
        .unwrap()
        .message_id();
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
            meta(peer, n),
            Instant(3),
            &mut app,
            &PublicPaths(&[(Code::GET, "/x")]),
        )
        .unwrap();
    assert_eq!(futures_lite::future::block_on(operation), Ok(()));
}

#[test]
fn msg_1_unsupported_versions_are_silently_ignored() {
    let shared = Shared::<64, 1>::new();
    let mut endpoint = Endpoint::<_, 64, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app =
        |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| panic!("unsupported packet dispatched");
    for version in [0, 2, 3] {
        let bytes = [version << 6, 1, 0, 1];
        endpoint
            .receive(
                &bytes,
                meta("127.0.0.1:99".parse().unwrap(), 4),
                Instant(0),
                &mut app,
                &PublicPaths(&[]),
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_none());
    }
    let bytes = [0x49, 1, 0, 1];
    endpoint
        .receive(
            &bytes,
            meta("127.0.0.1:99".parse().unwrap(), 4),
            Instant(0),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    let output = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(output.packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::Reset
    );
}

#[test]
fn srv_1_queue_pressure_drops_requests_before_dispatch() {
    let shared = Shared::<64, 1>::new();
    let mut endpoint = Endpoint::<_, 64, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| {
        calls.set(calls.get() + 1);
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    for i in 0..16u8 {
        let remote = core::net::SocketAddr::from(([192, 0, 2, i + 1], 5683));
        endpoint
            .receive(
                &[0x40, 0, 0, i],
                meta(remote, 4),
                Instant(0),
                &mut app,
                &policy,
            )
            .unwrap();
    }
    let mut bytes = [0; 64];
    let n = request(&mut bytes, 123, b"t", MessageType::Confirmable);
    let remote = "192.0.2.99:5683".parse().unwrap();
    endpoint
        .receive(&bytes[..n], meta(remote, n), Instant(0), &mut app, &policy)
        .unwrap();
    assert_eq!(calls.get(), 0);
    assert_eq!(endpoint.counters().dropped_messages, 1);
    while endpoint.pop_outgoing().is_some() {}
    endpoint
        .receive(&bytes[..n], meta(remote, n), Instant(1), &mut app, &policy)
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert!(endpoint.pop_outgoing().is_some());
}

#[test]
fn msg_5_response_error_preserves_the_critical_option_number() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer: core::net::SocketAddr = "127.0.0.1:99".parse().unwrap();
    let mut bytes = [0; 128];
    let n = request(&mut bytes, 0, &[], MessageType::Confirmable);
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
    let output = endpoint.pop_outgoing().unwrap();
    let sent = MessageView::parse(output.packet.as_slice()).unwrap();
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        sent.message_id(),
        sent.token(),
    )
    .unwrap();
    b.option(OptionNumber(99), b"unknown").unwrap();
    let n = b.finish(&[]).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Err(Code::NOT_FOUND);
    endpoint
        .receive(
            &bytes[..n],
            meta(peer, n),
            Instant(1),
            &mut app,
            &PublicPaths(&[]),
        )
        .unwrap();
    assert_eq!(
        futures_lite::future::block_on(operation).unwrap_err(),
        Error::BadOption(OptionNumber(99))
    );
}

#[test]
fn srv_3_deferred_non_response_does_not_need_exchange_capacity() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = core::cell::Cell::new(None);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        ticket.set(Some(request.deferred_ticket().unwrap()));
        Ok(Disposition::Deferred)
    };
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    for (i, ty) in [MessageType::Confirmable, MessageType::NonConfirmable]
        .into_iter()
        .enumerate()
    {
        let mut bytes = [0; 128];
        let n = request(&mut bytes, i as u16, b"t", ty);
        endpoint
            .receive(
                &bytes[..n],
                meta("127.0.0.1:99".parse().unwrap(), n),
                Instant(i as u64),
                &mut app,
                &policy,
            )
            .unwrap();
        if ty == MessageType::Confirmable {
            assert_eq!(
                MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
                    .unwrap()
                    .code(),
                Code::EMPTY
            );
        }
        let mut response = shared
            .handle()
            .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(i as u64)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .message_type(),
            ty
        );
        if ty == MessageType::Confirmable {
            assert!(
                futures_lite::future::block_on(futures_lite::future::poll_once(&mut response))
                    .is_none()
            );
            drop(response);
        } else {
            assert_eq!(futures_lite::future::block_on(response), Ok(()));
        }
    }
}
