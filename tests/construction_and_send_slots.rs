//! Public construction, error conversion and independently bounded send storage.
#![cfg(all(feature = "server", feature = "client"))]
mod support;
use core::net::SocketAddr;
#[cfg(feature = "observe")]
use core::task::{Context, Waker};
use futures_lite::future::{block_on, poll_once};
use mai_coap::{
    Error,
    codec::{Code, ContentFormat, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Disposition, Endpoint, Request, Response, ResponseError, ResponseWriter, RunError, Shared,
        Unsecured,
    },
    messaging::TransmissionParameters,
    rate::Limits,
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

#[test]
fn rel_3_reply_pool_pressure_does_not_dispatch_a_con_post_twice() {
    fn check<const EXCHANGES: usize, const RECORDS: usize, const REPLIES: usize>() {
        let shared = Shared::<1152, EXCHANGES>::new();
        let mut endpoint = Endpoint::<_, 1152, EXCHANGES, RECORDS, 4, REPLIES>::new(
            &shared,
            Unsecured(rand::rng()),
        )
        .unwrap();
        let calls = core::cell::Cell::new(0);
        let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 1152>| {
            calls.set(calls.get() + 1);
            response.set_code(Code::CHANGED);
            response.set_payload(b"created")?;
            Ok(Disposition::Complete)
        };
        let policy = PublicPaths(&[(Code::POST, "/")]);
        let remote = "192.0.2.1:5683".parse().unwrap();
        let local = "192.0.2.2".parse().unwrap();
        let request = |id| [0x41, 2, 0, id, 42];
        let mut last_reply = None;
        for id in 1..=REPLIES + 1 {
            let bytes = request(id as u8);
            endpoint
                .receive(
                    &bytes,
                    Metadata::new(remote, local, bytes.len()),
                    Instant(0),
                    &mut app,
                    &policy,
                )
                .unwrap();
            last_reply = Some(endpoint.pop_outgoing().unwrap().packet);
        }
        let bytes = request(1);
        let metadata = Metadata::new(remote, local, bytes.len());
        endpoint
            .receive(&bytes, metadata, Instant(3000), &mut app, &policy)
            .unwrap();
        assert_eq!(calls.get(), REPLIES + 1);
        let outgoing = endpoint.pop_outgoing().unwrap();
        let refusal = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(refusal.code(), Code::UNAVAILABLE);
        assert_eq!(refusal.message_type(), MessageType::Acknowledgement);
        assert_eq!(refusal.message_id(), 1);
        assert_eq!(refusal.token(), &[42]);
        assert_eq!(refusal.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(0));
        assert_eq!(endpoint.counters().dedup_reply_misses, 1);
        let mut non = bytes;
        non[0] = 0x51;
        endpoint
            .receive(&non, metadata, Instant(3000), &mut app, &policy)
            .unwrap();
        assert!(endpoint.pop_outgoing().is_none());
        assert_eq!(calls.get(), REPLIES + 1);
        assert_eq!(endpoint.counters().dedup_reply_misses, 1);
        let bytes = request((REPLIES + 1) as u8);
        endpoint
            .receive(&bytes, metadata, Instant(3000), &mut app, &policy)
            .unwrap();
        assert_eq!(
            endpoint.pop_outgoing().unwrap().packet.as_slice(),
            last_reply.unwrap().as_slice()
        );
        assert_eq!(calls.get(), REPLIES + 1);
        let bytes = request(1);
        endpoint
            .receive(&bytes, metadata, Instant(247_000), &mut app, &policy)
            .unwrap();
        assert_eq!(
            calls.get(),
            REPLIES + 2,
            "the duplicate record still expires normally"
        );
        assert!(endpoint.pop_outgoing().is_some());
    }
    check::<8, 32, 8>();
    check::<4, 16, 2>();
}

#[test]
fn plt_7_single_send_slot_defers_commands_and_retries_without_changing_wire_bytes() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Endpoint::<_, 128, 2, 4, 1, 1, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
    endpoint
        .set_send_policy(mai_coap::endpoint::SendPolicy::default().with_max_wait_ms(4000))
        .unwrap();
    let handle = shared.handle();
    let first = handle
        .client(SocketAddr::from(([192, 0, 2, 1], 5683)))
        .request(Code::GET, "/one")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let initial = endpoint.pop_outgoing().unwrap();
    let second = handle
        .client(SocketAddr::from(([192, 0, 2, 2], 5683)))
        .request(Code::GET, "/two")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    // With the sole send slot occupied, the first retry must keep its original deadline.
    endpoint.poll(Instant(3000)).unwrap();
    let other = endpoint.pop_outgoing().unwrap();
    assert_ne!(other.remote, initial.remote);
    endpoint.poll(Instant(3000)).unwrap();
    let retry = endpoint.pop_outgoing().unwrap();
    assert_eq!(retry.remote, initial.remote);
    assert_eq!(retry.packet.as_slice(), initial.packet.as_slice());
    assert_eq!(endpoint.counters().retransmissions, 1);
    drop((first, second));
    endpoint.poll(Instant(3001)).unwrap();
    assert_eq!(endpoint.counters().dropped_messages, 0);
    assert!(endpoint.pop_outgoing().is_none());
}

#[test]
fn plt_7_queued_cancellation_and_deferred_reply_survive_one_send_slot() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Endpoint::<_, 128, 2, 4, 1, 1, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote = SocketAddr::from(([192, 0, 2, 1], 5683));
    let mut ticket = None;
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        ticket = Some(request.deferred_ticket().unwrap());
        Ok(Disposition::Deferred)
    };
    let bytes = [0x41, 1, 0, 1, 42];
    let policy = PublicPaths(&[(Code::GET, "/")]);
    endpoint
        .receive(
            &bytes,
            Metadata::new(remote, "192.0.2.2".parse().unwrap(), bytes.len()),
            Instant(0),
            &mut app,
            &policy,
        )
        .unwrap();
    let handle = shared.handle();
    let cancelled = handle
        .client(remote)
        .request(Code::GET, "/cancelled")
        .unwrap()
        .send()
        .unwrap();
    let mut response = Response::new(Code::CONTENT);
    response.set_payload(b"done").unwrap();
    let mut done = core::pin::pin!(handle.respond(ticket.unwrap(), &response).unwrap());
    endpoint.poll(Instant(0)).unwrap();
    assert!(block_on(poll_once(done.as_mut())).is_none());
    drop(cancelled);
    let ack = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(ack.packet.as_slice()).unwrap().code(),
        Code::EMPTY
    );
    endpoint.poll(Instant(1)).unwrap();
    let response = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(response.packet.as_slice())
            .unwrap()
            .payload(),
        b"done"
    );
    assert!(block_on(poll_once(done.as_mut())).unwrap().is_ok());
    endpoint.poll(Instant(1)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(endpoint.counters().dropped_messages, 0);
    assert!(matches!(
        Endpoint::<_, 128, 2, 4, 1, 1, 0>::new(&shared, Unsecured(rand::rng())),
        Err(Error::Capacity)
    ));
}

#[test]
fn api_5_raw_submission_preserves_named_controls_and_copies_only_on_send() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let handle = shared.handle();
    let remote = SocketAddr::from(([192, 0, 2, 1], 5683));
    let client = handle
        .client(remote)
        .parameters(TransmissionParameters::default().with_nstart(2))
        .unwrap();
    let mut wire = [0; 128];
    let n = MessageBuilder::new(
        &mut wire,
        MessageType::NonConfirmable,
        Code::POST,
        99,
        b"old",
    )
    .unwrap()
    .finish(b"raw")
    .unwrap();
    assert!(matches!(
        client.request_raw(&wire[..n]).unwrap().token_length(9),
        Err(Error::Malformed)
    ));
    let pending = client
        .request_raw(&wire[..n])
        .unwrap()
        .token_length(3)
        .unwrap()
        .wait_for_nstart(false);
    endpoint.poll(Instant(0)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    let operation = pending.send().unwrap();
    wire.fill(0);
    endpoint.poll(Instant(0)).unwrap();
    let sent = endpoint.pop_outgoing().unwrap();
    let message = MessageView::parse(sent.packet.as_slice()).unwrap();
    assert_eq!(message.token().len(), 3);
    assert_eq!(message.payload(), b"raw");
    assert_eq!(message.message_type(), MessageType::NonConfirmable);
    drop(operation);
    let ping = client
        .request_raw(&[0x40, 0, 0, 1])
        .unwrap()
        .token_length(0)
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    let sent = endpoint.pop_outgoing().unwrap();
    let message = MessageView::parse(sent.packet.as_slice()).unwrap();
    assert_eq!(message.code(), Code::EMPTY);
    assert!(message.token().is_empty());
    drop(ping);
}

#[test]
fn api_2_explicit_peer_never_falls_back_to_an_unsecured_request() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote = SocketAddr::from(([192, 0, 2, 1], 5683));
    let operation = shared
        .handle()
        .client(remote)
        .peer(mai_coap::security::PeerId(1))
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(block_on(operation).unwrap_err(), Error::ContextNotFound);
}

#[test]
fn api_6_response_building_errors_are_local_and_driver_sources_are_preserved() {
    fn handler(response: &mut ResponseWriter<'_, 32>) -> Result<Disposition, Code> {
        response.set_payload(&[0; 33])?;
        Ok(Disposition::Complete)
    }
    assert_eq!(
        handler(&mut ResponseWriter::new(&mut [0; 32], Code::CONTENT, &[]).unwrap()),
        Err(Code::INTERNAL_ERROR)
    );
    assert_eq!(Error::from(ResponseError::Capacity), Error::Capacity);
    assert_eq!(Error::from(ResponseError::InvalidTimeout), Error::Malformed);
    assert_eq!(
        ResponseWriter::<32>::new(&mut [0; 32], Code::CONTENT, &[])
            .unwrap()
            .set_deferred_timeout(0),
        Err(ResponseError::InvalidTimeout)
    );
    let transport = RunError::Transport(std::io::Error::other("failed"));
    assert_eq!(transport.to_string(), "transport: failed");
    assert_eq!(
        std::error::Error::source(&transport).unwrap().to_string(),
        "failed"
    );
    let protocol = RunError::<std::io::Error>::Protocol(Error::Malformed);
    assert!(std::error::Error::source(&protocol).unwrap().is::<Error>());
}

#[test]
fn api_5_public_settings_construct_without_exhaustive_literals() {
    let remote = SocketAddr::from(([192, 0, 2, 1], 5683));
    let metadata = Metadata::new(remote, "192.0.2.2".parse().unwrap(), 5).with_interface(Some(7));
    assert_eq!(metadata.interface, Some(7));
    assert_eq!(
        TransmissionParameters::default()
            .with_ack_timeout_ms(0)
            .validate(),
        Err(Error::Malformed)
    );
    assert!(matches!(
        Limits::default().with_source_burst(0).validate(),
        Err(Error::Malformed)
    ));
    let body = mai_coap::server::SliceBody::new(b"body", ContentFormat::TEXT);
    assert!(body.etag.is_empty());
    assert_eq!(body.max_age, 60);
    assert!(matches!(body.with_etag(&[0; 9]), Err(Error::Capacity)));
    let chunk = mai_coap::server::BodyChunk::new(4, ContentFormat::TEXT)
        .with_total(Some(4))
        .with_etag(b"v1")
        .unwrap()
        .with_max_age(10);
    assert_eq!(chunk.total, Some(4));
    assert_eq!(chunk.etag.as_slice(), b"v1");
    assert_eq!(chunk.max_age, 10);
}

#[cfg(feature = "observe")]
#[test]
fn obs_4_due_observers_resume_as_a_single_send_slot_drains() {
    use mai_coap::{codec::OptionNumber, observe::Settings, server::Router};
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Endpoint::<_, 128, 2, 4, 2, 1, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.set_payload(b"changed")?;
        Ok(Disposition::Complete)
    };
    let mut router = Router::<128, 1>::new(&policy);
    router.route("/x", &[Code::GET], &mut app).unwrap();
    let resource = router
        .observable("/x", Settings::new(7).with_confirmable_ms(10_000))
        .unwrap();
    for id in 1..=2 {
        let mut wire = [0; 128];
        let mut builder = MessageBuilder::new(
            &mut wire,
            MessageType::Confirmable,
            Code::GET,
            id,
            &[id as u8],
        )
        .unwrap();
        builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        builder.option(OptionNumber::URI_PATH, b"x").unwrap();
        let n = builder.finish(&[]).unwrap();
        endpoint
            .receive(
                &wire[..n],
                Metadata::new(
                    SocketAddr::from(([192, 0, 2, id as u8], 5683)),
                    "192.0.2.9".parse().unwrap(),
                    n,
                ),
                Instant(0),
                &mut router,
                &policy,
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
    }
    shared.handle().notify(resource).unwrap();
    let mut destinations = std::vec::Vec::new();
    for _ in 0..2 {
        endpoint.poll(Instant(1)).unwrap();
        endpoint
            .poll_resources(
                Instant(1),
                &mut router,
                &policy,
                &mut Context::from_waker(Waker::noop()),
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert!(
            MessageView::parse(out.packet.as_slice())
                .unwrap()
                .option(OptionNumber::OBSERVE)
                .is_some()
        );
        destinations.push(out.remote);
    }
    assert_ne!(destinations[0], destinations[1]);
    assert_eq!(endpoint.counters().dropped_messages, 0);
}
