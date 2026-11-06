//! Observe ownership and packet-pool pressure regressions.
#![cfg(all(feature = "server", feature = "client", feature = "observe"))]

use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    observe::Settings,
    security::{ProtectedOnly, PublicPaths},
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

mod support;

fn metadata(peer: core::net::SocketAddr, length: usize) -> Metadata {
    Metadata::new(peer, "127.0.0.2".parse().unwrap(), length).with_interface(Some(1))
}

fn observe_request<const D: usize>(
    output: &mut [u8; D],
    code: Code,
    mid: u16,
    token: &[u8],
) -> usize {
    let mut builder =
        MessageBuilder::new(output, MessageType::Confirmable, code, mid, token).unwrap();
    builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    builder.option(OptionNumber::URI_PATH, b"x").unwrap();
    builder
        .finish(if code == Code::FETCH {
            b"selector"
        } else {
            b""
        })
        .unwrap()
}

#[test]
fn two_packet_observe_refresh_and_cancellation_reuse_the_original_slot() {
    type SmallPoolEndpoint<'a> =
        Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, 128, 1, 2, 1, 1, 2, 1, 0, 0, 2>;
    let peer = "192.0.2.1:5683".parse().unwrap();

    for cancel in [false, true] {
        let shared = Shared::<128, 1>::new();
        let mut endpoint = SmallPoolEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut bytes = [0; 128];
        let length = observe_request(&mut bytes, Code::FETCH, 1, b"observe");
        let operation = shared
            .handle()
            .client(peer)
            .parameters(TransmissionParameters::default())
            .unwrap()
            .request_raw(&bytes[..length])
            .unwrap()
            .token_length(8)
            .unwrap()
            .wait_for_nstart(true)
            .send()
            .unwrap();

        endpoint.poll(Instant(0)).unwrap();
        let request = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(request.packet.as_slice()).unwrap();
        let mut response = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            request.message_id(),
            request.token(),
        )
        .unwrap();
        response.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        response.uint_option(OptionNumber::MAX_AGE, 1).unwrap();
        let length = response.finish(b"result").unwrap();
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        endpoint
            .receive(
                &bytes[..length],
                metadata(peer, length),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        if cancel {
            drop(operation);
        }

        endpoint.poll(Instant(3000)).unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let refreshed = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(refreshed.code(), Code::FETCH);
        assert_eq!(refreshed.payload(), b"selector");
        assert_eq!(
            refreshed.option(OptionNumber::OBSERVE).unwrap().uint(),
            Ok(u64::from(cancel))
        );
        assert!(endpoint.pop_outgoing().is_none());
    }
}

#[test]
fn server_notification_reserves_before_dispatch_and_reclaims_cache_at_pool_pressure() {
    type SmallPoolEndpoint<'a> =
        Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, 128, 1, 2, 1, 2, 2, 0, 0, 0, 2>;
    let peer = "192.0.2.1:5683".parse().unwrap();
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let calls = core::cell::Cell::new(0);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(b"notification").unwrap();
        Ok(Disposition::Complete)
    };
    let mut router = mai_coap::server::Router::<128, 1>::new(&policy);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    let resource = router
        .observable(
            "/x",
            Settings::new(7)
                .with_minimum_ms(0)
                .with_maximum_ms(60_000)
                .with_confirmable_ms(86_400_000),
        )
        .unwrap();
    let shared = Shared::<128, 0>::new();
    let mut endpoint = SmallPoolEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut bytes = [0; 128];

    for (mid, observing) in [(1, true), (2, false)] {
        let token = if observing {
            b"t".as_slice()
        } else {
            b"other".as_slice()
        };
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, mid, token)
                .unwrap();
        if observing {
            builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        }
        builder.option(OptionNumber::URI_PATH, b"x").unwrap();
        let length = builder.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..length],
                metadata(peer, length),
                Instant(mid.into()),
                &mut router,
                &policy,
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_some());
    }
    assert_eq!(calls.get(), 2);

    shared.handle().notify(resource).unwrap();
    endpoint
        .poll_resources(
            Instant(3),
            &mut router,
            &policy,
            &mut core::task::Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let message = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(message.message_type(), MessageType::NonConfirmable);
    assert_eq!(message.token(), b"t");
    assert_eq!(message.payload(), b"notification");
    assert_eq!(calls.get(), 3);
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    assert!(endpoint.pop_outgoing().is_none());
}

#[cfg(feature = "software-crypto")]
#[test]
fn protected_observe_refresh_keeps_plaintext_request_length() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        endpoint::Protection,
        oscore::{Context, Oscore},
        security::PeerId,
    };

    type ProtectedEndpoint<'a> = Endpoint<
        'a,
        Oscore<SoftwareCrypto<rand::rngs::ThreadRng>, 1>,
        128,
        1,
        2,
        1,
        1,
        2,
        1,
        0,
        0,
        2,
    >;
    let peer = "192.0.2.1:5683".parse().unwrap();
    let client_peer = PeerId(1);
    let mut client_crypto = SoftwareCrypto::new(rand::rng());
    let client_context = Context::derive(
        &mut client_crypto,
        &[1; 16],
        None,
        &[0],
        &[1],
        None,
        client_peer,
    )
    .unwrap();
    let mut client_protection = Oscore::<_, 1>::new(client_crypto);
    client_protection.install_fresh(client_context).unwrap();

    let mut server_crypto = SoftwareCrypto::new(rand::rng());
    let server_context = Context::derive(
        &mut server_crypto,
        &[1; 16],
        None,
        &[1],
        &[0],
        None,
        client_peer,
    )
    .unwrap();
    let mut server = Oscore::<_, 1>::new(server_crypto);
    server.install_fresh(server_context).unwrap();

    let shared = Shared::<128, 1>::new();
    let mut endpoint = ProtectedEndpoint::new(&shared, client_protection).unwrap();
    let operation = shared
        .handle()
        .client(peer)
        .peer(client_peer)
        .request(Code::FETCH, "/x")
        .unwrap()
        .uint_option(OptionNumber::OBSERVE, 0)
        .unwrap()
        .payload(b"selector")
        .unwrap()
        .token_length(8)
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let request = endpoint.pop_outgoing().unwrap();
    let mut server_plain = [0; 128];
    let (server_plain_length, _, mut binding) = server
        .incoming::<128>(
            MessageView::parse(request.packet.as_slice()).unwrap(),
            metadata(peer, request.packet.as_slice().len()),
            &mut server_plain,
        )
        .unwrap();
    let request = MessageView::parse(&server_plain[..server_plain_length]).unwrap();
    let mut response_plain = [0; 128];
    let mut response = MessageBuilder::new(
        &mut response_plain,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap();
    response.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    response.uint_option(OptionNumber::MAX_AGE, 1).unwrap();
    let response_plain_length = response.finish(b"result").unwrap();
    let mut response_wire = [0; 128];
    let response_wire_length = server
        .response::<128>(
            MessageView::parse(&response_plain[..response_plain_length]).unwrap(),
            binding.as_mut().unwrap(),
            &mut response_wire,
        )
        .unwrap();
    server.release(binding.take().unwrap());
    endpoint
        .receive(
            &response_wire[..response_wire_length],
            metadata(peer, response_wire_length),
            Instant(0),
            &mut |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete),
            &ProtectedOnly,
        )
        .unwrap();

    endpoint.poll(Instant(3000)).unwrap();
    let refresh = endpoint.pop_outgoing().unwrap();
    let mut refresh_plain = [0; 128];
    let (refresh_length, _, binding) = server
        .incoming::<128>(
            MessageView::parse(refresh.packet.as_slice()).unwrap(),
            metadata(peer, refresh.packet.as_slice().len()),
            &mut refresh_plain,
        )
        .unwrap();
    let refresh = MessageView::parse(&refresh_plain[..refresh_length]).unwrap();
    assert_eq!(refresh.code(), Code::FETCH);
    assert_eq!(refresh.payload(), b"selector");
    assert_eq!(refresh.option(OptionNumber::OBSERVE).unwrap().uint(), Ok(0));
    server.release(binding.unwrap());
    drop(operation);
}

#[test]
fn zero_outbound_capacity_declines_observe_registration() {
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.set_payload(b"current")?;
        Ok(Disposition::Complete)
    };
    let mut router = mai_coap::server::Router::<128, 1>::new(&policy);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    router.observable("/x", Settings::new(1)).unwrap();
    let shared = Shared::<128, 0>::new();
    let mut endpoint =
        Endpoint::<_, 128, 0, 2, 1, 1, 2, 0, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let mut bytes = [0; 128];
    let length = observe_request(&mut bytes, Code::GET, 1, b"t");
    endpoint
        .receive(
            &bytes[..length],
            metadata("192.0.2.1:5683".parse().unwrap(), length),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(reply.payload(), b"current");
    assert!(reply.option(OptionNumber::OBSERVE).is_none());
}

#[test]
fn inline_pool_pressure_does_not_delay_notifications_or_other_commands() {
    use core::{
        cell::Cell,
        net::SocketAddr,
        task::{Context, Waker},
    };
    type TinyEndpoint<'a> =
        Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, 128, 2, 4, 1, 1, 2, 2, 0, 0, 2>;
    let shared = Shared::<128, 2>::new();
    let calls = Cell::new(0);
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(b"notification")?;
        Ok(Disposition::Complete)
    };
    let mut router = mai_coap::server::Router::<128, 1>::new(&policy);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    let resource = router
        .observable("/x", Settings::new(7).with_confirmable_ms(86_400_000))
        .unwrap();
    let mut endpoint = TinyEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let peer = "192.0.2.3:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::NonConfirmable,
        Code::GET,
        1,
        b"observe",
    )
    .unwrap();
    b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let first = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 2, b"other").unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    shared.handle().notify(resource).unwrap();
    endpoint
        .poll_resources(
            Instant(0),
            &mut router,
            &policy,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
    assert_eq!(calls.get(), 2);
    // Completing this send makes its cache owner reclaimable at the same time.
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let second = shared
        .handle()
        .client("192.0.2.4:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert_eq!(
        MessageView::parse(
            endpoint
                .front_outgoing()
                .expect("inline pressure must not throttle commands")
                .bytes
        )
        .unwrap()
        .code(),
        Code::GET
    );
    drop(second);
    endpoint.poll(Instant(0)).unwrap();
    endpoint
        .poll_resources(
            Instant(0),
            &mut router,
            &policy,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
    let notification = MessageView::parse(
        endpoint
            .front_outgoing()
            .expect("freed slot is immediately usable")
            .bytes,
    )
    .unwrap();
    assert_eq!(
        notification.option(OptionNumber::OBSERVE).unwrap().uint(),
        Ok(1)
    );
    assert_eq!(calls.get(), 3);
    drop(first);
}
