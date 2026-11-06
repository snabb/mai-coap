//! Server CON exchanges share OUTBOUND capacity with client exchanges.
#![cfg(feature = "server")]

use core::{
    cell::Cell,
    future::Future,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    security::AllowAll,
    time::Instant,
    transport::Metadata,
};

const D: usize = 128;

fn metadata(length: usize) -> Metadata {
    Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        length,
    )
}

fn check_deferred<const EXCHANGES: usize>(accept: bool) {
    let shared = Shared::<D, 2>::new();
    let mut endpoint =
        Endpoint::<_, D, EXCHANGES, 4, 0, 2, 2, 2, 1, 0, 4>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let ticket = Cell::new(None);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, D>| {
        ticket.set(request.deferred_ticket());
        Ok(Disposition::Deferred)
    };
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(0), &mut app, &AllowAll)
        .unwrap();
    let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    if EXCHANGES == 0 {
        assert_eq!(ticket.get(), None);
        assert_eq!(reply.code(), Code::UNAVAILABLE);
        return;
    }
    assert_eq!(reply.code(), Code::EMPTY);
    endpoint.complete_outgoing(Instant(0));
    let operation = shared
        .handle()
        .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
        .unwrap();
    let mut operation = core::pin::pin!(operation);
    endpoint.poll(Instant(1)).unwrap();
    assert!(
        operation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    assert_eq!(
        MessageView::parse(&original).unwrap().message_type(),
        MessageType::Confirmable
    );
    if accept {
        endpoint.complete_outgoing(Instant(500));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let retry_at = endpoint.deadline(Instant(500));
        assert!((2500..=3500).contains(&retry_at.0));
        endpoint.poll(Instant(retry_at.0 - 1)).unwrap();
        assert!(endpoint.front_outgoing().is_none());
        endpoint.poll(retry_at).unwrap();
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
        endpoint.complete_outgoing(retry_at);
        assert_eq!(endpoint.counters().retransmissions, 1);
        let mid = MessageView::parse(&original).unwrap().message_id();
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
            .receive(&bytes[..n], metadata(n), retry_at, &mut app, &AllowAll)
            .unwrap();
        assert!(matches!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
    } else {
        endpoint.poll(Instant(1001)).unwrap();
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.counters().local_send_timeouts, 1);
        assert!(matches!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(mai_coap::Error::LocalSendTimeout))
        ));
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 2, b"u")
            .unwrap()
            .finish(&[])
            .unwrap();
        endpoint
            .receive(&bytes[..n], metadata(n), Instant(1002), &mut app, &AllowAll)
            .unwrap();
        endpoint.complete_outgoing(Instant(1002));
        let _next = shared
            .handle()
            .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(1002)).unwrap();
        assert_eq!(
            MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                .unwrap()
                .message_type(),
            MessageType::Confirmable
        );
    }
}

#[test]
fn zero_exchange_capacity_refuses_deferred_con_even_with_command_slots() {
    check_deferred::<0>(false);
}

#[test]
fn accepted_server_con_arms_retransmission_without_a_client_role() {
    check_deferred::<1>(true);
}

#[test]
fn expired_server_con_releases_exchange_capacity() {
    check_deferred::<1>(false);
}

#[cfg(feature = "observe")]
fn check_notification<const EXCHANGES: usize>() {
    use mai_coap::{codec::OptionNumber, observe::Settings, server::Router};

    let shared = Shared::<D, 2>::new();
    let mut endpoint =
        Endpoint::<_, D, EXCHANGES, 4, 1, 2, 2, 2, 0, 0, 4>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Ok(Disposition::Complete);
    let mut app = Router::<D, 1, 0, 0>::new(&AllowAll);
    app.route("/", &[Code::GET], &mut handler).unwrap();
    app.observable(
        "/",
        Settings::new(1).with_maximum_ms(1).with_confirmable_ms(10),
    )
    .unwrap();
    let mut bytes = [0; D];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    let n = builder.finish(&[]).unwrap();
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(0), &mut app, &AllowAll)
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .code(),
        Code::CONTENT
    );
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .option(OptionNumber::OBSERVE)
            .is_some(),
        EXCHANGES != 0
    );
    endpoint.complete_outgoing(Instant(0));
    let mut cx = Context::from_waker(Waker::noop());
    endpoint
        .poll_resources(Instant(10), &mut app, &AllowAll, &mut cx)
        .unwrap();
    if EXCHANGES == 0 {
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.counters().local_send_timeouts, 0);
        return;
    }
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    let notification = MessageView::parse(&original).unwrap();
    assert_eq!(notification.message_type(), MessageType::Confirmable);
    let mid = notification.message_id();
    endpoint.complete_outgoing(Instant(500));
    let retry_at = endpoint.deadline(Instant(500));
    assert!((2500..=3500).contains(&retry_at.0));
    endpoint.poll(retry_at).unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
    endpoint.complete_outgoing(retry_at);
    assert_eq!(endpoint.counters().retransmissions, 1);
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
        .receive(&bytes[..n], metadata(n), retry_at, &mut app, &AllowAll)
        .unwrap();
    endpoint
        .poll_resources(retry_at.after(1), &mut app, &AllowAll, &mut cx)
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .message_type(),
        MessageType::NonConfirmable
    );
}

#[cfg(feature = "observe")]
#[test]
fn zero_exchange_capacity_declines_observe_even_with_observer_slots() {
    check_notification::<0>();
}

#[cfg(feature = "observe")]
#[test]
fn accepted_server_notification_arms_retry_and_updates_confirmation_time() {
    check_notification::<1>();
}
