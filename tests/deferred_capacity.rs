//! Deferred admission is independent of immediate server handling.
#![cfg(feature = "server")]
use core::{
    future::Future,
    net::SocketAddr,
    pin::pin,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Protection, Request, ResponseWriter, Shared, Unsecured},
    messaging::TransmissionParameters,
    security::AllowAll,
    server::work::WorkQueue,
    time::Instant,
    transport::Metadata,
};
use std::{cell::Cell, rc::Rc};

fn metadata(peer: SocketAddr, length: usize) -> Metadata {
    Metadata::new(peer, "192.0.2.2".parse().unwrap(), length)
}

fn request(bytes: &mut [u8; 128], mid: u16) -> usize {
    let mut builder = MessageBuilder::new(
        bytes,
        MessageType::Confirmable,
        Code::POST,
        mid,
        &[mid as u8],
    )
    .unwrap();
    builder.option(OptionNumber::URI_PATH, b"x").unwrap();
    builder.finish(&[]).unwrap()
}

#[test]
fn immediate_handler_remains_usable_when_deferred_capacity_is_full() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint =
        Endpoint::<_, 128, 1, 2, 0, 1, 2, 1, 1, 0, 2>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let queue = WorkQueue::<128, 1, 128>::new();
    let mut deferred = queue.handler(1_000).unwrap();
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];

    let n = request(&mut bytes, 1);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(0),
            &mut deferred,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .code(),
        Code::EMPTY
    );
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );

    let mut called = false;
    let mut immediate = |request: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        called = true;
        assert!(request.deferred_ticket().is_none());
        response.set_payload(b"immediate")?;
        Ok(Disposition::Complete)
    };
    let n = request(&mut bytes, 2);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(1),
            &mut immediate,
            &AllowAll,
        )
        .unwrap();
    assert!(called);
    assert_eq!(
        MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .payload(),
        b"immediate"
    );

    let mut next = pin!(queue.next());
    let Poll::Ready(job) = next.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
        panic!("the first request should still be queued");
    };
    assert_eq!(job.request().unwrap().message.message_id(), 1);
}

fn assert_work_queue_rejects<
    const OUTBOUND: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
>() {
    let shared = Shared::<128, COMMANDS>::new();
    let mut endpoint = Endpoint::<_, 128, OUTBOUND, 2, 0, 1, 2, COMMANDS, DEFERRED, 0, 1>::new(
        &shared,
        Unsecured(rand::rng()),
    )
    .unwrap();
    let queue = WorkQueue::<128, 1, 128>::new();
    let mut handler = queue.handler(1_000).unwrap();
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let n = request(&mut bytes, 1);

    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(0),
            &mut handler,
            &AllowAll,
        )
        .unwrap();
    let response = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(response.code(), Code::UNAVAILABLE);
    assert_eq!(
        response.option(OptionNumber::MAX_AGE).unwrap().uint(),
        Ok(1)
    );

    let mut next = pin!(queue.next());
    assert!(matches!(
        next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Pending
    ));
}

#[test]
fn work_queue_rejects_when_deferred_or_command_capacity_is_disabled() {
    assert_work_queue_rejects::<1, 1, 0>();
    assert_work_queue_rejects::<1, 0, 1>();
    assert_work_queue_rejects::<0, 1, 1>();
}

#[test]
fn deferred_expiry_releases_swapped_entries_once_and_preserves_live_tickets() {
    struct BoundRequests {
        inner: Unsecured<rand::rngs::ThreadRng>,
        releases: Rc<Cell<usize>>,
    }
    impl Protection for BoundRequests {
        mai_coap::delegate_protection!(inner, (); except [incoming, release]);
        fn incoming<const N: usize>(
            &mut self,
            message: MessageView<'_>,
            metadata: Metadata,
            output: &mut [u8],
        ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
            let (length, state, _) = self.inner.incoming::<N>(message, metadata, output)?;
            Ok((length, state, Some(())))
        }
        fn release(&mut self, _: ()) {
            self.releases.set(self.releases.get() + 1);
        }
    }

    let releases = Rc::new(Cell::new(0));
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 8, 0, 1, 2, 1, 3, 0, 2>::new(
        &shared,
        BoundRequests {
            inner: Unsecured(rand::rng()),
            releases: releases.clone(),
        },
    )
    .unwrap();
    let grace = TransmissionParameters::default().exchange_lifetime();
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let mut handler = |request: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        assert!(request.deferred_ticket().is_some());
        response.set_deferred_timeout(if request.message.message_id() == 2 {
            100
        } else {
            10
        })?;
        Ok(Disposition::Deferred)
    };
    for mid in 1..=3 {
        let n = request(&mut bytes, mid);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(0),
                &mut handler,
                &AllowAll,
            )
            .unwrap();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    endpoint.poll(Instant(grace + 9)).unwrap();
    assert_eq!(releases.get(), 0);
    endpoint.poll(Instant(grace + 10)).unwrap();
    assert_eq!(releases.get(), 2);
    endpoint.poll(Instant(grace + 10)).unwrap();
    assert_eq!(releases.get(), 2);

    // Both freed slots must be reusable while the longer-lived ticket remains.
    for mid in 4..=5 {
        let n = request(&mut bytes, mid);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(grace + 10),
                &mut handler,
                &AllowAll,
            )
            .unwrap();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    endpoint.poll(Instant(grace + 100)).unwrap();
    assert_eq!(releases.get(), 3);
    endpoint.poll(Instant(2 * grace + 20)).unwrap();
    assert_eq!(releases.get(), 5);
    endpoint.poll(Instant(2 * grace + 21)).unwrap();
    assert_eq!(releases.get(), 5);
}
