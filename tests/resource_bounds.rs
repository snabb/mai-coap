//! Packet ownership, independent capacities and protected-response diagnostics.
#![cfg(all(feature = "server", feature = "client"))]
use core::{cell::Cell, net::SocketAddr, pin::pin, task::Poll};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Disposition, Endpoint, Prepared, Protection, Request, ResponseWriter, ServerEndpoint,
        ServerShared, Shared, Target, Unsecured,
    },
    security::AllowAll,
    time::Instant,
    transport::Metadata,
};
use std::future::{Future, poll_fn};
use std::rc::Rc;
mod support;

fn metadata(remote: SocketAddr, length: usize) -> Metadata {
    Metadata::new(remote, "192.0.2.2".parse().unwrap(), length)
}
fn request(mid: u16, bytes: &mut [u8]) -> usize {
    MessageBuilder::new(bytes, MessageType::Confirmable, Code::POST, mid, &[1])
        .unwrap()
        .finish(b"body")
        .unwrap()
}
fn poll_once<F: Future>(mut future: core::pin::Pin<&mut F>) -> Option<F::Output> {
    futures_lite::future::block_on(poll_fn(|cx| {
        Poll::Ready(match future.as_mut().poll(cx) {
            Poll::Ready(value) => Some(value),
            Poll::Pending => None,
        })
    }))
}

#[test]
fn immediate_server_has_no_command_exchange_or_deferred_capacity() {
    let shared = ServerShared::<128>::new();
    let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let called = Cell::new(0);
    let mut app = |r: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        assert!(r.deferred_ticket().is_none());
        called.set(called.get() + 1);
        response.set_payload(b"reply")?;
        Ok(Disposition::Complete)
    };
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    for mid in 1..=12 {
        let n = request(mid, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(u64::from(mid)),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        assert_eq!(
            MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                .unwrap()
                .payload(),
            b"reply"
        );
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    assert_eq!(called.get(), 12);
    assert!(endpoint.counters().dedup_reply_drops > 0);
    assert_eq!(
        shared
            .handle()
            .client(peer)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .err(),
        Some(Error::Capacity)
    );
}

#[test]
fn pool_pressure_never_reprocesses_a_duplicate_or_reclaims_queued_bytes() {
    let shared = Shared::<128, 0>::new();
    let mut endpoint =
        Endpoint::<_, 128, 0, 8, 0, 2, 3, 0, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let calls = Cell::new(0);
    let mut app = |_: Request<'_>, r: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        r.set_payload(&[calls.get() as u8])?;
        Ok(Disposition::Complete)
    };
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    for mid in 1..=2 {
        let n = request(mid, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(0),
                &mut app,
                &AllowAll,
            )
            .unwrap();
    }
    let first = endpoint.front_outgoing().unwrap().bytes.to_vec();
    let n = request(3, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(
        calls.get(),
        2,
        "reserve before dispatch when both packets are pinned"
    );
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, first);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let second = endpoint.front_outgoing().unwrap().bytes.to_vec();
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(2),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(calls.get(), 3);
    let n = request(1, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(3),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(endpoint.counters().dedup_reply_misses, 1);
    assert_eq!(endpoint.counters().dropped_messages, 1);
    assert_eq!(endpoint.counters().duplicates, 1);
    assert_eq!(
        calls.get(),
        3,
        "queued packets must not be reclaimed for a refusal"
    );
    while endpoint.front_outgoing().is_some() {
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    let n = request(1, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(3),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(calls.get(), 3);
    assert!(endpoint.front_outgoing().is_none());
    assert_eq!(endpoint.counters().dedup_reply_misses, 2);
    assert_eq!(endpoint.counters().duplicates, 2);
    assert_eq!(endpoint.counters().dropped_messages, 1);
    let n = request(2, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(3),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, second);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
}

#[test]
fn lost_reply_refusal_never_reclaims_another_cached_reply() {
    let shared = Shared::<128, 0>::new();
    let mut endpoint =
        Endpoint::<_, 128, 0, 8, 0, 2, 3, 0, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let calls = Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(&[calls.get()])?;
        Ok(Disposition::Complete)
    };
    let a = "192.0.2.1:5683".parse().unwrap();
    let b = "192.0.2.3:5683".parse().unwrap();
    let mut retained = Vec::new();
    let mut bytes = [0; 128];
    for (peer, mid) in [(a, 1), (a, 2), (b, 3)] {
        let n = request(mid, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(0),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        retained.push(endpoint.front_outgoing().unwrap().bytes.to_vec());
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    for _ in 0..2 {
        let n = request(1, &mut bytes);
        endpoint
            .receive(&bytes[..n], metadata(a, n), Instant(1), &mut app, &AllowAll)
            .unwrap();
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    }
    assert_eq!(endpoint.counters().dedup_reply_misses, 2);
    assert_eq!(endpoint.counters().duplicates, 2);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    for (peer, mid, original) in [(a, 2, &retained[1]), (b, 3, &retained[2])] {
        let n = request(mid, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(1),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    assert_eq!(calls.get(), 3);
    assert_eq!(endpoint.counters().duplicates, 4);
}

#[test]
fn lost_reply_refusal_expires_cached_replies_without_an_intervening_poll() {
    let shared = Shared::<128, 0>::new();
    let mut endpoint =
        Endpoint::<_, 128, 0, 8, 0, 2, 3, 0, 0, 0, 2>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let calls = Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(&[calls.get()])?;
        Ok(Disposition::Complete)
    };
    let a = "192.0.2.1:5683".parse().unwrap();
    let b = "192.0.2.3:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let mut latest = Vec::new();
    // Same-peer reclamation drops A's newer reply while B's older reply stays cached.
    for (peer, mid, now) in [(b, 1, 0), (a, 2, 1000), (a, 3, 2000)] {
        let n = request(mid, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(now),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        latest = endpoint.front_outgoing().unwrap().bytes.to_vec();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    let expired_at = mai_coap::messaging::TransmissionParameters::default().exchange_lifetime();
    let n = request(2, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(a, n),
            Instant(expired_at),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    let outgoing = endpoint
        .front_outgoing()
        .expect("B's expired reply frees a slot");
    let refusal = MessageView::parse(outgoing.bytes).unwrap();
    assert_eq!(refusal.code(), Code::UNAVAILABLE);
    assert_eq!(refusal.message_type(), MessageType::Acknowledgement);
    assert_eq!(refusal.message_id(), 2);
    assert_eq!(refusal.token(), &[1]);
    assert_eq!(refusal.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(0));
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    assert_eq!(endpoint.counters().dedup_reply_drops, 1);
    assert_eq!(endpoint.counters().dedup_record_evictions, 0);
    assert_eq!(endpoint.counters().dedup_reply_misses, 1);
    assert_eq!(endpoint.counters().duplicates, 1);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    let n = request(3, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(a, n),
            Instant(expired_at + 1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, latest);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    assert_eq!(calls.get(), 3);
}

#[test]
fn disabled_outbound_completes_promptly_and_cancellation_releases_packets() {
    let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let shared = Shared::<128, 1>::new();
    let mut endpoint =
        Endpoint::<_, 128, 0, 4, 0, 1, 2, 1, 0, 0, 1>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    let mut operation = pin!(
        shared
            .handle()
            .client(peer)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap()
    );
    endpoint.poll(Instant(0)).unwrap();
    assert_eq!(
        poll_once(operation.as_mut()).unwrap().unwrap_err(),
        Error::Capacity
    );

    let shared = Shared::<128, 1>::new();
    let mut endpoint =
        Endpoint::<_, 128, 1, 4, 0, 1, 2, 1, 0, 0, 1>::new(&shared, Unsecured(rand::rng()))
            .unwrap();
    for _ in 0..5 {
        let operation = shared
            .handle()
            .client(peer)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        assert!(endpoint.front_outgoing().is_some());
        drop(operation);
        endpoint.poll(Instant(0)).unwrap();
        assert!(
            endpoint.front_outgoing().is_none(),
            "cancelled unsent requests release queue ownership"
        );
    }
}

struct Protected(Unsecured<rand::rngs::ThreadRng>);
impl Protection for Protected {
    mai_coap::delegate_protection!(0, (); except [outgoing, received_response]);
    fn outgoing<const N: usize>(
        &mut self,
        _: Target,
        message: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<()>, Error> {
        let bytes = message.as_bytes();
        output[..bytes.len()].copy_from_slice(bytes);
        Ok(Prepared::Request {
            length: bytes.len(),
            binding: Some(()),
        })
    }
    fn received_response<const N: usize>(
        &mut self,
        _: MessageView<'_>,
        _: &mut (),
        _: &mut [u8],
    ) -> Result<usize, Error> {
        Err(Error::Protection)
    }
}

#[test]
fn unauthenticated_errors_complete_without_applying_peer_backoff_or_accepting_success() {
    let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4, 0, 1, 2, 1, 0, 0, 1>::new(
        &shared,
        Protected(Unsecured(rand::rng())),
    )
    .unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    for (offset, code) in [
        Code::BAD_REQUEST,
        Code::UNAUTHORIZED,
        Code::TOO_MANY_REQUESTS,
        Code::UNAVAILABLE,
    ]
    .into_iter()
    .enumerate()
    {
        let mut operation = pin!(
            shared
                .handle()
                .client(peer)
                .request(Code::GET, "/")
                .unwrap()
                .send()
                .unwrap()
        );
        endpoint.poll(Instant(offset as u64)).unwrap();
        let outgoing = endpoint.front_outgoing().unwrap();
        let request = MessageView::parse(outgoing.bytes).unwrap();
        let mut bytes = [0; 128];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            code,
            request.message_id(),
            request.token(),
        )
        .unwrap();
        b.uint_option(OptionNumber::MAX_AGE, u32::MAX.into())
            .unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(offset as u64),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        assert_eq!(
            poll_once(operation.as_mut()).unwrap().unwrap_err(),
            Error::UnprotectedResponse(code)
        );
    }
    assert_eq!(endpoint.counters().unprotected_responses, 4);
    assert_eq!(endpoint.counters().protection_failures, 0);
    let mut operation = pin!(
        shared
            .handle()
            .client(peer)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap()
    );
    endpoint.poll(Instant(10)).unwrap();
    let outgoing = endpoint.front_outgoing().unwrap();
    let request = MessageView::parse(outgoing.bytes).unwrap();
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(10),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert!(poll_once(operation.as_mut()).is_none());
    endpoint.poll(Instant(10000)).unwrap();
    assert!(
        endpoint.front_outgoing().is_none(),
        "matching ACK stops retransmission even when payload authentication fails"
    );
}

#[test]
fn retention_query_can_reenter_shared_without_a_live_critical_section_borrow() {
    struct Reentrant<'a> {
        inner: Unsecured<rand::rngs::ThreadRng>,
        shared: &'a Shared<128, 1>,
        calls: Cell<usize>,
    }
    impl Protection for Reentrant<'_> {
        mai_coap::delegate_protection!(inner, (); except [requires_request_retention]);
        fn requires_request_retention(&self, target: Target) -> bool {
            self.calls.set(self.calls.get() + 1);
            assert!(
                self.shared
                    .handle()
                    .client(target.remote)
                    .request(Code::GET, "/")
                    .unwrap()
                    .send()
                    .is_err()
            );
            false
        }
    }
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4, 0, 1, 2, 1, 0, 0, 1>::new(
        &shared,
        Reentrant {
            inner: Unsecured(rand::rng()),
            shared: &shared,
            calls: Cell::new(0),
        },
    )
    .unwrap();
    let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let operation = shared
        .handle()
        .client(peer)
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    assert_eq!(endpoint.protection_mut().calls.get(), 1);
    drop(operation);
    endpoint.poll(Instant(0)).unwrap();
}

#[test]
fn malformed_inner_request_releases_its_protection_binding() {
    struct MalformedInner {
        inner: Unsecured<rand::rngs::ThreadRng>,
        releases: usize,
    }
    impl Protection for MalformedInner {
        mai_coap::delegate_protection!(inner, (); except [incoming,release]);
        fn incoming<const N: usize>(
            &mut self,
            _: MessageView<'_>,
            _: Metadata,
            output: &mut [u8],
        ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
            output[0] = 0;
            Ok((1, mai_coap::security::SecurityState::Unprotected, Some(())))
        }
        fn release(&mut self, _: ()) {
            self.releases += 1;
        }
    }
    let shared = ServerShared::<128>::new();
    let mut endpoint = ServerEndpoint::new(
        &shared,
        MalformedInner {
            inner: Unsecured(rand::rng()),
            releases: 0,
        },
    )
    .unwrap();
    let peer = "192.0.2.1:5683".parse().unwrap();
    let mut bytes = [0; 128];
    let n = request(1, &mut bytes);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        panic!("malformed requests must not reach the application")
    };
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(endpoint.protection_mut().releases, 1);
    assert_eq!(endpoint.counters().dropped_messages, 1);
}

#[derive(Clone, Copy)]
enum Continuation {
    Handshake,
    Recovery,
}

struct RetainingProtection {
    inner: Unsecured<rand::rngs::ThreadRng>,
    continuation: Continuation,
    releases: Rc<Cell<usize>>,
}

impl Protection for RetainingProtection {
    mai_coap::delegate_protection!(inner, (); except [
        requires_request_retention,
        outgoing,
        handshake_response,
        recover,
        release
    ]);

    fn requires_request_retention(&self, _: Target) -> bool {
        true
    }

    fn outgoing<const N: usize>(
        &mut self,
        _: Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<()>, Error> {
        let bytes = request.as_bytes();
        output
            .get_mut(..bytes.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        Ok(match self.continuation {
            Continuation::Handshake => Prepared::Handshake {
                length: bytes.len(),
            },
            Continuation::Recovery => Prepared::Request {
                length: bytes.len(),
                binding: Some(()),
            },
        })
    }

    fn handshake_response<const N: usize>(
        &mut self,
        _: Target,
        _: MessageView<'_>,
        original: MessageView<'_>,
        _: Instant,
        output: &mut [u8],
    ) -> Result<Prepared<()>, Error> {
        let bytes = original.as_bytes();
        output
            .get_mut(..bytes.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        Ok(Prepared::Handshake {
            length: bytes.len(),
        })
    }

    fn recover<const N: usize>(
        &mut self,
        _: Target,
        original: MessageView<'_>,
        _: Instant,
        output: &mut [u8],
    ) -> Result<Prepared<()>, Error> {
        let bytes = original.as_bytes();
        output
            .get_mut(..bytes.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        Ok(Prepared::Request {
            length: bytes.len(),
            binding: Some(()),
        })
    }

    fn release(&mut self, _: ()) {
        self.releases.set(self.releases.get() + 1);
    }
}

fn assert_pool_pressure_continuation<const PACKETS: usize>(
    continuation: Continuation,
    piggybacked: bool,
    expect_unrelated: bool,
    peer: SocketAddr,
) {
    type TinyEndpoint<'a, const PACKETS: usize> =
        Endpoint<'a, RetainingProtection, 128, 1, 4, 0, 1, 2, 2, 0, 0, PACKETS>;
    let shared = Shared::<128, 2>::new();
    let releases = Rc::new(Cell::new(0));
    let mut endpoint = TinyEndpoint::<PACKETS>::new(
        &shared,
        RetainingProtection {
            inner: Unsecured(rand::rng()),
            continuation,
            releases: releases.clone(),
        },
    )
    .unwrap();
    let target = shared
        .handle()
        .client(peer)
        .peer(mai_coap::security::PeerId(1));
    let client = match continuation {
        Continuation::Handshake => target,
        Continuation::Recovery => target.recovery(true),
    };
    let mut operation = Box::pin(
        client
            .request(Code::GET, "/protected")
            .unwrap()
            .send()
            .unwrap(),
    );
    endpoint.poll(Instant(0)).unwrap();
    let (initial_mid, token) = {
        let outgoing = endpoint.front_outgoing().unwrap();
        let message = MessageView::parse(outgoing.bytes).unwrap();
        (message.message_id(), message.token().to_vec())
    };
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );

    let mut bytes = [0; 128];
    if !piggybacked {
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::EMPTY,
            initial_mid,
            &[],
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
            response.set_payload(b"queued unrelated reply")?;
            Ok(Disposition::Complete)
        };
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(0),
                &mut app,
                &AllowAll,
            )
            .unwrap();
    }
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.set_payload(b"queued unrelated reply")?;
        Ok(Disposition::Complete)
    };
    let n = request(70, &mut bytes);
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    let unrelated = endpoint
        .front_outgoing()
        .map(|outgoing| outgoing.bytes.to_vec());
    assert_eq!(unrelated.is_some(), expect_unrelated);
    assert_eq!(
        endpoint.counters().dropped_messages,
        u64::from(!expect_unrelated)
    );
    assert_eq!(endpoint.counters().dedup_reply_drops, 0);

    let code = match continuation {
        Continuation::Handshake => Code::CONTENT,
        Continuation::Recovery => Code::UNAUTHORIZED,
    };
    let (response_type, response_mid) = if piggybacked {
        (MessageType::Acknowledgement, initial_mid)
    } else {
        (MessageType::Confirmable, 71)
    };
    let n = MessageBuilder::new(&mut bytes, response_type, code, response_mid, &token)
        .unwrap()
        .finish(&[])
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            metadata(peer, n),
            Instant(2),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert!(poll_once(operation.as_mut()).is_none());
    if let Some(unrelated) = unrelated {
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, unrelated);
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    if !piggybacked {
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(2),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        let ack = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        assert_eq!(ack.message_type(), MessageType::Acknowledgement);
        assert_eq!(ack.code(), Code::EMPTY);
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
    }
    let continuation_packet = endpoint.front_outgoing().unwrap();
    let message = MessageView::parse(continuation_packet.bytes).unwrap();
    assert_eq!(message.code(), Code::GET);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    if matches!(continuation, Continuation::Recovery) {
        assert_eq!(releases.get(), 1, "old recovery binding released");
    }
    drop(operation);
    endpoint.poll(Instant(3)).unwrap();
    if matches!(continuation, Continuation::Recovery) {
        assert_eq!(releases.get(), 2, "continued binding released on cancel");
    }

    let fresh = shared
        .handle()
        .client(peer)
        .peer(mai_coap::security::PeerId(1))
        .request(Code::GET, "/fresh")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(3)).unwrap();
    assert!(
        endpoint.front_outgoing().is_some(),
        "pool slot leaked after failure"
    );
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    drop(fresh);
    endpoint.poll(Instant(3)).unwrap();
}

#[test]
fn full_packet_pool_retries_handshake_and_recovery_without_leaking_refs() {
    let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    for continuation in [Continuation::Handshake, Continuation::Recovery] {
        assert_pool_pressure_continuation::<2>(continuation, false, true, peer);
        assert_pool_pressure_continuation::<3>(continuation, true, true, peer);
        assert_pool_pressure_continuation::<2>(continuation, true, false, peer);
    }
}

#[test]
fn handshake_and_recovery_errors_complete_and_count_one_dropped_message() {
    struct Failing(RetainingProtection);
    impl Protection for Failing {
        mai_coap::delegate_protection!(0, (); except [handshake_response, recover]);
        fn handshake_response<const N: usize>(
            &mut self,
            _: Target,
            _: MessageView<'_>,
            _: MessageView<'_>,
            _: Instant,
            _: &mut [u8],
        ) -> Result<Prepared<()>, Error> {
            Err(Error::Edhoc)
        }
        fn recover<const N: usize>(
            &mut self,
            _: Target,
            _: MessageView<'_>,
            _: Instant,
            _: &mut [u8],
        ) -> Result<Prepared<()>, Error> {
            Err(Error::Edhoc)
        }
    }
    let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    for continuation in [Continuation::Handshake, Continuation::Recovery] {
        let shared = Shared::<128, 1>::new();
        let mut endpoint = Endpoint::<_, 128, 1, 4, 0, 1, 2, 1, 0, 0, 3>::new(
            &shared,
            Failing(RetainingProtection {
                inner: Unsecured(rand::rng()),
                continuation,
                releases: Rc::new(Cell::new(0)),
            }),
        )
        .unwrap();
        let mut operation = pin!(
            shared
                .handle()
                .client(peer)
                .request(Code::GET, "/protected")
                .unwrap()
                .send()
                .unwrap()
        );
        endpoint.poll(Instant(0)).unwrap();
        let request = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        let mut bytes = [0; 128];
        let code = match continuation {
            Continuation::Handshake => Code::CONTENT,
            Continuation::Recovery => Code::UNAUTHORIZED,
        };
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            code,
            request.message_id(),
            request.token(),
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        endpoint.complete_outgoing(
            endpoint
                .front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        endpoint
            .receive(
                &bytes[..n],
                metadata(peer, n),
                Instant(1),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        assert_eq!(
            poll_once(operation.as_mut()).unwrap().unwrap_err(),
            Error::Edhoc
        );
        endpoint.poll(Instant(2)).unwrap();
        assert_eq!(endpoint.counters().dropped_messages, 1);
        assert_eq!(endpoint.counters().protection_failures, 1);
        assert!(endpoint.front_outgoing().is_none());
    }
}

#[test]
fn router_driver_accepts_small_and_immediate_server_capacity_profiles() {
    use mai_coap::{
        endpoint::{SmallEndpoint, SmallShared},
        server::Router,
    };
    let network = support::Network::default();
    let policy = AllowAll;
    let mut router = Router::<1152, 0, 0, 0>::new(&policy);
    let mut socket = network.socket("192.0.2.1:5683");
    let shared = SmallShared::new();
    let mut endpoint = SmallEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    {
        let mut driver = pin!(router.run(&mut endpoint, &mut socket, &network));
        assert!(poll_once(driver.as_mut()).is_none());
    }
    let shared = ServerShared::<1152>::new();
    let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut driver = pin!(router.run(&mut endpoint, &mut socket, &network));
    assert!(poll_once(driver.as_mut()).is_none());
}

#[cfg(feature = "_xarxa")]
#[test]
fn backing_shortage_preserves_continuation_state_and_unacknowledged_responses() {
    use mai_coap::XarxaStorage;
    use xarxa::{Pool, StaticPool};
    struct Counting(RetainingProtection, Rc<Cell<usize>>);
    impl Protection for Counting {
        mai_coap::delegate_protection!(0, (); except [handshake_response, recover]);
        fn handshake_response<const N: usize>(
            &mut self,
            target: Target,
            response: MessageView<'_>,
            original: MessageView<'_>,
            now: Instant,
            output: &mut [u8],
        ) -> Result<Prepared<()>, Error> {
            self.1.set(self.1.get() + 1);
            self.0
                .handshake_response::<N>(target, response, original, now, output)
        }
        fn recover<const N: usize>(
            &mut self,
            target: Target,
            original: MessageView<'_>,
            now: Instant,
            output: &mut [u8],
        ) -> Result<Prepared<()>, Error> {
            self.1.set(self.1.get() + 1);
            self.0.recover::<N>(target, original, now, output)
        }
    }
    type TinyEndpoint<'a, S> = Endpoint<'a, Counting, 128, 1, 4, 0, 1, 2, 1, 0, 0, 4, S>;
    for continuation in [Continuation::Handshake, Continuation::Recovery] {
        for piggybacked in [false, true] {
            static NETWORK: StaticPool<128, 3> = StaticPool::new();
            let shared = Shared::<128, 1>::new();
            let calls = Rc::new(Cell::new(0));
            let releases = Rc::new(Cell::new(0));
            let storage = XarxaStorage::<_, 4>::new(|| NETWORK.alloc());
            let mut endpoint = TinyEndpoint::with_storage(
                &shared,
                Counting(
                    RetainingProtection {
                        inner: Unsecured(rand::rng()),
                        continuation,
                        releases: releases.clone(),
                    },
                    calls.clone(),
                ),
                storage,
            )
            .unwrap();
            let peer: SocketAddr = "192.0.2.1:5683".parse().unwrap();
            let target = Target::new(peer);
            let mut operation = Box::pin(
                shared
                    .handle()
                    .client(target)
                    .recovery(matches!(continuation, Continuation::Recovery))
                    .request(Code::GET, "/protected")
                    .unwrap()
                    .send()
                    .unwrap(),
            );
            endpoint.poll(Instant(0)).unwrap();
            let original_wire = endpoint.front_outgoing().unwrap().bytes.to_vec();
            let original = MessageView::parse(&original_wire).unwrap();
            let mut app =
                |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
            endpoint.complete_outgoing(
                endpoint
                    .front_outgoing()
                    .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
            );
            let mut bytes = [0; 128];
            if !piggybacked {
                let n = MessageBuilder::new(
                    &mut bytes,
                    MessageType::Acknowledgement,
                    Code::EMPTY,
                    original.message_id(),
                    &[],
                )
                .unwrap()
                .finish(&[])
                .unwrap();
                endpoint
                    .receive(
                        &bytes[..n],
                        metadata(peer, n),
                        Instant(1),
                        &mut app,
                        &AllowAll,
                    )
                    .unwrap();
            } else {
                endpoint.poll(Instant(4000)).unwrap();
                assert_eq!(endpoint.front_outgoing().unwrap().bytes, original_wire);
            }
            let mut held = Some(core::iter::from_fn(|| NETWORK.alloc()).collect::<Vec<_>>());
            let code = match continuation {
                Continuation::Handshake => Code::CONTENT,
                Continuation::Recovery => Code::UNAUTHORIZED,
            };
            let ty = if piggybacked {
                MessageType::Acknowledgement
            } else {
                MessageType::Confirmable
            };
            let mid = if piggybacked {
                original.message_id()
            } else {
                71
            };
            let n = MessageBuilder::new(&mut bytes, ty, code, mid, original.token())
                .unwrap()
                .finish(&[])
                .unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    metadata(peer, n),
                    Instant(4001),
                    &mut app,
                    &AllowAll,
                )
                .unwrap();
            assert!(poll_once(operation.as_mut()).is_none());
            assert_eq!(
                calls.get(),
                0,
                "protection state was consumed before reservation"
            );
            assert_eq!(releases.get(), 0, "old binding must remain pinned");
            if piggybacked {
                assert_eq!(endpoint.front_outgoing().unwrap().bytes, original_wire);
                endpoint.complete_outgoing(
                    endpoint
                        .front_outgoing()
                        .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
                );
                // The wire is now unique and reusable, despite the external pool
                // still being exhausted. No third backing buffer is required.
            } else {
                assert!(
                    endpoint.front_outgoing().is_none(),
                    "do not ACK a discarded continuation"
                );
                drop(held.take());
                endpoint
                    .receive(
                        &bytes[..n],
                        metadata(peer, n),
                        Instant(4002),
                        &mut app,
                        &AllowAll,
                    )
                    .unwrap();
                let ack = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
                assert_eq!(ack.message_type(), MessageType::Acknowledgement);
                assert_eq!(ack.code(), Code::EMPTY);
                endpoint.complete_outgoing(
                    endpoint
                        .front_outgoing()
                        .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
                );
            }
            if piggybacked {
                endpoint
                    .receive(
                        &bytes[..n],
                        metadata(peer, n),
                        Instant(4002),
                        &mut app,
                        &AllowAll,
                    )
                    .unwrap();
            }
            assert_eq!(calls.get(), 1);
            assert!(poll_once(operation.as_mut()).is_none());
            assert_eq!(
                MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                    .unwrap()
                    .code(),
                Code::GET
            );
            drop(held);
            drop(operation);
            endpoint.poll(Instant(4003)).unwrap();
            assert_eq!(
                releases.get(),
                if matches!(continuation, Continuation::Recovery) {
                    2
                } else {
                    0
                }
            );
            assert!(endpoint.front_outgoing().is_none());
            assert_eq!(
                core::iter::from_fn(|| NETWORK.alloc())
                    .collect::<Vec<_>>()
                    .len(),
                3
            );
        }
    }
}
