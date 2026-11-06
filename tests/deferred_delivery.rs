//! Deferred response completion milestones and detached delivery (REL-2, REL-7, API-7).
#![cfg(feature = "server")]

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{
        Disposition, Endpoint, Request, Response, ResponseOperation, ResponseWriter, RunError,
        Shared, Ticket, Unsecured,
    },
    security::AllowAll,
    time::Instant,
    transport::{DatagramSender, Metadata, SendOutcome},
};

const D: usize = 128;
type Driver<'a, const N: usize> =
    Endpoint<'a, Unsecured<rand::rngs::ThreadRng>, D, N, 8, 0, 2, 4, 1, 2, 0, 4>;

fn cx() -> Context<'static> {
    Context::from_waker(Waker::noop())
}
fn poll(operation: &mut ResponseOperation<'_, D, 1>) -> Poll<Result<(), Error>> {
    Pin::new(operation).poll(&mut cx())
}
fn metadata(n: usize) -> Metadata {
    Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    )
}
fn defer<const N: usize>(
    endpoint: &mut Driver<'_, N>,
    ty: MessageType,
    mid: u16,
    now: Instant,
) -> Ticket {
    defer_with_token(endpoint, ty, mid, b"t", now)
}
fn defer_with_token<const N: usize>(
    endpoint: &mut Driver<'_, N>,
    ty: MessageType,
    mid: u16,
    token: &[u8],
    now: Instant,
) -> Ticket {
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, ty, Code::GET, mid, token)
        .unwrap()
        .finish(&[])
        .unwrap();
    let mut ticket = None;
    endpoint
        .receive(
            &bytes[..n],
            metadata(n),
            now,
            &mut |request: Request<'_>, _: &mut ResponseWriter<'_, D>| {
                ticket = request.deferred_ticket();
                Ok(Disposition::Deferred)
            },
            &AllowAll,
        )
        .unwrap();
    if ty == MessageType::Confirmable {
        assert_eq!(
            MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                .unwrap()
                .code(),
            Code::EMPTY
        );
        endpoint.complete_outgoing(now);
    }
    ticket.unwrap()
}
fn signal<const N: usize>(endpoint: &mut Driver<'_, N>, ty: MessageType, mid: u16, now: Instant) {
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, ty, Code::EMPTY, mid, &[])
        .unwrap()
        .finish(&[])
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            metadata(n),
            now,
            &mut |_: Request<'_>, _: &mut ResponseWriter<'_, D>| panic!("ACK/RST dispatched"),
            &AllowAll,
        )
        .unwrap();
}
#[derive(Default)]
struct Sender {
    busy: bool,
    error: Option<bool>,
    sent: usize,
}
impl DatagramSender for Sender {
    type Error = bool;
    fn discard_send_error(error: &bool) -> bool {
        *error
    }
    fn poll_send(
        &mut self,
        _: core::net::SocketAddr,
        _: Option<core::net::IpAddr>,
        _: Option<u32>,
        _: &[u8],
        _: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, bool>> {
        Poll::Ready(if let Some(error) = self.error {
            Err(error)
        } else if self.busy {
            Ok(SendOutcome::RetryLater)
        } else {
            self.sent += 1;
            Ok(SendOutcome::Accepted)
        })
    }
}

#[test]
fn con_outcome_distinguishes_ack_reset_and_exhausted_retransmissions() {
    for outcome in [Ok(()), Err(Error::Reset), Err(Error::Timeout)] {
        let shared = Shared::<D, 1>::new();
        let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
        let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
        let mut operation = shared
            .handle()
            .respond_confirmed(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        assert!(poll(&mut operation).is_pending());
        let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
        let mid = MessageView::parse(&original).unwrap().message_id();
        endpoint.complete_outgoing(Instant(500));
        assert!(poll(&mut operation).is_pending());
        if outcome == Err(Error::Timeout) {
            for _ in 0..4 {
                let at = endpoint.deadline(Instant(500));
                endpoint.poll(at).unwrap();
                assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
                endpoint.complete_outgoing(at);
                assert!(poll(&mut operation).is_pending());
            }
            let at = endpoint.deadline(Instant(500));
            endpoint.poll(at).unwrap();
            assert!(endpoint.front_outgoing().is_none());
        } else {
            signal(
                &mut endpoint,
                MessageType::Acknowledgement,
                mid.wrapping_add(1),
                Instant(501),
            );
            assert!(poll(&mut operation).is_pending());
            signal(
                &mut endpoint,
                if outcome.is_ok() {
                    MessageType::Acknowledgement
                } else {
                    MessageType::Reset
                },
                mid,
                Instant(502),
            );
        }
        assert_eq!(poll(&mut operation), Poll::Ready(outcome));
        assert!(endpoint.front_outgoing().is_none());
        assert!(
            shared
                .handle()
                .respond_confirmed(ticket, &Response::new(Code::CONTENT))
                .is_ok()
        );
    }
}

#[test]
fn zero_exchange_non_waits_for_acceptance_and_reports_initial_send_failure() {
    for outcome in [
        Ok(()),
        Err(Error::LocalSendTimeout),
        Err(Error::LocalSendFailed),
    ] {
        let shared = Shared::<D, 1>::new();
        let mut endpoint = Driver::<0>::new(&shared, Unsecured(rand::rng())).unwrap();
        let ticket = defer(&mut endpoint, MessageType::NonConfirmable, 1, Instant(0));
        let mut operation = shared
            .handle()
            .respond_confirmed(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        assert!(poll(&mut operation).is_pending());
        let mut sender = Sender {
            busy: true,
            ..Default::default()
        };
        assert!(
            endpoint
                .poll_transmit(&mut sender, Instant(1), &mut cx())
                .is_pending()
        );
        assert!(poll(&mut operation).is_pending());
        if outcome == Err(Error::LocalSendTimeout) {
            endpoint.poll(Instant(1001)).unwrap();
            assert_eq!(sender.sent, 0);
        } else {
            sender.busy = false;
            sender.error = (outcome == Err(Error::LocalSendFailed)).then_some(true);
            assert!(matches!(
                endpoint.poll_transmit(&mut sender, Instant(2), &mut cx()),
                Poll::Ready(Ok(()))
            ));
        }
        assert_eq!(poll(&mut operation), Poll::Ready(outcome));
        assert!(endpoint.front_outgoing().is_none());
    }
}

#[test]
fn respond_hands_off_and_frees_the_command_slot_before_transport_acceptance() {
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        let shared = Shared::<D, 1>::new();
        let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
        let ticket = defer(&mut endpoint, ty, 1, Instant(0));
        let handle = shared.handle();
        let mut operation = handle
            .respond(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        assert!(poll(&mut operation).is_pending());
        endpoint.poll(Instant(1)).unwrap();
        assert_eq!(poll(&mut operation), Poll::Ready(Ok(())));
        assert!(endpoint.front_outgoing().is_some());

        // Reuse the slot without dropping the completed future or sending its packet.
        let next = handle
            .respond(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        drop(next);
        let mut sender = Sender {
            busy: true,
            ..Default::default()
        };
        assert!(
            endpoint
                .poll_transmit(&mut sender, Instant(1), &mut cx())
                .is_pending()
        );
        endpoint.poll(Instant(1001)).unwrap();
        assert_eq!(sender.sent, 0);
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.counters().local_send_timeouts, 1);
    }
}

#[test]
fn deferred_reply_uses_the_exact_request_token_and_reliability() {
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        for token in [&b""[..], b"t", b"12345678"] {
            let shared = Shared::<D, 1>::new();
            let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
            let ticket = defer_with_token(&mut endpoint, ty, 1, token, Instant(0));
            let mut operation = shared
                .handle()
                .respond(ticket, &Response::new(Code::CONTENT))
                .unwrap();
            endpoint.poll(Instant(1)).unwrap();
            assert_eq!(poll(&mut operation), Poll::Ready(Ok(())));
            let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
            assert_eq!(reply.message_type(), ty);
            assert_eq!(reply.token(), token);
            assert_eq!(reply.code(), Code::CONTENT);
        }
    }
}

#[test]
fn queue_handoff_and_dropping_waiters_do_not_cancel_committed_delivery() {
    for queued in [false, true] {
        let shared = Shared::<D, 1>::new();
        let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
        let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
        let handle = shared.handle();
        let mut operation = if queued {
            handle.respond(ticket, &Response::new(Code::CONTENT))
        } else {
            handle.respond_confirmed(ticket, &Response::new(Code::CONTENT))
        }
        .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        if queued {
            assert_eq!(poll(&mut operation), Poll::Ready(Ok(())));
        } else {
            assert!(poll(&mut operation).is_pending());
        }
        let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
        let mid = MessageView::parse(&original).unwrap().message_id();
        drop(operation);
        // Reuse the detached completion slot while the original response is live.
        let next_ticket = defer(&mut endpoint, MessageType::NonConfirmable, 2, Instant(1));
        let mut next = handle
            .respond_confirmed(next_ticket, &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        endpoint.complete_outgoing(Instant(2));
        signal(&mut endpoint, MessageType::Acknowledgement, mid, Instant(3));
        signal(&mut endpoint, MessageType::Acknowledgement, mid, Instant(3));
        signal(&mut endpoint, MessageType::Reset, mid, Instant(3));
        assert!(
            poll(&mut next).is_pending(),
            "old completion reached a reused slot"
        );
        endpoint.complete_outgoing(Instant(4));
        assert_eq!(poll(&mut next), Poll::Ready(Ok(())));
        assert!(endpoint.front_outgoing().is_none());
    }
}

#[test]
fn detached_con_still_retransmits_and_pre_handoff_cancellation_preserves_ticket() {
    let shared = Shared::<D, 1>::new();
    let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
    drop(
        shared
            .handle()
            .respond_confirmed(ticket, &Response::new(Code::CONTENT))
            .unwrap(),
    );
    endpoint.poll(Instant(1)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
    let operation = shared
        .handle()
        .respond_confirmed(ticket, &Response::new(Code::CONTENT))
        .unwrap();
    endpoint.poll(Instant(2)).unwrap();
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    endpoint.complete_outgoing(Instant(2));
    drop(operation);
    let at = endpoint.deadline(Instant(2));
    endpoint.poll(at).unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
    endpoint.poll(at.after(1000)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
    let mid = MessageView::parse(&original).unwrap().message_id();
    signal(
        &mut endpoint,
        MessageType::Acknowledgement,
        mid,
        at.after(1001),
    );
}

#[test]
fn local_retry_expiry_does_not_fail_an_accepted_con_and_fatal_send_allows_restart() {
    let shared = Shared::<D, 1>::new();
    let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
    let mut operation = shared
        .handle()
        .respond_confirmed(ticket, &Response::new(Code::CONTENT))
        .unwrap();
    endpoint.poll(Instant(1)).unwrap();
    let mid = MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
        .unwrap()
        .message_id();
    let mut sender = Sender {
        error: Some(false),
        ..Default::default()
    };
    assert!(matches!(
        endpoint.poll_transmit(&mut sender, Instant(1), &mut cx()),
        Poll::Ready(Err(RunError::Transport(false)))
    ));
    assert!(poll(&mut operation).is_pending());
    sender.error = None;
    assert!(matches!(
        endpoint.poll_transmit(&mut sender, Instant(2), &mut cx()),
        Poll::Ready(Ok(()))
    ));
    let at = endpoint.deadline(Instant(2));
    endpoint.poll(at).unwrap();
    endpoint.poll(at.after(1000)).unwrap();
    assert!(poll(&mut operation).is_pending());
    signal(
        &mut endpoint,
        MessageType::Acknowledgement,
        mid,
        at.after(1001),
    );
    assert_eq!(poll(&mut operation), Poll::Ready(Ok(())));
}

#[test]
fn con_initial_rejection_and_expiry_report_failure_and_release_waiter() {
    for reject in [false, true] {
        let shared = Shared::<D, 1>::new();
        let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
        let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
        let mut operation = shared
            .handle()
            .respond_confirmed(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(1)).unwrap();
        let expected = if reject {
            let mut sender = Sender {
                error: Some(true),
                ..Default::default()
            };
            assert!(matches!(
                endpoint.poll_transmit(&mut sender, Instant(1), &mut cx()),
                Poll::Ready(Ok(()))
            ));
            Error::LocalSendFailed
        } else {
            endpoint.poll(Instant(1001)).unwrap();
            Error::LocalSendTimeout
        };
        assert_eq!(poll(&mut operation), Poll::Ready(Err(expected)));
        assert!(endpoint.front_outgoing().is_none());
    }
}

#[test]
fn local_acceptance_preserves_con_waiter_and_matching_ack_wakes_it() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Count(AtomicUsize);
    impl std::task::Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let count = Arc::new(Count(AtomicUsize::new(0)));
    let waker = Waker::from(count.clone());
    let mut cx = Context::from_waker(&waker);
    let shared = Shared::<D, 1>::new();
    let mut endpoint = Driver::<1>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = defer(&mut endpoint, MessageType::Confirmable, 1, Instant(0));
    let mut operation = shared
        .handle()
        .respond_confirmed(ticket, &Response::new(Code::CONTENT))
        .unwrap();
    assert!(Pin::new(&mut operation).poll(&mut cx).is_pending());
    endpoint.poll(Instant(1)).unwrap();
    let mid = MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
        .unwrap()
        .message_id();
    endpoint.complete_outgoing(Instant(2));
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    signal(&mut endpoint, MessageType::Acknowledgement, mid, Instant(3));
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(Pin::new(&mut operation).poll(&mut cx), Poll::Ready(Ok(())));
}

#[cfg(feature = "client")]
#[test]
fn lost_ack_retries_the_same_response_and_client_acks_without_redelivery() {
    let server_shared = Shared::<D, 1>::new();
    let client_shared = Shared::<D, 1>::new();
    let mut server = Driver::<1>::new(&server_shared, Unsecured(rand::rng())).unwrap();
    let mut client = Driver::<1>::new(&client_shared, Unsecured(rand::rng())).unwrap();
    let mut request = client_shared
        .handle()
        .client("192.0.2.2:5683".parse::<core::net::SocketAddr>().unwrap())
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    client.poll(Instant(0)).unwrap();
    let wire = client.front_outgoing().unwrap().bytes.to_vec();
    let ticket = core::cell::Cell::new(None);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, D>| {
        ticket.set(request.deferred_ticket());
        Ok(Disposition::Deferred)
    };
    server
        .receive(&wire, metadata(wire.len()), Instant(0), &mut app, &AllowAll)
        .unwrap();
    client.complete_outgoing(Instant(0));
    let ack = server.front_outgoing().unwrap().bytes.to_vec();
    server.complete_outgoing(Instant(0));
    let peer = "192.0.2.2:5683".parse().unwrap();
    let local = "192.0.2.1".parse().unwrap();
    let mut no_requests =
        |_: Request<'_>, _: &mut ResponseWriter<'_, D>| panic!("response dispatched as request");
    client
        .receive(
            &ack,
            Metadata::new(peer, local, ack.len()),
            Instant(0),
            &mut no_requests,
            &AllowAll,
        )
        .unwrap();
    let mut response = server_shared
        .handle()
        .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
        .unwrap();
    server.poll(Instant(1)).unwrap();
    let original = server.front_outgoing().unwrap().bytes.to_vec();
    server.complete_outgoing(Instant(1));
    client
        .receive(
            &original,
            Metadata::new(peer, local, original.len()),
            Instant(1),
            &mut no_requests,
            &AllowAll,
        )
        .unwrap();
    let first_ack = client.front_outgoing().unwrap().bytes.to_vec();
    client.complete_outgoing(Instant(1)); // Lost on the link.
    assert!(matches!(
        Pin::new(&mut request).poll(&mut cx()),
        Poll::Ready(Ok(_))
    ));
    assert!(poll(&mut response).is_pending());
    let at = server.deadline(Instant(1));
    server.poll(at).unwrap();
    assert_eq!(server.front_outgoing().unwrap().bytes, original);
    server.complete_outgoing(at);
    client
        .receive(
            &original,
            Metadata::new(peer, local, original.len()),
            at,
            &mut no_requests,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(client.counters().duplicates, 1);
    assert_eq!(client.front_outgoing().unwrap().bytes, first_ack);
    client.complete_outgoing(at);
    server
        .receive(
            &first_ack,
            metadata(first_ack.len()),
            at,
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(poll(&mut response), Poll::Ready(Ok(())));
    assert!(server.front_outgoing().is_none());
}
