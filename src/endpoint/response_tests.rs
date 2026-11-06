//! Shared-slot handoff and generation invariants (API-7, PLT-7).
use super::*;

#[test]
fn response_cleanup_classification_preserves_binding_and_security_state() {
    let secured = SecurityState::Protected {
        peer: crate::security::PeerId(7),
    };
    assert!(!protected_response(false, SecurityState::Unprotected));
    assert!(protected_response(true, SecurityState::Unprotected));
    assert!(protected_response(false, secured));
    assert!(protected_response(true, secured));
}

#[cfg(feature = "proxy")]
#[test]
fn local_dispatch_discards_declined_forward_probe_content() {
    struct Probe;
    impl Application<64> for Probe {
        fn handle(
            &mut self,
            _: Request<'_>,
            response: &mut ResponseWriter<'_, 64>,
        ) -> Result<Disposition, Code> {
            assert!(response.payload().is_empty());
            assert_eq!(response.code(), Code::CONTENT);
            response.set_payload(b"local")?;
            Ok(Disposition::Complete)
        }
        fn recognizes(&self, _: OptionNumber) -> bool {
            false
        }
        fn forward(
            &mut self,
            _: Request<'_>,
            _: Instant,
            response: &mut ResponseWriter<'_, 64>,
        ) -> Option<Result<Disposition, Code>> {
            response.set_code(Code::BAD_REQUEST);
            response.option(OptionNumber::ETAG, b"probe").unwrap();
            response.set_payload(b"discarded").unwrap();
            None
        }
    }
    let shared = ServerShared::<64>::new();
    let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut bytes = [0; 64];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut Probe,
            &crate::security::AllowAll,
        )
        .unwrap();
    let response = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(response.code(), Code::CONTENT);
    assert_eq!(response.payload(), b"local");
    assert!(response.option(OptionNumber::ETAG).is_none());
}

#[cfg(feature = "software-crypto")]
type TestCrypto = crate::crypto::SoftwareCrypto<rand::rngs::ThreadRng>;

#[cfg(feature = "software-crypto")]
fn oscore_pair() -> (
    crate::oscore::Context,
    TestCrypto,
    crate::oscore::Oscore<TestCrypto, 1>,
) {
    let mut client_crypto = TestCrypto::new(rand::rng());
    let mut server_crypto = TestCrypto::new(rand::rng());
    let client = crate::oscore::Context::derive(
        &mut client_crypto,
        &[1; 16],
        None,
        &[0],
        &[1],
        None,
        crate::security::PeerId(7),
    )
    .unwrap();
    let server = crate::oscore::Context::derive(
        &mut server_crypto,
        &[1; 16],
        None,
        &[1],
        &[0],
        None,
        crate::security::PeerId(7),
    )
    .unwrap();
    let mut table = crate::oscore::Oscore::new(server_crypto);
    table.install_fresh(server).unwrap();
    (client, client_crypto, table)
}

#[cfg(feature = "software-crypto")]
#[test]
fn endpoint_enables_cleanup_for_oscore_responses_but_not_plaintext() {
    for protected in [false, true] {
        let (mut client, mut crypto, server) = oscore_pair();
        let shared = ServerShared::<128>::new();
        let mut endpoint = ServerEndpoint::new(&shared, server).unwrap();
        let mut plain = [0; 128];
        let n = MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::GET, 1, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        let mut wire = [0; 128];
        let bytes = if protected {
            let (n, _) = client
                .protect_request::<128>(
                    &mut crypto,
                    MessageView::parse(&plain[..n]).unwrap(),
                    &mut wire,
                )
                .unwrap();
            &wire[..n]
        } else {
            &plain[..n]
        };
        let before = writer::wipe_events();
        endpoint
            .receive(
                bytes,
                Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    bytes.len(),
                ),
                Instant(0),
                &mut |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
                    response.set_payload(b"reply")?;
                    Ok(Disposition::Complete)
                },
                &crate::security::AllowAll,
            )
            .unwrap();
        assert_eq!(writer::wipe_events() - before, usize::from(protected));
        let response = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        assert_eq!(response.option(OptionNumber::OSCORE).is_some(), protected);
        assert_eq!(endpoint.counters().requests, 1);
    }
}

#[cfg(all(feature = "software-crypto", feature = "observe"))]
#[test]
fn endpoint_enables_cleanup_for_oscore_notifications() {
    let (mut client, mut crypto, server) = oscore_pair();
    let shared = ServerShared::<128>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4, 1, 2, 2, 0, 0, 0, 2>::new(&shared, server).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        response.set_payload(b"value")?;
        Ok(Disposition::Complete)
    };
    let mut router = crate::server::Router::<128, 1, 0, 0>::new(&crate::security::AllowAll);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    let resource =
        crate::server::Router::observable(&mut router, "/x", crate::observe::Settings::new(7))
            .unwrap();
    let mut plain = [0; 128];
    let mut builder =
        MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    builder.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = builder.finish(&[]).unwrap();
    let mut wire = [0; 128];
    let (n, _) = client
        .protect_request::<128>(
            &mut crypto,
            MessageView::parse(&plain[..n]).unwrap(),
            &mut wire,
        )
        .unwrap();
    let before = writer::wipe_events();
    endpoint
        .receive(
            &wire[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut router,
            &crate::security::AllowAll,
        )
        .unwrap();
    assert_eq!(writer::wipe_events() - before, 1);
    endpoint.complete_outgoing(Instant(0));
    let before = writer::wipe_events();
    shared.handle().notify(resource).unwrap();
    endpoint
        .poll_resources(
            Instant(1),
            &mut router,
            &crate::security::AllowAll,
            &mut TaskContext::from_waker(Waker::noop()),
        )
        .unwrap();
    assert_eq!(writer::wipe_events() - before, 1);
    let notification = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert!(notification.option(OptionNumber::OSCORE).is_some());
}

#[test]
fn cancellation_during_preparation_prevents_handoff_and_releases_the_slot() {
    let shared = Shared::<64, 1>::new();
    let operation = shared
        .handle()
        .respond_confirmed(Ticket(1), &Response::new(Code::CONTENT))
        .unwrap();
    let key = (operation.operation.index, operation.operation.generation);
    assert!(shared.claim(key.0, key.1).is_some());
    drop(operation);
    assert!(!shared.response_handoff(key, "192.0.2.1:5683".parse().unwrap(), 1, true, false));
    shared.complete(key.0, key.1, Err(Error::Cancelled));
    assert!(
        shared
            .handle()
            .respond_confirmed(Ticket(1), &Response::new(Code::CONTENT))
            .is_ok()
    );
}

#[test]
fn detachment_reuses_the_slot_without_old_delivery_completing_the_new_operation() {
    let shared = Shared::<64, 1>::new();
    let remote = "192.0.2.1:5683".parse().unwrap();
    let operation = shared
        .handle()
        .respond_confirmed(Ticket(1), &Response::new(Code::CONTENT))
        .unwrap();
    let old = (operation.operation.index, operation.operation.generation);
    shared.claim(old.0, old.1).unwrap();
    assert!(shared.response_handoff(old, remote, 1, true, false));
    drop(operation);
    let mut next = shared
        .handle()
        .respond_confirmed(Ticket(2), &Response::new(Code::CONTENT))
        .unwrap();
    let key = (next.operation.index, next.operation.generation);
    assert_ne!(old.1, key.1);
    shared.claim(key.0, key.1).unwrap();
    assert!(shared.response_handoff(key, remote, 2, false, false));
    shared.complete(old.0, old.1, Err(Error::Timeout));
    shared.complete_response(remote, 1, false, Ok(()));
    assert!(
        Pin::new(&mut next)
            .poll(&mut TaskContext::from_waker(Waker::noop()))
            .is_pending()
    );
    shared.complete_response(remote, 2, true, Ok(()));
    assert_eq!(
        Pin::new(&mut next).poll(&mut TaskContext::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    );
}

#[test]
fn cancellation_inside_response_encoding_restores_ticket_and_binding() {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };
    struct Cancel<F> {
        inner: Unsecured<rand::rngs::ThreadRng>,
        cancel: F,
        releases: Rc<Cell<usize>>,
    }
    impl<F: FnMut()> Protection for Cancel<F> {
        crate::delegate_protection!(inner, (); except [incoming, response, release]);
        fn incoming<const N: usize>(
            &mut self,
            message: MessageView<'_>,
            metadata: Metadata,
            output: &mut [u8],
        ) -> Result<(usize, crate::security::SecurityState, Option<()>), Error> {
            let (length, state, _) = self.inner.incoming::<N>(message, metadata, output)?;
            Ok((length, state, Some(())))
        }
        fn response<const N: usize>(
            &mut self,
            message: MessageView<'_>,
            binding: &mut (),
            output: &mut [u8],
        ) -> Result<usize, Error> {
            (self.cancel)();
            self.inner.response::<N>(message, binding, output)
        }
        fn release(&mut self, _: ()) {
            self.releases.set(self.releases.get() + 1);
        }
    }
    for ty in [MessageType::Confirmable, MessageType::NonConfirmable] {
        let shared = Shared::<64, 1>::new();
        let cancelled = RefCell::new(None);
        let releases = Rc::new(Cell::new(0));
        let mut endpoint = Endpoint::<_, 64, 1, 4, 0, 1, 2, 1, 1, 0, 2>::new(
            &shared,
            Cancel {
                inner: Unsecured(rand::rng()),
                cancel: || {
                    drop(cancelled.borrow_mut().take());
                },
                releases: releases.clone(),
            },
        )
        .unwrap();
        let mut bytes = [0; 64];
        let n = MessageBuilder::new(&mut bytes, ty, Code::GET, 1, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        let remote = "192.0.2.1:5683".parse().unwrap();
        let meta = Metadata::new(remote, "192.0.2.2".parse().unwrap(), n);
        let mut ticket = None;
        endpoint
            .receive(
                &bytes[..n],
                meta,
                Instant(0),
                &mut |request: Request<'_>, _: &mut ResponseWriter<'_, 64>| {
                    ticket = request.deferred_ticket();
                    Ok(Disposition::Deferred)
                },
                &crate::security::AllowAll,
            )
            .unwrap();
        if ty == MessageType::Confirmable {
            endpoint.complete_outgoing(Instant(0));
        }
        let ticket = ticket.unwrap();
        *cancelled.borrow_mut() = Some(
            shared
                .handle()
                .respond_confirmed(ticket, &Response::new(Code::CONTENT))
                .unwrap(),
        );
        endpoint.poll(Instant(1)).unwrap();
        assert!(cancelled.borrow().is_none());
        assert!(endpoint.front_outgoing().is_none());
        assert!(endpoint.exchanges.is_empty());
        assert_eq!(endpoint.pool.available(), 2);
        assert_eq!(
            releases.get(),
            0,
            "cancelled preparation must restore the binding to the ticket"
        );
        let mut retry = shared
            .handle()
            .respond_confirmed(ticket, &Response::new(Code::CONTENT))
            .unwrap();
        endpoint.poll(Instant(2)).unwrap();
        let mid = MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
            .unwrap()
            .message_id();
        endpoint.complete_outgoing(Instant(3));
        if ty == MessageType::Confirmable {
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
                    Metadata::new(remote, meta.local, n),
                    Instant(4),
                    &mut |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| panic!("ACK dispatched"),
                    &crate::security::AllowAll,
                )
                .unwrap();
        }
        assert_eq!(
            Pin::new(&mut retry).poll(&mut TaskContext::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        );
        assert_eq!(releases.get(), 1);
        assert_eq!(endpoint.pool.available(), 2);
    }
}

#[test]
fn control_response_capacity_is_unavailable_and_malformed_input_is_bad_request() {
    struct Control {
        inner: Unsecured<rand::rngs::ThreadRng>,
        malformed: bool,
    }
    impl Protection for Control {
        crate::delegate_protection!(inner, (); except [control]);
        fn control<const D: usize>(
            &mut self,
            _: Request<'_>,
            _: Instant,
            response: &mut ResponseWriter<'_, D>,
        ) -> Result<bool, Error> {
            response.set_code(Code::CHANGED);
            response.uint_option(
                OptionNumber::CONTENT_FORMAT,
                crate::codec::ContentFormat::EDHOC.0.into(),
            )?;
            if self.malformed {
                return Err(Error::Malformed);
            }
            // Fits an owned payload, but not the complete 16-byte response.
            response.set_payload(&[1, 2])?;
            Ok(true)
        }
    }
    for malformed in [false, true] {
        let shared = ServerShared::<16>::new();
        let mut endpoint = ServerEndpoint::<_, 16>::new(
            &shared,
            Control {
                inner: Unsecured(rand::rng()),
                malformed,
            },
        )
        .unwrap();
        let mut wire = [0; 16];
        let n = MessageBuilder::new(
            &mut wire,
            MessageType::Confirmable,
            Code::POST,
            1,
            b"token123",
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        endpoint
            .receive(
                &wire[..n],
                Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    n,
                ),
                Instant(0),
                &mut |_: Request<'_>,
                      _: &mut ResponseWriter<'_, 16>|
                 -> Result<Disposition, Code> {
                    panic!("control requests must not reach application dispatch")
                },
                &crate::security::PublicPaths(&[]),
            )
            .unwrap();
        let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
        assert_eq!(
            reply.code(),
            if malformed {
                Code::BAD_REQUEST
            } else {
                Code::UNAVAILABLE
            }
        );
        assert_eq!(reply.message_type(), MessageType::Acknowledgement);
        assert_eq!(reply.message_id(), 1);
        assert_eq!(reply.token(), b"token123");
        assert!(reply.options().next().is_none());
        assert!(reply.payload().is_empty());
    }
}

#[cfg(feature = "edhoc")]
#[test]
fn minimum_writer_returns_a_bare_error_when_edhoc_diagnostics_do_not_fit() {
    struct Reject {
        inner: Unsecured<rand::rngs::ThreadRng>,
    }
    impl Protection for Reject {
        crate::delegate_protection!(inner, (); except [incoming]);
        fn incoming<const D: usize>(
            &mut self,
            _: MessageView<'_>,
            _: Metadata,
            _: &mut [u8],
        ) -> Result<(usize, SecurityState, Option<()>), Error> {
            Err(Error::Edhoc)
        }
    }
    let shared = ServerShared::<16>::new();
    let mut endpoint = ServerEndpoint::<_, 16>::new(
        &shared,
        Reject {
            inner: Unsecured(rand::rng()),
        },
    )
    .unwrap();
    let mut wire = [0; 16];
    let mut builder = MessageBuilder::new(
        &mut wire,
        MessageType::Confirmable,
        Code::POST,
        1,
        b"token123",
    )
    .unwrap();
    builder.option(OptionNumber::EDHOC, &[]).unwrap();
    let n = builder.finish(&[]).unwrap();
    endpoint
        .receive(
            &wire[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut |_: Request<'_>, _: &mut ResponseWriter<'_, 16>| -> Result<Disposition, Code> {
                panic!("request must be refused")
            },
            &crate::security::PublicPaths(&[]),
        )
        .unwrap();
    let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(reply.code(), Code::INTERNAL_ERROR);
    assert_eq!(reply.token(), b"token123");
    assert!(reply.options().next().is_none());
    assert!(reply.payload().is_empty());
}
