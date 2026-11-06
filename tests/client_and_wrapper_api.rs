//! Wrapper overrides, observable identities and complete client responses.
#![cfg(all(feature = "server", feature = "client"))]
mod support;
use futures_lite::future::{block_on, poll_once};
#[cfg(feature = "observe")]
use mai_coap::codec::MessageBuilder;
use mai_coap::{
    Error,
    codec::{Code, MessageType, MessageView, OptionNumber},
    endpoint::{
        Application, Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Target,
        Unsecured,
    },
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

#[test]
fn get_helpers_preserve_error_codes_options_and_diagnostics() {
    for configured in [false, true] {
        for code in [
            Code::CONTENT,
            Code::NOT_FOUND,
            Code::PRECONDITION_FAILED,
            Code::INTERNAL_ERROR,
        ] {
            let shared = Shared::<256, 2>::new();
            let handle = shared.handle();
            let mut endpoint =
                Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
            let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
            let mut get = core::pin::pin!(async {
                if configured {
                    handle.client(Target::new(remote)).get("/x").await
                } else {
                    handle.client(remote).get("/x").await
                }
            });
            assert!(block_on(poll_once(get.as_mut())).is_none());
            endpoint.poll(Instant(0)).unwrap();
            let outgoing = endpoint.pop_outgoing().unwrap();
            let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            let mut response = Response::<256>::new(code);
            response.set_payload(b"diagnostic").unwrap();
            response.uint_option(OptionNumber::MAX_AGE, 0).unwrap();
            let mut bytes = [0; 256];
            let n = response
                .encode(
                    &mut bytes,
                    MessageType::Acknowledgement,
                    request.message_id(),
                    request.token(),
                )
                .unwrap();
            let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
            endpoint
                .receive(
                    &bytes[..n],
                    Metadata::new(remote, "192.0.2.2".parse().unwrap(), n),
                    Instant(1),
                    &mut unused,
                    &PublicPaths(&[]),
                )
                .unwrap();
            let reply = block_on(poll_once(get.as_mut())).unwrap().unwrap();
            let message = reply.message().unwrap();
            assert_eq!(message.code(), code);
            assert_eq!(message.payload(), b"diagnostic");
            assert_eq!(
                message
                    .option(OptionNumber::MAX_AGE)
                    .unwrap()
                    .uint()
                    .unwrap(),
                0
            );
        }
        let shared = Shared::<128, 1>::new();
        let handle = shared.handle();
        let mut endpoint = Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut get = core::pin::pin!(async {
            let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
            if configured {
                handle.client(Target::new(remote)).get("/x").await
            } else {
                handle.client(remote).get("/x").await
            }
        });
        assert!(block_on(poll_once(get.as_mut())).is_none());
        endpoint.poll(Instant(0)).unwrap();
        endpoint.pop_outgoing().unwrap();
        endpoint.poll(Instant(u64::MAX - 1)).unwrap();
        assert_eq!(
            block_on(poll_once(get.as_mut())).unwrap().unwrap_err(),
            Error::Timeout
        );
    }
}

#[test]
fn target_constructor_preserves_defaults_and_allows_explicit_configuration() {
    let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let mut target = Target::new(remote);
    assert_eq!(target.remote, remote);
    assert_eq!(target.peer, None);
    assert!(target.combined_edhoc && target.recover);
    assert!(target.source.is_none() && target.interface.is_none());
    assert_eq!(target.parameters.ack_timeout_ms, 2000);
    target.peer = Some(mai_coap::security::PeerId(3));
    target.interface = Some(4);
    assert_eq!(target.peer, Some(mai_coap::security::PeerId(3)));
    assert_eq!(Target::from(remote).remote, remote);
}

#[test]
fn application_override_preserves_the_remaining_delegation_contract() {
    struct Inner {
        polls: usize,
        aborted: u64,
        #[cfg(feature = "proxy")]
        forwarded: usize,
    }
    impl Application<128> for Inner {
        fn handle(
            &mut self,
            _: Request<'_>,
            _: &mut ResponseWriter<'_, 128>,
        ) -> Result<Disposition, Code> {
            panic!("wrapper must override dispatch")
        }
        fn recognizes(&self, number: OptionNumber) -> bool {
            number.0 == 99
        }
        fn poll(&mut self, _: Instant, cx: &mut core::task::Context<'_>) {
            self.polls += 10;
            cx.waker().wake_by_ref();
        }
        fn deadline(&self) -> Option<Instant> {
            Some(Instant(5))
        }
        fn uses_context(&self, generation: u64) -> bool {
            generation == 7
        }
        fn abort_context(&mut self, generation: u64) {
            self.aborted = generation;
        }
    }
    struct Wrapper(Inner);
    impl Application<128> for Wrapper {
        mai_coap::delegate_application!(0, 128; except [handle, forward]);
        #[cfg(feature = "proxy")]
        fn forward(
            &mut self,
            _: Request<'_>,
            _: Instant,
            _: &mut ResponseWriter<'_, 128>,
        ) -> Option<Result<Disposition, Code>> {
            self.0.forwarded += 1;
            None
        }
        fn handle(
            &mut self,
            _request: Request<'_>,
            response: &mut ResponseWriter<'_, 128>,
        ) -> Result<Disposition, Code> {
            #[cfg(feature = "proxy")]
            assert!(self.forward(_request, Instant(0), response).is_none());
            response.set_payload(b"wrapped").unwrap();
            Ok(Disposition::Complete)
        }
    }
    struct Wake(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Wake {
        fn wake(self: std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let mut app = Wrapper(Inner {
        polls: 0,
        aborted: 0,
        #[cfg(feature = "proxy")]
        forwarded: 0,
    });
    assert!(app.recognizes(OptionNumber(99)));
    assert_eq!(app.deadline(), Some(Instant(5)));
    assert!(app.uses_context(7));
    app.abort_context(7);
    let wake = std::sync::Arc::new(Wake(std::sync::atomic::AtomicUsize::new(0)));
    let waker = core::task::Waker::from(wake.clone());
    app.poll(Instant(0), &mut core::task::Context::from_waker(&waker));
    assert_eq!((app.0.polls, app.0.aborted), (10, 7));
    assert_eq!(wake.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 2>::new(&shared, Unsecured(rand::rng())).unwrap();
    let bytes = [0x40, 1, 0, 1];
    endpoint
        .receive(
            &bytes,
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                bytes.len(),
            ),
            Instant(0),
            &mut app,
            &PublicPaths(&[(Code::GET, "/")]),
        )
        .unwrap();
    assert_eq!(
        MessageView::parse(endpoint.pop_outgoing().unwrap().packet.as_slice())
            .unwrap()
            .payload(),
        b"wrapped"
    );
    #[cfg(feature = "proxy")]
    assert_eq!(app.0.forwarded, 2);
}

#[cfg(feature = "observe")]
#[test]
fn router_rejects_duplicate_observable_ids_and_notifies_only_the_selected_route() {
    use mai_coap::{observe::Settings, server::Router};
    let policy = PublicPaths(&[(Code::GET, "/one"), (Code::GET, "/two")]);
    let mut one = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        response.set_payload(b"one").unwrap();
        Ok(Disposition::Complete)
    };
    let mut two = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        response.set_payload(b"two").unwrap();
        Ok(Disposition::Complete)
    };
    let mut router = Router::<256, 2>::new(&policy);
    router.route("/one", &[Code::GET], &mut one).unwrap();
    router.route("/two", &[Code::GET], &mut two).unwrap();
    let settings = Settings::new(1)
        .with_minimum_ms(0)
        .with_maximum_ms(60000)
        .with_confirmable_ms(60000);
    let one = Router::observable(&mut router, "/one", settings).unwrap();
    assert_eq!(
        Router::observable(&mut router, "/two", settings),
        Err(Error::Malformed)
    );
    struct Wrapper<A>(A);
    impl<A: Application<256>> Application<256> for Wrapper<A> {
        mai_coap::delegate_application!(0, 256; except [handle]);
        fn handle(
            &mut self,
            request: Request<'_>,
            response: &mut ResponseWriter<'_, 256>,
        ) -> Result<Disposition, Code> {
            self.0.handle(request, response)
        }
    }
    assert_eq!(
        Router::observable(&mut router, "/one", settings).unwrap(),
        one
    );
    let two = Router::observable(&mut router, "/two", Settings::new(2)).unwrap();
    assert_eq!(
        Router::observable(&mut router, "/two", settings),
        Err(Error::Malformed)
    );
    let mut router = Wrapper(router);
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (index, path) in ["/one", "/two"].into_iter().enumerate() {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            index as u16,
            &[index as u8],
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        mai_coap::uri::path_options(path, &mut b).unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    n,
                ),
                Instant(0),
                &mut router,
                &policy,
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_some());
    }
    for (index, resource) in [one, two].into_iter().enumerate() {
        shared.handle().notify(resource).unwrap();
        endpoint
            .poll_resources(
                Instant(index as u64 + 1),
                &mut router,
                &policy,
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let message = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(message.token(), &[index as u8]);
        assert!(endpoint.pop_outgoing().is_none());
    }
}

#[cfg(feature = "software-crypto")]
#[test]
fn protection_override_preserves_bindings_and_context_leases() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        endpoint::{Prepared, Protection},
        oscore::{Context, Oscore},
        security::PeerId,
    };
    struct Wrapper<P> {
        inner: P,
        calls: usize,
    }
    impl<P: Protection> Protection for Wrapper<P> {
        mai_coap::delegate_protection!(inner, P::Binding; except [outgoing, random]);
        fn outgoing<const N: usize>(
            &mut self,
            target: Target,
            request: MessageView<'_>,
            output: &mut [u8],
        ) -> Result<Prepared<Self::Binding>, Error> {
            self.calls += 1;
            self.inner.outgoing::<N>(target, request, output)
        }
        fn random(&mut self, bytes: &mut [u8]) {
            self.calls += 10;
            self.inner.random(bytes);
        }
    }
    let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let peer = PeerId(1);
    let mut inner = Oscore::<_, 1>::new(SoftwareCrypto::new(rand::rng()));
    let context = Context::derive(
        &mut SoftwareCrypto::new(rand::rng()),
        &[1; 16],
        None,
        &[0],
        &[1],
        None,
        peer,
    )
    .unwrap();
    inner.install_fresh(context).unwrap();
    let mut protection = Wrapper { inner, calls: 0 };
    let mut target = Target::new(remote);
    target.peer = Some(peer);
    let mut bytes = [0; 128];
    let Prepared::Request {
        binding: Some(binding),
        ..
    } = protection
        .outgoing::<128>(
            target,
            MessageView::parse(&[0x40, 1, 0, 1]).unwrap(),
            &mut bytes,
        )
        .unwrap()
    else {
        panic!("expected protected request");
    };
    let epoch = protection.generation(&binding).unwrap();
    protection.pin_epoch(epoch).unwrap();
    protection.release(binding);
    assert_eq!(protection.inner.forget_peer(peer), Err(Error::Capacity));
    protection.unpin_epoch(epoch);
    protection.inner.forget_peer(peer).unwrap();
    protection.random(&mut [0; 1]);
    assert_eq!(protection.calls, 11);
    assert_eq!(protection.context_evictions(), 0);
}
