//! MID, send-queue and context pressure across requests and notifications (REL, OBS, OSC).
#![cfg(all(feature = "server", feature = "client", feature = "block1"))]
mod support;
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    security::PublicPaths,
    server::Router,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

fn meta(remote: &str, n: usize) -> Metadata {
    Metadata::new(remote.parse().unwrap(), "192.0.2.2".parse().unwrap(), n)
}

#[cfg(feature = "software-crypto")]
#[test]
fn osc_15_fresh_epoch_admission_reclaims_idle_contexts() {
    use mai_coap::{crypto::SoftwareCrypto, oscore::Context, oscore::Oscore, security::PeerId};
    let mut crypto = SoftwareCrypto::new(rand::rng());
    let mut table = Oscore::<_, 4>::new(SoftwareCrypto::new(rand::rng()));
    for i in 0..17u8 {
        let context =
            Context::derive(&mut crypto, &[i; 16], None, &[200], &[i], None, PeerId(1)).unwrap();
        let result = table.install_fresh(context);
        assert!(result.is_ok(), "install {i} failed: {result:?}");
    }
    assert_eq!(table.len(), 4);
    assert_eq!(table.evictions(), 13);
}

#[test]
fn rel_1_sparse_non_replies_continue_across_mid_rollover() {
    use mai_coap::rate::Limits;
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    endpoint
        .set_rate_limits(
            Limits::default()
                .with_per_source(1_000_000)
                .with_source_burst(1_000_000)
                .with_overall(1_000_000)
                .with_overall_burst(1_000_000),
        )
        .unwrap();
    let mut handler = |_: Request<'_>, r: &mut ResponseWriter<'_, 256>| {
        r.set_code(Code::CONTENT);
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.route("/x", &[Code::GET], &mut handler).unwrap();
    for i in 0..65537u32 {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::GET,
            i as u16,
            b"t",
        )
        .unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        let n = b.finish(&[]).unwrap();
        // 10 s apart: one request per 10 s, well below any rate limit.
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:5683", n),
                Instant(u64::from(i) * 10_000),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().expect("reply at every allocation");
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
            Code::CONTENT
        );
    }
    assert_eq!(endpoint.counters().dropped_messages, 0);
}

#[cfg(feature = "observe")]
#[test]
fn obs_4_simultaneously_due_observers_are_all_notified() {
    use mai_coap::observe::Settings;
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, r: &mut ResponseWriter<'_, 256>| {
        r.set_code(Code::CONTENT);
        r.set_payload(b"v").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/obs")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.route("/obs", &[Code::GET], &mut handler).unwrap();
    router
        .observable(
            "/obs",
            Settings::new(7)
                .with_minimum_ms(0)
                .with_maximum_ms(60_000)
                .with_confirmable_ms(86_400_000),
        )
        .unwrap();
    for (i, (remote, token)) in [("192.0.2.1:5683", b"a"), ("192.0.2.3:5683", b"b")]
        .iter()
        .enumerate()
    {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            i as u16,
            *token,
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.option(OptionNumber::URI_PATH, b"obs").unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(i as u64 + 1),
                &mut router,
                &policy,
            )
            .unwrap();
        while endpoint.pop_outgoing().is_some() {}
    }
    shared.handle().notify(7).unwrap();
    endpoint
        .poll_resources(
            Instant(10),
            &mut router,
            &policy,
            &mut core::task::Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    let mut to = Vec::new();
    while let Some(o) = endpoint.pop_outgoing() {
        to.push(o.remote);
    }
    assert_eq!(to.len(), 2);
}

#[test]
fn rel_1_mid_pressure_drops_one_reply_and_recovers_after_expiry() {
    use mai_coap::rate::Limits;
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    endpoint
        .set_rate_limits(
            Limits::default()
                .with_per_source(1_000_000)
                .with_source_burst(1_000_000)
                .with_overall(1_000_000)
                .with_overall_burst(1_000_000),
        )
        .unwrap();
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    for i in 0..65537u32 {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::GET,
            i as u16,
            b"t",
        )
        .unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:5683", n),
                Instant(0),
                &mut handler,
                &policy,
            )
            .unwrap();
        assert_eq!(endpoint.pop_outgoing().is_some(), i < 65536);
    }
    assert_eq!(endpoint.counters().dropped_messages, 1);
    let mut bytes = [0; 256];
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::NonConfirmable,
        Code::GET,
        500,
        b"t",
    )
    .unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("192.0.2.1:5683", n),
            Instant(248_000),
            &mut handler,
            &policy,
        )
        .unwrap();
    assert!(endpoint.pop_outgoing().is_some());
}

#[test]
fn rel_4_queue_pressure_preserves_due_retries_and_run_keeps_progressing() {
    use futures_lite::future::{block_on, poll_once};
    use mai_coap::messaging::TransmissionParameters;
    let shared = Shared::<256, 20>::new();
    let mut endpoint = Endpoint::<_, 256, 20, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let parameters = TransmissionParameters::default().with_ack_random_factor(1000);
    let mut bytes = [0; 256];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, b"")
        .unwrap()
        .finish(&[])
        .unwrap();
    let mut operations = Vec::new();
    let mut originals = Vec::new();
    for port in 1..=20 {
        let remote = core::net::SocketAddr::from(([192, 0, 2, 1], port));
        operations.push(
            shared
                .handle()
                .client(remote)
                .parameters(parameters)
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
        originals.push(endpoint.pop_outgoing().unwrap().packet);
    }
    let policy = PublicPaths(&[]);
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    for mid in 0..16u16 {
        let ping = [0x40, 0, 0, mid as u8];
        endpoint
            .receive(
                &ping,
                meta(&format!("192.0.2.{}:5683", mid + 10), 4),
                Instant(2000),
                &mut unused,
                &policy,
            )
            .unwrap();
    }
    endpoint.poll(Instant(2000)).unwrap();
    assert_eq!(endpoint.counters().retransmissions, 0);
    let network = support::Network::default();
    network.advance(2000);
    let mut socket = network.socket("192.0.2.2:5683");
    block_on(async {
        let driver = endpoint.run(&mut socket, &network, &mut unused, &policy);
        assert!(poll_once(core::pin::pin!(driver)).await.is_none());
    });
    let sent = network.sent();
    let retried: Vec<_> = sent
        .iter()
        .filter(|p| MessageView::parse(&p.bytes).unwrap().code() == Code::GET)
        .collect();
    assert_eq!(retried.len(), 20);
    for retry in retried {
        assert_eq!(
            retry.bytes,
            originals[usize::from(retry.to.port() - 1)].as_slice()
        );
    }
    assert_eq!(endpoint.counters().retransmissions, 20);
    drop(operations);
}

#[cfg(feature = "software-crypto")]
#[test]
fn osc_15_context_installation_does_not_create_a_destination_policy() {
    use mai_coap::{
        crypto::SoftwareCrypto,
        endpoint::{Prepared, Protection},
        oscore::{Context, Oscore},
        security::PeerId,
    };
    let remote = "192.0.2.1:5683".parse().unwrap();
    let mut crypto = SoftwareCrypto::new(rand::rng());
    let context =
        Context::derive(&mut crypto, &[8; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
    let mut protection = Oscore::<_, 1>::new(crypto);
    protection.install_fresh(context).unwrap();
    let mut request = [0; 256];
    let n = MessageBuilder::new(&mut request, MessageType::Confirmable, Code::GET, 0, b"x")
        .unwrap()
        .finish(&[])
        .unwrap();
    let message = MessageView::parse(&request[..n]).unwrap();
    assert!(matches!(
        protection.outgoing::<256>(
            mai_coap::endpoint::Target::new(remote),
            message,
            &mut [0; 256]
        ),
        Ok(Prepared::Request { binding: None, .. })
    ));
    let mut target = mai_coap::endpoint::Target::new(remote);
    target.peer = Some(PeerId(1));
    let prepared = protection
        .outgoing::<256>(target, message, &mut [0; 256])
        .unwrap();
    match prepared {
        Prepared::Request {
            binding: Some(binding),
            ..
        } => protection.release(binding),
        _ => panic!("an explicit peer must use its installed context"),
    }
    protection.forget_peer(PeerId(1)).unwrap();
    assert!(matches!(
        protection.outgoing::<256>(target, message, &mut [0; 256]),
        Err(Error::ContextNotFound)
    ));
}

#[cfg(feature = "observe")]
#[test]
fn obs_4_failed_notification_discards_partial_response() {
    use core::cell::Cell;
    use mai_coap::observe::Settings;
    for failure in [
        Err(Code::NOT_FOUND),
        Err(Code::GET),
        Ok(Disposition::Deferred),
    ] {
        let shared = Shared::<256, 1>::new();
        let mut endpoint =
            Endpoint::<_, 256, 1, 2, 1>::new(&shared, Unsecured(rand::rng())).unwrap();
        let calls = Cell::new(0);
        let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            response.option(OptionNumber::ETAG, b"tag").unwrap();
            response
                .uint_option(OptionNumber::CONTENT_FORMAT, 0)
                .unwrap();
            response.uint_option(OptionNumber::MAX_AGE, 10).unwrap();
            response.set_payload(b"partial representation").unwrap();
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(Disposition::Complete)
            } else {
                failure
            }
        };
        let policy = PublicPaths(&[(Code::GET, "/obs")]);
        let mut router = Router::<256, 1, 1, 32>::new(&policy);
        router.route("/obs", &[Code::GET], &mut handler).unwrap();
        router
            .observable(
                "/obs",
                Settings::new(7)
                    .with_minimum_ms(0)
                    .with_maximum_ms(60_000)
                    .with_confirmable_ms(86_400_000),
            )
            .unwrap();
        let mut bytes = [0; 256];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
        builder.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        builder.option(OptionNumber::URI_PATH, b"obs").unwrap();
        let n = builder.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:1", n),
                Instant(0),
                &mut router,
                &policy,
            )
            .unwrap();
        let initial = endpoint.pop_outgoing().unwrap();
        assert!(
            MessageView::parse(initial.packet.as_slice())
                .unwrap()
                .option(OptionNumber::OBSERVE)
                .is_some()
        );
        shared.handle().notify(7).unwrap();
        endpoint
            .poll_resources(
                Instant(1),
                &mut router,
                &policy,
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        let expected = match failure {
            Err(Code::GET) => Code::INTERNAL_ERROR,
            Err(code) => code,
            Ok(_) => Code::UNAVAILABLE,
        };
        assert_eq!(response.code(), expected);
        assert_eq!(response.options().count(), 0);
        assert!(response.payload().is_empty());
        shared.handle().notify(7).unwrap();
        endpoint
            .poll_resources(
                Instant(2),
                &mut router,
                &policy,
                &mut core::task::Context::from_waker(core::task::Waker::noop()),
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_none());
        assert_eq!(calls.get(), 2);
    }
}

#[cfg(feature = "observe")]
struct FailingResponses {
    inner: Unsecured<rand::rngs::ThreadRng>,
    failures: std::rc::Rc<core::cell::Cell<usize>>,
    releases: std::rc::Rc<core::cell::Cell<usize>>,
}

#[cfg(feature = "observe")]
impl mai_coap::endpoint::Protection for FailingResponses {
    type Binding = ();
    fn random(&mut self, bytes: &mut [u8]) {
        self.inner.random(bytes);
    }
    fn outgoing<const D: usize>(
        &mut self,
        target: mai_coap::endpoint::Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<mai_coap::endpoint::Prepared<()>, Error> {
        self.inner.outgoing::<D>(target, request, output)
    }
    fn incoming<const D: usize>(
        &mut self,
        request: MessageView<'_>,
        metadata: Metadata,
        output: &mut [u8],
    ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
        let (n, security, _) = self.inner.incoming::<D>(request, metadata, output)?;
        Ok((n, security, Some(())))
    }
    fn response<const D: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut (),
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if self.failures.get() != 0 {
            self.failures.set(self.failures.get() - 1);
            return Err(Error::SequenceExhausted);
        }
        self.inner.response::<D>(response, binding, output)
    }
    fn received_response<const D: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut (),
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.inner.received_response::<D>(response, binding, output)
    }
    fn release(&mut self, binding: ()) {
        self.releases.set(self.releases.get() + 1);
        self.inner.release(binding);
    }
    fn control<const D: usize>(
        &mut self,
        request: Request<'_>,
        now: Instant,
        response: &mut ResponseWriter<'_, D>,
    ) -> Result<bool, Error> {
        if request
            .message
            .values(OptionNumber::URI_PATH)
            .eq([b"control".as_slice()])
        {
            response.option(OptionNumber::ETAG, b"tag")?;
            response.uint_option(OptionNumber::CONTENT_FORMAT, 0)?;
            response.uint_option(OptionNumber::MAX_AGE, 10)?;
            response.set_payload(b"partial control response")?;
            return Err(Error::Capacity);
        }
        self.inner.control(request, now, response)
    }
}

#[cfg(feature = "observe")]
#[test]
fn failed_control_discards_partial_response_and_releases_binding() {
    use std::{cell::Cell, rc::Rc};
    let releases = Rc::new(Cell::new(0));
    let protection = FailingResponses {
        inner: Unsecured(rand::rng()),
        failures: Rc::new(Cell::new(0)),
        releases: releases.clone(),
    };
    let shared = Shared::<256, 1>::new();
    let mut endpoint = Endpoint::<_, 256, 1, 2>::new(&shared, protection).unwrap();
    let mut handler =
        |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| -> Result<Disposition, Code> {
            panic!("failed control must not reach the handler")
        };
    let mut bytes = [0; 256];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 1, b"t").unwrap();
    builder.option(OptionNumber::URI_PATH, b"control").unwrap();
    let n = builder.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("192.0.2.1:1", n),
            Instant(0),
            &mut handler,
            &PublicPaths(&[]),
        )
        .unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.code(), Code::UNAVAILABLE);
    assert_eq!(response.options().count(), 0);
    assert!(response.payload().is_empty());
    assert_eq!(releases.get(), 1);
}

#[cfg(feature = "observe")]
#[test]
fn obs_4_one_failed_notification_releases_its_binding_and_run_continues() {
    use futures_lite::future::{block_on, poll_once};
    use mai_coap::observe::Settings;
    use std::{cell::Cell, rc::Rc};
    let failures = Rc::new(Cell::new(0));
    let releases = Rc::new(Cell::new(0));
    let protection = FailingResponses {
        inner: Unsecured(rand::rng()),
        failures: failures.clone(),
        releases: releases.clone(),
    };
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 8>::new(&shared, protection).unwrap();
    let mut handler = |_: Request<'_>, r: &mut ResponseWriter<'_, 256>| {
        r.set_payload(b"live").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/obs")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.route("/obs", &[Code::GET], &mut handler).unwrap();
    router
        .observable(
            "/obs",
            Settings::new(7)
                .with_minimum_ms(0)
                .with_maximum_ms(60_000)
                .with_confirmable_ms(86_400_000),
        )
        .unwrap();
    for (i, remote) in ["192.0.2.1:5683", "192.0.2.3:5683"].into_iter().enumerate() {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            i as u16,
            b"t",
        )
        .unwrap();
        b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
        b.option(OptionNumber::URI_PATH, b"obs").unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(0),
                &mut router,
                &policy,
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
    }
    failures.set(1);
    shared.handle().notify(7).unwrap();
    let network = support::Network::default();
    network.advance(10);
    let mut socket = network.socket("192.0.2.2:5683");
    block_on(async {
        let mut driver = core::pin::pin!(endpoint.run(&mut socket, &network, &mut router, &policy));
        assert!(poll_once(driver.as_mut()).await.is_none());
        assert_eq!(network.sent().len(), 1);
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 9, b"new")
            .unwrap();
        b.option(OptionNumber::URI_PATH, b"obs").unwrap();
        let n = b.finish(&[]).unwrap();
        network.inject(
            "192.0.2.9:5683".parse().unwrap(),
            "192.0.2.2:5683".parse().unwrap(),
            &bytes[..n],
        );
        assert!(poll_once(driver.as_mut()).await.is_none());
        assert_eq!(network.sent().len(), 2);
    });
    assert_eq!(releases.get(), 2);
    assert_eq!(endpoint.counters().dropped_messages, 1);
    assert_eq!(endpoint.counters().protection_failures, 1);
}

fn exhaust_message_ids<const E: usize>(
    endpoint: &mut Endpoint<'_, Unsecured<rand::rngs::ThreadRng>, 256, E, 8>,
    count: usize,
    now: Instant,
) {
    endpoint
        .set_rate_limits(
            mai_coap::rate::Limits::default()
                .with_per_source(1_000_000)
                .with_source_burst(1_000_000)
                .with_overall(1_000_000)
                .with_overall_burst(1_000_000),
        )
        .unwrap();
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    for mid in 0..count {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::GET,
            mid as u16,
            b"x",
        )
        .unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        let n = b.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.99:5683", n),
                now,
                &mut app,
                &policy,
            )
            .unwrap();
        assert!(endpoint.pop_outgoing().is_some());
    }
}

#[cfg(feature = "observe")]
#[test]
fn obs_4_mid_pressure_preserves_observation_until_ids_are_reusable() {
    use mai_coap::observe::Settings;
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = |_: Request<'_>, r: &mut ResponseWriter<'_, 256>| {
        r.set_payload(b"live").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/obs")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.route("/obs", &[Code::GET], &mut app).unwrap();
    router
        .observable(
            "/obs",
            Settings::new(7)
                .with_minimum_ms(0)
                .with_maximum_ms(600_000)
                .with_confirmable_ms(86_400_000),
        )
        .unwrap();
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"obs").unwrap();
    b.uint_option(OptionNumber::OBSERVE, 0).unwrap();
    b.option(OptionNumber::URI_PATH, b"obs").unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("192.0.2.1:5683", n),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    endpoint.pop_outgoing().unwrap();
    exhaust_message_ids(&mut endpoint, 65536, Instant(0));
    shared.handle().notify(7).unwrap();
    endpoint
        .poll_resources(
            Instant(1),
            &mut router,
            &policy,
            &mut core::task::Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(endpoint.counters().dropped_messages, 0);
    assert_eq!(endpoint.deadline(Instant(1)), Instant(248_000));
    endpoint
        .poll_resources(
            Instant(248_000),
            &mut router,
            &policy,
            &mut core::task::Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    let outgoing = endpoint
        .pop_outgoing()
        .expect("observation resumes after MID quarantine");
    let message = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(message.payload(), b"live");
    assert!(message.option(OptionNumber::OBSERVE).is_some());
}

#[test]
fn rel_4_command_burst_waits_for_send_queue_space() {
    use futures_lite::future::{block_on, poll_once};
    use mai_coap::messaging::TransmissionParameters;
    let shared = Shared::<256, 20>::new();
    let mut endpoint = Endpoint::<_, 256, 20, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut bytes = [0; 256];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, b"")
        .unwrap()
        .finish(&[])
        .unwrap();
    let mut operations = Vec::new();
    for port in 1..=20 {
        operations.push(
            shared
                .handle()
                .client(core::net::SocketAddr::from(([192, 0, 2, 1], port)))
                .parameters(TransmissionParameters::default())
                .unwrap()
                .request_raw(&bytes[..n])
                .unwrap()
                .token_length(8)
                .unwrap()
                .wait_for_nstart(false)
                .send()
                .unwrap(),
        );
    }
    endpoint.poll(Instant(0)).unwrap();
    block_on(async {
        for operation in &mut operations {
            assert!(
                poll_once(operation).await.is_none(),
                "queue pressure must keep commands pending"
            );
        }
    });
    let network = support::Network::default();
    let mut socket = network.socket("192.0.2.2:5683");
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    block_on(async {
        let mut driver =
            core::pin::pin!(endpoint.run(&mut socket, &network, &mut unused, &PublicPaths(&[])));
        assert!(poll_once(driver.as_mut()).await.is_none());
    });
    assert_eq!(network.sent().len(), 20);
    assert_eq!(endpoint.counters().dropped_messages, 0);
}

#[test]
fn rel_1_srv_3_commands_wait_for_mid_reuse_without_losing_the_ticket() {
    use futures_lite::future::{block_on, poll_once};
    use mai_coap::messaging::TransmissionParameters;
    let shared = Shared::<256, 4>::new();
    let mut endpoint = Endpoint::<_, 256, 4, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let ticket = core::cell::Cell::new(None);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 256>| {
        ticket.set(Some(request.deferred_ticket().unwrap()));
        Ok(Disposition::Deferred)
    };
    exhaust_message_ids(&mut endpoint, 65535, Instant(0));
    let policy = PublicPaths(&[(Code::GET, "/x")]);
    let mut bytes = [0; 256];
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::NonConfirmable,
        Code::GET,
        0,
        b"defer",
    )
    .unwrap();
    b.option(OptionNumber::URI_PATH, b"x").unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            meta("192.0.2.1:5683", n),
            Instant(2000),
            &mut app,
            &policy,
        )
        .unwrap();
    exhaust_message_ids(&mut endpoint, 1, Instant(2000));
    let mut response = shared
        .handle()
        .respond_confirmed(ticket.get().unwrap(), &Response::new(Code::CONTENT))
        .unwrap();
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, b"")
        .unwrap()
        .finish(&[])
        .unwrap();
    let mut request = shared
        .handle()
        .client("192.0.2.3:5683".parse::<core::net::SocketAddr>().unwrap())
        .parameters(TransmissionParameters::default())
        .unwrap()
        .request_raw(&bytes[..n])
        .unwrap()
        .token_length(8)
        .unwrap()
        .wait_for_nstart(false)
        .send()
        .unwrap();
    endpoint.poll(Instant(2001)).unwrap();
    block_on(async {
        assert!(poll_once(&mut response).await.is_none());
        assert!(poll_once(&mut request).await.is_none());
    });
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(endpoint.deadline(Instant(2001)), Instant(248_000));
    endpoint.poll(Instant(248_000)).unwrap();
    assert!(block_on(poll_once(&mut response)).is_none());
    let mut codes = Vec::new();
    while let Some(outgoing) = endpoint.pop_outgoing() {
        codes.push(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
        );
    }
    codes.sort_by_key(|code| code.0);
    assert_eq!(codes, [Code::GET, Code::CONTENT]);
    assert_eq!(block_on(response), Ok(()));
    block_on(async {
        assert!(poll_once(&mut request).await.is_none());
    });
    assert_eq!(endpoint.counters().dropped_messages, 0);
}
