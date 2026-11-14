//! API-7/PRX-1: direct deferred handoff reserves protocol storage, not command slots.
#![cfg(feature = "proxy")]
mod support;

use core::{
    net::SocketAddr,
    task::{Context, Waker},
};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{
        Application, DeferredResponses, Disposition, Endpoint, Request, ResponseWriter, Shared,
        Ticket, Unsecured,
    },
    security::AllowAll,
    time::Instant,
    transport::Metadata,
};
use rand::{SeedableRng, rngs::StdRng};
use support::PopOutgoing;

const D: usize = 128;
type Driver<'a, const N: usize, const Q: usize, const P: usize> =
    Endpoint<'a, Unsecured<StdRng>, D, N, 8, 0, 2, Q, 1, 2, 0, P>;

#[derive(Default)]
struct Work {
    pending: std::collections::VecDeque<(Ticket, u8)>,
    enabled: bool,
    writes: usize,
    last: Option<Result<(), Error>>,
    retry: Option<Instant>,
    fail_write: bool,
    reported_length: Option<usize>,
}
impl Application<D> for Work {
    fn handle(
        &mut self,
        request: Request<'_>,
        _: &mut ResponseWriter<'_, D>,
    ) -> Result<Disposition, Code> {
        assert!(self.pending.len() < 2);
        self.pending.push_back((
            request.deferred_ticket().unwrap(),
            request.message.token()[0],
        ));
        Ok(Disposition::Deferred)
    }
    fn recognizes(&self, _: mai_coap::codec::OptionNumber) -> bool {
        false
    }
    fn deadline(&self) -> Option<Instant> {
        self.retry
    }
    fn poll_deferred(
        &mut self,
        now: Instant,
        _: &mut Context<'_>,
        sink: &mut dyn DeferredResponses<D>,
    ) {
        if !self.enabled {
            return;
        }
        let Some(&(ticket, byte)) = self.pending.front() else {
            return;
        };
        let result = sink.respond(ticket, &mut |bytes| {
            self.writes += 1;
            if self.fail_write {
                return Err(Error::Capacity);
            }
            let length =
                MessageBuilder::new(bytes, MessageType::NonConfirmable, Code::CONTENT, 0, &[])?
                    .finish(&[byte; 8])?;
            Ok(self.reported_length.unwrap_or(length))
        });
        self.last = Some(result);
        self.retry = (result == Err(Error::Capacity)).then(|| now.after(100));
        if result != Err(Error::Capacity) {
            self.pending.pop_front();
        }
    }
}
fn peer(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 5683))
}
fn admit<const N: usize, const Q: usize, const P: usize>(
    driver: &mut Driver<'_, N, Q, P>,
    app: &mut Work,
    remote: SocketAddr,
    mid: u16,
    token: u8,
) {
    let mut bytes = [0; D];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Confirmable,
        Code::GET,
        mid,
        &[token],
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    driver
        .receive(
            &bytes[..n],
            Metadata::new(remote, peer(2).ip(), n).with_interface(Some(7)),
            Instant(0),
            app,
            &AllowAll,
        )
        .unwrap();
}
fn resources<const N: usize, const Q: usize, const P: usize>(
    driver: &mut Driver<'_, N, Q, P>,
    app: &mut Work,
    now: u64,
) {
    driver
        .poll_resources(
            Instant(now),
            app,
            &AllowAll,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
}
fn ack<const N: usize, const Q: usize, const P: usize>(
    driver: &mut Driver<'_, N, Q, P>,
    app: &mut Work,
    remote: SocketAddr,
    mid: u16,
) {
    let mut bytes = [0; D];
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
    driver
        .receive(
            &bytes[..n],
            Metadata::new(remote, peer(2).ip(), n),
            Instant(1),
            app,
            &AllowAll,
        )
        .unwrap();
}

#[test]
fn direct_handoff_does_not_need_a_free_command_slot() {
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<2, 2, 4>::new(&shared, Unsecured(StdRng::seed_from_u64(1))).unwrap();
    let mut app = Work::default();
    admit(&mut driver, &mut app, peer(1), 1, b'a');
    driver.pop_outgoing().unwrap();
    let handle = shared.handle();
    let occupied = handle
        .client(peer(9))
        .request(Code::GET, "/other")
        .unwrap()
        .send()
        .unwrap();
    assert!(matches!(
        handle
            .client(peer(9))
            .request(Code::GET, "/full")
            .unwrap()
            .send(),
        Err(Error::Capacity)
    ));
    app.enabled = true;
    resources(&mut driver, &mut app, 0);
    assert_eq!(app.last, Some(Ok(())));
    assert_eq!(app.writes, 1);
    let outgoing = driver.pop_outgoing().unwrap();
    assert_eq!(outgoing.interface, Some(7));
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.message_type(), MessageType::Confirmable);
    assert_eq!(response.token(), b"a");
    assert_eq!(response.payload(), &[b'a'; 8]);
    drop(occupied);
}

#[test]
fn non_handoff_needs_no_outbound_exchange() {
    let shared = Shared::<D, 1>::new();
    let mut driver = Endpoint::<_, D, 0, 8, 0, 2, 2, 1, 2, 0, 2>::new(
        &shared,
        Unsecured(StdRng::seed_from_u64(9)),
    )
    .unwrap();
    let mut app = Work::default();
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, MessageType::NonConfirmable, Code::GET, 7, b"n")
        .unwrap()
        .finish(&[])
        .unwrap();
    driver
        .receive(
            &bytes[..n],
            Metadata::new(peer(1), peer(2).ip(), n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    app.enabled = true;
    driver
        .poll_resources(
            Instant(0),
            &mut app,
            &AllowAll,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
    assert_eq!(app.last, Some(Ok(())));
    let outgoing = driver.pop_outgoing().unwrap();
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.message_type(), MessageType::NonConfirmable);
    assert_eq!(response.token(), b"n");
    assert_eq!(response.payload(), &[b'n'; 8]);
    assert!(driver.front_outgoing().is_none());
}

#[test]
fn oversized_writer_length_is_rejected_without_consuming_the_ticket() {
    for length in [D + 1, usize::MAX] {
        let shared = Shared::<D, 1>::new();
        let mut driver =
            Driver::<2, 2, 4>::new(&shared, Unsecured(StdRng::seed_from_u64(10))).unwrap();
        let mut app = Work::default();
        admit(&mut driver, &mut app, peer(1), 1, b'a');
        driver.pop_outgoing().unwrap();
        let pending = *app.pending.front().unwrap();
        app.enabled = true;
        app.reported_length = Some(length);
        resources(&mut driver, &mut app, 0);
        assert_eq!(app.last, Some(Err(Error::Malformed)));
        assert!(driver.front_outgoing().is_none());
        app.pending.push_back(pending);
        app.reported_length = None;
        resources(&mut driver, &mut app, 0);
        assert_eq!(app.last, Some(Ok(())));
        let outgoing = driver.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .payload(),
            &[b'a'; 8]
        );
    }
}

#[test]
fn queue_pressure_leaves_writer_and_ticket_untouched() {
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<2, 1, 4>::new(&shared, Unsecured(StdRng::seed_from_u64(2))).unwrap();
    let mut app = Work::default();
    admit(&mut driver, &mut app, peer(1), 1, b'a');
    app.enabled = true;
    resources(&mut driver, &mut app, 0);
    assert_eq!(app.last, Some(Err(Error::Capacity)));
    assert_eq!(app.writes, 0);
    assert_eq!(app.pending.len(), 1);
    assert_eq!(app.deadline(), Some(Instant(100)));
    driver.pop_outgoing().unwrap();
    resources(&mut driver, &mut app, 1);
    assert_eq!(app.last, Some(Ok(())));
    assert_eq!(app.writes, 1);
}

fn pressure<const N: usize, const P: usize>(same_peer: bool) {
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<N, 4, P>::new(&shared, Unsecured(StdRng::seed_from_u64(3))).unwrap();
    let mut app = Work::default();
    let second_peer = if same_peer { peer(1) } else { peer(3) };
    admit(&mut driver, &mut app, peer(1), 1, b'a');
    driver.pop_outgoing().unwrap();
    admit(&mut driver, &mut app, second_peer, 2, b'b');
    driver.pop_outgoing().unwrap();
    app.enabled = true;
    resources(&mut driver, &mut app, 0);
    let first = driver.pop_outgoing().unwrap();
    let mid = MessageView::parse(first.packet.as_slice())
        .unwrap()
        .message_id();
    resources(&mut driver, &mut app, 0);
    assert_eq!(app.last, Some(Err(Error::Capacity)));
    assert_eq!(app.writes, 1);
    assert_eq!(app.pending.len(), 1);
    ack(&mut driver, &mut app, peer(1), mid);
    resources(&mut driver, &mut app, 1);
    assert_eq!(app.last, Some(Ok(())));
    assert_eq!(app.writes, 2);
    let second = driver.pop_outgoing().unwrap();
    assert_eq!(
        MessageView::parse(second.packet.as_slice())
            .unwrap()
            .payload(),
        &[b'b'; 8]
    );
    assert_eq!(second.remote, second_peer);
    assert_eq!(second.interface, Some(7));
}
#[test]
fn packet_pressure_recovers_after_the_accepted_response_is_acked() {
    pressure::<2, 1>(false);
}
#[test]
fn exchange_pressure_recovers_after_the_accepted_response_is_acked() {
    pressure::<1, 4>(false);
}
#[test]
fn nstart_pressure_recovers_after_the_accepted_response_is_acked() {
    pressure::<2, 4>(true);
}

#[test]
fn failed_writer_can_retry_the_same_ticket() {
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<2, 2, 2>::new(&shared, Unsecured(StdRng::seed_from_u64(4))).unwrap();
    let mut app = Work::default();
    admit(&mut driver, &mut app, peer(1), 1, b'a');
    driver.pop_outgoing().unwrap();
    app.enabled = true;
    app.fail_write = true;
    resources(&mut driver, &mut app, 0);
    assert_eq!(app.last, Some(Err(Error::Capacity)));
    assert!(driver.pop_outgoing().is_none());
    assert_eq!(app.pending.len(), 1);
    app.fail_write = false;
    resources(&mut driver, &mut app, 100);
    assert_eq!(app.last, Some(Ok(())));
    assert_eq!(app.writes, 2);
}

#[test]
fn duplicate_handoff_cannot_replace_the_stored_confirmable_response() {
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<2, 2, 4>::new(&shared, Unsecured(StdRng::seed_from_u64(5))).unwrap();
    let mut app = Work::default();
    admit(&mut driver, &mut app, peer(1), 1, b'a');
    driver.pop_outgoing().unwrap();
    let ticket = app.pending.front().unwrap().0;
    app.enabled = true;
    resources(&mut driver, &mut app, 0);
    let first = driver.pop_outgoing().unwrap();
    app.pending.push_back((ticket, b'x'));
    resources(&mut driver, &mut app, 0);
    assert_eq!(app.last, Some(Err(Error::Cancelled)));
    assert_eq!(app.writes, 1);
    assert!(driver.pop_outgoing().is_none());
    let retry_at = driver.deadline(Instant(0));
    driver.poll(retry_at).unwrap();
    let retry = driver.pop_outgoing().unwrap();
    assert_eq!(retry.packet.as_slice(), first.packet.as_slice());
    assert_eq!(retry.remote, first.remote);
    assert_eq!(retry.source, first.source);
    assert_eq!(retry.interface, first.interface);
}

#[test]
fn protection_capacity_failure_keeps_the_ticket_and_binding_for_retry() {
    use mai_coap::endpoint::Protection;
    struct Capacity {
        inner: Unsecured<StdRng>,
        fail: bool,
        releases: usize,
    }
    impl Protection for Capacity {
        mai_coap::delegate_protection!(inner, (); except [incoming, response, release]);
        fn incoming<const N: usize>(
            &mut self,
            request: MessageView<'_>,
            metadata: Metadata,
            output: &mut [u8],
        ) -> Result<(usize, mai_coap::security::SecurityState, Option<()>), Error> {
            let (length, security, _) = self.inner.incoming::<N>(request, metadata, output)?;
            Ok((length, security, Some(())))
        }
        fn response<const N: usize>(
            &mut self,
            message: MessageView<'_>,
            _: &mut (),
            output: &mut [u8],
        ) -> Result<usize, Error> {
            if self.fail {
                self.fail = false;
                return Err(Error::Capacity);
            }
            let bytes = message.as_bytes();
            output
                .get_mut(..bytes.len())
                .ok_or(Error::Capacity)?
                .copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn release(&mut self, _: ()) {
            self.releases += 1;
        }
    }
    let shared = Shared::<D, 1>::new();
    let mut driver = Endpoint::<_, D, 2, 8, 0, 2, 2, 1, 2, 0, 4>::new(
        &shared,
        Capacity {
            inner: Unsecured(StdRng::seed_from_u64(6)),
            fail: true,
            releases: 0,
        },
    )
    .unwrap();
    let mut app = Work::default();
    let mut bytes = [0; D];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a")
        .unwrap()
        .finish(&[])
        .unwrap();
    driver
        .receive(
            &bytes[..n],
            Metadata::new(peer(1), peer(2).ip(), n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    driver.pop_outgoing().unwrap();
    app.enabled = true;
    driver
        .poll_resources(
            Instant(0),
            &mut app,
            &AllowAll,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
    assert_eq!(app.last, Some(Err(Error::Capacity)));
    assert_eq!(app.pending.len(), 1);
    assert_eq!(driver.protection_mut().releases, 0);
    assert!(driver.pop_outgoing().is_none());
    driver
        .poll_resources(
            Instant(100),
            &mut app,
            &AllowAll,
            &mut Context::from_waker(Waker::noop()),
        )
        .unwrap();
    assert_eq!(app.last, Some(Ok(())));
    assert_eq!(app.writes, 2);
    let outgoing = driver.pop_outgoing().unwrap();
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
    driver
        .receive(
            &bytes[..n],
            Metadata::new(peer(1), peer(2).ip(), n),
            Instant(101),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(driver.protection_mut().releases, 1);
}

#[test]
fn router_forwards_the_deferred_hook_to_its_handler() {
    use mai_coap::{codec::OptionNumber, server::Router};
    let shared = Shared::<D, 1>::new();
    let mut driver = Driver::<2, 2, 4>::new(&shared, Unsecured(StdRng::seed_from_u64(7))).unwrap();
    let mut app = Work {
        enabled: true,
        ..Work::default()
    };
    {
        let mut router = Router::<D, 1>::new(&AllowAll);
        router.route("/x", &[Code::GET], &mut app).unwrap();
        let mut bytes = [0; D];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a").unwrap();
        builder.option(OptionNumber::URI_PATH, b"x").unwrap();
        let n = builder.finish(&[]).unwrap();
        driver
            .receive(
                &bytes[..n],
                Metadata::new(peer(1), peer(2).ip(), n),
                Instant(0),
                &mut router,
                &AllowAll,
            )
            .unwrap();
        driver.pop_outgoing().unwrap();
        driver
            .poll_resources(
                Instant(0),
                &mut router,
                &AllowAll,
                &mut Context::from_waker(Waker::noop()),
            )
            .unwrap();
        let response = driver.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(response.packet.as_slice())
                .unwrap()
                .payload(),
            &[b'a'; 8]
        );
    }
    assert_eq!(app.writes, 1);
    assert_eq!(app.last, Some(Ok(())));
}
