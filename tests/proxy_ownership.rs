//! PRX-1/PRX-4: independent command bounds must not create a forwarding cycle.
#![cfg(feature = "proxy")]
mod support;

use core::{net::SocketAddr, task::Context};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Application, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    proxy::{ForwardProxy, Routing},
    security::ProtectedOnly,
    time::Instant,
    transport::Metadata,
};
use rand::{SeedableRng, rngs::StdRng};
use support::PopOutgoing;

type Node<'a> = Endpoint<'a, Unsecured<StdRng>, 256, 2, 8, 0, 2, 4, 1, 2, 0, 6>;

struct Route;
impl Routing for Route {
    fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
        true
    }
}

fn address(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 5683))
}

fn forward_request(token: u8) -> mai_coap::Packet<256> {
    forward_request_to(token, b"coap://192.0.2.9/x")
}

fn forward_request_to(token: u8, uri: &[u8]) -> mai_coap::Packet<256> {
    let mut bytes = [0; 256];
    let mut builder = MessageBuilder::new(
        &mut bytes,
        MessageType::Confirmable,
        Code::GET,
        u16::from(token),
        &[token],
    )
    .unwrap();
    builder.option(OptionNumber::PROXY_URI, uri).unwrap();
    let n = builder.finish(&[]).unwrap();
    mai_coap::Packet::copy_from(&bytes[..n]).unwrap()
}

fn origin_response(request: &mai_coap::Packet<256>, payload: &[u8]) -> mai_coap::Packet<256> {
    let request = MessageView::parse(request.as_slice()).unwrap();
    let mut bytes = [0; 256];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap()
    .finish(payload)
    .unwrap();
    mai_coap::Packet::copy_from(&bytes[..n]).unwrap()
}

#[test]
fn opposite_forwards_complete_with_one_command_slot_per_endpoint() {
    let shared_a = Shared::<256, 1>::new();
    let shared_b = Shared::<256, 1>::new();
    let mut a = Node::new(&shared_a, Unsecured(StdRng::seed_from_u64(1))).unwrap();
    let mut b = Node::new(&shared_b, Unsecured(StdRng::seed_from_u64(2))).unwrap();
    let local = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    let mut app_a = ForwardProxy::<_, _, 256, 1, 1>::with_outbound(
        local,
        Route,
        shared_a.handle(),
        shared_b.handle(),
    )
    .unwrap();
    let mut app_b = ForwardProxy::<_, _, 256, 1, 1>::with_outbound(
        local,
        Route,
        shared_b.handle(),
        shared_a.handle(),
    )
    .unwrap();
    for (endpoint, app, token, requester, interface) in [
        (&mut a, &mut app_a, b'a', address(1), 7),
        (&mut b, &mut app_b, b'b', address(2), 8),
    ] {
        let packet = forward_request(token);
        endpoint
            .receive(
                packet.as_slice(),
                Metadata::new(requester, address(3).ip(), packet.as_slice().len())
                    .with_interface(Some(interface)),
                Instant(0),
                app,
                &ProtectedOnly,
            )
            .unwrap();
        let ack = endpoint.pop_outgoing().unwrap();
        assert_eq!(ack.packet.as_slice(), &[0x60, 0, 0, token]);
    }
    a.poll(Instant(0)).unwrap();
    b.poll(Instant(0)).unwrap();
    let request_a = a.pop_outgoing().unwrap();
    let request_b = b.pop_outgoing().unwrap();
    assert_eq!(request_a.remote, address(9));
    assert_eq!(request_b.remote, address(9));
    // Each completed upstream operation owns the other endpoint's only command
    // slot. Holding it while waiting for a downstream slot would create a cycle.
    for (endpoint, app, request, payload) in [
        (&mut a, &mut app_a, &request_a, b"for-b"),
        (&mut b, &mut app_b, &request_b, b"for-a"),
    ] {
        let packet = origin_response(&request.packet, payload);
        endpoint
            .receive(
                packet.as_slice(),
                Metadata::new(address(9), address(3).ip(), packet.as_slice().len()),
                Instant(0),
                app,
                &ProtectedOnly,
            )
            .unwrap();
    }
    for _ in 0..4 {
        a.poll_resources(
            Instant(0),
            &mut app_a,
            &ProtectedOnly,
            &mut Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
        a.poll(Instant(0)).unwrap();
        b.poll_resources(
            Instant(0),
            &mut app_b,
            &ProtectedOnly,
            &mut Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
        b.poll(Instant(0)).unwrap();
    }
    for (endpoint, token, payload, requester, interface) in [
        (&mut a, b'a', b"for-a", address(1), 7),
        (&mut b, b'b', b"for-b", address(2), 8),
    ] {
        let outgoing = endpoint
            .pop_outgoing()
            .expect("forwarding cycle did not resolve");
        let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(response.code(), Code::CONTENT);
        assert_eq!(response.message_type(), MessageType::Confirmable);
        assert_eq!(response.token(), &[token]);
        assert_eq!(response.payload(), payload);
        assert_eq!(outgoing.remote, requester);
        assert_eq!(outgoing.interface, Some(interface));
    }
}

#[test]
fn expired_receiving_ticket_releases_a_retained_upstream_completion() {
    type Receiving<'a> = Endpoint<'a, Unsecured<StdRng>, 256, 2, 8, 0, 2, 1, 1, 2, 0, 6>;
    let incoming = Shared::<256, 1>::new();
    let outgoing = Shared::<256, 1>::new();
    let mut receiving = Receiving::new(&incoming, Unsecured(StdRng::seed_from_u64(3))).unwrap();
    let mut origin = Node::new(&outgoing, Unsecured(StdRng::seed_from_u64(4))).unwrap();
    let mut app = ForwardProxy::<_, _, 256, 1, 1>::with_outbound(
        |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND),
        Route,
        incoming.handle(),
        outgoing.handle(),
    )
    .unwrap();
    let request = forward_request(b'a');
    receiving
        .receive(
            request.as_slice(),
            Metadata::new(address(1), address(3).ip(), request.as_slice().len()),
            Instant(0),
            &mut app,
            &ProtectedOnly,
        )
        .unwrap();
    // Keep the Empty ACK queued, preventing the separate response from entering
    // this one-entry send queue after its upstream result becomes ready.
    origin.poll(Instant(0)).unwrap();
    let sent = origin.pop_outgoing().unwrap();
    let response = origin_response(&sent.packet, b"ready but blocked");
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    origin
        .receive(
            response.as_slice(),
            Metadata::new(address(9), address(3).ip(), response.as_slice().len()),
            Instant(0),
            &mut unused,
            &ProtectedOnly,
        )
        .unwrap();
    receiving
        .poll_resources(
            Instant(0),
            &mut app,
            &ProtectedOnly,
            &mut Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    let handle = outgoing.handle();
    assert!(matches!(
        handle
            .client(address(9))
            .request(Code::GET, "/full")
            .unwrap()
            .send(),
        Err(mai_coap::Error::Capacity)
    ));
    receiving.poll(Instant(1_000_000)).unwrap();
    receiving
        .poll_resources(
            Instant(1_000_000),
            &mut app,
            &ProtectedOnly,
            &mut Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    assert!(receiving.pop_outgoing().is_none());
    assert_eq!(app.deadline(), None);
    let next = handle
        .client(address(9))
        .request(Code::GET, "/reused")
        .unwrap()
        .send()
        .unwrap();
    receiving
        .poll_resources(
            Instant(1_000_001),
            &mut app,
            &ProtectedOnly,
            &mut Context::from_waker(core::task::Waker::noop()),
        )
        .unwrap();
    assert!(receiving.pop_outgoing().is_none());
    drop(next);
}

fn worker_replies_and_forwards<const COMMANDS: usize, const EXCHANGES: usize>(workers: usize) {
    use core::{future::Future, pin::Pin, task::Poll};
    use mai_coap::{
        Error, InlineStorage,
        endpoint::{Disposition, Response, Ticket, role},
        security::AllowAll,
    };
    #[derive(Default)]
    struct Workers(Vec<Ticket>);
    impl Application<256> for Workers {
        fn handle(
            &mut self,
            request: Request<'_>,
            _: &mut ResponseWriter<'_, 256>,
        ) -> Result<Disposition, Code> {
            assert!(self.0.len() < 2);
            self.0.push(request.deferred_ticket().unwrap());
            Ok(Disposition::Deferred)
        }
        fn recognizes(&self, _: OptionNumber) -> bool {
            false
        }
    }
    type Receiving<'a, const COMMANDS: usize, const EXCHANGES: usize> = Endpoint<
        'a,
        Unsecured<StdRng>,
        256,
        EXCHANGES,
        8,
        0,
        2,
        2,
        COMMANDS,
        EXCHANGES,
        0,
        6,
        InlineStorage<256, 6>,
        role::Server,
    >;
    type Upstream<'a> = Endpoint<
        'a,
        Unsecured<StdRng>,
        256,
        2,
        4,
        0,
        0,
        2,
        2,
        0,
        0,
        2,
        InlineStorage<256, 2>,
        role::Client,
    >;
    assert!(workers <= COMMANDS);
    let incoming = Shared::<256, COMMANDS>::new();
    let outgoing = Shared::<256, 2>::new();
    let mut receiving = Receiving::<COMMANDS, EXCHANGES>::new_with_role(
        &incoming,
        Unsecured(StdRng::seed_from_u64(21)),
    )
    .unwrap();
    let mut upstream =
        Upstream::new_with_role(&outgoing, Unsecured(StdRng::seed_from_u64(22))).unwrap();
    let mut app = ForwardProxy::<_, _, 256, COMMANDS, 2, 2>::with_outbound(
        Workers::default(),
        Route,
        incoming.handle(),
        outgoing.handle(),
    )
    .unwrap();
    let mut bytes = [0; 256];
    for (remote, token) in [(address(1), b'a'), (address(2), b'b')]
        .into_iter()
        .take(workers)
    {
        let n = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            u16::from(token),
            &[token],
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        receiving
            .receive(
                &bytes[..n],
                Metadata::new(remote, address(20).ip(), n),
                Instant(0),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        let ack = receiving.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(ack.packet.as_slice()).unwrap().code(),
            Code::EMPTY
        );
    }
    assert_eq!(app.inner_mut().0.len(), workers);
    for (remote, token, uri) in [
        (address(3), b'f', b"coap://192.0.2.9/f"),
        (address(4), b'g', b"coap://192.0.2.9/g"),
    ] {
        let request = forward_request_to(token, uri);
        receiving
            .receive(
                request.as_slice(),
                Metadata::new(remote, address(20).ip(), request.as_slice().len()),
                Instant(0),
                &mut app,
                &AllowAll,
            )
            .unwrap();
        let ack = receiving.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(ack.packet.as_slice()).unwrap().code(),
            Code::EMPTY
        );
    }
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    for _ in 0..2 {
        upstream.poll(Instant(0)).unwrap();
        let request = upstream
            .pop_outgoing()
            .expect("upstream NSTART must recover");
        let view = MessageView::parse(request.packet.as_slice()).unwrap();
        let path = view
            .options()
            .find(|option| option.number == OptionNumber::URI_PATH)
            .unwrap();
        let reply = origin_response(&request.packet, path.value);
        upstream
            .receive(
                reply.as_slice(),
                Metadata::new(address(9), address(20).ip(), reply.as_slice().len()),
                Instant(0),
                &mut unused,
                &AllowAll,
            )
            .unwrap();
    }
    let handle = incoming.handle();
    let mut response = Response::<256>::new(Code::CONTENT);
    response.set_payload(b"worker").unwrap();
    let tickets = app.inner_mut().0.clone();
    let mut deliveries: Vec<_> = tickets
        .iter()
        .map(|ticket| handle.respond(*ticket, &response).unwrap())
        .collect();
    if workers == COMMANDS {
        assert!(matches!(
            handle.respond(tickets[0], &response),
            Err(Error::Capacity)
        ));
    }
    let mut cx = Context::from_waker(core::task::Waker::noop());
    for operation in &mut deliveries {
        assert!(Pin::new(operation).poll(&mut cx).is_pending());
    }
    // Worker submissions occupy their command slots before either upstream result
    // is pulled. Forwarding must make progress with no extra receiving reservation.
    receiving
        .poll_resources(Instant(0), &mut app, &AllowAll, &mut cx)
        .unwrap();
    let mut forwards = Vec::new();
    for _ in 0..2 {
        let packet = receiving
            .pop_outgoing()
            .expect("forward needs no extra command slot");
        let reply = MessageView::parse(packet.packet.as_slice()).unwrap();
        assert_eq!(reply.message_type(), MessageType::Confirmable);
        assert_eq!(reply.code(), Code::CONTENT);
        forwards.push((
            packet.remote,
            reply.token().to_vec(),
            reply.payload().to_vec(),
        ));
    }
    forwards.sort_unstable();
    assert_eq!(
        forwards,
        [
            (address(3), vec![b'f'], vec![b'f']),
            (address(4), vec![b'g'], vec![b'g']),
        ]
    );
    for operation in &mut deliveries {
        assert!(Pin::new(operation).poll(&mut cx).is_pending());
    }
    receiving.poll(Instant(0)).unwrap();
    for operation in &mut deliveries {
        assert_eq!(Pin::new(operation).poll(&mut cx), Poll::Ready(Ok(())));
    }
    let mut worker_replies = Vec::new();
    for _ in 0..workers {
        let packet = receiving
            .pop_outgoing()
            .expect("worker reply must retain its command");
        let reply = MessageView::parse(packet.packet.as_slice()).unwrap();
        assert_eq!(reply.message_type(), MessageType::Confirmable);
        assert_eq!(reply.code(), Code::CONTENT);
        assert_eq!(reply.payload(), b"worker");
        worker_replies.push((packet.remote, reply.token()[0]));
    }
    worker_replies.sort_unstable();
    let expected: Vec<_> = [(address(1), b'a'), (address(2), b'b')]
        .into_iter()
        .take(workers)
        .collect();
    assert_eq!(worker_replies, expected);
    assert!(receiving.front_outgoing().is_none());
    let outbound = outgoing.handle();
    let first = outbound
        .client(address(9))
        .request(Code::GET, "/again")
        .unwrap()
        .send()
        .unwrap();
    let second = outbound
        .client(address(9))
        .request(Code::GET, "/again")
        .unwrap()
        .send()
        .unwrap();
    drop((first, second));
}

#[test]
fn two_worker_replies_and_two_forwards_share_two_receiving_commands() {
    worker_replies_and_forwards::<2, 4>(2);
}

#[test]
fn proxy_without_workers_needs_only_one_receiving_command() {
    worker_replies_and_forwards::<1, 2>(0);
}
