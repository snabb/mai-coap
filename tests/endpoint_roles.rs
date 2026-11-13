//! REL-3/REL-6 and PRX-1 role restrictions retain message-layer reliability.
#![cfg(all(feature = "server", feature = "client"))]
mod support;

use core::{cell::Cell, net::SocketAddr};
use futures_lite::future::{block_on, poll_once};
use mai_coap::{
    Error, InlineStorage,
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured, role},
    security::{AllowAll, ProtectedOnly},
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

type Driver<'a, Mode> = Endpoint<
    'a,
    Unsecured<rand::rngs::ThreadRng>,
    128,
    2,
    4,
    0,
    1,
    2,
    2,
    2,
    0,
    4,
    InlineStorage<128, 4>,
    Mode,
>;
type Client<'a> = Endpoint<
    'a,
    Unsecured<rand::rngs::ThreadRng>,
    128,
    2,
    4,
    0,
    0,
    2,
    2,
    0,
    0,
    4,
    InlineStorage<128, 4>,
    role::Client,
>;

fn metadata(n: usize) -> Metadata {
    Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    )
    .with_interface(Some(7))
}

#[test]
fn server_rejects_client_commands_and_keeps_confirmed_deferred_responses() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint =
        Driver::<role::Server>::new_with_role(&shared, Unsecured(rand::rng())).unwrap();
    let operation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    assert_eq!(
        block_on(poll_once(operation))
            .expect("disabled command must complete in this poll")
            .unwrap_err(),
        Error::RoleDisabled,
    );
    assert!(endpoint.pop_outgoing().is_none());

    let ticket = Cell::new(None);
    let calls = Cell::new(0);
    let mut app = |request: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        ticket.set(request.deferred_ticket());
        Ok(Disposition::Deferred)
    };
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
        .unwrap()
        .finish(&[])
        .unwrap();
    for _ in 0..2 {
        endpoint
            .receive(&bytes[..n], metadata(n), Instant(0), &mut app, &AllowAll)
            .unwrap();
        assert_eq!(
            endpoint.pop_outgoing().unwrap().packet.as_slice(),
            &[0x60, 0, 0, 1]
        );
    }
    assert_eq!(calls.get(), 1);
    let mut response = Response::<128>::new(Code::CONTENT);
    response.set_payload(b"deferred").unwrap();
    let mut operation = core::pin::pin!(
        shared
            .handle()
            .respond_confirmed(ticket.get().unwrap(), &response)
            .unwrap()
    );
    endpoint.poll(Instant(0)).unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let reply = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(reply.message_type(), MessageType::Confirmable);
    assert_eq!(reply.payload(), b"deferred");
    assert!(block_on(poll_once(operation.as_mut())).is_none());
    // RFC 7252 5.2.2: a matching response ACK ends retransmission regardless
    // of a response code or payload supplied by the peer.
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CHANGED,
        reply.message_id(),
        b"other",
    )
    .unwrap()
    .finish(b"ignored")
    .unwrap();
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(1), &mut app, &AllowAll)
        .unwrap();
    block_on(poll_once(operation))
        .expect("matching ACK must finish the response")
        .unwrap();
    endpoint.poll(Instant(300_000)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
}

#[test]
fn client_rejects_requests_but_keeps_ping_and_unmatched_response_controls() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Client::new_with_role(&shared, Unsecured(rand::rng())).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        panic!("client role must not serve requests")
    };
    let mut bytes = [0; 128];
    for (index, (ty, code, reset)) in [
        (MessageType::Confirmable, Code::GET, true),
        (MessageType::NonConfirmable, Code::GET, false),
        (MessageType::Confirmable, Code::EMPTY, true),
        (MessageType::Acknowledgement, Code::EMPTY, false),
        (MessageType::Reset, Code::EMPTY, false),
        (MessageType::Confirmable, Code::CONTENT, true),
    ]
    .into_iter()
    .enumerate()
    {
        let mid = 77 + index as u16;
        let n = MessageBuilder::new(&mut bytes, ty, code, mid, &[])
            .unwrap()
            .finish(&[])
            .unwrap();
        endpoint
            .receive(
                &bytes[..n],
                metadata(n),
                Instant(0),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        if reset {
            let outgoing = endpoint.pop_outgoing().unwrap();
            assert_eq!(outgoing.packet.as_slice(), &[0x70, 0, 0, mid as u8]);
            assert_eq!(outgoing.interface, Some(7));
        } else {
            assert!(endpoint.pop_outgoing().is_none());
        }
    }
    assert_eq!(endpoint.counters().duplicates, 0);
}

#[test]
fn client_repeats_cached_reset_for_a_rejected_request() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Client::new_with_role(&shared, Unsecured(rand::rng())).unwrap();
    let mut app =
        |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| panic!("client role served a request");
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 33, b"x")
        .unwrap()
        .finish(&[])
        .unwrap();
    for now in [0, 1] {
        endpoint
            .receive(
                &bytes[..n],
                metadata(n),
                Instant(now),
                &mut app,
                &ProtectedOnly,
            )
            .unwrap();
        assert_eq!(
            endpoint.pop_outgoing().unwrap().packet.as_slice(),
            &[0x70, 0, 0, 33]
        );
    }
    assert_eq!(endpoint.counters().duplicates, 1);
}

#[test]
fn client_without_full_reply_cache_repeats_ack_after_operation_completion() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Client::new_with_role(&shared, Unsecured(rand::rng())).unwrap();
    let operation = shared
        .handle()
        .client("192.0.2.1:5683".parse::<SocketAddr>().unwrap())
        .request(Code::GET, "/x")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let request = endpoint.pop_outgoing().unwrap();
    let request = MessageView::parse(request.packet.as_slice()).unwrap();
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Confirmable,
        Code::CONTENT,
        91,
        request.token(),
    )
    .unwrap()
    .finish(b"origin")
    .unwrap();
    let mut app =
        |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| panic!("unexpected resource dispatch");
    endpoint
        .receive(
            &bytes[..n],
            metadata(n),
            Instant(0),
            &mut app,
            &ProtectedOnly,
        )
        .unwrap();
    assert_eq!(
        block_on(poll_once(operation))
            .expect("response must complete this poll")
            .unwrap()
            .message()
            .unwrap()
            .payload(),
        b"origin"
    );
    let first = endpoint.pop_outgoing().unwrap();
    assert_eq!(first.packet.as_slice(), &[0x60, 0, 0, 91]);
    endpoint
        .receive(
            &bytes[..n],
            metadata(n),
            Instant(1),
            &mut app,
            &ProtectedOnly,
        )
        .unwrap();
    let duplicate = endpoint.pop_outgoing().unwrap();
    assert_eq!(duplicate.packet, first.packet);
    assert_eq!(endpoint.counters().duplicates, 1);
}

#[test]
fn role_markers_do_not_add_endpoint_storage() {
    assert_eq!(
        core::mem::size_of::<Driver<'_, role::Combined>>(),
        core::mem::size_of::<Driver<'_, role::Server>>()
    );
    assert_eq!(
        core::mem::size_of::<Driver<'_, role::Combined>>(),
        core::mem::size_of::<Driver<'_, role::Client>>()
    );
    assert_eq!(core::mem::size_of::<role::Server>(), 0);
    assert_eq!(core::mem::size_of::<role::Client>(), 0);
}

#[test]
fn driver_keeps_send_futures_and_accepts_local_applications() {
    use core::{
        future::Future,
        task::{Context, Poll},
    };
    use mai_coap::{
        time::Clock,
        transport::{Datagram, SendOutcome, Transport},
    };
    use rand::SeedableRng;
    #[derive(Clone, Copy)]
    struct Socket;
    impl Transport for Socket {
        type Error = core::convert::Infallible;
        type Receiver<'a> = Self;
        type Sender<'a> = Self;
        fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
            (*self, *self)
        }
    }
    impl mai_coap::transport::DatagramReceiver for Socket {
        type Error = core::convert::Infallible;
        type Packet<'a>
            = Datagram<'a>
        where
            Self: 'a;
        async fn receive<'a>(&'a mut self, _: &'a mut [u8]) -> Result<Datagram<'a>, Self::Error> {
            core::future::pending().await
        }
    }
    impl mai_coap::transport::DatagramSender for Socket {
        type Error = core::convert::Infallible;
        fn poll_send(
            &mut self,
            _: SocketAddr,
            _: Option<core::net::IpAddr>,
            _: Option<u32>,
            _: &[u8],
            _: &mut Context<'_>,
        ) -> Poll<Result<SendOutcome, Self::Error>> {
            Poll::Pending
        }
    }
    struct Timer;
    impl Clock for Timer {
        fn now(&self) -> Instant {
            Instant(0)
        }
        fn sleep_until(&self, _: Instant) -> impl Future<Output = ()> {
            core::future::pending()
        }
    }
    fn assert_send<T: Send>(_: T) {}
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4, 0, 1, 2, 2, 0, 0, 4>::new(
        &shared,
        Unsecured(rand::rngs::StdRng::seed_from_u64(1)),
    )
    .unwrap();
    let mut socket = Socket;
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    assert_send(endpoint.run(&mut socket, &Timer, &mut app, &AllowAll));
    let local = std::rc::Rc::new(Cell::new(0));
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        local.set(local.get() + 1);
        Ok(Disposition::Complete)
    };
    let _local_future = endpoint.run(&mut socket, &Timer, &mut app, &AllowAll);
}
