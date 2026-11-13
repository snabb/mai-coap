//! PRX-1: forwarding completion must resume the receiving endpoint driver.
#![cfg(feature = "proxy")]
mod support;

use core::{future::Future, pin::Pin, task::Context};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    proxy::{ForwardProxy, Routing},
    security::ProtectedOnly,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

struct Route;
impl Routing for Route {
    fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
        true
    }
}
struct Wake(AtomicUsize);
impl std::task::Wake for Wake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn drive_to_idle(mut driver: Pin<&mut impl Future>, wake: &Wake, cx: &mut Context<'_>) -> usize {
    let mut wakes = 0;
    for _ in 0..20 {
        wake.0.store(0, Ordering::SeqCst);
        assert!(driver.as_mut().poll(cx).is_pending());
        let count = wake.0.load(Ordering::SeqCst);
        wakes += count;
        if count == 0 {
            return wakes;
        }
    }
    panic!("drivers did not become idle within 20 wake-driven polls");
}

fn check<Incoming: mai_coap::endpoint::role::Role, Outgoing: mai_coap::endpoint::role::Role>(
    separate: bool,
) {
    let network = support::Network::default();
    let incoming = Shared::<256, 3>::new();
    let outgoing = Shared::<256, 3>::new();
    let mut inbound = Endpoint::<
        _,
        256,
        3,
        8,
        8,
        8,
        16,
        3,
        3,
        8,
        40,
        mai_coap::InlineStorage<256, 40>,
        Incoming,
    >::new_with_role(&incoming, Unsecured(rand::rng()))
    .unwrap();
    let mut outbound = Endpoint::<
        _,
        256,
        3,
        8,
        8,
        8,
        16,
        3,
        3,
        8,
        40,
        mai_coap::InlineStorage<256, 40>,
        Outgoing,
    >::new_with_role(&outgoing, Unsecured(rand::rng()))
    .unwrap();
    let mut a = network.socket("192.0.2.2:5683");
    let mut b = network.socket("192.0.2.3:5683");
    let requester = "192.0.2.1:5683".parse().unwrap();
    let origin = "192.0.2.9:5683".parse().unwrap();
    let mut proxy = ForwardProxy::<_, _, 256, 3, 2>::with_outbound(
        |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND),
        Route,
        incoming.handle(),
        if separate {
            outgoing.handle()
        } else {
            incoming.handle()
        },
    )
    .unwrap();
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    let mut bytes = [0; 256];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"a").unwrap();
    builder
        .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = builder.finish(&[]).unwrap();
    network.inject(requester, a.local, &bytes[..n]);
    let wake = Arc::new(Wake(AtomicUsize::new(0)));
    let waker = std::task::Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let drivers = futures_lite::future::race(
        inbound.run(&mut a, &network, &mut proxy, &ProtectedOnly),
        outbound.run(&mut b, &network, &mut unused, &ProtectedOnly),
    );
    let mut drivers = core::pin::pin!(drivers);
    drive_to_idle(drivers.as_mut(), &wake, &mut cx);
    let upstream = network.sent().into_iter().find(|p| p.to == origin).unwrap();
    let request = MessageView::parse(&upstream.bytes).unwrap();
    let mut response = Response::<256>::new(Code::CONTENT);
    response.set_payload(b"origin").unwrap();
    let n = response
        .encode(
            &mut bytes,
            MessageType::Acknowledgement,
            request.message_id(),
            request.token(),
        )
        .unwrap();
    network.inject(origin, upstream.from, &bytes[..n]);
    assert!(
        drive_to_idle(drivers.as_mut(), &wake, &mut cx) > 0,
        "completion must wake the task"
    );
    let sent = network.sent();
    let relayed = sent
        .iter()
        .find(|p| {
            p.to == requester && MessageView::parse(&p.bytes).unwrap().code() == Code::CONTENT
        })
        .expect("completed upstream response must be relayed without advancing the clock");
    let response = MessageView::parse(&relayed.bytes).unwrap();
    assert_eq!(response.token(), b"a");
    assert_eq!(response.payload(), b"origin");
    assert_eq!(relayed.at, mai_coap::time::Instant(0));
}

#[test]
fn shared_endpoint_relays_without_timer() {
    check::<mai_coap::endpoint::role::Combined, mai_coap::endpoint::role::Combined>(false);
}

#[test]
fn separate_endpoint_relays_without_timer() {
    check::<mai_coap::endpoint::role::Combined, mai_coap::endpoint::role::Combined>(true);
}

#[test]
fn separate_server_and_client_roles_relay_without_timer() {
    check::<mai_coap::endpoint::role::Server, mai_coap::endpoint::role::Client>(true);
}
