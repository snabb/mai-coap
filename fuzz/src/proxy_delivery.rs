//! PRX-1/PRX-4, REL-3/REL-6: retained completion, opaque relay and exact CON retry.
use core::{
    net::SocketAddr,
    task::{Context, Waker},
};
use mai_coap::{
    Error, Packet,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Endpoint, Request, ResponseWriter, Shared, Unsecured},
    proxy::{ForwardProxy, Routing},
    security::ProtectedOnly,
    time::Instant,
    transport::Metadata,
};
use rand::{SeedableRng, rngs::StdRng};

struct Route;
impl Routing for Route {
    fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
        true
    }
}
fn peer(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 0, 2, last], 5683))
}

pub fn check(data: &[u8]) {
    const D: usize = 128;
    let flags = data.first().copied().unwrap_or(0);
    let payload = &data.get(1..).unwrap_or(&[])[..data.len().saturating_sub(1).min(64)];
    let incoming = Shared::<D, 1>::new();
    let outgoing = Shared::<D, 1>::new();
    let mut receive = Endpoint::<_, D, 2, 4, 0, 1, 1, 1, 2, 0, 4>::new(
        &incoming,
        Unsecured(StdRng::from_seed([21; 32])),
    )
    .unwrap();
    let mut origin = Endpoint::<_, D, 1, 4, 0, 1, 2, 1, 0, 0, 2>::new(
        &outgoing,
        Unsecured(StdRng::from_seed([22; 32])),
    )
    .unwrap();
    let mut proxy = ForwardProxy::<_, _, D, 1, 1>::with_outbound(
        |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND),
        Route,
        incoming.handle(),
        outgoing.handle(),
    )
    .unwrap();
    let mut bytes = [0; D];
    let mut builder = MessageBuilder::new(
        &mut bytes,
        MessageType::Confirmable,
        Code::GET,
        7,
        b"client",
    )
    .unwrap();
    builder
        .option(OptionNumber::PROXY_URI, b"coap://192.0.2.9/x")
        .unwrap();
    let n = builder.finish(&[]).unwrap();
    receive
        .receive(
            &bytes[..n],
            Metadata::new(peer(1), peer(2).ip(), n).with_interface(Some(7)),
            Instant(0),
            &mut proxy,
            &ProtectedOnly,
        )
        .unwrap();
    let blocked = flags & (1 | 8 | 16) != 0;
    if !blocked {
        receive.complete_outgoing(Instant(0));
    }
    let occupied = if flags & 64 != 0 {
        Some(
            incoming
                .handle()
                .client(peer(8))
                .request(Code::GET, "/other")
                .unwrap()
                .send()
                .unwrap(),
        )
    } else {
        None
    };
    origin.poll(Instant(0)).unwrap();
    let request = MessageView::parse(origin.front_outgoing().unwrap().bytes).unwrap();
    let ty = if flags & 2 != 0 {
        MessageType::Confirmable
    } else {
        MessageType::Acknowledgement
    };
    let mid = if ty == MessageType::Confirmable {
        333
    } else {
        request.message_id()
    };
    let mut builder =
        MessageBuilder::new(&mut bytes, ty, Code::CONTENT, mid, request.token()).unwrap();
    builder.option(OptionNumber::OSCORE, &[9, 7, 1]).unwrap();
    builder
        .option(OptionNumber(if flags & 4 != 0 { 99 } else { 100 }), b"safe")
        .unwrap();
    let n = builder.finish(payload).unwrap();
    origin.complete_outgoing(Instant(0));
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
    for _ in 0..2 {
        origin
            .receive(
                &bytes[..n],
                Metadata::new(peer(9), peer(3).ip(), n),
                Instant(0),
                &mut unused,
                &ProtectedOnly,
            )
            .unwrap();
    }
    while let Some(control) = origin.front_outgoing() {
        let view = MessageView::parse(control.bytes).unwrap();
        assert_eq!(view.message_type(), MessageType::Acknowledgement);
        assert_eq!(view.code(), Code::EMPTY);
        assert_eq!(view.message_id(), mid);
        origin.complete_outgoing(Instant(0));
    }
    let mut cx = Context::from_waker(Waker::noop());
    receive
        .poll_resources(Instant(0), &mut proxy, &ProtectedOnly, &mut cx)
        .unwrap();
    if blocked {
        // No reservation or writer may consume the upstream result while the
        // receiving send queue is full. Its one-slot bound stays recoverable.
        assert!(matches!(
            outgoing
                .handle()
                .client(peer(9))
                .request(Code::GET, "/full")
                .unwrap()
                .send(),
            Err(Error::Capacity)
        ));
    }
    if flags & 16 != 0 {
        drop(proxy);
        origin.poll(Instant(0)).unwrap();
    } else if flags & 8 != 0 {
        receive.poll(Instant(1_000_000)).unwrap();
        receive
            .poll_resources(Instant(1_000_000), &mut proxy, &ProtectedOnly, &mut cx)
            .unwrap();
        while let Some(packet) = receive.front_outgoing() {
            assert_ne!(packet.remote, peer(1));
            receive.complete_outgoing(Instant(1_000_000));
        }
    } else {
        if blocked {
            receive.complete_outgoing(Instant(0));
        }
        receive
            .poll_resources(Instant(1), &mut proxy, &ProtectedOnly, &mut cx)
            .unwrap();
        let packet = receive
            .front_outgoing()
            .expect("ready completion was not handed off");
        assert_eq!(packet.remote, peer(1));
        assert_eq!(packet.source, Some(peer(2).ip()));
        assert_eq!(packet.interface, Some(7));
        let response = MessageView::parse(packet.bytes).unwrap();
        assert_eq!(response.token(), b"client");
        assert_eq!(response.message_type(), MessageType::Confirmable);
        if flags & 4 != 0 {
            assert_eq!(response.code(), Code::BAD_GATEWAY);
            assert!(response.payload().is_empty());
        } else {
            assert_eq!(response.code(), Code::CONTENT);
            assert_eq!(response.payload(), payload);
            assert_eq!(
                response.option(OptionNumber::OSCORE).unwrap().value,
                &[9, 7, 1]
            );
            assert_eq!(response.option(OptionNumber(100)).unwrap().value, b"safe");
        }
        let stored = Packet::<D>::copy_from(packet.bytes).unwrap();
        receive.complete_outgoing(Instant(1));
        // Drop an unrelated receiving command before advancing the driver so
        // only the relayed CON response is scheduled for this retry assertion.
        drop(occupied);
        receive.poll(Instant(1)).unwrap();
        let retry = receive.deadline(Instant(1));
        receive.poll(retry).unwrap();
        let resent = receive.front_outgoing().expect("missing CON retry");
        assert_eq!(resent.bytes, stored.as_slice());
        receive.complete_outgoing(retry);
        let slot = outgoing
            .handle()
            .client(peer(9))
            .request(Code::GET, "/reused")
            .unwrap()
            .send()
            .unwrap();
        drop(slot);
        return;
    }
    let slot = outgoing
        .handle()
        .client(peer(9))
        .request(Code::GET, "/reused")
        .unwrap()
        .send()
        .unwrap();
    drop(slot);
    drop(occupied);
}
