//! IPv6 routing metadata and CoAP peer identity are independent.
#![cfg(all(feature = "server", feature = "client"))]
use core::{
    cell::Cell,
    net::{SocketAddr, SocketAddrV6},
    pin::pin,
};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    security::AllowAll,
    time::Instant,
    transport::Metadata,
};
fn address(ip: &str, scope: u32, flow: u32) -> SocketAddr {
    SocketAddrV6::new(ip.parse().unwrap(), 5683, flow, scope).into()
}
fn metadata(remote: SocketAddr, length: usize) -> Metadata {
    Metadata::new(remote, "2001:db8::2".parse().unwrap(), length).with_interface(Some(2))
}
fn once<F: core::future::Future>(mut future: core::pin::Pin<&mut F>) -> Option<F::Output> {
    futures_lite::future::block_on(core::future::poll_fn(|cx| {
        core::task::Poll::Ready(match future.as_mut().poll(cx) {
            core::task::Poll::Ready(value) => Some(value),
            core::task::Poll::Pending => None,
        })
    }))
}
#[test]
fn replies_match_global_ipv6_peers_without_altering_send_or_receive_addresses() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote = address("2001:db8::1", 2, 9);
    let mut operation = pin!(
        shared
            .handle()
            .client(remote)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap()
    );
    endpoint.poll(Instant(0)).unwrap();
    let outgoing = endpoint.front_outgoing().unwrap();
    assert_eq!(outgoing.remote, remote, "route hints survive peer matching");
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
    .finish(b"reply")
    .unwrap();
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let received = address("2001:db8::1", 0, 0);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    endpoint
        .receive(
            &bytes[..n],
            metadata(received, n),
            Instant(1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    let reply = once(operation.as_mut()).unwrap().unwrap();
    assert_eq!(reply.remote, received);
    assert_eq!(reply.message().unwrap().payload(), b"reply");
}
#[test]
fn link_local_scope_distinguishes_peers_but_flow_information_does_not() {
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let remote = address("fe80::1", 2, 9);
    let mut operation = pin!(
        shared
            .handle()
            .client(remote)
            .request(Code::GET, "/")
            .unwrap()
            .send()
            .unwrap()
    );
    endpoint.poll(Instant(0)).unwrap();
    let request = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CONTENT,
        request.message_id(),
        request.token(),
    )
    .unwrap()
    .finish(b"right zone")
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
            metadata(address("fe80::1", 3, 0), n),
            Instant(1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert!(once(operation.as_mut()).is_none());
    endpoint
        .receive(
            &bytes[..n],
            metadata(address("fe80::1", 2, 0), n),
            Instant(2),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(
        once(operation.as_mut())
            .unwrap()
            .unwrap()
            .message()
            .unwrap()
            .payload(),
        b"right zone"
    );
}
#[test]
fn duplicate_records_and_nstart_use_the_same_ipv6_peer_identity() {
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let calls = Cell::new(0);
    let mut app = |request: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        assert_eq!(request.metadata.remote, address("2001:db8::1", 2, 9));
        response.set_payload(b"stored")?;
        Ok(Disposition::Complete)
    };
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 1, b"t")
        .unwrap()
        .finish(b"write")
        .unwrap();
    endpoint
        .receive(
            &bytes[..n],
            metadata(address("2001:db8::1", 2, 9), n),
            Instant(0),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    let first = endpoint.front_outgoing().unwrap().bytes.to_vec();
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    endpoint
        .receive(
            &bytes[..n],
            metadata(address("2001:db8::1", 0, 0), n),
            Instant(1),
            &mut app,
            &AllowAll,
        )
        .unwrap();
    assert_eq!(endpoint.front_outgoing().unwrap().bytes, first);
    assert_eq!(calls.get(), 1);
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    let first = shared
        .handle()
        .client(address("2001:db8::1", 2, 9))
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    let second = shared
        .handle()
        .client(address("2001:db8::1", 0, 0))
        .request(Code::GET, "/")
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(2)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    endpoint.complete_outgoing(
        endpoint
            .front_outgoing()
            .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
    );
    endpoint.poll(Instant(3)).unwrap();
    assert!(
        endpoint.front_outgoing().is_none(),
        "same peer shares NSTART across route scope hints"
    );
    drop(first);
    endpoint.poll(Instant(4)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    drop(second);
}
#[cfg(feature = "block1")]
#[test]
fn upload_keys_normalize_global_scope_but_preserve_link_local_zones() {
    use mai_coap::block::BodyKey;
    let mut bytes = [0; 128];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::PUT, 1, b"t")
        .unwrap()
        .finish(b"part")
        .unwrap();
    let message = MessageView::parse(&bytes[..n]).unwrap();
    let key = |ip, scope, flow| {
        BodyKey::from_request(address(ip, scope, flow), 1, None, message).unwrap()
    };
    assert_eq!(key("2001:db8::1", 2, 9), key("2001:db8::1", 0, 0));
    assert_ne!(key("fe80::1", 2, 0), key("fe80::1", 3, 0));
}
