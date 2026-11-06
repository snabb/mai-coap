//! Multicast classification, leisure, source selection and bounded collection.
#![cfg(all(
    feature = "multicast",
    feature = "client",
    feature = "server",
    feature = "discovery"
))]
mod support;
use futures_lite::future::{block_on, poll_once};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

fn metadata(n: usize) -> Metadata {
    Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "224.0.1.187".parse().unwrap(),
        n,
    )
    .with_interface(Some(2))
}
fn packet(bytes: &mut [u8], ty: MessageType, protected: bool) -> usize {
    let mut b = MessageBuilder::new(bytes, ty, Code::GET, 1, b"test").unwrap();
    if protected {
        b.option(OptionNumber::OSCORE, &[]).unwrap();
    }
    mai_coap::uri::path_options("/.well-known/core", &mut b).unwrap();
    b.finish(&[]).unwrap()
}
#[test]
fn mc_1_2_4_no_ack_rst_errors_or_protection_and_unicast_reply_after_leisure() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut calls = 0;
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        calls += 1;
        response.set_payload(b"</x>").unwrap();
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::GET, "/.well-known/core")]);
    let mut bytes = [0; 256];
    for (ty, protected) in [
        (MessageType::Confirmable, false),
        (MessageType::NonConfirmable, true),
    ] {
        let n = packet(&mut bytes, ty, protected);
        endpoint
            .receive(&bytes[..n], metadata(n), Instant(0), &mut app, &policy)
            .unwrap();
        assert!(endpoint.pop_outgoing().is_none());
    }
    let n = packet(&mut bytes, MessageType::NonConfirmable, false);
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(0), &mut app, &policy)
        .unwrap();
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(1), &mut app, &policy)
        .unwrap();
    endpoint.poll(Instant(5000)).unwrap();
    let sent = endpoint.pop_outgoing().unwrap();
    assert_eq!(
        sent.source, None,
        "transport selects a unicast source on the receiving interface"
    );
    assert_eq!(sent.interface, Some(2));
    assert_eq!(sent.remote, metadata(n).remote);
    assert_eq!(
        MessageView::parse(sent.packet.as_slice())
            .unwrap()
            .message_type(),
        MessageType::NonConfirmable
    );
    assert!(endpoint.pop_outgoing().is_none());
    assert_eq!(calls, 1);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Err(Code::NOT_FOUND);
    bytes[3] = 2;
    endpoint
        .receive(&bytes[..n], metadata(n), Instant(6000), &mut app, &policy)
        .unwrap();
    endpoint.poll(Instant(11000)).unwrap();
    assert!(endpoint.pop_outgoing().is_none());
}

#[test]
fn mc_3_client_collects_sources_until_deadline_without_retransmitting() {
    block_on(async {
        let shared = Shared::<256, 2>::new();
        let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
        let handle = shared.handle();
        let mut collection = handle
            .discover_multicast("224.0.1.187:5683".parse().unwrap(), Instant(5000))
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let sent = endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(sent.packet.as_slice()).unwrap();
        assert_eq!(request.message_type(), MessageType::NonConfirmable);
        let mut application =
            |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
        let mut response = Response::<256>::new(Code::CONTENT);
        response.set_payload(b"</x>").unwrap();
        for (i, remote) in ["192.0.2.2:5683", "192.0.2.3:5683"].iter().enumerate() {
            let mut bytes = [0; 256];
            let n = response
                .encode(
                    &mut bytes,
                    MessageType::NonConfirmable,
                    i as u16,
                    request.token(),
                )
                .unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    Metadata::new(remote.parse().unwrap(), "192.0.2.1".parse().unwrap(), n)
                        .with_interface(Some(2)),
                    Instant(100),
                    &mut application,
                    &PublicPaths(&[]),
                )
                .unwrap();
        }
        assert_eq!(
            collection.next().await.unwrap().unwrap().remote,
            "192.0.2.2:5683".parse().unwrap()
        );
        assert_eq!(
            collection.next().await.unwrap().unwrap().remote,
            "192.0.2.3:5683".parse().unwrap()
        );
        assert!(poll_once(collection.next()).await.is_none());
        endpoint.poll(Instant(4999)).unwrap();
        assert!(endpoint.pop_outgoing().is_none());
        endpoint.poll(Instant(5000)).unwrap();
        assert!(collection.next().await.is_none());
    });
}
