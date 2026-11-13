//! REL-3/REL-6 and API-4: explicit roles restrict work without changing controls.
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    Error, InlineStorage,
    codec::{Code, MessageBuilder, MessageType},
    endpoint::{Endpoint, Request, ResponseWriter, Shared, Unsecured, role},
    security::ProtectedOnly,
    time::Instant,
    transport::Metadata,
};
use rand::SeedableRng;

pub fn check(data: &[u8]) {
    let shared = Shared::<64, 1>::new();
    let mut client =
        Endpoint::<_, 64, 1, 2, 0, 0, 1, 1, 0, 0, 2, InlineStorage<64, 2>, role::Client>::new_with_role(
            &shared,
            Unsecured(rand::rngs::StdRng::from_seed([13; 32])),
        )
        .unwrap();
    let mut app =
        |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| panic!("client role served a request");
    for &flags in data.iter().take(32) {
        let ty = match flags & 3 {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            _ => MessageType::Reset,
        };
        let code =
            if flags & 16 != 0 || matches!(ty, MessageType::Acknowledgement | MessageType::Reset) {
                Code::EMPTY
            } else if flags & 4 != 0 {
                Code::CONTENT
            } else {
                Code::GET
            };
        let mid = u16::from(flags);
        let mut bytes = [0; 64];
        let n = MessageBuilder::new(&mut bytes, ty, code, mid, &[])
            .unwrap()
            .finish(&[])
            .unwrap();
        let metadata = Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            n,
        );
        client
            .receive(&bytes[..n], metadata, Instant(0), &mut app, &ProtectedOnly)
            .unwrap();
        // RFC 7252 4.2/4.3: no matching context means CON gets an Empty RST;
        // NON may be ignored, and ACK/RST must not elicit another ACK/RST.
        if ty == MessageType::Confirmable {
            let outgoing = client.front_outgoing().expect("missing role rejection");
            let mid = mid.to_be_bytes();
            assert_eq!(outgoing.bytes, &[0x70, 0, mid[0], mid[1]]);
            client.complete_outgoing(Instant(0));
        } else {
            assert!(client.front_outgoing().is_none());
        }
    }

    let shared = Shared::<64, 1>::new();
    let mut server =
        Endpoint::<_, 64, 1, 2, 0, 1, 1, 1, 1, 0, 2, InlineStorage<64, 2>, role::Server>::new_with_role(
            &shared,
            Unsecured(rand::rngs::StdRng::from_seed([14; 32])),
        )
        .unwrap();
    for _ in data.iter().take(8) {
        let mut operation = shared
            .handle()
            .client("192.0.2.1:5683".parse::<core::net::SocketAddr>().unwrap())
            .request(Code::GET, "/x")
            .unwrap()
            .send()
            .unwrap();
        server.poll(Instant(0)).unwrap();
        assert!(matches!(
            Pin::new(&mut operation).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(Error::RoleDisabled))
        ));
        assert!(server.front_outgoing().is_none());
    }
}
