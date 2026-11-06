//! Compact context tables exercise the same endpoint install paths as defaults.
#![cfg(all(
    feature = "server",
    feature = "client",
    feature = "edhoc",
    feature = "software-crypto"
))]
mod support;

use core::cell::Cell;
use futures_lite::future::{block_on, poll_once, race};
use mai_coap::{
    codec::Code,
    crypto::SoftwareCrypto,
    edhoc::{Identity, TrustedPeer, TrustedPeers, endpoint::Edhoc},
    endpoint::{Disposition, Endpoint, Protection, Request, ResponseWriter, Shared},
    security::{PeerId, ProtectedOnly, SecurityState},
};
use rand::{SeedableRng, rngs::StdRng};

type Compact = Edhoc<SoftwareCrypto<StdRng>, 1, 1, TrustedPeers<1>, 0>;

fn protection(seed: u8, credential: &[u8], private: &str, peer: PeerId, trusted: &[u8]) -> Compact {
    let mut crypto = SoftwareCrypto::new(StdRng::from_seed([seed; 32]));
    let identity = Identity::new(credential, support::hex(private), &mut crypto).unwrap();
    let mut peers = TrustedPeers::new();
    peers
        .insert(TrustedPeer::new(peer, trusted).unwrap())
        .unwrap();
    Compact::with_store(crypto, identity, peers).unwrap()
}

#[test]
fn zero_capacity_edhoc_installs_both_roles_and_reuses_context() {
    for combined in [false, true] {
        let initiator = include_bytes!("fixtures/client-kid-01.ccs");
        let responder = include_bytes!("fixtures/node-empty-kid.ccs");
        let client_protection = protection(
            1,
            initiator,
            "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b",
            PeerId(2),
            responder,
        );
        let server_protection = protection(
            2,
            responder,
            "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac",
            PeerId(1),
            initiator,
        );
        let network = support::Network::default();
        let client_shared = Shared::<512, 1>::new();
        let server_shared = Shared::<512, 1>::new();
        let mut client = Endpoint::<_, 512, 1, 4>::new(&client_shared, client_protection).unwrap();
        let mut server = Endpoint::<_, 512, 1, 4>::new(&server_shared, server_protection).unwrap();
        let mut client_socket = network.socket("192.0.2.1:5683");
        let mut server_socket = network.socket("192.0.2.2:5683");
        let handled = Cell::new(0);
        let mut application = |request: Request<'_>, response: &mut ResponseWriter<'_, 512>| {
            assert_eq!(
                request.security,
                SecurityState::Protected { peer: PeerId(1) }
            );
            assert_eq!(request.message.code(), Code::GET);
            handled.set(handled.get() + 1);
            response.set_payload(b"compact").unwrap();
            Ok(Disposition::Complete)
        };
        let mut unused =
            |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| panic!("unexpected request");
        block_on(async {
            let mut drivers = core::pin::pin!(race(
                client.run(&mut client_socket, &network, &mut unused, &ProtectedOnly),
                server.run(
                    &mut server_socket,
                    &network,
                    &mut application,
                    &ProtectedOnly
                ),
            ));
            let handle = client_shared.handle();
            let requester = handle
                .client("192.0.2.2:5683".parse::<core::net::SocketAddr>().unwrap())
                .peer(PeerId(2))
                .combined_edhoc(combined);
            for _ in 0..2 {
                let mut operation = core::pin::pin!(requester.get("/x"));
                let mut complete = false;
                for _ in 0..100 {
                    assert!(poll_once(drivers.as_mut()).await.is_none());
                    if let Some(reply) = poll_once(operation.as_mut()).await {
                        assert_eq!(reply.unwrap().message().unwrap().payload(), b"compact");
                        complete = true;
                        break;
                    }
                    network.advance(1);
                }
                assert!(
                    complete,
                    "compact endpoint must complete the protected request"
                );
            }
        });
        assert_eq!(handled.get(), 2);
        for protection in [client.protection_mut(), server.protection_mut()] {
            assert_eq!(protection.contexts(), 1);
            assert_eq!(protection.handshake_runs(), 1);
        }
    }
}
