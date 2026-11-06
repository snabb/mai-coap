//! Endpoint counters remain available without shared snapshot publication.
#![cfg(all(feature = "server", not(feature = "shared-counters")))]

mod support;

use core::{cell::Cell, future::Future, task::Context};
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, OptionNumber},
    endpoint::{
        Application, Disposition, Protection, Request, ResponseWriter, ServerEndpoint,
        ServerShared, Unsecured,
    },
    security::AllowAll,
};
use std::task::Waker;

struct ReportingProtection<'a> {
    inner: Unsecured<rand::rngs::ThreadRng>,
    reads: &'a Cell<usize>,
}
impl Protection for ReportingProtection<'_> {
    mai_coap::delegate_protection!(inner, (); except [handshake_runs, context_evictions]);

    fn handshake_runs(&self) -> u64 {
        self.reads.set(self.reads.get() + 1);
        7
    }
    fn context_evictions(&self) -> u64 {
        self.reads.set(self.reads.get() + 1);
        3
    }
}

struct Resource;
impl Application<128> for Resource {
    fn handle(
        &mut self,
        _: Request<'_>,
        response: &mut ResponseWriter<'_, 128>,
    ) -> Result<Disposition, Code> {
        response.set_payload(b"ok")?;
        Ok(Disposition::Complete)
    }
    fn recognizes(&self, _: OptionNumber) -> bool {
        false
    }
}

#[test]
fn api_8_driver_omits_snapshot_queries_but_keeps_endpoint_counters() {
    let shared = const { ServerShared::<128>::new() };
    let reads = Cell::new(0);
    let mut endpoint = ServerEndpoint::new(
        &shared,
        ReportingProtection {
            inner: Unsecured(rand::rng()),
            reads: &reads,
        },
    )
    .unwrap();
    let network = support::Network::default();
    let mut socket = network.socket("192.0.2.2:5683");
    let mut bytes = [0; 4];
    let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[])
        .unwrap()
        .finish(&[])
        .unwrap();
    network.inject("192.0.2.1:5683".parse().unwrap(), socket.local, &bytes[..n]);
    {
        let mut app = Resource;
        let mut driver = core::pin::pin!(endpoint.run(&mut socket, &network, &mut app, &AllowAll));
        assert!(
            driver
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(reads.get(), 0);
    }
    let counters = endpoint.counters();
    assert_eq!(reads.get(), 2);
    assert_eq!(counters.requests, 1);
    assert_eq!(counters.edhoc_runs, 7);
    assert_eq!(counters.context_evictions, 3);
}
