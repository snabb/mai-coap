//! Endpoint rate-admission accounting (DOS-1, API-8).
#![cfg(feature = "server")]

use core::{cell::Cell, net::SocketAddr};
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Application, Disposition, Protection, Request, ResponseWriter, ServerEndpoint,
        ServerShared, Unsecured,
    },
    rate::Limits,
    security::{AllowAll, SecurityState},
    time::Instant,
    transport::Metadata,
};

fn limits() -> Limits {
    Limits::default()
        .with_per_source(1)
        .with_source_burst(1)
        .with_overall(1)
        .with_overall_burst(1)
}

fn offer<P: Protection>(
    endpoint: &mut ServerEndpoint<'_, P, 128>,
    bytes: &[u8],
    peer: SocketAddr,
    now: u64,
    app: &mut impl Application<128>,
) {
    endpoint
        .receive(
            bytes,
            Metadata::new(peer, "192.0.2.2".parse().unwrap(), bytes.len()),
            Instant(now),
            app,
            &AllowAll,
        )
        .unwrap();
}

#[test]
fn denied_cached_duplicates_are_counted_without_dispatch_or_cache_loss() {
    for overall in [false, true] {
        let shared = ServerShared::<128>::new();
        let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
        let budgets = if overall {
            limits().with_source_burst(10)
        } else {
            limits().with_overall_burst(10)
        };
        endpoint.set_rate_limits(budgets).unwrap();
        let calls = Cell::new(0);
        let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
            calls.set(calls.get() + 1);
            response.set_payload(b"cached reply")?;
            Ok(Disposition::Complete)
        };
        let peer = "192.0.2.1:5683".parse().unwrap();
        let mut bytes = [0; 128];
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        offer(&mut endpoint, &bytes[..n], peer, 0, &mut app);
        let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
        endpoint.complete_outgoing(Instant(0));
        for count in 1..=2 {
            offer(&mut endpoint, &bytes[..n], peer, 0, &mut app);
            assert!(endpoint.front_outgoing().is_none());
            assert_eq!(endpoint.counters().rate_limited, count);
            assert_eq!(endpoint.counters().duplicates, 0);
        }
        offer(&mut endpoint, &bytes[..n], peer, 1000, &mut app);
        assert_eq!(endpoint.front_outgoing().unwrap().bytes, original);
        endpoint.complete_outgoing(Instant(1000));
        assert_eq!(endpoint.counters().rate_limited, 2);
        assert_eq!(endpoint.counters().duplicates, 1);
        assert_eq!(calls.get(), 1);

        bytes[3] = 2;
        let other_peer = "192.0.2.3:5683".parse().unwrap();
        offer(&mut endpoint, &bytes[..n], other_peer, 1000, &mut app);
        assert_eq!(endpoint.front_outgoing().is_none(), overall);
        assert_eq!(
            endpoint.counters().rate_limited,
            if overall { 3 } else { 2 }
        );
        assert_eq!(calls.get(), if overall { 1 } else { 2 });
        assert_eq!(endpoint.counters().requests, calls.get());
        assert_eq!(endpoint.counters().dedup_reply_drops, 0);
        assert_eq!(endpoint.counters().dedup_reply_misses, 0);
        assert_eq!(endpoint.counters().dropped_messages, 0);
    }
}

#[test]
fn suppressed_resets_count_once_for_empty_and_malformed_confirmable_messages() {
    for bytes in [&[0x40, 0, 0, 7][..], &[0x49, 1, 0, 7][..]] {
        let shared = ServerShared::<128>::new();
        let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
        endpoint.set_rate_limits(limits()).unwrap();
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
            panic!("reset handling must not dispatch")
        };
        let peer = "192.0.2.1:5683".parse().unwrap();
        offer(&mut endpoint, bytes, peer, 0, &mut app);
        assert_eq!(
            MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                .unwrap()
                .message_type(),
            MessageType::Reset
        );
        endpoint.complete_outgoing(Instant(0));
        offer(&mut endpoint, bytes, peer, 0, &mut app);
        assert!(endpoint.front_outgoing().is_none());
        assert_eq!(endpoint.counters().rate_limited, 1);
        offer(&mut endpoint, &[0x60, 0, 0, 7], peer, 0, &mut app);
        assert_eq!(endpoint.counters().rate_limited, 1);
        assert_eq!(endpoint.counters().dropped_messages, 0);
    }
}

struct RejectIncoming {
    inner: Unsecured<rand::rngs::ThreadRng>,
}
impl Protection for RejectIncoming {
    mai_coap::delegate_protection!(inner, (); except [incoming]);

    fn incoming<const D: usize>(
        &mut self,
        _: MessageView<'_>,
        _: Metadata,
        _: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<()>), Error> {
        Err(Error::ContextNotFound)
    }
}

#[test]
fn suppressed_protection_errors_count_separately_from_security_failures() {
    let shared = ServerShared::<128>::new();
    let mut endpoint = ServerEndpoint::new(
        &shared,
        RejectIncoming {
            inner: Unsecured(rand::rng()),
        },
    )
    .unwrap();
    endpoint.set_rate_limits(limits()).unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| {
        panic!("failed protection must not dispatch")
    };
    let peer = "192.0.2.1:5683".parse().unwrap();
    for mid in 1..=2 {
        let mut bytes = [0; 128];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, mid, b"t")
                .unwrap();
        builder.option(OptionNumber::OSCORE, &[]).unwrap();
        let n = builder.finish(&[]).unwrap();
        offer(&mut endpoint, &bytes[..n], peer, 0, &mut app);
        if mid == 1 {
            assert_eq!(
                MessageView::parse(endpoint.front_outgoing().unwrap().bytes)
                    .unwrap()
                    .code(),
                Code::UNAUTHORIZED
            );
            endpoint.complete_outgoing(Instant(0));
        } else {
            assert!(endpoint.front_outgoing().is_none());
        }
    }
    assert_eq!(endpoint.counters().rate_limited, 1);
    assert_eq!(endpoint.counters().protection_failures, 2);
    assert_eq!(endpoint.counters().requests, 0);
    assert_eq!(endpoint.counters().dropped_messages, 0);
}

#[cfg(feature = "multicast")]
#[test]
fn suppressed_multicast_work_counts_but_silent_duplicates_do_not() {
    let shared = ServerShared::<128>::new();
    let mut endpoint = ServerEndpoint::new(&shared, Unsecured(rand::rng())).unwrap();
    endpoint.set_rate_limits(limits()).unwrap();
    let calls = Cell::new(0);
    let mut app = |_: Request<'_>, response: &mut ResponseWriter<'_, 128>| {
        calls.set(calls.get() + 1);
        response.set_payload(b"</x>")?;
        Ok(Disposition::Complete)
    };
    let mut bytes = [0; 128];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::NonConfirmable, Code::GET, 1, b"t").unwrap();
    mai_coap::uri::path_options("/.well-known/core", &mut builder).unwrap();
    let n = builder.finish(&[]).unwrap();
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "224.0.1.187".parse().unwrap(),
        n,
    );
    for mid in [1, 1, 2] {
        bytes[3] = mid;
        endpoint
            .receive(&bytes[..n], metadata, Instant(0), &mut app, &AllowAll)
            .unwrap();
    }
    assert_eq!(calls.get(), 1);
    assert_eq!(endpoint.counters().duplicates, 1);
    assert_eq!(endpoint.counters().rate_limited, 1);
    assert_eq!(endpoint.counters().dropped_messages, 0);
    endpoint.poll(Instant(5000)).unwrap();
    assert!(endpoint.front_outgoing().is_some());
    endpoint.complete_outgoing(Instant(5000));
    endpoint
        .receive(&bytes[..n], metadata, Instant(5000), &mut app, &AllowAll)
        .unwrap();
    assert_eq!(calls.get(), 2);
    assert_eq!(endpoint.counters().rate_limited, 1);
}
