//! Proxy normalization, authorization, opaque forwarding and independent interop.
#![cfg(feature = "proxy")]
use crate::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    proxy::{Routing, prepare},
};
use core::net::SocketAddr;
use std::{vec, vec::Vec};
struct Allowed;

#[test]
fn prx_4_unrecognized_safe_options_are_preserved_in_both_directions() {
    for (number, values, safe) in [
        (OptionNumber::ETAG, vec![vec![7; 9]], true),
        (OptionNumber::ACCEPT, vec![vec![60], vec![42]], true),
        (OptionNumber::OSCORE, vec![vec![8, 1], vec![8, 2]], true),
        (OptionNumber::MAX_AGE, vec![vec![0; 5]], false),
        (OptionNumber::URI_HOST, vec![vec![b'a'], vec![b'b']], false),
    ] {
        for code in [Code::POST, Code::CONTENT] {
            let mut bytes = [0; 256];
            let mut b =
                MessageBuilder::new(&mut bytes, MessageType::Confirmable, code, 1, b"t").unwrap();
            for value in &values {
                b.option(number, value).unwrap();
            }
            if code.is_request() {
                b.option(OptionNumber::PROXY_URI, b"coap://target/x")
                    .unwrap();
            }
            let n = b.finish(b"opaque payload").unwrap();
            let message = MessageView::parse(&bytes[..n]).unwrap();
            let mut output = [0; 256];
            let relayed;
            let forwarded = if code.is_request() {
                let result = prepare(
                    message,
                    "192.0.2.1:1".parse().unwrap(),
                    &Allowed,
                    &mut output,
                );
                if !safe {
                    assert_eq!(result, Err(Code::BAD_OPTION));
                    continue;
                }
                let (_, n) = result.unwrap();
                MessageView::parse(&output[..n]).unwrap()
            } else {
                relayed = super::relay::<256>(reply(message));
                let forwarded = MessageView::parse(relayed.as_slice()).unwrap();
                if !safe {
                    assert_eq!(forwarded.code(), Code::BAD_GATEWAY);
                    continue;
                }
                assert!(forwarded.token().is_empty());
                forwarded
            };
            assert_eq!(forwarded.payload(), b"opaque payload");
            let actual: Vec<_> = forwarded
                .options()
                .filter(|o| o.number == number)
                .map(|o| o.value.to_vec())
                .collect();
            assert_eq!(actual, values);
        }
    }
}

fn reply<const D: usize>(message: MessageView<'_>) -> crate::endpoint::Reply<D> {
    crate::endpoint::Reply {
        remote: "192.0.2.9:5683".parse().unwrap(),
        packet: crate::Packet::copy_from(message.as_bytes()).unwrap(),
    }
}

#[test]
fn relay_rejects_more_options_than_the_response_bound() {
    for (count, expected) in [(16, Code::CONTENT), (17, Code::BAD_GATEWAY)] {
        let mut bytes = [0; 128];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::NonConfirmable,
            Code::CONTENT,
            1,
            b"t",
        )
        .unwrap();
        for _ in 0..count {
            b.option(OptionNumber::ETAG, b"e").unwrap();
        }
        let n = b.finish(&[]).unwrap();
        let view = MessageView::parse(&bytes[..n]).unwrap();
        let relayed = super::relay::<128>(reply(view));
        assert_eq!(
            MessageView::parse(relayed.as_slice()).unwrap().code(),
            expected
        );
    }
}

/// RFC 7252 section 5.10.7 forbids a "." or ".." Location-Path, so the upstream
/// response is invalid and the proxy answers 5.02 (section 5.9.3.3).
#[test]
fn dot_segment_location_path_from_upstream_is_bad_gateway() {
    for (value, expected) in [
        (b"..".as_slice(), Code::BAD_GATEWAY),
        (b"a..", Code::CREATED),
    ] {
        let mut bytes = [0; 64];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CREATED,
            1,
            b"t",
        )
        .unwrap();
        b.option(OptionNumber::LOCATION_PATH, value).unwrap();
        let n = b.finish(&[]).unwrap();
        let relayed = super::relay::<64>(reply(MessageView::parse(&bytes[..n]).unwrap()));
        assert_eq!(
            MessageView::parse(relayed.as_slice()).unwrap().code(),
            expected
        );
    }
}

#[test]
fn prx_5_hop_limit_zero_range_and_supernumerary_encodings() {
    for (values, expected) in [
        (vec![vec![]], Err(Code::BAD_REQUEST)),
        (vec![vec![0]], Err(Code::BAD_REQUEST)),
        (vec![vec![1, 0]], Ok(vec![vec![16], vec![1, 0]])),
        (vec![vec![1]], Err(Code::HOP_LIMIT_REACHED)),
        (vec![vec![2]], Ok(vec![vec![1]])),
        (vec![vec![255]], Ok(vec![vec![254]])),
        (
            vec![vec![3], vec![], vec![0; 9]],
            Ok(vec![vec![2], vec![], vec![0; 9]]),
        ),
        (vec![vec![0, 3]], Ok(vec![vec![16], vec![0, 3]])),
        (vec![vec![0, 255]], Ok(vec![vec![16], vec![0, 255]])),
        (vec![vec![0, 0]], Ok(vec![vec![16], vec![0, 0]])),
        (vec![vec![255; 16]], Ok(vec![vec![16], vec![255; 16]])),
        (vec![], Ok(vec![vec![16]])),
    ] {
        let mut bytes = [0; 256];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 1, b"t").unwrap();
        for value in &values {
            b.option(OptionNumber::HOP_LIMIT, value).unwrap();
        }
        b.option(OptionNumber::PROXY_URI, b"coap://target/x")
            .unwrap();
        let n = b.finish(&[]).unwrap();
        let mut output = [0; 256];
        let result = prepare(
            MessageView::parse(&bytes[..n]).unwrap(),
            "192.0.2.1:1".parse().unwrap(),
            &Allowed,
            &mut output,
        );
        match expected {
            Err(code) => assert_eq!(result, Err(code)),
            Ok(values) => {
                let (_, n) = result.unwrap();
                let message = MessageView::parse(&output[..n]).unwrap();
                let actual: Vec<_> = message
                    .options()
                    .filter(|o| o.number == OptionNumber::HOP_LIMIT)
                    .map(|o| o.value.to_vec())
                    .collect();
                assert_eq!(actual, values);
            }
        }
    }
}

#[test]
fn prx_2_proxy_scratch_follows_the_datagram_capacity() {
    for payload in [b"short".as_slice(), &[9; 3000]] {
        let mut request = [0; 4096];
        let mut b =
            MessageBuilder::new(&mut request, MessageType::Confirmable, Code::POST, 1, b"x")
                .unwrap();
        b.option(OptionNumber::PROXY_URI, b"coap://target/a/../last?q=x")
            .unwrap();
        let n = b.finish(payload).unwrap();
        let mut output = [0; 4096];
        let (_, n) = prepare(
            MessageView::parse(&request[..n]).unwrap(),
            "192.0.2.1:1".parse().unwrap(),
            &Allowed,
            &mut output,
        )
        .unwrap();
        let message = MessageView::parse(&output[..n]).unwrap();
        assert_eq!(
            message.option(OptionNumber::URI_PATH).unwrap().value,
            b"last"
        );
        assert_eq!(message.payload(), payload);
    }
    let mut request = [0; 64];
    let mut b =
        MessageBuilder::new(&mut request, MessageType::Confirmable, Code::GET, 1, b"").unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://target/x")
        .unwrap();
    let n = b.finish(&[]).unwrap();
    assert!(
        prepare(
            MessageView::parse(&request[..n]).unwrap(),
            "192.0.2.1:1".parse().unwrap(),
            &Allowed,
            &mut [0; 64]
        )
        .is_ok()
    );
}
impl Routing for Allowed {
    fn allow(&self, _: SocketAddr, host: &str, port: u16) -> bool {
        host == "target" && port == 5683
    }
    fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        self.allow("192.0.2.1:1".parse().unwrap(), host, port)
            .then(|| "192.0.2.2:5683".parse().unwrap())
    }
}
#[test]
fn prx_1_2_4_5_opaque_options_uri_decomposition_and_hop_errors() {
    let requester = "192.0.2.1:1".parse().unwrap();
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 1, b"old").unwrap();
    b.option(OptionNumber::OSCORE, &[9, 0, 1]).unwrap();
    b.option(OptionNumber::EDHOC, &[]).unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://tar%67et/a%2fb?q=x%20y")
        .unwrap();
    b.option(OptionNumber(100), b"safe").unwrap();
    let n = b.finish(b"opaque ciphertext").unwrap();
    let mut output = [0; 256];
    let (remote, n) = prepare(
        MessageView::parse(&bytes[..n]).unwrap(),
        requester,
        &Allowed,
        &mut output,
    )
    .unwrap();
    assert_eq!(remote, "192.0.2.2:5683".parse().unwrap());
    let m = MessageView::parse(&output[..n]).unwrap();
    assert_eq!(m.payload(), b"opaque ciphertext");
    assert_eq!(m.option(OptionNumber::OSCORE).unwrap().value, &[9, 0, 1]);
    assert_eq!(m.option(OptionNumber::EDHOC).unwrap().value, &[]);
    assert_eq!(m.option(OptionNumber::URI_PATH).unwrap().value, b"a/b");
    assert_eq!(m.option(OptionNumber::URI_QUERY).unwrap().value, b"q=x y");
    assert_eq!(m.option(OptionNumber::HOP_LIMIT).unwrap().uint(), Ok(16));
    assert!(m.option(OptionNumber::PROXY_URI).is_none());
    assert_eq!(m.option(OptionNumber(100)).unwrap().value, b"safe");
    for (hop, expected) in [(0, Code::BAD_REQUEST), (1, Code::HOP_LIMIT_REACHED)] {
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
        b.option(OptionNumber::HOP_LIMIT, &[hop as u8]).unwrap();
        b.option(OptionNumber::PROXY_URI, b"coap://target/")
            .unwrap();
        let n = b.finish(&[]).unwrap();
        assert_eq!(
            prepare(
                MessageView::parse(&bytes[..n]).unwrap(),
                requester,
                &Allowed,
                &mut output
            ),
            Err(expected)
        );
    }
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
    b.option(OptionNumber::PROXY_URI, b"coap://target/")
        .unwrap();
    b.option(OptionNumber(98), b"unsafe").unwrap();
    let n = b.finish(&[]).unwrap();
    assert_eq!(
        prepare(
            MessageView::parse(&bytes[..n]).unwrap(),
            requester,
            &Allowed,
            &mut output
        ),
        Err(Code::BAD_OPTION)
    );
}

#[test]
fn prx_2_default_policy_denies_forwarding_and_schemes_are_checked() {
    let mut bytes = [0; 128];
    for (uri, expected) in [
        ("coap://target/", Code::FORBIDDEN),
        ("coaps://target/", Code::PROXY_UNSUPPORTED),
        ("coap://target/%xx", Code::BAD_REQUEST),
    ] {
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
        b.option(OptionNumber::PROXY_URI, uri.as_bytes()).unwrap();
        let n = b.finish(&[]).unwrap();
        assert_eq!(
            prepare(
                MessageView::parse(&bytes[..n]).unwrap(),
                "192.0.2.1:1".parse().unwrap(),
                &crate::proxy::Deny,
                &mut [0; 128]
            ),
            Err(expected)
        );
    }
}
