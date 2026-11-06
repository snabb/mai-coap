//! Uri-Path and Location-Path values are never "." or ".." (RFC 7252 §§5.10.1, 5.10.7).
#![cfg(all(feature = "server", feature = "client"))]
mod support;
use support::PopOutgoing;

use core::net::SocketAddr;
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Disposition, Endpoint, Request, Response, ResponseError, ResponseWriter, Shared, Unsecured,
    },
    security::PublicPaths,
    time::Instant,
    transport::Metadata,
    uri::{self, Uri},
};

fn paths(message: MessageView<'_>) -> Vec<Vec<u8>> {
    message
        .values(OptionNumber::URI_PATH)
        .map(<[u8]>::to_vec)
        .collect()
}

fn decomposed(input: &str) -> Vec<Vec<u8>> {
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
    Uri::parse(input)
        .unwrap()
        .options_with_scratch(&mut b, &mut [0; 256])
        .unwrap();
    let n = b.finish(&[]).unwrap();
    paths(MessageView::parse(&bytes[..n]).unwrap())
}

#[test]
fn encoded_dots_are_removed_like_literal_dots() {
    // RFC 3986 sections 2.3 and 6.2.2: "%2E" is equivalent to ".".
    for (path, expected) in [
        ("/%2E", "/"),
        ("/a/%2e%2E", "/"),
        ("/a/.%2E/b", "/b"),
        ("/a/%2E/b", "/a/b"),
        ("%2E%2E/a", "a"),
        ("/a%2Eb/%2E%2E%2E", "/a%2Eb/%2E%2E%2E"),
    ] {
        let mut bytes = [0; 64];
        let n = uri::normalize_path(path.as_bytes(), &mut bytes).unwrap();
        assert_eq!(&bytes[..n], expected.as_bytes(), "{path}");
    }
    assert_eq!(decomposed("coap://h/a/%2E%2E/b"), [b"b".to_vec()]);
    assert!(decomposed("coap://h/%2E").is_empty());
    assert_eq!(
        decomposed("coap://h/a%2Eb/%2E%2E%2E"),
        [b"a.b".to_vec(), b"...".to_vec()]
    );
}

#[test]
fn path_helpers_refuse_dot_segments() {
    for target in ["/a/../b", "/.", "%2E%2E", "/a/%2e?q"] {
        let mut bytes = [0; 64];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
        assert_eq!(
            uri::path_query_options(target, &mut b),
            Err(Error::Malformed),
            "{target}"
        );
    }
}

#[test]
fn client_targets_are_resolved_before_decomposition() {
    for (target, expected) in [
        ("/a/../b/./c?x", vec![b"b".to_vec(), b"c".to_vec()]),
        ("/a/%2E%2E/b", vec![b"b".to_vec()]),
        ("coap://192.0.2.1/a/%2E%2E/b", vec![b"b".to_vec()]),
        // Resolving to "/" alone yields no Uri-Path (RFC 7252 section 6.4, step 8).
        ("./", vec![]),
        ("/a/../", vec![]),
        // Relative targets merge with "/" first: "/.//a" resolves to "//a".
        (".//a", vec![b"".to_vec(), b"a".to_vec()]),
        ("/a/b/..", vec![b"a".to_vec(), b"".to_vec()]),
    ] {
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        let exchange = shared
            .handle()
            .client(SocketAddr::from(([192, 0, 2, 1], 5683)))
            .request(Code::GET, target)
            .unwrap()
            .send()
            .unwrap();
        endpoint.poll(Instant(0)).unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        let message = MessageView::parse(output.packet.as_slice()).unwrap();
        assert_eq!(paths(message), expected, "{target}");
        drop(exchange);
    }
}

#[test]
fn dot_segment_uri_path_is_bad_option() {
    for value in [b".".as_slice(), b".."] {
        let policy = PublicPaths(&[(Code::GET, "/x")]);
        let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
        let mut bytes = [0; 64];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        b.option(OptionNumber::URI_PATH, value).unwrap();
        let n = b.finish(&[]).unwrap();
        let shared = Shared::<128, 2>::new();
        let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                Metadata::new(
                    "192.0.2.1:1".parse().unwrap(),
                    "192.0.2.10".parse().unwrap(),
                    n,
                ),
                Instant(0),
                &mut app,
                &policy,
            )
            .unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(output.packet.as_slice()).unwrap().code(),
            Code::BAD_OPTION
        );
    }
}

#[test]
fn dot_segment_location_path_rejects_the_response() {
    let mut bytes = [0; 64];
    let mut b = MessageBuilder::new(
        &mut bytes,
        MessageType::Acknowledgement,
        Code::CREATED,
        1,
        b"t",
    )
    .unwrap();
    b.option(OptionNumber::LOCATION_PATH, b"a").unwrap();
    b.option(OptionNumber::LOCATION_PATH, b"..").unwrap();
    let n = b.finish(&[]).unwrap();
    let message = MessageView::parse(&bytes[..n]).unwrap();
    // Elective, but dropping one segment would change the location.
    assert_eq!(
        message.check_options(|_| true),
        Err(Error::BadOption(OptionNumber::LOCATION_PATH))
    );
    // An unrecognized elective option is ignored (RFC 7252 section 5.4.1).
    assert_eq!(message.check_options(|_| false), Ok(()));
}

#[test]
fn escaped_relative_targets_need_only_wire_capacity() {
    // The escaped path is longer than the 64-byte datagram; its options are not.
    let target = format!("/{}", "%41".repeat(30));
    let shared = Shared::<64, 2>::new();
    let mut endpoint = Endpoint::<_, 64, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let exchange = shared
        .handle()
        .client(SocketAddr::from(([192, 0, 2, 1], 5683)))
        .request(Code::GET, &target)
        .unwrap()
        .send()
        .unwrap();
    endpoint.poll(Instant(0)).unwrap();
    let output = endpoint.pop_outgoing().unwrap();
    let message = MessageView::parse(output.packet.as_slice()).unwrap();
    assert_eq!(paths(message), [b"A".repeat(30)]);
    drop(exchange);
}

#[test]
fn response_builder_refuses_dot_segment_paths() {
    let mut response = Response::<128>::new(Code::CREATED);
    response.option(OptionNumber::LOCATION_PATH, b"a").unwrap();
    for number in [OptionNumber::LOCATION_PATH, OptionNumber::URI_PATH] {
        assert_eq!(
            response.option(number, b".."),
            Err(ResponseError::InvalidOption)
        );
        assert_eq!(
            response.set_option(number, b"."),
            Err(ResponseError::InvalidOption)
        );
    }
    // The rejected replacement left the existing Location-Path in place.
    let mut bytes = [0; 64];
    let n = response
        .encode(&mut bytes, MessageType::Acknowledgement, 1, &[])
        .unwrap();
    let encoded = MessageView::parse(&bytes[..n]).unwrap();
    let locations: Vec<_> = encoded.values(OptionNumber::LOCATION_PATH).collect();
    assert_eq!(locations, [b"a".as_slice()]);
}
