//! URI decomposition and composition, including escaped option boundaries.
use mai_coap::{
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    uri::{self, Uri},
};

#[test]
fn msg_4_7_srv_4_uri_composition_roundtrip_ipv6_queries_and_empty_segments() {
    for input in [
        "coap://[2001:db8::1]:1234/a%2Fb//c?q=x%26y&&z=%ff",
        "CoAP://local%68ost/hello?",
        "coap://127.0.0.1/",
        "coap://example.org/a@b:c?x=/yes?no",
    ] {
        let mut a = [0; 512];
        let mut b =
            MessageBuilder::new(&mut a, MessageType::Confirmable, Code::GET, 1, b"x").unwrap();
        Uri::parse(input)
            .unwrap()
            .options_with_scratch(&mut b, &mut [0; 512])
            .unwrap();
        let n = b.finish(&[]).unwrap();
        let message = MessageView::parse(&a[..n]).unwrap();
        let mut composed = [0; 1024];
        let normalized =
            uri::compose(message, "192.0.2.1:5683".parse().unwrap(), &mut composed).unwrap();
        let mut bytes = [0; 512];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"x").unwrap();
        Uri::parse(normalized)
            .unwrap()
            .options_with_scratch(&mut b, &mut [0; 512])
            .unwrap();
        let used = b.finish(&[]).unwrap();
        assert_eq!(&a[..n], &bytes[..used], "{normalized}");
        assert!(uri::compose(message, "192.0.2.1:5683".parse().unwrap(), &mut [0; 5]).is_err());
    }
    for bad in [
        "coaps://host/",
        "coap://[::1",
        "coap://host:65536/",
        "coap://host/%xz",
        "coap://host/#fragment",
        "coap://user@host/",
        "coap://host^/",
        "coap://host/\\bad",
    ] {
        assert!(Uri::parse(bad).is_err(), "{bad}");
    }
    let mut bytes = [0; 128];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, 0, &[]).unwrap();
    let uri = Uri::parse("coap://host/x?a=b").unwrap();
    uri.authority_options(&mut b).unwrap();
    uri::path_options(uri.path, &mut b).unwrap();
    b.uint_option(OptionNumber::CONTENT_FORMAT, 60).unwrap();
    uri::query_options(uri.query, &mut b).unwrap();
    b.finish(&[]).unwrap();
}

#[test]
fn msg_7_rfc3986_reference_resolution_removes_dot_segments() {
    for (path, expected) in [
        ("/a/b/c/./../../g", "/a/g"),
        ("mid/content=5/../6", "mid/6"),
        ("/a//b/../", "/a//"),
        ("/a/.", "/a/"),
        ("/a/..", "/"),
        ("../a", "a"),
    ] {
        let mut bytes = [0; 128];
        let n = uri::normalize_path(path.as_bytes(), &mut bytes).unwrap();
        assert_eq!(&bytes[..n], expected.as_bytes());
    }
}

#[test]
fn msg_7_uri_normalization_uses_caller_capacity() {
    let path = "/segment".repeat(200);
    let uri = format!("coap://example.org{path}/../last");
    let mut bytes = [0; 2048];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"x").unwrap();
    Uri::parse(&uri)
        .unwrap()
        .options_with_scratch(&mut b, &mut [0; 2048])
        .unwrap();
    let n = b.finish(&[]).unwrap();
    let message = MessageView::parse(&bytes[..n]).unwrap();
    let paths: Vec<_> = message.values(OptionNumber::URI_PATH).collect();
    assert_eq!(paths.len(), 200);
    assert_eq!(paths[199], b"last");
}
