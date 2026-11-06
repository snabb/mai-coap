//! CoRE link formatting and policy-filtered discovery.
#![cfg(feature = "link-format")]
mod support;
use mai_coap::link_format::{Links, Writer};
#[cfg(any(feature = "discovery", all(feature = "server", feature = "block")))]
use support::PopOutgoing;

#[test]
fn singleton_attributes_relations_and_long_values_follow_link_matching_rules() {
    for name in ["ct", "rt", "if", "sz"] {
        let text = format!("</x>;{name}=one;{name}=two");
        assert!(
            Links::new(text.as_bytes())
                .unwrap()
                .next()
                .unwrap()
                .is_err()
        );
        let mut bytes = [0; 128];
        let mut writer = Writer::new(&mut bytes);
        assert!(
            writer
                .link("/x", &[(name, Some("one")), (name, Some("two"))])
                .is_err()
        );
        assert!(writer.is_empty());
    }
    let value = "a".repeat(300);
    let text = format!(
        r#"</x>;title="{value}";rt="long-{value} temperature";rel="alternate describedby""#
    );
    let link = Links::new(text.as_bytes())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(link.matches(&format!("title={value}")).unwrap());
    assert!(link.matches("title=aaa*").unwrap());
    assert!(!link.matches("title=absent").unwrap());
    assert!(link.matches("rt=temperature").unwrap());
    assert!(link.matches("rt=long-aaa*").unwrap());
    assert!(!link.matches("rt=perature").unwrap());
    assert!(link.matches("rel=describedby").unwrap());
    let escaped = Links::new(br#"</x>;rel="alternate\ describedby";title="a\"b""#)
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(escaped.matches("rel=describedby").unwrap());
    assert!(escaped.matches("title=a\"b").unwrap());
    let text = format!(r#"</first>;title="{value}",</second>;title="wanted""#);
    let mut links = Links::new(text.as_bytes())
        .unwrap()
        .map(|l| l.unwrap().matches("title=wanted"));
    assert_eq!(links.next().unwrap(), Ok(false));
    assert_eq!(links.next().unwrap(), Ok(true));
}

#[cfg(feature = "discovery")]
#[test]
fn discovery_encodes_decoded_paths_and_rejects_invalid_attributes_at_registration() {
    use mai_coap::{
        Error,
        codec::{Code, MessageBuilder, MessageType, MessageView},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        server::Router,
        time::Instant,
        transport::Metadata,
    };
    let path = "/my resource%?#<>\"é";
    let policy = PublicPaths(&[(Code::GET, "/.well-known/core"), (Code::GET, path)]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256>::new(&policy);
    router.route(path, &[Code::GET], &mut handler).unwrap();
    for bad in [
        &[("bad name", None)][..],
        &[("title", Some("bad\nvalue"))],
        &[("rt", Some("one")), ("rt", Some("two"))],
        &[("if", Some("one")), ("if", Some("two"))],
        &[("sz", Some("1")), ("sz", Some("2"))],
    ] {
        assert_eq!(router.describe(path, bad, false), Err(Error::Malformed));
    }
    router
        .describe(path, &[("rt", Some("sensor"))], false)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    mai_coap::uri::path_options("/.well-known/core", &mut b).unwrap();
    let n = b.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..n],
            Metadata::new(
                "192.0.2.1:1".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.code(), Code::CONTENT);
    let link = Links::new(response.payload())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(link.href(), "/my%20resource%25%3F%23%3C%3E%22%C3%A9");
}

#[test]
fn dsc_2_3_attributes_quoted_escapes_queries_and_atomic_writer() {
    let mut bytes = [0; 512];
    let mut writer = Writer::new(&mut bytes);
    writer
        .link(
            "/sensor",
            &[
                ("rt", Some("temperature outdoor")),
                ("title", Some("a, \"b\"")),
                ("obs", None),
            ],
        )
        .unwrap();
    let n = writer.len();
    assert!(writer.link("/bad", &[("invalid name", None)]).is_err());
    assert_eq!(writer.len(), n);
    let link = Links::new(&bytes[..n]).unwrap().next().unwrap().unwrap();
    assert!(link.matches("rt=temp*").unwrap());
    assert!(link.matches("rt=outdoor").unwrap());
    assert!(link.matches("href=/sen*").unwrap());
    assert!(!link.matches("ct=60").unwrap());
    assert!(!link.matches("title=\"b\"").unwrap());
    let title = Links::new(b"</x>;title=\"a & b\"")
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(title.matches("title=a & b").unwrap());
    assert!(!title.matches("title=b").unwrap());
    let title = link
        .attributes()
        .map(Result::unwrap)
        .find(|a| a.name == "title")
        .unwrap();
    let mut decoded = [0; 64];
    let n = title.decode_value(&mut decoded).unwrap();
    assert_eq!(&decoded[..n], b"a, \"b\"");
    for bad in [
        b"</a>;ct=0;ct=40".as_slice(),
        b"</a>;title=\"open",
        b"</a>,",
        b"</a>;x=\"ok\"trailing",
    ] {
        assert!(Links::new(bad).unwrap().any(|l| l.is_err()));
    }
}

#[cfg(feature = "discovery")]
#[test]
fn dsc_1_2_aut_6_filtered_discovery_hides_inaccessible_resources() {
    use mai_coap::{
        codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        server::Router,
        time::Instant,
        transport::Metadata,
    };
    let policy = PublicPaths(&[(Code::GET, "/.well-known/core"), (Code::GET, "/public")]);
    let mut a = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut b = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256>::new(&policy);
    router.route("/public", &[Code::GET], &mut a).unwrap();
    router
        .describe(
            "/public",
            &[("ct", Some("0")), ("rt", Some("temperature"))],
            false,
        )
        .unwrap();
    router.route("/private", &[Code::GET], &mut b).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (id, query, expected) in [(0, "rt=temp*", true), (1, "rt=absent", false)] {
        let mut bytes = [0; 256];
        let mut builder =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, id, b"t").unwrap();
        mai_coap::uri::path_options("/.well-known/core", &mut builder).unwrap();
        builder
            .option(OptionNumber::URI_QUERY, query.as_bytes())
            .unwrap();
        let n = builder.finish(&[]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                Metadata::new(
                    "192.0.2.1:5683".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    n,
                ),
                Instant(id.into()),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(response.code(), Code::CONTENT);
        assert_eq!(
            response
                .option(OptionNumber::CONTENT_FORMAT)
                .unwrap()
                .uint(),
            Ok(40)
        );
        let links: Vec<_> = Links::new(response.payload())
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(links.len(), usize::from(expected));
        if expected {
            assert_eq!(links[0].href(), "/public");
        }
    }
}

#[cfg(feature = "discovery")]
#[test]
fn dsc_1_blk_2_discovery_streams_large_links_with_a_stable_etag() {
    use mai_coap::{
        block::{Block, etag},
        codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        server::Router,
        time::Instant,
        transport::Metadata,
    };
    let title = "large title ".repeat(500);
    let attributes = [("title", Some(title.as_str()))];
    let mut expected = vec![0; 8000];
    let mut writer = Writer::new(&mut expected);
    writer.link("/x", &attributes).unwrap();
    let n = writer.len();
    expected.truncate(n);
    assert!(expected.len() > 4096);
    let validator = etag(&expected);
    let policy = PublicPaths(&[(Code::GET, "/.well-known/core"), (Code::GET, "/x")]);
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.route("/x", &[Code::GET], &mut app).unwrap();
    router.describe("/x", &attributes, false).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut collected = Vec::new();
    for index in 0..expected.len().div_ceil(64) {
        let mut bytes = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            index as u16,
            b"d",
        )
        .unwrap();
        mai_coap::uri::path_options("/.well-known/core", &mut b).unwrap();
        b.option(OptionNumber::URI_QUERY, b"href=/x").unwrap();
        b.uint_option(
            OptionNumber::BLOCK2,
            Block::new(index as u32, false, 2)
                .unwrap()
                .encode()
                .unwrap(),
        )
        .unwrap();
        let n = b.finish(&[]).unwrap();
        let metadata = Metadata::new(
            "192.0.2.1:5683".parse().unwrap(),
            "192.0.2.2".parse().unwrap(),
            n,
        );
        endpoint
            .receive(
                &bytes[..n],
                metadata,
                Instant(index as u64 * 1000),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(response.code(), Code::CONTENT);
        assert_eq!(
            response.option(OptionNumber::ETAG).unwrap().value,
            validator
        );
        collected.extend_from_slice(response.payload());
    }
    assert_eq!(collected, expected);
}

#[cfg(all(feature = "server", feature = "block"))]
#[test]
fn representation_error_after_filling_payload_returns_no_body() {
    use mai_coap::{
        codec::{Code, ContentFormat, MessageBuilder, MessageType, MessageView, OptionNumber},
        endpoint::{Endpoint, Shared, Unsecured},
        security::PublicPaths,
        server::{Router, SliceBody},
        time::Instant,
        transport::Metadata,
    };

    let policy = PublicPaths(&[(Code::GET, "/body")]);
    let mut source = SliceBody::new(b"representation", ContentFormat::TEXT);
    let mut router = Router::<128>::new(&policy);
    router.representation("/body", &mut source).unwrap();
    let shared = Shared::<128, 2>::new();
    let mut endpoint = Endpoint::<_, 128, 2, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut bytes = [0; 128];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"t").unwrap();
    builder.option(OptionNumber::URI_PATH, b"body").unwrap();
    builder
        .uint_option(OptionNumber::ACCEPT, ContentFormat::CBOR.0.into())
        .unwrap();
    let length = builder.finish(&[]).unwrap();
    endpoint
        .receive(
            &bytes[..length],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                length,
            ),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let outgoing = endpoint.pop_outgoing().unwrap();
    let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
    assert_eq!(response.code(), Code::NOT_ACCEPTABLE);
    assert!(response.payload().is_empty());
}

#[cfg(feature = "discovery")]
#[test]
fn dsc_1_long_route_policy_probes_keep_the_full_arena_with_an_eight_byte_token() {
    use mai_coap::{
        codec::{Code, MessageBuilder, MessageType, MessageView},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        server::Router,
        time::Instant,
        transport::Metadata,
    };
    // The synthetic policy request is exactly 128 bytes: four-byte header,
    // two option-header bytes and the 122-byte decoded path segment.
    let path = format!("/{}", "x".repeat(122));
    let entries = [(Code::GET, "/.well-known/core"), (Code::GET, path.as_str())];
    let policy = PublicPaths(&entries);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 128>| Ok(Disposition::Complete);
    let mut router = Router::<128>::new(&policy);
    router.set_block_caps(1, 1).unwrap();
    router.route(&path, &[Code::GET], &mut handler).unwrap();
    let shared = Shared::<128, 1>::new();
    let mut endpoint = Endpoint::<_, 128, 1, 4>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut wire = [0; 128];
    let mut builder = MessageBuilder::new(
        &mut wire,
        MessageType::Confirmable,
        Code::GET,
        1,
        b"token123",
    )
    .unwrap();
    mai_coap::uri::path_options("/.well-known/core", &mut builder).unwrap();
    let n = builder.finish(&[]).unwrap();
    endpoint
        .receive(
            &wire[..n],
            Metadata::new(
                "192.0.2.1:5683".parse().unwrap(),
                "192.0.2.2".parse().unwrap(),
                n,
            ),
            Instant(0),
            &mut router,
            &policy,
        )
        .unwrap();
    let reply = MessageView::parse(endpoint.front_outgoing().unwrap().bytes).unwrap();
    assert_eq!(reply.code(), Code::CONTENT);
    assert_eq!(reply.token(), b"token123");
    assert_eq!(reply.payload(), &format!("<{path}>").as_bytes()[..32]);
}
