//! Block geometry, consistency, transactional writes and resource integration.
#![cfg(feature = "block")]
mod support;
#[cfg(feature = "block1")]
use mai_coap::block::{BodyKey, BufferedUpload, Progress, StreamingUpload, UploadSink};
#[cfg(any(feature = "server", feature = "block1"))]
use mai_coap::codec::Code;
#[cfg(feature = "server")]
use mai_coap::server::BodyWindow;
#[cfg(feature = "block1")]
use mai_coap::time::Instant;
use mai_coap::{
    Error,
    block::{Block, Download},
};
#[cfg(all(feature = "server", feature = "client", feature = "block1"))]
use support::PopOutgoing;

#[cfg(feature = "block1")]
#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    begins: usize,
    writes: usize,
    commits: usize,
    aborts: usize,
    fail: bool,
}
#[cfg(feature = "block1")]
impl UploadSink for Sink {
    fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
        self.begins += 1;
        self.bytes.clear();
        Ok(())
    }
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.writes += 1;
        if self.fail {
            return Err(Error::Capacity);
        }
        assert_eq!(offset, self.bytes.len());
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn commit(&mut self) -> Result<(), Error> {
        self.commits += 1;
        Ok(())
    }
    fn abort(&mut self) {
        self.aborts += 1;
    }
}
#[cfg(feature = "block1")]
fn key() -> BodyKey {
    BodyKey {
        remote: "192.0.2.1:1".parse().unwrap(),
        resource: 1,
        context: Some(1),
        match_options: [0; 32],
        tags: heapless::Vec::new(),
    }
}

#[test]
fn blk_1_2_geometry_cap_random_access_and_rfc7959_values() {
    for szx in 0..=6 {
        let block = Block::new(0xfffff, true, szx).unwrap();
        assert_eq!(Block::decode(block.encode().unwrap()), Ok(block));
        assert_eq!(block.size().unwrap(), 1 << (szx + 4));
    }
    assert!(Block::new(0x100000, false, 0).is_err());
    assert!(Block::decode(7).is_err());
    let block = Block::new(2, false, 6).unwrap().capped(0).unwrap();
    assert_eq!(block.number, 128);
    assert_eq!(block.offset().unwrap(), 2048);
    let source = [3; 2100];
    let (actual, slice) = block.slice(&source, 0).unwrap();
    assert!(actual.more);
    assert_eq!(slice.len(), 16);
    assert_eq!(Block::new(0, true, 6).unwrap().encode(), Ok(14));
}

#[cfg(feature = "server")]
#[test]
fn body_window_hashes_the_full_binary_representation() {
    use mai_coap::{block::etag, codec::ContentFormat};

    let body: Vec<u8> = (0..97).map(|n| (n * 37) as u8).collect();
    for (offset, capacity) in [(0, 16), (13, 11), (91, 16)] {
        let mut output = [0xa5; 16];
        let mut window = BodyWindow::new(offset, &mut output[..capacity]);
        window.write(&body[..7]).unwrap();
        window.write(&body[7..48]).unwrap();
        window.write(&body[48..]).unwrap();
        let chunk = window.finish(ContentFormat::OCTET_STREAM, 17).unwrap();
        assert_eq!(chunk.total, Some(body.len()));
        assert_eq!(chunk.written, (body.len() - offset).min(capacity));
        assert_eq!(
            &output[..chunk.written],
            &body[offset..offset + chunk.written]
        );
        assert_eq!(chunk.etag.as_slice(), &etag(&body)[..]);
        assert_eq!(chunk.max_age, 17);
    }
    assert_eq!(
        BodyWindow::new(98, &mut [0; 8])
            .finish(ContentFormat::OCTET_STREAM, 0)
            .unwrap_err(),
        Code::BAD_OPTION
    );
}

#[cfg(feature = "server")]
#[test]
fn body_window_etag_tracks_each_exact_rendered_snapshot() {
    use mai_coap::codec::ContentFormat;

    let mut output = [0; 4];
    let mut first_window = BodyWindow::new(0, &mut output);
    first_window.write(b"snapshot one").unwrap();
    let first = first_window
        .finish(ContentFormat::OCTET_STREAM, 60)
        .unwrap();
    let mut second_window = BodyWindow::new(0, &mut output);
    second_window.write(b"snapshot two").unwrap();
    let second = second_window
        .finish(ContentFormat::OCTET_STREAM, 60)
        .unwrap();
    assert_ne!(first.etag, second.etag);
    assert_eq!(&output[..], b"snap");
}
#[cfg(feature = "block1")]
#[test]
fn blk_4a_5_buffered_limits_order_duplicates_expiry_and_tag_boundaries() {
    let mut upload = BufferedUpload::<32>::new(Instant(100));
    let first = Block::new(0, true, 0).unwrap();
    let final_block = Block::new(1, false, 0).unwrap();
    assert_eq!(
        upload.push(final_block, b"end", None, Instant(0), Instant(100)),
        Err(Error::Response(Code::INCOMPLETE))
    );
    assert_eq!(
        upload.push(first, &[7; 16], Some(40), Instant(0), Instant(100)),
        Err(Error::Response(Code::TOO_LARGE))
    );
    assert_eq!(
        upload.push(first, &[7; 16], Some(19), Instant(0), Instant(100)),
        Ok(Progress::Continue)
    );
    assert_eq!(upload.complete_body(), None);
    assert_eq!(
        upload.push(first, &[7; 16], Some(19), Instant(1), Instant(100)),
        Ok(Progress::Duplicate)
    );
    assert_eq!(
        upload.push(final_block, b"end", Some(19), Instant(2), Instant(100)),
        Ok(Progress::Complete)
    );
    assert_eq!(
        upload.complete_body().unwrap(),
        &[&[7; 16][..], b"end"].concat()
    );
    assert_eq!(
        upload.push(final_block, b"end", Some(19), Instant(3), Instant(100)),
        Ok(Progress::Duplicate)
    );
    assert_eq!(
        upload.push(final_block, b"end", None, Instant(100), Instant(200)),
        Ok(Progress::Duplicate)
    );
    assert_eq!(upload.complete_body().unwrap().len(), 19);
    let mut a = key();
    a.add_tag(b"a").unwrap();
    a.add_tag(b"bc").unwrap();
    let mut b = key();
    b.add_tag(b"ab").unwrap();
    b.add_tag(b"c").unwrap();
    assert_ne!(a, b);
    let mut c = a.clone();
    c.context = Some(2);
    assert_ne!(a, c);
}
#[cfg(feature = "block1")]
#[test]
fn blk_4a_expired_partial_body_can_restart_without_stale_ordering() {
    let mut upload = BufferedUpload::<32>::new(Instant(100));
    let first = Block::new(0, true, 0).unwrap();
    let last = Block::new(1, false, 0).unwrap();
    upload
        .push(first, &[1; 16], None, Instant(0), Instant(100))
        .unwrap();
    assert_eq!(
        upload.push(last, b"old", None, Instant(100), Instant(200)),
        Err(Error::Timeout)
    );
    assert_eq!(upload.complete_body(), None);
    assert_eq!(
        upload.push(first, &[2; 16], None, Instant(101), Instant(200)),
        Ok(Progress::Continue)
    );
    assert_eq!(
        upload.push(last, b"new", None, Instant(102), Instant(200)),
        Ok(Progress::Complete)
    );
    assert_eq!(
        upload.complete_body().unwrap(),
        &[&[2; 16][..], b"new"].concat()
    );
}
#[cfg(feature = "block1")]
#[test]
fn blk_4b_streaming_exactly_once_commit_abort_and_retry_bytes() {
    let mut sink = Sink::default();
    assert!(StreamingUpload::<16>::begin(&key(), Some(33), 32, Instant(100), &mut sink).is_err());
    assert_eq!(sink.begins, 0);
    let mut upload =
        StreamingUpload::<16>::begin(&key(), Some(19), 32, Instant(100), &mut sink).unwrap();
    let first = Block::new(0, true, 0).unwrap();
    let final_block = Block::new(1, false, 0).unwrap();
    assert_eq!(
        upload.push(first, &[7; 16], Instant(0), Instant(100), &mut sink),
        Ok(Progress::Continue)
    );
    assert_eq!(
        upload.push(first, &[7; 16], Instant(1), Instant(100), &mut sink),
        Ok(Progress::Duplicate)
    );
    assert_eq!(sink.writes, 1);
    assert_eq!(sink.commits, 0);
    assert_eq!(
        upload.push(
            Block::new(2, false, 0).unwrap(),
            b"end",
            Instant(1),
            Instant(100),
            &mut sink
        ),
        Err(Error::Response(Code::INCOMPLETE))
    );
    assert_eq!(
        upload.push(final_block, b"end", Instant(2), Instant(100), &mut sink),
        Ok(Progress::Complete)
    );
    assert_eq!(
        upload.push(final_block, b"end", Instant(3), Instant(100), &mut sink),
        Ok(Progress::Duplicate)
    );
    assert_eq!(sink.writes, 2);
    assert_eq!(sink.commits, 1);
    assert!(!upload.expire(Instant(101), &mut sink));
    assert_eq!(sink.aborts, 0);
    let mut upload =
        StreamingUpload::<16>::begin(&key(), None, 32, Instant(100), &mut sink).unwrap();
    sink.fail = true;
    assert!(
        upload
            .push(first, &[7; 16], Instant(0), Instant(100), &mut sink)
            .is_err()
    );
    assert!(upload.closed());
    assert_eq!(sink.aborts, 1);
    assert!(
        upload
            .push(first, &[7; 16], Instant(1), Instant(100), &mut sink)
            .is_err()
    );
    assert!(!upload.expire(Instant(101), &mut sink));
    assert_eq!(sink.aborts, 1);
}
#[test]
fn blk_3_download_restart_bound_and_resume_etag() {
    let mut download = Download::new(16).with_restart_limit(1);
    assert_eq!(
        download.accept(Block::new(1, true, 0).unwrap(), &[1; 16], Some(b"a")),
        Ok(true)
    );
    assert_eq!(
        download.accept(Block::new(2, false, 0).unwrap(), b"end", Some(b"b")),
        Ok(false)
    );
    assert_eq!(download.next_offset(), 0);
    assert_eq!(
        download.accept(Block::new(0, true, 0).unwrap(), &[1; 16], Some(b"b")),
        Ok(true)
    );
    assert_eq!(
        download.accept(Block::new(1, false, 0).unwrap(), b"end", Some(b"c")),
        Err(Error::RepresentationChanged)
    );
}

#[cfg(all(feature = "server", feature = "client", feature = "block1"))]
mod resources {
    use super::*;
    use mai_coap::{
        codec::{MessageBuilder, MessageType, MessageView, OptionNumber},
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        server::Router,
        transport::Metadata,
    };
    #[test]
    fn blk_4_duplicate_final_block_replays_content_with_its_current_token() {
        let shared = Shared::<256, 2>::new();
        let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut calls = 0;
        let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            calls += 1;
            response.set_code(Code::CHANGED);
            response.option(OptionNumber::ETAG, b"tag").unwrap();
            response.set_payload(b"done").unwrap();
            Ok(Disposition::Complete)
        };
        let policy = PublicPaths(&[(Code::POST, "/upload")]);
        let mut router = Router::<256, 2, 1, 32>::new(&policy);
        router
            .buffered_upload("/upload", &[Code::POST], &mut handler)
            .unwrap();
        let first = Block::new(0, true, 0).unwrap();
        let last = Block::new(1, false, 0).unwrap();
        for (mid, token, block, body) in [
            (1, &b"first"[..], first, &[7; 16][..]),
            (2, b"last", last, b"end"),
            (3, b"retried", last, b"end"),
        ] {
            let mut bytes = [0; 256];
            let mut b =
                MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, mid, token)
                    .unwrap();
            b.option(OptionNumber::URI_PATH, b"upload").unwrap();
            b.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
                .unwrap();
            let n = b.finish(body).unwrap();
            endpoint
                .receive(
                    &bytes[..n],
                    Metadata::new(
                        "192.0.2.1:5683".parse().unwrap(),
                        "192.0.2.2".parse().unwrap(),
                        n,
                    ),
                    Instant(u64::from(mid)),
                    &mut router,
                    &policy,
                )
                .unwrap();
            let outgoing = endpoint.pop_outgoing().unwrap();
            let reply = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(reply.message_id(), mid);
            assert_eq!(reply.token(), token);
            assert_eq!(
                reply.option(OptionNumber::BLOCK1).unwrap().uint(),
                Ok(block.encode().unwrap())
            );
            if block == last {
                assert_eq!(reply.code(), Code::CHANGED);
                assert_eq!(reply.option(OptionNumber::ETAG).unwrap().value, b"tag");
                assert_eq!(reply.payload(), b"done");
            } else {
                assert_eq!(reply.code(), Code::CONTINUE);
            }
        }
        drop(router);
        assert_eq!(calls, 1);
    }
    #[test]
    fn srv_3_blk_4_5_buffered_dispatch_final_duplicate_and_size1_response() {
        let shared = Shared::<256, 2>::new();
        let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
        let mut bodies = Vec::new();
        let mut handler = |request: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
            bodies.push(request.payload().to_vec());
            response.set_code(Code::CHANGED);
            Ok(Disposition::Complete)
        };
        let policy = PublicPaths(&[(Code::POST, "/upload")]);
        {
            let mut router = Router::<256, 2, 1, 32>::new(&policy);
            router
                .buffered_upload("/upload", &[Code::POST], &mut handler)
                .unwrap();
            for (index, (block, payload, tag, size, expected)) in [
                (
                    Block::new(0, true, 0).unwrap(),
                    &[7; 16][..],
                    b"one".as_slice(),
                    19,
                    Code::CONTINUE,
                ),
                (
                    Block::new(1, false, 0).unwrap(),
                    b"end".as_slice(),
                    b"two".as_slice(),
                    19,
                    Code::INCOMPLETE,
                ),
                (
                    Block::new(1, false, 0).unwrap(),
                    b"end".as_slice(),
                    b"one".as_slice(),
                    19,
                    Code::CHANGED,
                ),
                (
                    Block::new(1, false, 0).unwrap(),
                    b"end".as_slice(),
                    b"one".as_slice(),
                    19,
                    Code::CHANGED,
                ),
            ]
            .iter()
            .enumerate()
            {
                let mut bytes = [0; 256];
                let mut b = MessageBuilder::new(
                    &mut bytes,
                    MessageType::Confirmable,
                    Code::POST,
                    index as u16,
                    b"t",
                )
                .unwrap();
                b.option(OptionNumber::URI_PATH, b"upload").unwrap();
                b.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
                    .unwrap();
                b.uint_option(OptionNumber::SIZE1, *size).unwrap();
                b.option(OptionNumber::REQUEST_TAG, tag).unwrap();
                let n = b.finish(payload).unwrap();
                endpoint
                    .receive(
                        &bytes[..n],
                        Metadata::new(
                            "192.0.2.1:5683".parse().unwrap(),
                            "192.0.2.2".parse().unwrap(),
                            n,
                        ),
                        Instant(index as u64),
                        &mut router,
                        &policy,
                    )
                    .unwrap();
                let outgoing = endpoint.pop_outgoing().unwrap();
                let response = MessageView::parse(outgoing.packet.as_slice()).unwrap();
                assert_eq!(response.code(), *expected);
                assert!(response.check_options(|_| true).is_ok());
            }
        }
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].len(), 19);
    }
}

#[cfg(all(feature = "server", feature = "client", feature = "software-crypto"))]
#[cfg(feature = "block1")]
#[test]
fn blk_5_osc_15_partial_body_retains_its_epoch_until_commit() {
    use mai_coap::{
        codec::{MessageBuilder, MessageType, MessageView, OptionNumber},
        crypto::SoftwareCrypto,
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared},
        oscore::{Context, Oscore},
        security::{PeerId, ProtectedOnly},
        server::Router,
        transport::Metadata,
    };
    let remote = "192.0.2.1:5683".parse().unwrap();
    let mut cp = SoftwareCrypto::new(rand::rng());
    let mut client = Context::derive(&mut cp, &[1; 16], None, &[0], &[1], None, PeerId(1)).unwrap();
    let mut sp = SoftwareCrypto::new(rand::rng());
    let server = Context::derive(&mut sp, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
    let mut protection = Oscore::<_, 1>::new(sp);
    protection.install_fresh(server).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, protection).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        response.set_code(Code::CHANGED);
        Ok(Disposition::Complete)
    };
    let mut router = Router::<256>::new(&ProtectedOnly);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    for (number, payload, more) in [(0, &[1; 16][..], true), (1, b"end".as_slice(), false)] {
        let mut bytes = [0; 256];
        let mut wire = [0; 256];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::POST,
            number as u16,
            b"t",
        )
        .unwrap();
        b.option(OptionNumber::URI_PATH, b"upload").unwrap();
        b.uint_option(
            OptionNumber::BLOCK1,
            Block::new(number, more, 0).unwrap().encode().unwrap(),
        )
        .unwrap();
        b.uint_option(OptionNumber::SIZE1, 19).unwrap();
        b.option(OptionNumber::REQUEST_TAG, b"one").unwrap();
        let n = b.finish(payload).unwrap();
        let (n, _) = client
            .protect_request::<256>(&mut cp, MessageView::parse(&bytes[..n]).unwrap(), &mut wire)
            .unwrap();
        endpoint
            .receive(
                &wire[..n],
                Metadata::new(remote, "192.0.2.2".parse().unwrap(), n),
                Instant(number as u64),
                &mut router,
                &ProtectedOnly,
            )
            .unwrap();
        endpoint.pop_outgoing().unwrap();
        let p = endpoint.protection_mut();
        let next = Context::derive(
            &mut SoftwareCrypto::new(rand::rng()),
            &[2; 16],
            None,
            &[3],
            &[2],
            None,
            PeerId(2),
        )
        .unwrap();
        let result = p.install_fresh(next);
        if more {
            assert_eq!(result, Err(Error::Capacity));
        } else {
            assert!(result.is_ok());
        }
    }
}

#[cfg(feature = "block1")]
#[test]
fn blk_5_matchable_requests_bind_method_query_format_but_not_block_coordinates() {
    use mai_coap::codec::{MessageBuilder, MessageType, MessageView, OptionNumber};
    let make = |method, query: &[u8], format, block| {
        let mut bytes = [0; 128];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, method, 0, b"t").unwrap();
        b.option(OptionNumber::URI_PATH, b"image").unwrap();
        b.uint_option(OptionNumber::CONTENT_FORMAT, format).unwrap();
        b.option(OptionNumber::URI_QUERY, query).unwrap();
        b.uint_option(OptionNumber::BLOCK1, block).unwrap();
        b.option(OptionNumber::REQUEST_TAG, b"body").unwrap();
        let n = b.finish(&[]).unwrap();
        BodyKey::from_request(
            "192.0.2.1:5683".parse().unwrap(),
            1,
            Some(1),
            MessageView::parse(&bytes[..n]).unwrap(),
        )
        .unwrap()
    };
    let initial = make(Code::PUT, b"slot=a", 42, 8);
    assert_eq!(initial, make(Code::PUT, b"slot=a", 42, 16));
    assert_ne!(initial, make(Code::POST, b"slot=a", 42, 16));
    assert_ne!(initial, make(Code::PUT, b"slot=b", 42, 16));
    assert_ne!(initial, make(Code::PUT, b"slot=a", 60, 16));
}
