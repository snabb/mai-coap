//! Router Block1 table reclamation, restart and timeout behavior (BLK-4).
#![cfg(all(feature = "server", feature = "client", feature = "block1"))]
mod support;
use mai_coap::{
    Error,
    block::Block,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
    security::PublicPaths,
    server::Router,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

fn block_request(mid: u16, block: Block, payload: &[u8], out: &mut [u8; 256]) -> usize {
    let mut b = MessageBuilder::new(out, MessageType::Confirmable, Code::POST, mid, b"t").unwrap();
    b.option(OptionNumber::URI_PATH, b"upload").unwrap();
    b.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
        .unwrap();
    b.finish(payload).unwrap()
}

fn meta(remote: &str, n: usize) -> Metadata {
    Metadata::new(remote.parse().unwrap(), "192.0.2.2".parse().unwrap(), n)
}

#[test]
fn blk_4_finished_body_can_start_another_upload() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        response.set_code(Code::CHANGED);
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 2, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    let mut codes = Vec::new();
    let steps: [(&str, u16, Block, &[u8]); 5] = [
        (
            "192.0.2.1:5683",
            1,
            Block::new(0, true, 0).unwrap(),
            &[1; 16],
        ),
        (
            "192.0.2.1:5683",
            2,
            Block::new(1, false, 0).unwrap(),
            b"end",
        ),
        // Same client, new upload, 1 s later.
        (
            "192.0.2.1:5683",
            3,
            Block::new(0, true, 0).unwrap(),
            &[2; 16],
        ),
        // Different client.
        (
            "192.0.2.9:5683",
            4,
            Block::new(0, true, 0).unwrap(),
            &[3; 16],
        ),
        (
            "192.0.2.9:5683",
            5,
            Block::new(0, true, 0).unwrap(),
            &[3; 16],
        ),
    ];
    for (i, (remote, mid, block, payload)) in steps.iter().enumerate() {
        let mut bytes = [0; 256];
        let n = block_request(*mid, *block, payload, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(1000 * (i as u64 + 1)),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        codes.push(MessageView::parse(out.packet.as_slice()).unwrap().code());
    }
    assert_eq!(codes[2], Code::CONTINUE, "second upload from same client");
    assert_eq!(codes[3], Code::CONTINUE, "upload from another client");
}

#[test]
fn blk_4_table_reclaims_completed_without_interrupting_active_bodies() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let calls = core::cell::Cell::new(0);
    let mut handler = |_: Request<'_>, response: &mut ResponseWriter<'_, 256>| {
        calls.set(calls.get() + 1);
        response.set_code(Code::CHANGED);
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 2, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    for (remote, mid, block, payload, code, count) in [
        (
            "192.0.2.1:5683",
            1,
            Block::new(0, true, 0).unwrap(),
            &[1; 16][..],
            Code::CONTINUE,
            0,
        ),
        (
            "192.0.2.2:5683",
            2,
            Block::new(0, false, 0).unwrap(),
            b"done".as_slice(),
            Code::CHANGED,
            1,
        ),
        (
            "192.0.2.2:5683",
            2,
            Block::new(0, false, 0).unwrap(),
            b"done".as_slice(),
            Code::CHANGED,
            1,
        ),
        (
            "192.0.2.3:5683",
            3,
            Block::new(0, true, 0).unwrap(),
            &[3; 16][..],
            Code::CONTINUE,
            1,
        ),
        (
            "192.0.2.1:5683",
            4,
            Block::new(1, false, 0).unwrap(),
            b"end".as_slice(),
            Code::CHANGED,
            2,
        ),
        (
            "192.0.2.4:5683",
            5,
            Block::new(0, true, 0).unwrap(),
            &[4; 16][..],
            Code::CONTINUE,
            2,
        ),
        (
            "192.0.2.5:5683",
            6,
            Block::new(0, true, 0).unwrap(),
            &[5; 16][..],
            Code::UNAVAILABLE,
            2,
        ),
        (
            "192.0.2.3:5683",
            7,
            Block::new(1, false, 0).unwrap(),
            b"end".as_slice(),
            Code::CHANGED,
            3,
        ),
        (
            "192.0.2.4:5683",
            8,
            Block::new(1, false, 0).unwrap(),
            b"end".as_slice(),
            Code::CHANGED,
            4,
        ),
        (
            "192.0.2.4:5683",
            9,
            Block::new(1, false, 0).unwrap(),
            b"end".as_slice(),
            Code::CHANGED,
            4,
        ),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(mid, block, payload, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(u64::from(mid)),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
            code
        );
        assert_eq!(calls.get(), count);
    }
}

#[test]
fn blk_4_upload_timeout_is_configurable() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    assert_eq!(router.set_upload_timeout(0), Err(Error::Malformed));
    router.set_upload_timeout(100).unwrap();
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    for (remote, mid, now, expected) in [
        ("192.0.2.1:5683", 1, 0, Code::CONTINUE),
        ("192.0.2.1:5683", 2, 99, Code::CONTINUE),
        ("192.0.2.1:5683", 3, 199, Code::INCOMPLETE),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(u32::from(mid - 1), true, 0).unwrap(),
            &[3; 16],
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(now),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
            expected
        );
    }
}

#[test]
fn blk_4_aborted_streams_are_reclaimed_and_timeout_aborts_only_once() {
    use core::cell::Cell;
    use mai_coap::block::{BodyKey, UploadSink};
    struct Sink<'a> {
        fail: &'a Cell<bool>,
        aborts: &'a Cell<usize>,
        commits: &'a Cell<usize>,
    }
    impl UploadSink for Sink<'_> {
        fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            Ok(())
        }
        fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
            if self.fail.replace(false) {
                Err(Error::Protection)
            } else {
                Ok(())
            }
        }
        fn commit(&mut self) -> Result<(), Error> {
            self.commits.set(self.commits.get() + 1);
            Ok(())
        }
        fn abort(&mut self) {
            self.aborts.set(self.aborts.get() + 1);
        }
    }
    let fail = Cell::new(true);
    let aborts = Cell::new(0);
    let commits = Cell::new(0);
    let mut sink = Sink {
        fail: &fail,
        aborts: &aborts,
        commits: &commits,
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.set_upload_timeout(100).unwrap();
    router
        .streaming_upload("/upload", &[Code::POST], 64, &mut sink)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (remote, mid, block, payload, now, code) in [
        (
            "192.0.2.1:5683",
            1,
            Block::new(0, true, 0).unwrap(),
            &[1; 16][..],
            0,
            Code::INTERNAL_ERROR,
        ),
        (
            "192.0.2.3:5683",
            2,
            Block::new(0, false, 0).unwrap(),
            b"done".as_slice(),
            1,
            Code::CHANGED,
        ),
        (
            "192.0.2.4:5683",
            3,
            Block::new(0, true, 0).unwrap(),
            &[2; 16][..],
            2,
            Code::CONTINUE,
        ),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(mid, block, payload, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(now),
                &mut router,
                &policy,
            )
            .unwrap();
        let output = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(output.packet.as_slice()).unwrap().code(),
            code
        );
    }
    assert_eq!(commits.get(), 1);
    assert_eq!(aborts.get(), 1);
    mai_coap::endpoint::Application::poll(
        &mut router,
        Instant(102),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    mai_coap::endpoint::Application::poll(
        &mut router,
        Instant(103),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    assert_eq!(aborts.get(), 2);
}

#[test]
fn blk_4_buffered_upload_restarts_partway_without_reusing_old_bytes() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let committed = core::cell::RefCell::new(Vec::new());
    let mut handler = |request: Request<'_>, _: &mut ResponseWriter<'_, 256>| {
        committed.borrow_mut().push(request.payload().to_vec());
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    for (mid, number, more, payload, expected) in [
        (1, 0, true, &[1; 16][..], Code::CONTINUE),
        (2, 0, true, &[1; 16][..], Code::CONTINUE),
        (3, 1, true, &[2; 16][..], Code::CONTINUE),
        (4, 0, true, &[3; 16][..], Code::CONTINUE),
        (5, 1, false, b"end".as_slice(), Code::CHANGED),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            payload,
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:5683", n),
                Instant(u64::from(mid)),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(out.packet.as_slice()).unwrap().code(),
            expected
        );
    }
    assert_eq!(*committed.borrow(), [[&[3; 16][..], b"end"].concat()]);
}

#[test]
fn blk_4_stream_restart_aborts_once_and_preserves_block_retries() {
    use core::cell::{Cell, RefCell};
    use mai_coap::block::{BodyKey, UploadSink};
    struct Sink<'a> {
        body: &'a RefCell<Vec<u8>>,
        begins: &'a Cell<usize>,
        aborts: &'a Cell<usize>,
        commits: &'a Cell<usize>,
    }
    impl UploadSink for Sink<'_> {
        fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            self.begins.set(self.begins.get() + 1);
            self.body.borrow_mut().clear();
            Ok(())
        }
        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
            assert_eq!(offset, self.body.borrow().len());
            self.body.borrow_mut().extend_from_slice(bytes);
            Ok(())
        }
        fn abort(&mut self) {
            self.aborts.set(self.aborts.get() + 1);
            self.body.borrow_mut().clear();
        }
        fn commit(&mut self) -> Result<(), Error> {
            self.commits.set(self.commits.get() + 1);
            Ok(())
        }
    }
    let body = RefCell::new(Vec::new());
    let begins = Cell::new(0);
    let aborts = Cell::new(0);
    let commits = Cell::new(0);
    let mut sink = Sink {
        body: &body,
        begins: &begins,
        aborts: &aborts,
        commits: &commits,
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 2, 64>::new(&policy);
    router
        .streaming_upload("/upload", &[Code::POST], 64, &mut sink)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (mid, number, more, payload, expected, starts, stops) in [
        (1, 0, true, &[1; 16][..], Code::CONTINUE, 1, 0),
        (1, 0, true, &[1; 16][..], Code::CONTINUE, 1, 0),
        (2, 0, true, &[1; 16][..], Code::CONTINUE, 1, 0),
        (3, 1, true, &[2; 16][..], Code::CONTINUE, 1, 0),
        (4, 0, true, b"short".as_slice(), Code::INCOMPLETE, 1, 0),
        (5, 0, true, &[3; 16][..], Code::CONTINUE, 2, 1),
        (6, 0, true, &[4; 16][..], Code::CONTINUE, 3, 2),
        (7, 1, false, b"end".as_slice(), Code::CHANGED, 3, 2),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            payload,
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:5683", n),
                Instant(u64::from(mid)),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(out.packet.as_slice()).unwrap().code(),
            expected
        );
        assert_eq!((begins.get(), aborts.get()), (starts, stops));
    }
    assert_eq!(*body.borrow(), [&[4; 16][..], b"end"].concat());
    assert_eq!(commits.get(), 1);
    for (remote, mid, number, more, payload, starts, stops, now) in [
        ("192.0.2.1:5683", 8, 0, true, &[5; 16][..], 4, 2, 8),
        ("192.0.2.2:5683", 9, 0, true, &[6; 16][..], 5, 3, 123_508),
        (
            "192.0.2.2:5683",
            10,
            1,
            false,
            b"end".as_slice(),
            5,
            3,
            123_509,
        ),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            payload,
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(now),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(out.packet.as_slice()).unwrap().code(),
            if more { Code::CONTINUE } else { Code::CHANGED }
        );
        assert_eq!((begins.get(), aborts.get()), (starts, stops));
    }
    assert_eq!(*body.borrow(), [&[6; 16][..], b"end"].concat());
    assert_eq!(commits.get(), 2);
    mai_coap::endpoint::Application::poll(
        &mut router,
        Instant(300_000),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    assert_eq!(aborts.get(), 3);
}

#[test]
fn blk_4_eviction_tracks_progress_instead_of_duplicate_traffic_or_deadlines() {
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256, 2, 2, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    router.set_upload_timeout(120).unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (remote, mid, number, more, code) in [
        ("192.0.2.1:5683", 1, 0, true, Code::CONTINUE),
        ("192.0.2.2:5683", 2, 0, true, Code::CONTINUE),
        ("192.0.2.1:5683", 3, 1, true, Code::CONTINUE),
        ("192.0.2.2:5683", 4, 0, true, Code::CONTINUE),
        ("192.0.2.3:5683", 5, 0, true, Code::CONTINUE),
        ("192.0.2.2:5683", 6, 1, true, Code::INCOMPLETE),
        ("192.0.2.1:5683", 7, 2, false, Code::CHANGED),
    ] {
        if mid == 3 {
            router.set_upload_timeout(100).unwrap();
        }
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            &[1; 16],
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(if mid >= 5 {
                    u64::from(mid) + 57
                } else {
                    u64::from(mid)
                }),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(out.packet.as_slice()).unwrap().code(),
            code
        );
    }
}

#[test]
fn blk_4_rejected_first_block_does_not_evict_an_unrelated_upload() {
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256, 2, 1, 32>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (remote, mid, block, payload, code) in [
        (
            "192.0.2.1:5683",
            1,
            Block::new(0, true, 0).unwrap(),
            &[1; 16][..],
            Code::CONTINUE,
        ),
        (
            "192.0.2.2:5683",
            2,
            Block::new(0, true, 2).unwrap(),
            &[2; 64][..],
            Code::TOO_LARGE,
        ),
        (
            "192.0.2.1:5683",
            3,
            Block::new(1, false, 0).unwrap(),
            b"end".as_slice(),
            Code::CHANGED,
        ),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(mid, block, payload, &mut bytes);
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(u64::from(mid)),
                &mut router,
                &policy,
            )
            .unwrap();
        let out = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(out.packet.as_slice()).unwrap().code(),
            code
        );
    }
}

#[test]
fn blk_4_recent_buffered_upload_survives_another_clients_block_zero() {
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    let committed = core::cell::RefCell::new(Vec::new());
    let mut handler = |request: Request<'_>, _: &mut ResponseWriter<'_, 256>| {
        committed.borrow_mut().push(request.payload().to_vec());
        Ok(Disposition::Complete)
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    for (remote, mid, number, more, expected) in [
        ("192.0.2.1:5683", 1, 0, true, Code::CONTINUE),
        ("192.0.2.9:5683", 2, 0, true, Code::UNAVAILABLE),
        ("192.0.2.1:5683", 3, 1, true, Code::CONTINUE),
        ("192.0.2.9:5683", 4, 1, true, Code::INCOMPLETE),
        ("192.0.2.1:5683", 5, 2, false, Code::CHANGED),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            &[mid as u8; 16],
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(u64::from(mid) * 100),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let message = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(message.code(), expected);
        if expected == Code::UNAVAILABLE {
            assert_eq!(message.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(1));
        }
    }
    assert_eq!(
        *committed.borrow(),
        [[&[1; 16][..], &[3; 16], &[5; 16]].concat()]
    );
}

#[test]
fn blk_4_stream_replacement_waits_for_idle_and_aborts_once() {
    use core::cell::Cell;
    use mai_coap::block::{BodyKey, UploadSink};
    struct Sink<'a> {
        begins: &'a Cell<usize>,
        aborts: &'a Cell<usize>,
        commits: &'a Cell<usize>,
    }
    impl UploadSink for Sink<'_> {
        fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            self.begins.set(self.begins.get() + 1);
            Ok(())
        }
        fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
        fn commit(&mut self) -> Result<(), Error> {
            self.commits.set(self.commits.get() + 1);
            Ok(())
        }
        fn abort(&mut self) {
            self.aborts.set(self.aborts.get() + 1);
        }
    }
    let begins = Cell::new(0);
    let aborts = Cell::new(0);
    let commits = Cell::new(0);
    let mut sink = Sink {
        begins: &begins,
        aborts: &aborts,
        commits: &commits,
    };
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut router = Router::<256, 2, 2, 64>::new(&policy);
    router
        .streaming_upload("/upload", &[Code::POST], 64, &mut sink)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (remote, mid, number, more, now, expected, starts, stops) in [
        ("192.0.2.1:5683", 1, 0, true, 0, Code::CONTINUE, 1, 0),
        ("192.0.2.2:5683", 2, 0, true, 100, Code::UNAVAILABLE, 1, 0),
        ("192.0.2.1:5683", 3, 1, true, 200, Code::CONTINUE, 1, 0),
        (
            "192.0.2.2:5683",
            4,
            0,
            true,
            123_699,
            Code::UNAVAILABLE,
            1,
            0,
        ),
        ("192.0.2.1:5683", 5, 1, true, 123_699, Code::CONTINUE, 1, 0),
        ("192.0.2.2:5683", 6, 0, true, 123_700, Code::CONTINUE, 2, 1),
        (
            "192.0.2.1:5683",
            7,
            2,
            false,
            123_701,
            Code::INCOMPLETE,
            2,
            1,
        ),
        ("192.0.2.2:5683", 8, 1, false, 123_702, Code::CHANGED, 2, 1),
    ] {
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            &[1; 16],
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(now),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        let message = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(message.code(), expected);
        if expected == Code::UNAVAILABLE {
            assert!(message.option(OptionNumber::MAX_AGE).is_some());
        }
        assert_eq!((begins.get(), aborts.get()), (starts, stops));
    }
    assert_eq!(commits.get(), 1);
    mai_coap::endpoint::Application::poll(
        &mut router,
        Instant(400_000),
        &mut core::task::Context::from_waker(core::task::Waker::noop()),
    );
    assert_eq!(aborts.get(), 1);
}

#[test]
fn blk_4_timeout_reconfiguration_preserves_an_existing_uploads_grace() {
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router.set_upload_timeout(120).unwrap();
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (remote, mid, number, more, now, expected) in [
        ("192.0.2.1:5683", 1, 0, true, 0, Code::CONTINUE),
        ("192.0.2.2:5683", 2, 0, true, 59, Code::UNAVAILABLE),
        ("192.0.2.1:5683", 3, 0, true, 59, Code::CONTINUE),
        ("192.0.2.2:5683", 4, 0, true, 60, Code::CONTINUE),
        ("192.0.2.1:5683", 5, 1, false, 61, Code::INCOMPLETE),
        ("192.0.2.2:5683", 6, 1, false, 62, Code::CHANGED),
    ] {
        if mid == 2 {
            router.set_upload_timeout(10).unwrap();
        }
        let mut bytes = [0; 256];
        let n = block_request(
            mid,
            Block::new(number, more, 0).unwrap(),
            &[1; 16],
            &mut bytes,
        );
        endpoint
            .receive(
                &bytes[..n],
                meta(remote, n),
                Instant(now),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
            expected
        );
    }
}

#[test]
fn blk_4_same_remote_can_reclaim_its_own_recent_body_with_a_new_tag() {
    let policy = PublicPaths(&[(Code::POST, "/upload")]);
    let mut handler = |_: Request<'_>, _: &mut ResponseWriter<'_, 256>| Ok(Disposition::Complete);
    let mut router = Router::<256, 2, 1, 64>::new(&policy);
    router
        .buffered_upload("/upload", &[Code::POST], &mut handler)
        .unwrap();
    let shared = Shared::<256, 2>::new();
    let mut endpoint = Endpoint::<_, 256, 2, 8>::new(&shared, Unsecured(rand::rng())).unwrap();
    for (mid, tag, number, more, expected) in [
        (1, 1, 0, true, Code::CONTINUE),
        (2, 2, 0, true, Code::CONTINUE),
        (3, 2, 1, false, Code::CHANGED),
        (4, 1, 1, false, Code::INCOMPLETE),
    ] {
        let mut bytes = [0; 256];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::POST, mid, b"t")
                .unwrap();
        b.option(OptionNumber::URI_PATH, b"upload").unwrap();
        b.uint_option(
            OptionNumber::BLOCK1,
            Block::new(number, more, 0).unwrap().encode().unwrap(),
        )
        .unwrap();
        b.option(OptionNumber::REQUEST_TAG, &[tag]).unwrap();
        let n = b.finish(&[tag; 16]).unwrap();
        endpoint
            .receive(
                &bytes[..n],
                meta("192.0.2.1:5683", n),
                Instant(u64::from(mid)),
                &mut router,
                &policy,
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        assert_eq!(
            MessageView::parse(outgoing.packet.as_slice())
                .unwrap()
                .code(),
            expected
        );
    }
}
