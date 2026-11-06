//! Block-wise client exchanges against a scripted peer (BLK-3, BLK-6–7, RFC 7959, RFC 9175).
#![cfg(all(feature = "server", feature = "client", feature = "block"))]
mod support;
use core::future::Future;
use futures_lite::future::{block_on, poll_once};
use mai_coap::{
    Error,
    block::Block,
    codec::{Code, MessageType, MessageView, OptionNumber},
    endpoint::{Endpoint, Request, Response, ResponseWriter, Shared, Unsecured, client::*},
    security::ProtectedOnly,
    time::Instant,
    transport::Metadata,
};
use support::PopOutgoing;

const D: usize = 256;
type Rng = rand::rngs::ThreadRng;
type TestEndpoint<'a> = Endpoint<'a, Unsecured<Rng>, D, 4, 8>;

fn remote() -> core::net::SocketAddr {
    "192.0.2.1:5683".parse().unwrap()
}
fn body(length: usize) -> Vec<u8> {
    (0..length).map(|i| i as u8).collect()
}

struct Rig<'a> {
    endpoint: TestEndpoint<'a>,
    now: u64,
    /// Every datagram sent, including retransmissions.
    sent: Vec<Vec<u8>>,
}
impl<'a> Rig<'a> {
    fn new(shared: &'a Shared<D, 4>) -> Self {
        Self {
            endpoint: TestEndpoint::new(shared, Unsecured(rand::rng())).unwrap(),
            now: 0,
            sent: Vec::new(),
        }
    }
    /// Polls `operation` to completion. `peer` returns the datagrams answering a request.
    fn pump<F: Future>(
        &mut self,
        operation: F,
        peer: &mut impl FnMut(MessageView<'_>) -> Vec<Vec<u8>>,
    ) -> F::Output {
        let mut operation = core::pin::pin!(operation);
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
        for _ in 0..4000 {
            if let Some(output) = block_on(poll_once(operation.as_mut())) {
                return output;
            }
            self.endpoint.poll(Instant(self.now)).unwrap();
            let mut idle = true;
            while let Some(outgoing) = self.endpoint.pop_outgoing() {
                idle = false;
                let bytes = outgoing.packet.as_slice().to_vec();
                for answer in peer(MessageView::parse(&bytes).unwrap()) {
                    self.endpoint
                        .receive(
                            &answer,
                            Metadata::new(remote(), "192.0.2.2".parse().unwrap(), answer.len())
                                .with_interface(Some(1)),
                            Instant(self.now),
                            &mut unused,
                            &ProtectedOnly,
                        )
                        .unwrap();
                }
                self.sent.push(bytes);
            }
            if idle {
                self.now += 250;
            }
        }
        panic!("operation did not complete");
    }
    fn requests(&self) -> impl Iterator<Item = MessageView<'_>> {
        self.sent.iter().map(|b| MessageView::parse(b).unwrap())
    }
}

fn respond(
    request: MessageView<'_>,
    code: Code,
    payload: &[u8],
    options: impl FnOnce(&mut Response<D>),
) -> Vec<u8> {
    let mut response = Response::<D>::new(code);
    options(&mut response);
    response.set_payload(payload).unwrap();
    let (ty, mid) = if request.message_type() == MessageType::Confirmable {
        (MessageType::Acknowledgement, request.message_id())
    } else {
        (
            MessageType::NonConfirmable,
            request.message_id().wrapping_add(0x4000),
        )
    };
    let mut bytes = [0; D];
    let n = response
        .encode(&mut bytes, ty, mid, request.token())
        .unwrap();
    bytes[..n].to_vec()
}
fn block_of(message: MessageView<'_>, number: OptionNumber) -> Option<Block> {
    message
        .option(number)
        .map(|o| Block::decode(o.uint().unwrap()).unwrap())
}
/// Serves the requested slice of `representation` as RFC 7959 section 2.4 describes.
fn serve(
    request: MessageView<'_>,
    code: Code,
    representation: &[u8],
    largest_szx: u8,
    etag: Option<&[u8]>,
) -> Vec<u8> {
    let asked = block_of(request, OptionNumber::BLOCK2);
    let szx = asked.map_or(largest_szx, |b| b.szx.min(largest_szx));
    let offset = asked.map_or(0, |b| b.number as usize * (16 << b.szx));
    let size = 16usize << szx;
    let end = (offset + size).min(representation.len());
    let block = Block::new((offset / size) as u32, end < representation.len(), szx).unwrap();
    respond(request, code, &representation[offset..end], |r| {
        r.uint_option(OptionNumber::BLOCK2, block.encode().unwrap())
            .unwrap();
        if let Some(etag) = etag {
            r.option(OptionNumber::ETAG, etag).unwrap();
        }
    })
}

#[derive(Default)]
struct Sink {
    begun: Vec<(usize, Option<u64>)>,
    bytes: Vec<u8>,
    restarts: usize,
    finished: Option<usize>,
}
impl DownloadSink for Sink {
    async fn begin(&mut self, offset: usize, total: Option<u64>) -> Result<(), Error> {
        self.begun.push((offset, total));
        Ok(())
    }
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let base = self.begun.last().unwrap().0;
        assert_eq!(offset, base + self.bytes.len(), "writes are ordered");
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    async fn restart(&mut self) -> Result<(), Error> {
        self.bytes.clear();
        self.restarts += 1;
        Ok(())
    }
    async fn finish(&mut self, total: usize) -> Result<(), Error> {
        self.finished = Some(total);
        Ok(())
    }
}

#[test]
fn blk_3_every_block_request_keeps_builder_options_and_message_type() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x?q=1")?
            .uint_option(OptionNumber::ACCEPT, 60)?
            .confirmable(false)
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        vec![serve(request, Code::CONTENT, &representation, 0, None)]
    });
    let result = result.unwrap();
    assert_eq!(result.length, 40);
    assert_eq!(sink.bytes, representation);
    assert_eq!(sink.finished, Some(40));
    let requests: Vec<_> = rig.requests().collect();
    assert_eq!(requests.len(), 3);
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.code(), Code::GET);
        assert_eq!(request.message_type(), MessageType::NonConfirmable);
        assert_eq!(request.option(OptionNumber::ACCEPT).unwrap().uint(), Ok(60));
        assert_eq!(
            request.option(OptionNumber::URI_PATH).unwrap().value,
            b"x",
            "request {index}"
        );
        assert_eq!(
            request.option(OptionNumber::URI_QUERY).unwrap().value,
            b"q=1"
        );
    }
    // Late negotiation: the first request has no Block2 (RFC 7959 figure 3 variant).
    assert!(block_of(requests[0], OptionNumber::BLOCK2).is_none());
    assert_eq!(
        block_of(requests[2], OptionNumber::BLOCK2).unwrap().number,
        2
    );
}

#[test]
fn blk_3_negotiated_size_and_resume_start_at_the_requested_block() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(200);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .block_size(2)?
            .resume_block(2)?
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        vec![serve(request, Code::CONTENT, &representation, 6, None)]
    });
    assert_eq!(result.unwrap().length, 200);
    assert_eq!(sink.begun, [(128, None)]);
    assert_eq!(sink.bytes, representation[128..]);
    let first = rig.requests().next().unwrap();
    let block = block_of(first, OptionNumber::BLOCK2).unwrap();
    assert_eq!((block.number, block.szx, block.more), (2, 2, false));
}

#[test]
fn blk_3_resume_is_refused_for_methods_that_are_not_retrievals() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::POST, "/x")?
            .resume_block(1)?
            .transfer(b"body", &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |_| Vec::new());
    assert_eq!(result.err(), Some(Error::Malformed));
    assert!(rig.sent.is_empty());
}

/// RFC 7959 section 2.4: the server may use a smaller size, and the client continues with it.
#[test]
fn blk_3_follows_a_smaller_server_size_and_rejects_a_larger_one() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(100);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .block_size(3)?
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        vec![serve(request, Code::CONTENT, &representation, 1, None)]
    });
    assert_eq!(result.unwrap().length, 100);
    assert_eq!(sink.bytes, representation);
    let requests: Vec<_> = rig.requests().collect();
    let second = block_of(requests[1], OptionNumber::BLOCK2).unwrap();
    assert_eq!((second.number, second.szx), (1, 1));

    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let handle = shared.handle();
    let mut sink = Sink::default();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .block_size(1)?
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        let block = Block::new(0, true, 2).unwrap();
        vec![respond(request, Code::CONTENT, &[0; 64], |r| {
            r.uint_option(OptionNumber::BLOCK2, block.encode().unwrap())
                .unwrap();
        })]
    });
    assert_eq!(result.err(), Some(Error::Malformed));
    assert_eq!(
        rig.sent.len(),
        1,
        "the first oversized block ends the exchange"
    );
}

#[test]
fn small_body_is_a_plain_request_and_a_plain_response_reaches_the_sink() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::POST, "/x")?
            .uint_option(OptionNumber::CONTENT_FORMAT, 0)?
            .transfer(b"hello", &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        vec![respond(request, Code::CHANGED, b"done", |_| {})]
    });
    let result = result.unwrap();
    assert_eq!(result.reply.message().unwrap().code(), Code::CHANGED);
    assert_eq!(sink.bytes, b"done");
    assert_eq!(sink.begun, [(0, Some(4))]);
    let requests: Vec<_> = rig.requests().collect();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].payload(), b"hello");
    for option in [
        OptionNumber::BLOCK1,
        OptionNumber::BLOCK2,
        OptionNumber::SIZE1,
        OptionNumber::REQUEST_TAG,
    ] {
        assert!(requests[0].option(option).is_none());
    }
}

/// RFC 8132 section 2: a FETCH payload selects the response, so each request repeats it.
/// RFC 7959 figures 10 and 11: other methods send no payload when retrieving later blocks.
#[test]
fn blk_3_only_fetch_repeats_its_payload_for_later_response_blocks() {
    for (method, repeats) in [(Code::FETCH, true), (Code::POST, false)] {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let representation = body(40);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(method, "/x")?
                .transfer(b"selector", &mut sink)
                .await
        };
        let code = if method == Code::FETCH {
            Code::CONTENT
        } else {
            Code::CHANGED
        };
        let result = rig.pump(transfer, &mut |request| {
            vec![serve(request, code, &representation, 0, None)]
        });
        assert_eq!(result.unwrap().length, 40);
        assert_eq!(sink.bytes, representation);
        let requests: Vec<_> = rig.requests().collect();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].payload(), b"selector");
        for request in &requests[1..] {
            assert_eq!(request.code(), method);
            assert_eq!(
                request.payload(),
                if repeats { &b"selector"[..] } else { b"" }
            );
        }
    }
}

/// RFC 7959 section 2.4: after a changed ETag, retrieve fresh values from block zero.
#[test]
fn blk_3_changed_etag_restarts_at_zero_and_discards_the_old_blocks() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let old = vec![1; 40];
    let new = vec![2; 40];
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let mut count = 0;
    let result = rig.pump(transfer, &mut |request| {
        count += 1;
        if count == 1 {
            vec![serve(request, Code::CONTENT, &old, 0, Some(b"a"))]
        } else {
            vec![serve(request, Code::CONTENT, &new, 0, Some(b"b"))]
        }
    });
    assert_eq!(result.unwrap().length, 40);
    assert_eq!(sink.bytes, new);
    assert_eq!(sink.restarts, 1);
    assert_eq!(sink.finished, Some(40));
    let numbers: Vec<_> = rig
        .requests()
        .map(|r| block_of(r, OptionNumber::BLOCK2).map(|b| b.number))
        .collect();
    assert_eq!(
        numbers,
        [None, Some(1), Some(0), Some(1), Some(2)],
        "restart repeats block zero"
    );
}

#[test]
fn blk_3_restarts_are_bounded_for_retrievals_and_absent_for_other_methods() {
    for (method, restarts) in [(Code::GET, 3), (Code::POST, 0)] {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let representation = body(40);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(method, "/x")?
                .transfer(&[], &mut sink)
                .await
        };
        let mut version = 0u8;
        let result = rig.pump(transfer, &mut |request| {
            version += 1;
            vec![serve(
                request,
                Code::CONTENT,
                &representation,
                0,
                Some(&[version]),
            )]
        });
        assert_eq!(result.err(), Some(Error::RepresentationChanged));
        assert_eq!(sink.restarts, restarts);
        assert_eq!(sink.finished, None);
    }
}

#[test]
fn error_response_keeps_its_diagnostic_and_leaves_the_sink_without_a_body() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        vec![respond(request, Code::NOT_FOUND, b"no such thing", |_| {})]
    });
    let result = result.unwrap();
    assert_eq!(result.length, 0);
    let message = result.reply.message().unwrap();
    assert_eq!(message.code(), Code::NOT_FOUND);
    assert_eq!(message.payload(), b"no such thing");
    assert!(sink.begun.is_empty() && sink.bytes.is_empty() && sink.finished.is_none());
    assert_eq!(
        result.clone().into_success().err(),
        Some(Error::Response(Code::NOT_FOUND))
    );
}

#[test]
fn error_response_during_retrieval_discards_earlier_blocks() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let mut count = 0;
    let result = rig.pump(transfer, &mut |request| {
        count += 1;
        if count == 1 {
            vec![serve(request, Code::CONTENT, &representation, 0, None)]
        } else {
            vec![respond(request, Code::UNAVAILABLE, b"later", |_| {})]
        }
    });
    let result = result.unwrap();
    assert_eq!(result.length, 0);
    assert_eq!(result.reply.message().unwrap().payload(), b"later");
    assert_eq!(sink.restarts, 1);
    assert!(sink.bytes.is_empty() && sink.finished.is_none());
}

/// RFC 7959 section 2.3 leaves this to the client, which "will typically abort".
#[test]
fn blk_3_changed_content_format_aborts_without_finishing() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |request| {
        let number = block_of(request, OptionNumber::BLOCK2).map_or(0, |b| b.number);
        let block = Block::new(number, true, 0).unwrap();
        let offset = number as usize * 16;
        vec![respond(
            request,
            Code::CONTENT,
            &representation[offset..offset + 16],
            |r| {
                r.uint_option(OptionNumber::CONTENT_FORMAT, number.into())
                    .unwrap();
                r.uint_option(OptionNumber::BLOCK2, block.encode().unwrap())
                    .unwrap();
            },
        )]
    });
    assert_eq!(result.err(), Some(Error::Malformed));
    assert_eq!(sink.finished, None);
}

#[test]
fn get_blocks_reports_error_responses_as_errors() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let mut output = [0; 64];
    let handle = shared.handle();
    let get = handle.client(remote()).get_blocks("/x", 2, &mut output);
    let result = rig.pump(get, &mut |request| {
        vec![respond(request, Code::FORBIDDEN, b"", |_| {})]
    });
    assert_eq!(result, Err(Error::Response(Code::FORBIDDEN)));
}

/// A block other than the one requested can't be assembled (RFC 7959 section 2.4).
#[test]
fn blk_3_reordered_block_is_rejected_without_finishing() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let mut count = 0;
    let result = rig.pump(transfer, &mut |request| {
        count += 1;
        if count == 1 {
            vec![serve(request, Code::CONTENT, &representation, 0, None)]
        } else {
            let block = Block::new(2, false, 0).unwrap();
            vec![respond(
                request,
                Code::CONTENT,
                &representation[32..],
                |r| {
                    r.uint_option(OptionNumber::BLOCK2, block.encode().unwrap())
                        .unwrap();
                },
            )]
        }
    });
    assert_eq!(result.err(), Some(Error::Malformed));
    assert_eq!(sink.finished, None);
}

#[test]
fn rel_3_lost_and_duplicated_responses_retransmit_exact_bytes_and_deliver_once() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::GET, "/x")?
            .transfer(&[], &mut sink)
            .await
    };
    let mut count = 0;
    let result = rig.pump(transfer, &mut |request| {
        count += 1;
        match count {
            // The first attempt at block zero is lost.
            1 => Vec::new(),
            // Its retransmission is answered twice.
            2 => {
                let answer = serve(request, Code::CONTENT, &representation, 0, None);
                vec![answer.clone(), answer]
            }
            _ => vec![serve(request, Code::CONTENT, &representation, 0, None)],
        }
    });
    assert_eq!(result.unwrap().length, 40);
    assert_eq!(sink.bytes, representation);
    assert_eq!(
        rig.sent[0], rig.sent[1],
        "retransmission reuses stored bytes"
    );
}

#[test]
fn rel_4_silent_peer_times_out_and_releases_the_operation_slot() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let mut sink = Sink::default();
    let handle = shared.handle();
    {
        let transfer = async {
            handle
                .client(remote())
                .request(Code::GET, "/x")?
                .transfer(&[], &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |_| Vec::new());
        assert_eq!(result.err(), Some(Error::Timeout));
    }
    assert_eq!(sink.finished, None);
    assert_slots_free(&mut rig, &shared);
}

#[test]
fn cancelled_transfer_releases_its_slot_and_ignores_the_late_response() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let representation = body(40);
    let handle = shared.handle();
    {
        let mut sink = Sink::default();
        let mut transfer = core::pin::pin!(async {
            handle
                .client(remote())
                .request(Code::GET, "/x")?
                .transfer(&[], &mut sink)
                .await
        });
        assert!(block_on(poll_once(transfer.as_mut())).is_none());
        rig.endpoint.poll(Instant(0)).unwrap();
        let outgoing = rig.endpoint.pop_outgoing().unwrap();
        let request = outgoing.packet.as_slice().to_vec();
        drop(outgoing);
        rig.sent.push(request);
    }
    let late = serve(
        MessageView::parse(&rig.sent[0]).unwrap(),
        Code::CONTENT,
        &representation,
        0,
        None,
    );
    rig.endpoint.poll(Instant(1)).unwrap();
    let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
    rig.endpoint
        .receive(
            &late,
            Metadata::new(remote(), "192.0.2.2".parse().unwrap(), late.len())
                .with_interface(Some(1)),
            Instant(1),
            &mut unused,
            &ProtectedOnly,
        )
        .unwrap();
    assert_slots_free(&mut rig, &shared);
}

/// All command slots accept new work, so nothing leaked.
fn assert_slots_free(rig: &mut Rig<'_>, shared: &Shared<D, 4>) {
    rig.endpoint.poll(Instant(rig.now)).unwrap();
    let handle = shared.handle();
    let operations: Vec<_> = (0..4)
        .map(|_| {
            handle
                .client(remote())
                .request(Code::GET, "/x")
                .unwrap()
                .send()
                .unwrap()
        })
        .collect();
    drop(operations);
}

#[cfg(feature = "block1")]
mod block1 {
    use super::*;
    use mai_coap::codec::ContentFormat;

    fn ack_block1(request: MessageView<'_>, code: Code, szx: Option<u8>) -> Vec<u8> {
        let mut block = block_of(request, OptionNumber::BLOCK1).unwrap();
        if let Some(szx) = szx {
            block.szx = szx;
        }
        respond(request, code, b"", |r| {
            r.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
                .unwrap();
        })
    }
    /// Answers each block as RFC 7959 section 2.5 describes, 2.31 until the last.
    fn receive_body(request: MessageView<'_>) -> Vec<u8> {
        let more = block_of(request, OptionNumber::BLOCK1).unwrap().more;
        let code = if more { Code::CONTINUE } else { Code::CHANGED };
        ack_block1(request, code, None)
    }

    #[test]
    fn blk_6_7_large_body_uses_block1_with_size1_and_one_request_tag() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(300);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .uint_option(OptionNumber::CONTENT_FORMAT, 42)?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| vec![receive_body(request)]);
        assert_eq!(
            result.unwrap().reply.message().unwrap().code(),
            Code::CHANGED
        );
        let requests: Vec<_> = rig.requests().collect();
        assert_eq!(requests.len(), 3);
        let mut received = Vec::new();
        for (index, request) in requests.iter().enumerate() {
            let block = block_of(*request, OptionNumber::BLOCK1).unwrap();
            assert_eq!(block.number as usize, index);
            assert_eq!(block.more, index < 2);
            assert_eq!(block.szx, 3);
            assert_eq!(request.option(OptionNumber::SIZE1).unwrap().uint(), Ok(300));
            assert_eq!(
                request.option(OptionNumber::CONTENT_FORMAT).unwrap().uint(),
                Ok(42)
            );
            assert_eq!(
                request.option(OptionNumber::REQUEST_TAG).unwrap().value,
                requests[0].option(OptionNumber::REQUEST_TAG).unwrap().value
            );
            received.extend_from_slice(request.payload());
        }
        assert_eq!(received, content);
    }

    #[test]
    fn separate_bodies_use_different_request_tags() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(300);
        let handle = shared.handle();
        let transfers = async {
            let mut sink = Sink::default();
            for _ in 0..2 {
                handle
                    .client(remote())
                    .request(Code::PUT, "/x")?
                    .transfer(&content, &mut sink)
                    .await?;
            }
            Ok::<_, Error>(())
        };
        let result = rig.pump(transfers, &mut |request| vec![receive_body(request)]);
        result.unwrap();
        let tags: Vec<_> = rig
            .requests()
            .map(|r| r.option(OptionNumber::REQUEST_TAG).unwrap().value.to_vec())
            .collect();
        assert_eq!(tags.first(), tags.get(tags.len() / 2 - 1));
        assert_ne!(tags.first(), tags.last());
    }

    /// RFC 7959 section 2.9.3: 4.13 with a smaller Block1 size invites a retry at that size.
    #[test]
    fn blk_6_too_large_restarts_the_body_at_the_smaller_size() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            let block = block_of(request, OptionNumber::BLOCK1).unwrap();
            if block.szx == 3 {
                vec![ack_block1(request, Code::TOO_LARGE, Some(2))]
            } else {
                vec![receive_body(request)]
            }
        });
        assert_eq!(
            result.unwrap().reply.message().unwrap().code(),
            Code::CHANGED
        );
        let received: Vec<u8> = rig
            .requests()
            .filter(|r| block_of(*r, OptionNumber::BLOCK1).unwrap().szx == 2)
            .flat_map(|r| r.payload().to_vec())
            .collect();
        assert_eq!(received, content);
    }

    #[test]
    fn blk_6_smaller_size_in_continue_applies_to_the_next_block() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            let block = block_of(request, OptionNumber::BLOCK1).unwrap();
            let code = if block.more {
                Code::CONTINUE
            } else {
                Code::CHANGED
            };
            vec![ack_block1(request, code, Some(2))]
        });
        result.unwrap();
        let requests: Vec<_> = rig.requests().collect();
        let second = block_of(requests[1], OptionNumber::BLOCK1).unwrap();
        // Byte 128 is block 2 at 64-byte blocks.
        assert_eq!((second.number, second.szx), (2, 2));
        let received: Vec<u8> = requests.iter().flat_map(|r| r.payload().to_vec()).collect();
        assert_eq!(received, content);
    }

    #[test]
    fn blk_6_failure_during_the_body_stops_and_returns_the_diagnostic() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(300);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let mut count = 0;
        let result = rig.pump(transfer, &mut |request| {
            count += 1;
            if count == 1 {
                vec![receive_body(request)]
            } else {
                vec![respond(request, Code::INCOMPLETE, b"gap", |_| {})]
            }
        });
        let result = result.unwrap();
        assert_eq!(result.reply.message().unwrap().code(), Code::INCOMPLETE);
        assert_eq!(result.reply.message().unwrap().payload(), b"gap");
        assert_eq!(rig.sent.len(), 2);
        assert!(sink.begun.is_empty());
    }

    /// RFC 7959 section 2.3: "the client is still expected to continue sending further
    /// blocks" after a 2.xx with M unset, and the last response carries the final code.
    #[test]
    fn blk_6_per_block_success_continues_and_the_last_response_is_final() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(300);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            let mut block = block_of(request, OptionNumber::BLOCK1).unwrap();
            let code = if block.more {
                Code::CHANGED
            } else {
                Code::CREATED
            };
            block.more = false;
            vec![respond(request, code, b"", |r| {
                r.uint_option(OptionNumber::BLOCK1, block.encode().unwrap())
                    .unwrap();
            })]
        });
        assert_eq!(
            result.unwrap().reply.message().unwrap().code(),
            Code::CREATED
        );
        let received: Vec<u8> = rig.requests().flat_map(|r| r.payload().to_vec()).collect();
        assert_eq!(received, content);
    }

    /// RFC 7959 section 2.9.1 defines 2.31 for blocks with more to come.
    #[test]
    fn blk_6_continue_for_the_last_block_is_malformed() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            vec![ack_block1(request, Code::CONTINUE, None)]
        });
        assert_eq!(result.err(), Some(Error::Malformed));
    }

    /// Acknowledging another block means the bodies disagree; the RFC leaves the reaction
    /// open, and this client aborts rather than risk a corrupt upload.
    #[test]
    fn blk_6_acknowledgement_of_another_block_aborts() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(300);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            let wrong = Block::new(7, true, 3).unwrap();
            vec![respond(request, Code::CONTINUE, b"", |r| {
                r.uint_option(OptionNumber::BLOCK1, wrong.encode().unwrap())
                    .unwrap();
            })]
        });
        assert_eq!(result.err(), Some(Error::Malformed));
        assert_eq!(rig.sent.len(), 1);
    }

    /// RFC 7959 section 2.3: only a block with M set must be full, so exact multiples need
    /// no empty trailing block.
    #[test]
    fn blk_6_body_of_exact_block_multiple_ends_on_a_full_block() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(256);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        rig.pump(transfer, &mut |request| vec![receive_body(request)])
            .unwrap();
        let blocks: Vec<_> = rig
            .requests()
            .map(|r| {
                let block = block_of(r, OptionNumber::BLOCK1).unwrap();
                (block.number, block.more, r.payload().len())
            })
            .collect();
        assert_eq!(blocks, [(0, true, 128), (1, false, 128)]);
    }

    /// A body that fit in one plain request can still be refused with a smaller size.
    #[test]
    fn blk_6_too_large_for_a_plain_request_retries_in_blocks() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(100);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(
            transfer,
            &mut |request| match block_of(request, OptionNumber::BLOCK1) {
                None => {
                    let hint = Block::new(0, false, 2).unwrap();
                    vec![respond(request, Code::TOO_LARGE, b"", |r| {
                        r.uint_option(OptionNumber::BLOCK1, hint.encode().unwrap())
                            .unwrap();
                    })]
                }
                Some(_) => vec![receive_body(request)],
            },
        );
        assert_eq!(
            result.unwrap().reply.message().unwrap().code(),
            Code::CHANGED
        );
        let requests: Vec<_> = rig.requests().collect();
        assert_eq!(requests.len(), 3);
        assert!(block_of(requests[0], OptionNumber::BLOCK1).is_none());
        let received: Vec<u8> = requests[1..]
            .iter()
            .flat_map(|r| r.payload().to_vec())
            .collect();
        assert_eq!(received, content);
    }

    /// RFC 7959 section 2.9.3: the same or a larger size, or a body over Size1, is final.
    #[test]
    fn blk_6_unusable_too_large_is_returned_without_retrying() {
        for (szx, size1) in [(3, None), (4, None), (2, Some(50))] {
            let shared = Shared::<D, 4>::new();
            let mut rig = Rig::new(&shared);
            let content = body(200);
            let mut sink = Sink::default();
            let handle = shared.handle();
            let transfer = async {
                handle
                    .client(remote())
                    .request(Code::PUT, "/x")?
                    .block_size(3)?
                    .transfer(&content, &mut sink)
                    .await
            };
            let result = rig.pump(transfer, &mut |request| {
                let hint = Block::new(0, false, szx).unwrap();
                vec![respond(request, Code::TOO_LARGE, b"limit", |r| {
                    r.uint_option(OptionNumber::BLOCK1, hint.encode().unwrap())
                        .unwrap();
                    if let Some(size1) = size1 {
                        r.uint_option(OptionNumber::SIZE1, size1).unwrap();
                    }
                })]
            });
            let result = result.unwrap();
            assert_eq!(result.reply.message().unwrap().payload(), b"limit");
            assert_eq!(rig.sent.len(), 1, "{szx} {size1:?}");
        }
    }

    /// RFC 7959 section 2.10: If-None-Match "MUST NOT be used on Block1 requests with
    /// NUM != 0"; a later request would otherwise fail on the resource it just created.
    #[test]
    fn blk_6_if_none_match_only_reaches_the_first_request() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let representation = body(40);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::PUT, "/x")?
                .option(OptionNumber::IF_NONE_MATCH, b"")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        rig.pump(transfer, &mut |request| {
            if block_of(request, OptionNumber::BLOCK1).is_some_and(|b| b.more) {
                vec![ack_block1(request, Code::CONTINUE, None)]
            } else {
                vec![serve(request, Code::CREATED, &representation, 0, None)]
            }
        })
        .unwrap();
        let carrying: Vec<_> = rig
            .requests()
            .map(|r| r.option(OptionNumber::IF_NONE_MATCH).is_some())
            .collect();
        assert_eq!(carrying, [true, false, false, false]);
    }

    /// RFC 7959 section 2.7 and figure 11, RFC 9175 section 3.4.
    #[test]
    fn blk_6_combined_exchange_negotiates_last_and_retrieves_without_block1() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let representation = body(100);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::POST, "/x")?
                .uint_option(OptionNumber::CONTENT_FORMAT, 42)?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            let block1 = block_of(request, OptionNumber::BLOCK1);
            if block1.is_some_and(|b| b.more) {
                vec![ack_block1(request, Code::CONTINUE, None)]
            } else {
                vec![serve(request, Code::CHANGED, &representation, 2, None)]
            }
        });
        assert_eq!(result.unwrap().length, 100);
        assert_eq!(sink.bytes, representation);
        let requests: Vec<_> = rig.requests().collect();
        assert_eq!(requests.len(), 3);
        assert!(block_of(requests[0], OptionNumber::BLOCK2).is_none());
        let negotiated = block_of(requests[1], OptionNumber::BLOCK2).unwrap();
        assert_eq!((negotiated.number, negotiated.szx), (0, 3));
        let tag = requests[0].option(OptionNumber::REQUEST_TAG).unwrap().value;
        let follow_up = requests[2];
        assert!(follow_up.option(OptionNumber::BLOCK1).is_none());
        assert!(follow_up.option(OptionNumber::SIZE1).is_none());
        assert!(follow_up.payload().is_empty());
        assert_eq!(block_of(follow_up, OptionNumber::BLOCK2).unwrap().number, 1);
        assert_eq!(
            follow_up.option(OptionNumber::REQUEST_TAG).unwrap().value,
            tag
        );
    }

    /// RFC 8132 section 2.5: a FETCH using Block1 retrieves as a POST does, with no payload
    /// on later requests, and its Block1 phase can't be repeated either.
    #[test]
    fn blk_6_fetch_with_block1_neither_repeats_its_body_nor_restarts() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let representation = body(100);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::FETCH, "/x")?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let mut version = 0u8;
        let result = rig.pump(transfer, &mut |request| {
            if block_of(request, OptionNumber::BLOCK1).is_some_and(|b| b.more) {
                return vec![ack_block1(request, Code::CONTINUE, None)];
            }
            if version == 1 {
                assert!(request.payload().is_empty());
            }
            version += 1;
            vec![serve(
                request,
                Code::CONTENT,
                &representation,
                1,
                Some(&[version]),
            )]
        });
        assert_eq!(result.err(), Some(Error::RepresentationChanged));
        assert_eq!(sink.restarts, 0);
    }

    /// The Block1 phase can't be repeated, so a changed response is reported.
    #[test]
    fn blk_6_changed_response_after_block1_is_not_restarted() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let representation = body(100);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::POST, "/x")?
                .transfer(&content, &mut sink)
                .await
        };
        let mut version = 0u8;
        let result = rig.pump(transfer, &mut |request| {
            if block_of(request, OptionNumber::BLOCK1).is_some_and(|b| b.more) {
                return vec![ack_block1(request, Code::CONTINUE, None)];
            }
            version += 1;
            vec![serve(
                request,
                Code::CHANGED,
                &representation,
                1,
                Some(&[version]),
            )]
        });
        assert_eq!(result.err(), Some(Error::RepresentationChanged));
        assert_eq!(sink.restarts, 0);
        assert_eq!(sink.finished, None);
    }

    /// Each request carries its own block options, whatever the builder was given.
    #[test]
    fn caller_supplied_block_options_do_not_reach_the_wire() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let content = body(200);
        let representation = body(40);
        let mut sink = Sink::default();
        let handle = shared.handle();
        let transfer = async {
            handle
                .client(remote())
                .request(Code::POST, "/x")?
                .uint_option(OptionNumber::BLOCK1, 0x7e)?
                .uint_option(OptionNumber::BLOCK2, 0x7e)?
                .uint_option(OptionNumber::SIZE1, 1)?
                .block_size(3)?
                .transfer(&content, &mut sink)
                .await
        };
        let result = rig.pump(transfer, &mut |request| {
            if block_of(request, OptionNumber::BLOCK1).is_some_and(|b| b.more) {
                vec![ack_block1(request, Code::CONTINUE, None)]
            } else {
                vec![serve(request, Code::CHANGED, &representation, 0, None)]
            }
        });
        assert_eq!(result.unwrap().length, 40);
        for request in rig.requests() {
            assert!(request.values(OptionNumber::BLOCK1).count() <= 1);
            assert_eq!(request.values(OptionNumber::BLOCK2).count().min(1), {
                usize::from(request.option(OptionNumber::BLOCK2).is_some())
            });
            assert!(request.values(OptionNumber::BLOCK2).count() <= 1);
            assert!(request.values(OptionNumber::SIZE1).count() <= 1);
            if let Some(block1) = block_of(request, OptionNumber::BLOCK1) {
                assert_eq!(block1.szx, 3);
                assert_eq!(request.option(OptionNumber::SIZE1).unwrap().uint(), Ok(200));
            } else {
                assert!(request.option(OptionNumber::SIZE1).is_none());
            }
        }
    }

    #[test]
    fn upload_returns_the_final_response_without_retrieving_more_blocks() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let representation = body(100);
        let handle = shared.handle();
        let upload = handle.client(remote()).upload(
            Code::POST,
            "/x",
            ContentFormat::OCTET_STREAM,
            b"small",
            3,
        );
        let result = rig.pump(upload, &mut |request| {
            vec![serve(request, Code::CHANGED, &representation, 2, None)]
        });
        assert_eq!(result.unwrap().message().unwrap().code(), Code::CHANGED);
        assert_eq!(rig.sent.len(), 1);
        let request = rig.requests().next().unwrap();
        assert_eq!(request.payload(), b"small");
        assert!(request.option(OptionNumber::BLOCK1).is_none());
        assert!(request.option(OptionNumber::BLOCK2).is_none());
        assert_eq!(
            request.option(OptionNumber::CONTENT_FORMAT).unwrap().uint(),
            Ok(ContentFormat::OCTET_STREAM.0.into())
        );
    }

    #[test]
    fn upload_reports_error_responses_as_errors() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let handle = shared.handle();
        let upload = handle.client(remote()).upload(
            Code::PUT,
            "/x",
            ContentFormat::OCTET_STREAM,
            b"small",
            3,
        );
        let result = rig.pump(upload, &mut |request| {
            vec![respond(request, Code::FORBIDDEN, b"", |_| {})]
        });
        assert_eq!(result.err(), Some(Error::Response(Code::FORBIDDEN)));
    }
}

#[cfg(not(feature = "block1"))]
#[test]
fn large_body_needs_block1() {
    let shared = Shared::<D, 4>::new();
    let mut rig = Rig::new(&shared);
    let content = body(300);
    let mut sink = Sink::default();
    let handle = shared.handle();
    let transfer = async {
        handle
            .client(remote())
            .request(Code::PUT, "/x")?
            .transfer(&content, &mut sink)
            .await
    };
    let result = rig.pump(transfer, &mut |_| Vec::new());
    assert_eq!(result.err(), Some(Error::Capacity));
    assert!(rig.sent.is_empty());
}

#[cfg(feature = "observe")]
mod observe {
    use super::*;

    fn notification(request: MessageView<'_>, sequence: u64, payload: &[u8]) -> Vec<u8> {
        respond(request, Code::CONTENT, payload, |r| {
            r.uint_option(OptionNumber::OBSERVE, sequence).unwrap();
        })
    }

    /// RFC 7959 section 2.6: the registration carries the desired size, and later blocks
    /// are plain retrievals.
    #[test]
    fn obs_6_negotiated_size_reaches_registration_and_followups_drop_observe() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let representation = body(100);
        let handle = shared.handle();
        let mut observation = handle
            .client(remote())
            .request(Code::GET, "/x")
            .unwrap()
            .uint_option(OptionNumber::ACCEPT, 60)
            .unwrap()
            .block_size(2)
            .unwrap()
            .observe()
            .unwrap();
        let mut sink = Sink::default();
        let next = observation.next_into(&mut sink);
        let result = rig.pump(next, &mut |request| {
            let observe = request.option(OptionNumber::OBSERVE).is_some();
            let block = Block::new(
                block_of(request, OptionNumber::BLOCK2).unwrap().number,
                false,
                2,
            )
            .unwrap();
            let offset = block.number as usize * 64;
            let end = (offset + 64).min(100);
            let block = Block::new(block.number, end < 100, 2).unwrap();
            vec![respond(
                request,
                Code::CONTENT,
                &representation[offset..end],
                |r| {
                    if observe {
                        r.uint_option(OptionNumber::OBSERVE, 1).unwrap();
                    }
                    r.uint_option(OptionNumber::BLOCK2, block.encode().unwrap())
                        .unwrap();
                },
            )]
        });
        assert_eq!(result.unwrap().unwrap().length, 100);
        assert_eq!(sink.bytes, representation);
        let requests: Vec<_> = rig.requests().collect();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0].option(OptionNumber::OBSERVE).unwrap().uint(),
            Ok(0)
        );
        assert_eq!(block_of(requests[0], OptionNumber::BLOCK2).unwrap().szx, 2);
        assert!(requests[1].option(OptionNumber::OBSERVE).is_none());
        assert_eq!(
            requests[1].option(OptionNumber::ACCEPT).unwrap().uint(),
            Ok(60)
        );
    }

    #[test]
    fn resume_does_not_apply_to_observations() {
        let shared = Shared::<D, 4>::new();
        let handle = shared.handle();
        let result = handle
            .client(remote())
            .request(Code::GET, "/x")
            .unwrap()
            .resume_block(1)
            .unwrap()
            .observe();
        assert_eq!(result.err(), Some(Error::Malformed));
    }

    #[test]
    fn notification_transfer_exposes_code_and_options() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let handle = shared.handle();
        let mut observation = handle.client(remote()).observe("/x").unwrap();
        let mut output = [0; 64];
        let next = observation.next_blocks(&mut output);
        let result = rig.pump(next, &mut |request| {
            vec![notification(request, 3, b"value")]
        });
        let transfer = result.unwrap().unwrap();
        assert_eq!(transfer.length, 5);
        let message = transfer.reply.message().unwrap();
        assert_eq!(message.code(), Code::CONTENT);
        assert_eq!(message.option(OptionNumber::OBSERVE).unwrap().uint(), Ok(3));
    }

    fn registered<'s>(
        rig: &mut Rig<'_>,
        shared: &'s Shared<D, 4>,
    ) -> mai_coap::endpoint::Observation<'s, D, 4> {
        let mut observation = shared.handle().client(remote()).observe("/x").unwrap();
        {
            let next = observation.next();
            let first = rig.pump(next, &mut |request| vec![notification(request, 1, b"one")]);
            assert_eq!(first.unwrap().unwrap().message().unwrap().payload(), b"one");
        }
        observation
    }

    /// RFC 7641 section 3.6: deregistration is a GET with Observe=1 and the same token.
    #[test]
    fn obs_8_deregister_sends_observe_1_and_returns_the_response() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let token = rig.requests().next().unwrap().token().to_vec();
        let deregister = observation.deregister();
        let result = rig.pump(deregister, &mut |request| {
            vec![respond(request, Code::CONTENT, b"final", |_| {})]
        });
        let reply = result.unwrap().unwrap();
        assert_eq!(reply.message().unwrap().payload(), b"final");
        let request = rig.requests().last().unwrap();
        assert_eq!(request.code(), Code::GET);
        assert_eq!(request.message_type(), MessageType::Confirmable);
        assert_eq!(request.option(OptionNumber::OBSERVE).unwrap().uint(), Ok(1));
        assert_eq!(request.token(), token);
        assert_slots_free(&mut rig, &shared);
    }

    /// RFC 7641 section 3.6: besides Observe and ETag, the request matches the registration.
    #[test]
    fn obs_8_deregister_repeats_the_registration_options_and_payload() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let mut observation = shared
            .handle()
            .client(remote())
            .request(Code::FETCH, "/x?q=1")
            .unwrap()
            .uint_option(OptionNumber::CONTENT_FORMAT, 60)
            .unwrap()
            .uint_option(OptionNumber::ACCEPT, 60)
            .unwrap()
            .payload(b"selector")
            .unwrap()
            .block_size(2)
            .unwrap()
            .observe()
            .unwrap();
        let next = observation.next();
        let first = rig.pump(next, &mut |request| vec![notification(request, 1, b"one")]);
        assert!(first.unwrap().is_ok());
        let deregister = observation.deregister();
        rig.pump(deregister, &mut |request| {
            vec![respond(request, Code::CONTENT, b"", |_| {})]
        })
        .unwrap();
        let requests: Vec<_> = rig.requests().collect();
        let (registration, cancellation) = (requests[0], *requests.last().unwrap());
        assert_eq!(
            cancellation.option(OptionNumber::OBSERVE).unwrap().uint(),
            Ok(1)
        );
        let others = |message: MessageView<'_>| -> Vec<(u32, Vec<u8>)> {
            message
                .options()
                .filter(|o| o.number != OptionNumber::OBSERVE)
                .map(|o| (o.number.0, o.value.to_vec()))
                .collect()
        };
        assert_eq!(others(registration), others(cancellation));
        assert_eq!(cancellation.code(), Code::FETCH);
        assert_eq!(cancellation.payload(), b"selector");
    }

    /// RFC 7641 section 4.1 forbids Observe here, and the RFC gives no client reaction;
    /// the observation stays ended either way.
    #[test]
    fn obs_8_deregister_response_with_observe_does_not_rearm() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let deregister = observation.deregister();
        let result = rig.pump(deregister, &mut |request| {
            vec![notification(request, 9, b"late")]
        });
        assert!(result.unwrap().is_some());
        assert_slots_free(&mut rig, &shared);
    }

    /// RFC 7641 section 3.6: a client that forgot an observation rejects its confirmable
    /// notifications with Reset, every time, and delivers nothing.
    #[test]
    fn obs_8_notifications_after_deregister_are_reset_and_not_delivered() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let registration = rig.sent[0].clone();
        let deregister = observation.deregister();
        rig.pump(deregister, &mut |request| {
            vec![respond(request, Code::CONTENT, b"", |_| {})]
        })
        .unwrap();
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
        for (index, mid) in [0x5501u16, 0x5502].into_iter().enumerate() {
            let mut bytes = notification(MessageView::parse(&registration).unwrap(), 5, b"late");
            bytes[0] &= 0xcf;
            bytes[2..4].copy_from_slice(&mid.to_be_bytes());
            rig.endpoint
                .receive(
                    &bytes,
                    Metadata::new(remote(), "192.0.2.2".parse().unwrap(), bytes.len())
                        .with_interface(Some(1)),
                    Instant(rig.now),
                    &mut unused,
                    &ProtectedOnly,
                )
                .unwrap();
            rig.endpoint.poll(Instant(rig.now)).unwrap();
            let outgoing = rig.endpoint.pop_outgoing().unwrap();
            let reply = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(
                reply.message_type(),
                MessageType::Reset,
                "notification {index}"
            );
            assert_eq!(reply.message_id(), mid);
        }
    }

    /// A driver sleeping until its next deadline must wake to send the Observe=1 request.
    #[test]
    fn obs_8_requested_deregistration_is_due_immediately() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let now = Instant(rig.now);
        assert!(rig.endpoint.deadline(now) > now);
        let mut deregister = core::pin::pin!(observation.deregister());
        assert!(block_on(poll_once(deregister.as_mut())).is_none());
        assert_eq!(rig.endpoint.deadline(now), now);
    }

    #[test]
    fn obs_8_deregister_retransmits_exact_bytes_after_loss() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let deregister = observation.deregister();
        let mut count = 0;
        let result = rig.pump(deregister, &mut |request| {
            count += 1;
            if count == 1 {
                Vec::new()
            } else {
                vec![respond(request, Code::CONTENT, b"", |_| {})]
            }
        });
        assert!(result.unwrap().is_some());
        let last = rig.sent.len() - 1;
        assert_eq!(rig.sent[last], rig.sent[last - 1]);
    }

    #[test]
    fn obs_8_deregister_times_out_and_releases_the_slot() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        let deregister = observation.deregister();
        let result = rig.pump(deregister, &mut |_| Vec::new());
        assert_eq!(result.err(), Some(Error::Timeout));
        assert_slots_free(&mut rig, &shared);
    }

    /// A notification sent before the server saw Observe=1 is not the final response.
    #[test]
    fn obs_8_deregister_discards_a_notification_already_delivered() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let mut observation = registered(&mut rig, &shared);
        // Delivered to the slot, not yet read by the application.
        {
            let registration = rig.sent[0].clone();
            let answer = notification(MessageView::parse(&registration).unwrap(), 2, b"two");
            let answer = {
                // A confirmable notification, as RFC 7641 section 4.5 permits.
                let mut bytes = answer;
                bytes[0] &= 0xcf;
                bytes[2] = 0x55;
                bytes
            };
            let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
            rig.endpoint
                .receive(
                    &answer,
                    Metadata::new(remote(), "192.0.2.2".parse().unwrap(), answer.len())
                        .with_interface(Some(1)),
                    Instant(rig.now),
                    &mut unused,
                    &ProtectedOnly,
                )
                .unwrap();
            rig.endpoint.poll(Instant(rig.now)).unwrap();
            // Discard the empty ACK for that notification.
            while rig.endpoint.pop_outgoing().is_some() {}
        }
        // The registration stays usable until deregistered.
        let _ = &mut observation;
        let deregister = observation.deregister();
        let result = rig.pump(deregister, &mut |request| {
            vec![respond(request, Code::CONTENT, b"final", |_| {})]
        });
        assert_eq!(
            result.unwrap().unwrap().message().unwrap().payload(),
            b"final"
        );
    }

    #[test]
    fn obs_8_dropped_deregister_still_sends_observe_1_and_frees_the_slot() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let observation = registered(&mut rig, &shared);
        {
            let mut deregister = core::pin::pin!(observation.deregister());
            assert!(block_on(poll_once(deregister.as_mut())).is_none());
        }
        rig.endpoint.poll(Instant(rig.now)).unwrap();
        let outgoing = rig.endpoint.pop_outgoing().unwrap();
        let request = MessageView::parse(outgoing.packet.as_slice()).unwrap();
        assert_eq!(request.option(OptionNumber::OBSERVE).unwrap().uint(), Ok(1));
        drop(outgoing);
        rig.now += 1;
        assert_slots_free(&mut rig, &shared);
    }

    /// RFC 7641 section 3.2: a response without Observe ends the relationship.
    #[test]
    fn obs_8_deregister_after_the_final_response_sends_nothing() {
        let shared = Shared::<D, 4>::new();
        let mut rig = Rig::new(&shared);
        let mut observation = shared.handle().client(remote()).observe("/x").unwrap();
        {
            let next = observation.next();
            let first = rig.pump(next, &mut |request| {
                vec![respond(request, Code::CONTENT, b"plain", |_| {})]
            });
            assert!(first.unwrap().is_ok());
        }
        let sent = rig.sent.len();
        let deregister = observation.deregister();
        let result = rig.pump(deregister, &mut |_| Vec::new());
        assert_eq!(result.ok().flatten().map(|_| ()), None);
        assert_eq!(rig.sent.len(), sent);
    }
}
