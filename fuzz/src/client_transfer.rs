//! Block-wise client exchanges against arbitrary responses, with RFC 7959 oracles.
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use mai_coap::{
    Error,
    block::Block,
    codec::{Code, MessageType, MessageView, OptionNumber},
    endpoint::{
        Endpoint, Request, Response, ResponseWriter, Shared, Unsecured, client::DownloadSink,
    },
    security::ProtectedOnly,
    time::Instant,
    transport::Metadata,
};
use rand::{SeedableRng, rngs::StdRng};

const D: usize = 256;
const CODES: [Code; 8] = [
    Code::CONTENT,
    Code::CONTENT,
    Code::CONTINUE,
    Code::CHANGED,
    Code::TOO_LARGE,
    Code::NOT_FOUND,
    Code::INCOMPLETE,
    Code::UNAVAILABLE,
];
const METHODS: [Code; 4] = [Code::GET, Code::FETCH, Code::POST, Code::PUT];

/// Oracle for the sink contract: ordered writes, and `finish` only with the whole body.
#[derive(Default)]
struct Sink {
    base: usize,
    bytes: Vec<u8>,
    begun: bool,
    finished: Option<usize>,
}
impl DownloadSink for Sink {
    async fn begin(&mut self, offset: usize, _: Option<u64>) -> Result<(), Error> {
        assert!(!self.begun, "begin without an intervening restart");
        assert_eq!(self.finished, None);
        (self.base, self.begun) = (offset, true);
        Ok(())
    }
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        assert!(self.begun, "write before begin");
        assert_eq!(self.finished, None);
        assert_eq!(offset, self.base + self.bytes.len(), "writes are ordered");
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    async fn restart(&mut self) -> Result<(), Error> {
        assert_eq!(self.finished, None, "a finished body can't be discarded");
        self.bytes.clear();
        self.begun = false;
        Ok(())
    }
    async fn finish(&mut self, total: usize) -> Result<(), Error> {
        assert!(self.begun, "finish before begin");
        assert_eq!(
            total,
            self.base + self.bytes.len(),
            "finish reports the body"
        );
        self.finished = Some(total);
        Ok(())
    }
}

/// Client-side requirements on every request sent during one exchange.
struct RequestOracle<'a> {
    method: Code,
    body: &'a [u8],
    /// No request has been sent yet.
    first: bool,
    block1_used: bool,
    /// The SZX the last response used; later Block2 requests must not exceed it.
    response_szx: Option<u8>,
}
impl RequestOracle<'_> {
    fn check(&mut self, request: MessageView<'_>) {
        assert_eq!(request.code(), self.method);
        // RFC 7959 section 2.1: "Either Block option MUST NOT occur more than once".
        assert!(request.values(OptionNumber::BLOCK1).count() <= 1);
        assert!(request.values(OptionNumber::BLOCK2).count() <= 1);
        assert!(request.option(OptionNumber::OBSERVE).is_none());
        if let Some(option) = request.option(OptionNumber::BLOCK1) {
            let block = Block::decode(option.uint().unwrap()).unwrap();
            let size = block.size().unwrap();
            let payload = request.payload();
            // RFC 7959 section 2.3: M set means a full block; the bytes are the body's.
            if block.more {
                assert_eq!(payload.len(), size);
            }
            assert!(payload.len() <= size);
            let offset = block.number as usize * size;
            assert_eq!(&self.body[offset..offset + payload.len()], payload);
            if !block.more {
                assert_eq!(offset + payload.len(), self.body.len());
            }
            // RFC 7959 section 2.10.
            if block.number != 0 {
                assert!(request.option(OptionNumber::IF_NONE_MATCH).is_none());
            }
            assert_eq!(
                request.option(OptionNumber::SIZE1).unwrap().uint(),
                Ok(self.body.len() as u64)
            );
            assert!(request.option(OptionNumber::REQUEST_TAG).is_some());
            self.block1_used = true;
        } else if !self.first {
            assert!(request.option(OptionNumber::IF_NONE_MATCH).is_none());
            assert!(request.option(OptionNumber::SIZE1).is_none());
            // RFC 8132 section 2 for a FETCH sent whole; RFC 7959 figures 10 and 11 otherwise.
            if self.method == Code::FETCH && !self.block1_used {
                assert_eq!(request.payload(), self.body);
            } else {
                assert!(request.payload().is_empty());
            }
        }
        if let Some(option) = request.option(OptionNumber::BLOCK2) {
            let block = Block::decode(option.uint().unwrap()).unwrap();
            // RFC 7959 section 2.4: "the client MUST set the M bit ... to zero".
            assert!(!block.more);
            // RFC 7959 section 2.4: continue with the size the response used. A request of
            // the Block1 phase isn't continuing a retrieval yet, whatever the peer sent.
            if let Some(szx) = self.response_szx
                && request.option(OptionNumber::BLOCK1).is_none()
            {
                assert!(block.szx <= szx);
            }
        }
        self.first = false;
    }
}

/// A header byte (method and preferred size), a body length byte, then 6-byte response
/// records: code, block number, block option bits, ETag, Content-Format and payload length.
pub fn client_transfer(data: &[u8]) {
    let [header, length, records @ ..] = data else {
        return;
    };
    let method = METHODS[usize::from(header & 3)];
    let negotiate = (header >> 2) & 7;
    let body: Vec<u8> = (0..usize::from(*length) * 4).map(|i| i as u8).collect();
    let mut oracle = RequestOracle {
        method,
        body: &body,
        first: true,
        block1_used: false,
        response_szx: None,
    };
    let shared = Shared::<D, 4>::new();
    let mut endpoint =
        Endpoint::<_, D, 4, 8>::new(&shared, Unsecured(StdRng::from_seed([7; 32]))).unwrap();
    let mut sink = Sink::default();
    let handle = shared.handle();
    let remote: core::net::SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let result = {
        let mut transfer = pin!(async {
            let mut request = handle
                .client(remote)
                .request(method, "/x")?
                .option(OptionNumber::IF_NONE_MATCH, b"")?;
            if negotiate < 7 {
                request = request.block_size(negotiate)?;
            }
            request.transfer(&body, &mut sink).await
        });
        let mut context = Context::from_waker(Waker::noop());
        let mut records = records.chunks_exact(6);
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, D>| Err(Code::NOT_FOUND);
        let mut now = 0;
        let mut result = None;
        // Each pass either answers a request or moves time on towards a retransmission.
        for _ in 0..2000 {
            if let Poll::Ready(output) = transfer.as_mut().poll(&mut context) {
                result = Some(output);
                break;
            }
            endpoint.poll(Instant(now)).unwrap();
            let Some(outgoing) = endpoint.front_outgoing() else {
                now += 1000;
                continue;
            };
            let bytes = outgoing.bytes.to_vec();
            let enqueued = outgoing.enqueued;
            endpoint.complete_outgoing(enqueued);
            let request = MessageView::parse(&bytes).unwrap();
            oracle.check(request);
            let Some(record) = records.next() else {
                break;
            };
            let [code, number, block, etag, format, payload] = record else {
                unreachable!();
            };
            let mut response = Response::<D>::new(CODES[usize::from(code & 7)]);
            let value = (u64::from(*number) << 4) | u64::from(block & 0x0f);
            if block & 0x10 != 0 {
                response.uint_option(OptionNumber::BLOCK1, value).unwrap();
            }
            if block & 0x20 != 0 {
                response.uint_option(OptionNumber::BLOCK2, value).unwrap();
                oracle.response_szx = Some(block & 7).filter(|szx| *szx < 7);
            }
            if etag & 0x80 != 0 {
                response.option(OptionNumber::ETAG, &[etag & 3]).unwrap();
            }
            if format & 0x80 != 0 {
                response
                    .uint_option(OptionNumber::CONTENT_FORMAT, u64::from(format & 3))
                    .unwrap();
            }
            if format & 0x40 != 0 {
                response
                    .uint_option(OptionNumber::SIZE2, u64::from(*payload))
                    .unwrap();
            }
            let content = [0x5a; 128];
            response
                .set_payload(&content[..usize::from(*payload).min(128)])
                .unwrap();
            let mut answer = [0; D];
            let Ok(n) = response.encode(
                &mut answer,
                MessageType::Acknowledgement,
                request.message_id(),
                request.token(),
            ) else {
                continue;
            };
            let metadata = Metadata::new(remote, "192.0.2.2".parse().unwrap(), n);
            let _ = endpoint.receive(
                &answer[..n],
                metadata,
                Instant(now),
                &mut unused,
                &ProtectedOnly,
            );
        }
        result
    };
    match result {
        Some(Ok(transfer)) => {
            let code = transfer.reply.message().unwrap().code();
            if code.is_success() {
                // A successful exchange delivered a complete body and nothing else.
                assert_eq!(sink.finished, Some(transfer.length));
            } else {
                // A failure leaves no body behind (the sink contract).
                assert_eq!(sink.finished, None);
                assert!(sink.bytes.is_empty());
                assert_eq!(transfer.length, 0);
            }
        }
        Some(Err(_)) | None => assert_eq!(
            sink.finished, None,
            "a failed or unfinished exchange never completes the sink"
        ),
    }
}
