mod client_transfer;
mod endpoint_roles;
pub mod response_writer;

pub use client_transfer::client_transfer;

use mai_coap::{
    codec::{MessageBuilder, MessageView},
    crypto::SoftwareCrypto,
    security::PeerId,
    time::Instant,
};
use rand::SeedableRng;

fn crypto() -> SoftwareCrypto<rand::rngs::StdRng> {
    SoftwareCrypto::new(rand::rngs::StdRng::from_seed([3; 32]))
}
pub fn codec(data: &[u8]) {
    if let Ok(message) = MessageView::parse(data) {
        let mut output = [0; 8192];
        if let Ok(mut b) = MessageBuilder::new(
            &mut output,
            message.message_type(),
            message.code(),
            message.message_id(),
            message.token(),
        ) {
            for option in message.options() {
                if b.option(option.number, option.value).is_err() {
                    return;
                }
            }
            if let Ok(n) = b.finish(message.payload()) {
                assert_eq!(&output[..n], data);
            }
        }
        // Option encoding is canonical: moving bytes must equal a complete re-encoding.
        let ty = message.message_type();
        let token = &data[data.len() - data.len() % 9..];
        if let Ok(mut b) =
            MessageBuilder::new(&mut output, ty, message.code(), data.len() as u16, token)
        {
            let encoded = message
                .options()
                .all(|option| b.option(option.number, option.value).is_ok());
            if encoded && let Ok(n) = b.finish(message.payload()) {
                let mut moved = [0; 8192];
                if let Some(prefix) = moved.get_mut(..data.len()) {
                    prefix.copy_from_slice(data);
                    assert_eq!(
                        mai_coap::__test_support::reheader(
                            &mut moved,
                            data.len(),
                            ty,
                            data.len() as u16,
                            token
                        ),
                        Ok(n)
                    );
                    assert_eq!(&moved[..n], &output[..n]);
                }
            }
        }
        let _ = message.check_options(|_| false);
        // RFC 7252 sections 5.10.1 and 5.10.7, applied only to recognized options.
        let dot = |o: &mai_coap::codec::MessageOption<'_>| {
            matches!(
                o.number,
                mai_coap::codec::OptionNumber::URI_PATH
                    | mai_coap::codec::OptionNumber::LOCATION_PATH
            ) && matches!(o.value, b"." | b"..")
        };
        if let Some(first) = message.options().find(dot) {
            assert_eq!(
                message.check_options(|_| true),
                Err(mai_coap::Error::BadOption(first.number))
            );
        }
        let _ = message.processed(|_| false, &mut output);
        if data.len() <= 8192 {
            let mut compacted = [0; 8192];
            for all in [false, true] {
                compacted[..data.len()].copy_from_slice(data);
                let recognized =
                    |number: mai_coap::codec::OptionNumber| all || number.definition().is_some();
                let expected = message.processed(recognized, &mut output);
                let actual =
                    MessageView::process_in_place(&mut compacted[..data.len()], recognized);
                assert_eq!(actual, expected);
                if let Ok(n) = actual {
                    assert_eq!(&compacted[..n], &output[..n]);
                    assert_eq!(
                        MessageView::process_in_place(&mut compacted[..n], recognized),
                        Ok(n)
                    );
                    assert_eq!(&compacted[..n], &output[..n]);
                } else if matches!(
                    actual,
                    Err(mai_coap::Error::BadOption(_) | mai_coap::Error::Malformed)
                ) {
                    assert_eq!(&compacted[..data.len()], data);
                }
            }
        }
        for option in message.options() {
            let _ = option.uint();
        }
    }
}
pub fn link_format(data: &[u8]) {
    if let Ok(links) = mai_coap::link_format::Links::new(data) {
        for link in links.flatten() {
            for attr in link.attributes().flatten() {
                let _ = attr;
            }
            let _ = link.matches("rt=x*");
            link_round_trip(link);
        }
    }
}
fn decoded_attributes(
    link: mai_coap::link_format::Link<'_>,
) -> Option<Vec<(&str, Option<String>)>> {
    link.attributes()
        .map(|attr| {
            let attr = attr.ok()?;
            let value = attr.value.map(|value| {
                let mut out = vec![0; value.len()];
                let n = attr.decode_value(&mut out).unwrap();
                out.truncate(n);
                // Decoding removes only ASCII backslashes, so UTF-8 is preserved.
                String::from_utf8(out).unwrap()
            });
            Some((attr.name, value))
        })
        .collect()
}
/// DSC-1: serializing a parsed link yields a link the parser reads back unchanged.
fn link_round_trip(link: mai_coap::link_format::Link<'_>) {
    let Some(attributes) = decoded_attributes(link) else {
        return;
    };
    let borrowed: Vec<(&str, Option<&str>)> = attributes
        .iter()
        .map(|(name, value)| (*name, value.as_deref()))
        .collect();
    let mut output = vec![0; 16384];
    let mut writer = mai_coap::link_format::Writer::new(&mut output);
    // A parsed link is always serializable, except for lack of output space and
    // the writer's refusal of control characters, which RFC 2616 quoted-pair
    // admits on input.
    let control = attributes
        .iter()
        .any(|(_, value)| value.as_ref().is_some_and(|v| v.bytes().any(|b| b < 32)));
    match writer.link(link.href(), &borrowed) {
        Err(mai_coap::Error::Capacity) => return,
        Err(mai_coap::Error::Malformed) if control => return,
        result => result.unwrap(),
    }
    let n = writer.len();
    let mut reparsed = mai_coap::link_format::Links::new(&output[..n]).unwrap();
    let again = reparsed.next().unwrap().unwrap();
    assert!(reparsed.next().is_none());
    assert_eq!(again.href(), link.href());
    assert_eq!(decoded_attributes(again), Some(attributes));
}
fn oscore_context<const N: usize>(
    provider: &mut SoftwareCrypto<rand::rngs::StdRng>,
    sender: &[u8],
    recipient: &[u8],
) -> mai_coap::oscore::BoundedContext<N> {
    mai_coap::oscore::BoundedContext::<N>::derive(
        provider,
        &[1; 16],
        Some(&[2; 8]),
        sender,
        recipient,
        None,
        PeerId(1),
    )
    .unwrap()
}
pub fn oscore(data: &[u8]) {
    // OSC-6: an accepted option value is the unique encoding of its fields.
    if let Ok(option) = mai_coap::oscore::OscoreOption::parse(data) {
        let mut encoded = [0; 270];
        let n = option.encode(&mut encoded).unwrap();
        assert_eq!(&encoded[..n], data);
    }
    if let Ok(message) = MessageView::parse(data) {
        let mut provider = crypto();
        let mut context = oscore_context::<255>(&mut provider, &[1], &[0]);
        let _ = context.unprotect_request::<4096>(&mut provider, message, &mut [0; 4096]);
        protected_request_round_trip(message, data);
    }
}
/// Fuzzes the plaintext side: random ciphertext almost never passes AEAD
/// verification, so code behind it is reached by protecting fuzzed requests.
fn protected_request_round_trip(plain: MessageView<'_>, data: &[u8]) {
    use mai_coap::{Error, codec::OptionNumber};
    let mut provider = crypto();
    // EDHOC's absent ID Context fits zero storage; protect plaintext to reach
    // authenticated processing with the compact representation (OSC-2, OSC-8).
    let mut client = oscore_context::<0>(&mut provider, &[0], &[1]);
    let mut server = oscore_context::<0>(&mut provider, &[1], &[0]);
    let mut protected = [0; 8192];
    let Ok((n, _)) = client.protect_request::<8192>(&mut provider, plain, &mut protected) else {
        return;
    };
    let outer = MessageView::parse(&protected[..n]).unwrap();
    let mut restored = [0; 8192];
    // OSC-8: a modified ciphertext fails without consuming its sequence number.
    let mut tampered = protected;
    // Ciphertext includes the 8-byte tag; an empty payload is an oracle failure.
    let ciphertext = outer.payload().len();
    assert!(ciphertext >= 9);
    tampered[n - 1 - usize::from(data[0]) % ciphertext] ^= 1;
    let tampered = MessageView::parse(&tampered[..n]).unwrap();
    assert!(
        server
            .unprotect_request::<8192>(&mut provider, tampered, &mut restored)
            .is_err()
    );
    let (used, _) = server
        .unprotect_request::<8192>(&mut provider, outer, &mut restored)
        .unwrap();
    // The EDHOC option is consumed by the EDHOC layer and not restored (RFC 9668).
    if plain.option(OptionNumber::EDHOC).is_none() {
        assert_eq!(&restored[..used], data);
    }
    assert_eq!(
        server
            .unprotect_request::<8192>(&mut provider, outer, &mut restored)
            .map(|(n, _)| n),
        Err(Error::Replay)
    );
    // RFC 8613 section 8.2 step 3: a known Partial IV is refused before decryption,
    // whatever its ciphertext.
    assert_eq!(
        server
            .unprotect_request::<8192>(&mut provider, tampered, &mut restored)
            .map(|(n, _)| n),
        Err(Error::Replay)
    );
}
pub fn edhoc(data: &[u8]) {
    let mut provider = crypto();
    let _ = mai_coap::edhoc::Identity::new(data, [1; 32], &mut provider);
    let _ = mai_coap::edhoc::TrustedPeer::new(PeerId(1), data);
    let _ = mai_coap::__test_support::combined_message_3_length(data);
    let _ = mai_coap::__test_support::sequential_message_3(data);
    fn key(value: &[u8; 64]) -> [u8; 32] {
        fn digit(c: u8) -> u8 {
            if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
        }
        let mut key = [0; 32];
        for (i, pair) in value.as_chunks::<2>().0.iter().enumerate() {
            key[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        key
    }
    let mut identity_provider = crypto();
    let Ok(identity) = mai_coap::edhoc::Identity::new(
        include_bytes!("../../tests/fixtures/r.ccs"),
        key(b"72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"),
        &mut identity_provider,
    ) else {
        return;
    };
    let _ = mai_coap::edhoc::Responder::start::<1024>(&mut crypto(), &identity, &[1], data, false);
    let mut provider = crypto();
    let (_, message_1) =
        mai_coap::edhoc::Initiator::start::<64>(&mut provider, &[2], &[2]).unwrap();
    let (responder, _) = mai_coap::edhoc::Responder::start::<1024>(
        &mut provider,
        &identity,
        &[1],
        message_1.as_slice(),
        false,
    )
    .unwrap();
    let peers = [mai_coap::edhoc::TrustedPeer::new(
        PeerId(2),
        include_bytes!("../../tests/fixtures/i.ccs"),
    )
    .unwrap()];
    if data.first().is_some_and(|b| b & 1 == 1) {
        let _ = responder.finish_with_message_4(&mut provider, &peers, data);
    } else {
        let _ = responder.finish(&mut provider, &peers, data);
    }
    if data.first().is_some_and(|b| b >> 5 == 2) {
        let mut identity_provider = crypto();
        let Ok(own) = mai_coap::edhoc::Identity::new(
            include_bytes!("../../tests/fixtures/i.ccs"),
            key(b"fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"),
            &mut identity_provider,
        ) else {
            return;
        };
        let peer = mai_coap::edhoc::TrustedPeer::new(
            PeerId(1),
            include_bytes!("../../tests/fixtures/r.ccs"),
        )
        .unwrap();
        let mut provider = crypto();
        let (initiator, _) =
            mai_coap::edhoc::Initiator::start::<64>(&mut provider, &[2], &[2]).unwrap();
        let _ = initiator.finish::<1024>(&mut provider, &own, &peer, data, false);
    }
}
pub fn block1(data: &[u8]) {
    use mai_coap::{
        Error,
        block::{Block, BodyKey, BufferedUpload, StreamingUpload, UploadSink},
    };
    #[derive(Default)]
    struct Sink(Vec<u8>);
    impl UploadSink for Sink {
        fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
            self.0.clear();
            Ok(())
        }
        fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
            assert_eq!(self.0.len(), offset);
            if offset + bytes.len() > 1024 {
                return Err(Error::Capacity);
            }
            self.0.extend_from_slice(bytes);
            Ok(())
        }
        fn commit(&mut self) -> Result<(), Error> {
            Ok(())
        }
        fn abort(&mut self) {
            self.0.clear();
        }
    }
    let mut upload = BufferedUpload::<1024>::new(Instant(10000));
    let mut sink = Sink::default();
    let key = BodyKey {
        remote: "192.0.2.1:1".parse().unwrap(),
        resource: 1,
        context: Some(1),
        match_options: [0; 32],
        tags: Default::default(),
    };
    let mut stream =
        StreamingUpload::<1024>::begin(&key, None, 1024, Instant(10000), &mut sink).unwrap();
    let mut remaining = data;
    for index in 0..100 {
        let Some(header) = remaining.get(..6) else {
            break;
        };
        let raw = u32::from_be_bytes(header[..4].try_into().unwrap());
        let len = usize::from(u16::from_be_bytes(header[4..6].try_into().unwrap())) % 1025;
        let Some(payload) = remaining.get(6..6 + len) else {
            break;
        };
        remaining = &remaining[6 + len..];
        if let Ok(block) = Block::decode(raw.into()) {
            let _ = upload.push(block, payload, None, Instant(index as u64), Instant(10000));
            let _ = stream.push(block, payload, Instant(index), Instant(10000), &mut sink);
        }
        let _ = upload.complete_body();
    }
    stream.expire(Instant(10000), &mut sink);
}
struct Route;
impl mai_coap::proxy::Routing for Route {
    fn allow(&self, _: core::net::SocketAddr, _: &str, _: u16) -> bool {
        true
    }
}
fn uri_options(uri: mai_coap::uri::Uri<'_>, output: &mut [u8]) -> Result<usize, mai_coap::Error> {
    use mai_coap::codec::{Code, MessageType};
    let mut builder = MessageBuilder::new(output, MessageType::Confirmable, Code::GET, 1, &[])?;
    // Composed paths are percent-encoded, up to three times the input length.
    uri.options_with_scratch(&mut builder, &mut [0; 32768])?;
    builder.finish(&[])
}
/// Composing a URI from decomposed options and decomposing it again yields the
/// same options (RFC 7252 sections 6.4 and 6.5).
fn uri_round_trip(uri: mai_coap::uri::Uri<'_>) {
    let mut first = [0; 8192];
    // A parsed URI always decomposes; dot segments are removed rather than
    // rejected (RFC 7252 section 5.10.1, RFC 3986 section 6.2.2).
    let n = match uri_options(uri, &mut first) {
        Err(mai_coap::Error::Capacity) => return,
        result => result.unwrap(),
    };
    let message = MessageView::parse(&first[..n]).unwrap();
    for path in message.values(mai_coap::codec::OptionNumber::URI_PATH) {
        assert!(path != b"." && path != b"..");
    }
    let mut composed = [0; 32768];
    let Ok(text) =
        mai_coap::uri::compose(message, "192.0.2.1:5683".parse().unwrap(), &mut composed)
    else {
        return;
    };
    let reparsed = mai_coap::uri::Uri::parse(text).unwrap();
    let mut second = [0; 8192];
    let m = uri_options(reparsed, &mut second).unwrap();
    assert_eq!(&second[..m], &first[..n], "{text}");
}
pub fn proxy_uri(data: &[u8]) {
    if let Ok(text) = core::str::from_utf8(data)
        && let Ok(uri) = mai_coap::uri::Uri::parse(text)
    {
        uri_round_trip(uri);
    }
    if let Ok(message) = MessageView::parse(data) {
        let _ = mai_coap::__test_support::prepare(
            message,
            "192.0.2.1:1".parse().unwrap(),
            &Route,
            &mut [0; 4096],
        );
    }
}
pub fn endpoint(data: &[u8]) {
    endpoint_roles::check(data);
    deferred_response(data);
    deduplication::<0>(data);
    deduplication::<2>(data);
    use mai_coap::{
        codec::Code,
        endpoint::{Disposition, Endpoint, Request, ResponseWriter, Shared, Unsecured},
        security::PublicPaths,
        transport::Metadata,
    };
    let shared = Shared::<2048, 2>::new();
    let mut endpoint =
        Endpoint::<_, 2048, 2, 4>::new(&shared, Unsecured(rand::rngs::StdRng::from_seed([7; 32])))
            .unwrap();
    let mut app = |_: Request<'_>, _: &mut ResponseWriter<'_, 2048>| Ok(Disposition::Complete);
    let metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        data.len(),
    );
    let _ = endpoint.receive(
        data,
        metadata,
        Instant(0),
        &mut app,
        &PublicPaths(&[(Code::GET, "/x")]),
    );
    // TR-5 / REL-2: local backpressure cannot alter bytes or accept expired work.
    struct Sender {
        busy: bool,
        accepted: Option<Vec<u8>>,
    }
    impl mai_coap::transport::DatagramSender for Sender {
        type Error = core::convert::Infallible;
        fn poll_send(
            &mut self,
            _: core::net::SocketAddr,
            _: Option<core::net::IpAddr>,
            _: Option<u32>,
            bytes: &[u8],
            _: &mut core::task::Context<'_>,
        ) -> core::task::Poll<Result<mai_coap::transport::SendOutcome, Self::Error>> {
            core::task::Poll::Ready(Ok(if self.busy {
                mai_coap::transport::SendOutcome::RetryLater
            } else {
                self.accepted = Some(bytes.to_vec());
                mai_coap::transport::SendOutcome::Accepted
            }))
        }
    }
    let mut sender = Sender {
        busy: true,
        accepted: None,
    };
    let mut now = Instant(0);
    for (index, step) in data.chunks(2).take(64).enumerate() {
        now = now.after(u64::from(step[0]) * 8);
        endpoint.poll(now).unwrap();
        let mut wire = [0; 32];
        let length = mai_coap::codec::MessageBuilder::new(
            &mut wire,
            mai_coap::codec::MessageType::NonConfirmable,
            Code::GET,
            index as u16,
            b"f",
        )
        .unwrap()
        .finish(&[])
        .unwrap();
        let mut metadata = metadata;
        metadata.original_len = length;
        endpoint
            .receive(
                &wire[..length],
                metadata,
                now,
                &mut app,
                &mai_coap::security::AllowAll,
            )
            .unwrap();
        let before = endpoint
            .front_outgoing()
            .map(|packet| (packet.bytes.to_vec(), packet.enqueued));
        sender.busy = step[0] & 1 == 0;
        sender.accepted = None;
        let _ = endpoint.poll_transmit(
            &mut sender,
            now,
            &mut core::task::Context::from_waker(core::task::Waker::noop()),
        );
        if let Some((bytes, enqueued)) = before {
            assert!(
                now < enqueued.after(1000),
                "expired datagram remained queued"
            );
            if let Some(accepted) = &sender.accepted {
                assert_eq!(*accepted, bytes);
            } else {
                assert_eq!(endpoint.front_outgoing().unwrap().bytes, bytes);
            }
        } else {
            assert!(sender.accepted.is_none());
        }
    }
    endpoint.poll(now.after(1000000)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
}

// REL-2/REL-7/API-7: queue handoff, local acceptance and peer ACK are distinct.
fn deferred_response(data: &[u8]) {
    use core::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };
    use mai_coap::{
        codec::{Code, MessageType},
        endpoint::{Disposition, Endpoint, Request, Response, ResponseWriter, Shared, Unsecured},
        security::AllowAll,
        transport::Metadata,
    };
    let flags = data.first().copied().unwrap_or(0);
    let con = flags & 1 != 0;
    let queued = flags & 2 != 0;
    let detached = flags & 4 != 0;
    let shared = Shared::<64, 1>::new();
    let mut endpoint = Endpoint::<_, 64, 1, 4, 0, 1, 2, 1, 1, 0, 2>::new(
        &shared,
        Unsecured(rand::rngs::StdRng::from_seed([11; 32])),
    )
    .unwrap();
    let mut bytes = [0; 64];
    let n = MessageBuilder::new(
        &mut bytes,
        if con {
            MessageType::Confirmable
        } else {
            MessageType::NonConfirmable
        },
        Code::GET,
        1,
        b"f",
    )
    .unwrap()
    .finish(&[])
    .unwrap();
    let mut metadata = Metadata::new(
        "192.0.2.1:5683".parse().unwrap(),
        "192.0.2.2".parse().unwrap(),
        n,
    );
    let mut ticket = None;
    endpoint
        .receive(
            &bytes[..n],
            metadata,
            Instant(0),
            &mut |request: Request<'_>, _: &mut ResponseWriter<'_, 64>| {
                ticket = request.deferred_ticket();
                Ok(Disposition::Deferred)
            },
            &AllowAll,
        )
        .unwrap();
    if con {
        endpoint.complete_outgoing(Instant(0));
    }
    let mut operation = Some(
        if queued {
            shared
                .handle()
                .respond(ticket.unwrap(), &Response::new(Code::CONTENT))
        } else {
            shared
                .handle()
                .respond_confirmed(ticket.unwrap(), &Response::new(Code::CONTENT))
        }
        .unwrap(),
    );
    endpoint.poll(Instant(1)).unwrap();
    let original = endpoint.front_outgoing().unwrap().bytes.to_vec();
    let mid = MessageView::parse(&original).unwrap().message_id();
    let mut cx = Context::from_waker(Waker::noop());
    let result = Pin::new(operation.as_mut().unwrap()).poll(&mut cx);
    assert_eq!(
        result,
        if queued {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    );
    if queued || detached {
        drop(operation.take());
    }
    let mut expected = None;
    let mut accepted = false;
    let mut now = Instant(1);
    for step in data.iter().skip(1).take(16) {
        now = now.after(u64::from(*step) * 8);
        endpoint.poll(now).unwrap();
        if !accepted && now >= Instant(1001) {
            expected = Some(Err(mai_coap::Error::LocalSendTimeout));
        }
        if let Some(wire) = endpoint.front_outgoing() {
            assert_eq!(wire.bytes, original);
            if step & 1 != 0 {
                endpoint.complete_outgoing(now);
                accepted = true;
                if !con {
                    expected = Some(Ok(()));
                }
            }
        }
        if con && accepted && step & 2 != 0 {
            let n = MessageBuilder::new(
                &mut bytes,
                MessageType::Acknowledgement,
                Code::EMPTY,
                mid,
                &[],
            )
            .unwrap()
            .finish(&[])
            .unwrap();
            metadata.original_len = n;
            endpoint
                .receive(
                    &bytes[..n],
                    metadata,
                    now,
                    &mut |_: Request<'_>, _: &mut ResponseWriter<'_, 64>| panic!("ACK dispatched"),
                    &AllowAll,
                )
                .unwrap();
            expected = Some(Ok(()));
        }
        if let Some(op) = operation.as_mut() {
            let result = Pin::new(op).poll(&mut cx);
            match expected {
                Some(value) => {
                    assert_eq!(result, Poll::Ready(value));
                    drop(operation.take());
                }
                None => assert!(result.is_pending()),
            }
        }
    }
    endpoint.poll(now.after(1_000_000)).unwrap();
    assert!(endpoint.front_outgoing().is_none());
    if let Some(op) = operation.as_mut() {
        assert_eq!(
            Pin::new(op).poll(&mut cx),
            Poll::Ready(Err(if accepted {
                mai_coap::Error::Timeout
            } else {
                mai_coap::Error::LocalSendTimeout
            }))
        );
    }
    drop(operation.take());
    let mut probe = shared
        .handle()
        .respond_confirmed(ticket.unwrap(), &Response::new(Code::CONTENT))
        .expect("response completion leaked its command slot");
    endpoint.poll(now.after(1_000_000)).unwrap();
    assert_eq!(
        Pin::new(&mut probe).poll(&mut cx),
        Poll::Ready(Err(mai_coap::Error::Cancelled))
    );
}

fn deduplication<const R: usize>(data: &[u8]) {
    use mai_coap::__test_support::{CachedReply, Deduplication, PacketPool};
    let mut table = Deduplication::<4, R>::new();
    let mut pool = PacketPool::<32, 8>::new();
    let peer = "192.0.2.1:5683".parse().unwrap();
    let local = "192.0.2.2".parse().unwrap();
    for (step, bytes) in data.chunks(40).take(64).enumerate() {
        let id = u16::from(bytes[0] & 15);
        let reply = (bytes[0] & 16 != 0).then_some(&bytes[1..]);
        let now = Instant(step as u64);
        let until = now.after(8);
        let input = match reply {
            None => CachedReply::Silent,
            Some(value) if value.len() <= 4 => CachedReply::inline(value).unwrap(),
            Some(value) if value.len() > 32 => {
                assert!(CachedReply::inline(value).is_err());
                continue;
            }
            Some(value) => {
                let packet = pool.reserve().unwrap();
                pool.write(&packet, value).unwrap();
                CachedReply::Full(packet)
            }
        };
        if table
            .remember(&mut pool, peer, local, id, until, input, now)
            .is_ok()
        {
            let actual = match table.lookup(peer, local, id, now) {
                None => None,
                Some(CachedReply::Silent) => Some(None),
                Some(CachedReply::Dropped) => panic!("newly stored reply was reclaimed"),
                Some(CachedReply::Inline { bytes, len }) => Some(Some(&bytes[..usize::from(*len)])),
                Some(CachedReply::Full(packet)) => Some(pool.get(packet)),
            };
            assert_eq!(actual, Some(reply));
        }
    }
}
