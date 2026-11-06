//! Bounded EDHOC over CoAP and combined-request endpoint integration.
use super::{CredentialStore, Identity, Initiator, Responder, TrustedPeer, TrustedPeers};
use crate::{
    Error,
    codec::{Code, ContentFormat, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{Prepared, Protection, Request, ResponseWriter, Target},
    messaging::TransmissionParameters,
    oscore::{
        MAX_ID_CONTEXT_BYTES, OscoreOption,
        endpoint::{Binding, Oscore},
    },
    security::{CryptoProvider, PeerId, SecurityState, path_matches},
    time::Instant,
};
use core::net::SocketAddr;

#[allow(
    clippy::large_enum_variant,
    reason = "handshake storage is bounded without an allocator"
)]
enum State {
    Initiator(Initiator, TrustedPeer),
    Responder(Responder),
    SequentialAcknowledgement,
}
struct Session {
    remote: SocketAddr,
    peer: Option<PeerId>,
    combined: bool,
    state: State,
    // Reconfiguring the timeout can change deadline order without changing age.
    started: Instant,
    deadline: Instant,
}
/// EDHOC + OSCORE on one provider, with four concurrent handshakes by default.
///
/// `ID_CONTEXT_BYTES` defaults to [`MAX_ID_CONTEXT_BYTES`] for externally
/// installed OSCORE contexts; construction rejects larger capacities at compile
/// time.
/// EDHOC-derived contexts have no ID Context; selecting zero removes its byte
/// reservation while retaining the same context and handshake counts.
pub struct Edhoc<
    P,
    const CONTEXTS: usize = 4,
    const HANDSHAKES: usize = 4,
    S = TrustedPeers<16>,
    const ID_CONTEXT_BYTES: usize = MAX_ID_CONTEXT_BYTES,
> {
    oscore: Oscore<P, CONTEXTS, ID_CONTEXT_BYTES>,
    identity: Identity,
    trusted: S,
    sessions: heapless::Vec<Session, HANDSHAKES>,
    path: &'static str,
    now: Instant,
    timeout_ms: u64,
    runs: u64,
    responder_limit: usize,
}
impl<
    P: CryptoProvider,
    const CONTEXTS: usize,
    const HANDSHAKES: usize,
    const ID_CONTEXT_BYTES: usize,
> Edhoc<P, CONTEXTS, HANDSHAKES, TrustedPeers<16>, ID_CONTEXT_BYTES>
{
    /// Creates an endpoint with no trusted peers.
    pub fn new(provider: P, identity: Identity) -> Result<Self, Error> {
        Self::with_store(provider, identity, TrustedPeers::new())
    }
}
impl<
    P: CryptoProvider,
    const CONTEXTS: usize,
    const HANDSHAKES: usize,
    const CREDENTIALS: usize,
    const ID_CONTEXT_BYTES: usize,
> Edhoc<P, CONTEXTS, HANDSHAKES, TrustedPeers<CREDENTIALS>, ID_CONTEXT_BYTES>
{
    /// Adds a peer to the in-memory store, rejecting a duplicate application identity.
    pub fn trust(&mut self, peer: TrustedPeer) -> Result<(), Error> {
        if self.trusted.get(peer.id).is_some() {
            return Err(Error::Malformed);
        }
        self.trusted.insert(peer)
    }
}
impl<
    P: CryptoProvider,
    const CONTEXTS: usize,
    const HANDSHAKES: usize,
    S: CredentialStore,
    const ID_CONTEXT_BYTES: usize,
> Edhoc<P, CONTEXTS, HANDSHAKES, S, ID_CONTEXT_BYTES>
{
    /// Creates an endpoint using nonblocking application-owned credential lookup.
    pub fn with_store(provider: P, identity: Identity, trusted: S) -> Result<Self, Error> {
        if CONTEXTS == 0 || HANDSHAKES == 0 {
            return Err(Error::Capacity);
        }
        Ok(Self {
            oscore: Oscore::new(provider),
            identity,
            trusted,
            sessions: heapless::Vec::new(),
            path: "/.well-known/edhoc",
            now: Instant(0),
            timeout_ms: TransmissionParameters::default().max_transmit_wait(),
            runs: 0,
            responder_limit: HANDSHAKES.min(2),
        })
    }
    /// Accesses credentials for subsequent handshakes. Existing epochs remain valid.
    /// Retire affected contexts and application work separately when revoking access.
    pub fn credentials_mut(&mut self) -> &mut S {
        &mut self.trusted
    }
    /// Bounds live responder handshakes per source IP, independently of UDP ports.
    /// Defaults to `min(2, HANDSHAKES)`. Keeping this below the total capacity
    /// leaves room for other sources; proxy clients share their proxy's allowance.
    /// Rejects zero or a limit greater than the handshake capacity.
    pub fn set_responder_limit(&mut self, limit: usize) -> Result<(), Error> {
        if limit == 0 || limit > HANDSHAKES {
            return Err(Error::Malformed);
        }
        self.responder_limit = limit;
        Ok(())
    }
    /// Configures the EDHOC resource path and handshake inactivity expiry.
    /// Defaults to CoAP's MAX_TRANSMIT_WAIT (93 seconds with default parameters).
    /// Increase it when using longer transmission waits.
    pub fn configure(&mut self, path: &'static str, timeout_ms: u64) -> Result<(), Error> {
        if !path.starts_with('/') || timeout_ms == 0 {
            return Err(Error::Malformed);
        }
        self.path = path;
        self.timeout_ms = timeout_ms;
        Ok(())
    }
    /// Established context count.
    pub fn contexts(&self) -> usize {
        self.oscore.len()
    }
    /// Number of started handshakes.
    pub const fn runs(&self) -> u64 {
        self.runs
    }
    /// Accesses context accounting and the common crypto provider.
    /// Externally installed contexts must use this endpoint's ID Context bound.
    pub fn oscore_mut(&mut self) -> &mut Oscore<P, CONTEXTS, ID_CONTEXT_BYTES> {
        &mut self.oscore
    }
    fn connection(&mut self, other: Option<&[u8]>) -> Result<heapless::Vec<u8, 7>, Error> {
        for _ in 0..256 {
            let mut byte = [0];
            self.oscore.provider.random(&mut byte);
            // EDH-6: one-byte CBOR integers save space; uniqueness covers live sessions too.
            let raw = if byte[0] % 48 < 24 {
                byte[0] % 48
            } else {
                0x20 + (byte[0] % 48 - 24)
            };
            let id = [raw];
            if other == Some(&id[..])
                || !self.oscore.id_available(&id)
                || self.sessions.iter().any(|s| match &s.state {
                    State::Responder(r) => r.connection_id() == id,
                    State::Initiator(i, _) => i.connection_id() == id,
                    _ => false,
                })
            {
                continue;
            }
            return heapless::Vec::from_slice(&id).map_err(|_| Error::Capacity);
        }
        Err(Error::Capacity)
    }
    fn control_packet<const DATAGRAM_BYTES: usize>(
        &self,
        original: MessageView<'_>,
        payload: &[u8],
        format: ContentFormat,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut b = MessageBuilder::new(
            output,
            MessageType::Confirmable,
            Code::POST,
            original.message_id(),
            original.token(),
        )?;
        for number in [OptionNumber::URI_HOST, OptionNumber::URI_PORT] {
            if let Some(option) = original.option(number) {
                b.option(number, option.value)?;
            }
        }
        crate::uri::path_options(self.path, &mut b)?;
        b.uint_option(OptionNumber::CONTENT_FORMAT, format.0.into())?;
        if let Some(option) = original.option(OptionNumber::PROXY_SCHEME) {
            b.option(option.number, option.value)?;
        }
        b.finish(payload)
    }
    fn begin<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        original: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<Binding>, Error> {
        let remote = target.remote;
        let peer = target.peer.ok_or(Error::ContextNotFound)?;
        let trusted = self.trusted.get(peer).ok_or(Error::ContextNotFound)?;
        if self.sessions.is_full()
            || !self.oscore.has_capacity()
            || self
                .sessions
                .iter()
                .any(|s| crate::transport::same_peer(s.remote, remote) && s.peer == Some(peer))
        {
            return Err(Error::Capacity);
        }
        let id = self.connection(None)?;
        let (state, message) =
            Initiator::start::<DATAGRAM_BYTES>(&mut self.oscore.provider, &id, &[2])?;
        let mut payload = heapless::Vec::<u8, DATAGRAM_BYTES>::new();
        payload.push(0xf5).map_err(|_| Error::Capacity)?;
        payload
            .extend_from_slice(message.as_slice())
            .map_err(|_| Error::Capacity)?;
        let length = self.control_packet::<DATAGRAM_BYTES>(
            original,
            &payload,
            ContentFormat::CID_EDHOC,
            output,
        )?;
        self.sessions
            .push(Session {
                remote,
                peer: Some(peer),
                combined: target.combined_edhoc,
                state: State::Initiator(state, trusted),
                started: self.now,
                deadline: self
                    .now
                    .after(self.timeout_ms.max(target.parameters.max_transmit_wait())),
            })
            .map_err(|_| Error::Capacity)?;
        self.runs += 1;
        Ok(Prepared::Handshake { length })
    }
    // Message-1 parsing and responder construction must not reserve stack during message 3.
    #[inline(never)]
    fn start_responder<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: Request<'_>,
        now: Instant,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<bool, Error> {
        let payload = request.message.payload();
        if !self.oscore.has_capacity() {
            response.set_code(Code::TOO_MANY_REQUESTS);
            response.uint_option(OptionNumber::MAX_AGE, 1)?;
            return Ok(true);
        }
        if super::validation::message_1(&payload[1..]).is_err() {
            Self::error(response, false)?;
            return Ok(true);
        }
        let parsed =
            lakers::BufferMessage1::new_from_slice(&payload[1..]).map_err(|_| Error::Malformed)?;
        let (method, suites, _, other, ead) = match lakers::parse_message_1(&parsed) {
            Ok(p) => p,
            Err(_) => {
                Self::error(response, false)?;
                return Ok(true);
            }
        };
        if suites.as_slice().last() != Some(&2) {
            Self::error(response, true)?;
            return Ok(true);
        }
        if method != 3 || ead.processed_critical_items().is_err() {
            Self::error(response, false)?;
            return Ok(true);
        }
        let source = request.metadata.remote.ip();
        let source_sessions = self
            .sessions
            .iter()
            .filter(|session| {
                session.remote.ip() == source && matches!(session.state, State::Responder(_))
            })
            .count();
        if source_sessions >= self.responder_limit {
            response.set_code(Code::TOO_MANY_REQUESTS);
            response.uint_option(OptionNumber::MAX_AGE, 1)?;
            return Ok(true);
        }
        let oldest = if self.sessions.is_full() {
            // Initiator work is never replaceable; source admission is checked first.
            let oldest = self
                .sessions
                .iter()
                .enumerate()
                .filter(|(_, session)| matches!(session.state, State::Responder(_)))
                .min_by_key(|(_, session)| session.started)
                .map(|(index, _)| index);
            if oldest.is_none() {
                response.set_code(Code::TOO_MANY_REQUESTS);
                response.uint_option(OptionNumber::MAX_AGE, 1)?;
                return Ok(true);
            }
            oldest
        } else {
            None
        };
        let id = self.connection(Some(other.as_slice()))?;
        match Responder::start::<DATAGRAM_BYTES>(
            &mut self.oscore.provider,
            &self.identity,
            &id,
            &payload[1..],
            false,
        ) {
            Ok((state, message)) => {
                response.set_code(Code::CHANGED);
                response
                    .uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::EDHOC.0.into())?;
                response.set_payload(message.as_slice())?;
                if let Some(index) = oldest {
                    self.sessions.swap_remove(index);
                }
                self.sessions
                    .push(Session {
                        remote: request.metadata.remote,
                        peer: None,
                        combined: false,
                        state: State::Responder(state),
                        started: now,
                        deadline: now.after(self.timeout_ms),
                    })
                    .map_err(|_| Error::Capacity)?;
                self.runs += 1;
            }
            Err(_) => Self::error(response, false)?,
        }
        Ok(true)
    }
    fn finish_responder(
        &mut self,
        remote: SocketAddr,
        id: &[u8],
        message: &[u8],
        confirm: bool,
    ) -> Result<crate::Packet<64>, Error> {
        let index = self
            .sessions
            .iter()
            .position(|s| {
                crate::transport::same_peer(s.remote, remote)
                    && matches!(&s.state,State::Responder(r) if r.connection_id()==id)
            })
            .ok_or(Error::ContextNotFound)?;
        // Refuse before consuming the session so a new-MID attempt can resume it.
        if !self.oscore.has_capacity() || !self.oscore.id_available(id) {
            return Err(Error::Capacity);
        }
        let entry = self.sessions.swap_remove(index);
        let State::Responder(state) = entry.state else {
            return Err(Error::Edhoc);
        };
        let (material, message_4) = if confirm {
            state.finish_with_message_4(&mut self.oscore.provider, &self.trusted, message)?
        } else {
            (
                state.finish(&mut self.oscore.provider, &self.trusted, message)?,
                crate::Packet::new(),
            )
        };
        let context = material.into_bounded_context(&mut self.oscore.provider)?;
        self.oscore.install_fresh(context)?;
        Ok(message_4)
    }
    // Reconstruction scratch is only needed after message-3 verification returns.
    #[inline(never)]
    fn incoming_combined<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: MessageView<'_>,
        metadata: crate::transport::Metadata,
        length: usize,
        output: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<Binding>), Error> {
        let mut wire = [0u8; DATAGRAM_BYTES];
        let mut b = MessageBuilder::new(
            &mut wire,
            request.message_type(),
            request.code(),
            request.message_id(),
            request.token(),
        )?;
        for o in request.options() {
            if o.number != OptionNumber::EDHOC {
                b.option(o.number, o.value)?;
            }
        }
        let n = b.finish(&request.payload()[length..])?;
        self.oscore
            .incoming::<DATAGRAM_BYTES>(MessageView::parse(&wire[..n])?, metadata, output)
    }
    fn error<const DATAGRAM_BYTES: usize>(
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
        suite: bool,
    ) -> Result<(), Error> {
        response.set_code(Code::BAD_REQUEST);
        response.uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::EDHOC.0.into())?;
        // EDH-9: suite negotiation is an EDHOC CBOR sequence, not a diagnostic string.
        response.set_payload(if suite { &[2, 2] } else { &[1, 0x60] })?;
        Ok(())
    }
}
impl<
    P: CryptoProvider,
    const CONTEXTS: usize,
    const HANDSHAKES: usize,
    S: CredentialStore,
    const ID_CONTEXT_BYTES: usize,
> Protection for Edhoc<P, CONTEXTS, HANDSHAKES, S, ID_CONTEXT_BYTES>
{
    fn pin_epoch(&mut self, generation: u64) -> Result<(), Error> {
        self.oscore.pin(generation)
    }
    fn unpin_epoch(&mut self, generation: u64) {
        self.oscore.unpin(generation);
    }
    type Binding = Binding;
    fn random(&mut self, bytes: &mut [u8]) {
        self.oscore.random(bytes);
    }
    fn requires_request_retention(&self, target: Target) -> bool {
        target.peer.is_some()
    }
    fn outgoing<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<Binding>, Error> {
        match self
            .oscore
            .outgoing::<DATAGRAM_BYTES>(target, request, output)
        {
            Err(Error::ContextNotFound) => self.begin::<DATAGRAM_BYTES>(target, request, output),
            other => other,
        }
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn incoming<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: MessageView<'_>,
        metadata: crate::transport::Metadata,
        output: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<Binding>), Error> {
        if request
            .option(OptionNumber::EDHOC)
            .is_some_and(|o| o.value.is_empty())
        {
            if request
                .options()
                .filter(|o| o.number == OptionNumber::EDHOC)
                .count()
                != 1
            {
                return Err(Error::Malformed);
            }
            let option = OscoreOption::parse(
                request
                    .option(OptionNumber::OSCORE)
                    .ok_or(Error::Malformed)?
                    .value,
            )?;
            let kid = option.kid.ok_or(Error::Malformed)?;
            let length = super::combined_message_3_length(request.payload())?;
            if !self.oscore.has_recipient(kid, option.kid_context) {
                self.finish_responder(metadata.remote, kid, &request.payload()[..length], false)
                    .map_err(|error| {
                        if error == Error::Capacity {
                            error
                        } else {
                            Error::Edhoc
                        }
                    })?;
            }
            self.incoming_combined::<DATAGRAM_BYTES>(request, metadata, length, output)
        } else {
            self.oscore
                .incoming::<DATAGRAM_BYTES>(request, metadata, output)
        }
    }
    fn response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Binding,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.oscore
            .response::<DATAGRAM_BYTES>(response, binding, output)
    }
    fn received_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Binding,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.oscore
            .received_response::<DATAGRAM_BYTES>(response, binding, output)
    }
    fn release(&mut self, binding: Binding) {
        self.oscore.release(binding);
    }
    fn handshake_runs(&self) -> u64 {
        self.runs
    }
    fn context_evictions(&self) -> u64 {
        self.oscore.evictions()
    }
    fn control<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: Request<'_>,
        now: Instant,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<bool, Error> {
        self.now = now;
        if !path_matches(request.message, self.path) {
            return Ok(false);
        }
        if request.message.code() != Code::POST {
            response.set_code(Code::METHOD_NOT_ALLOWED);
            return Ok(true);
        }
        let payload = request.message.payload();
        if payload.first() == Some(&0xf5) {
            return self.start_responder(request, now, response);
        } else {
            let (id, message) = super::sequential_message_3(payload)?;
            match self.finish_responder(request.metadata.remote, id.as_slice(), message, true) {
                Err(Error::Capacity) => {
                    response.set_code(Code::UNAVAILABLE);
                    response.uint_option(OptionNumber::MAX_AGE, 1)?;
                }
                Err(_) => Self::error(response, false)?,
                Ok(message_4) => {
                    response.set_code(Code::CHANGED);
                    response
                        .uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::EDHOC.0.into())?;
                    response.set_payload(message_4.as_slice())?;
                }
            }
        }
        Ok(true)
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn handshake_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        response: MessageView<'_>,
        original: MessageView<'_>,
        now: Instant,
        output: &mut [u8],
    ) -> Result<Prepared<Binding>, Error> {
        let remote = target.remote;
        self.now = now;
        let peer = target.peer.ok_or(Error::ContextNotFound)?;
        let index = self
            .sessions
            .iter()
            .position(|s| {
                crate::transport::same_peer(s.remote, remote)
                    && s.peer == Some(peer)
                    && !matches!(s.state, State::Responder(_))
            })
            .ok_or(Error::Edhoc)?;
        let entry = self.sessions.swap_remove(index);
        if !response.code().is_success() {
            return Err(Error::Edhoc);
        }
        match entry.state {
            State::SequentialAcknowledgement => self
                .oscore
                .outgoing::<DATAGRAM_BYTES>(target, original, output),
            State::Initiator(state, trusted) => {
                let (message_3, material) = state.finish::<DATAGRAM_BYTES>(
                    &mut self.oscore.provider,
                    &self.identity,
                    &trusted,
                    response.payload(),
                    false,
                )?;
                let remote_id = material.sender.clone();
                let context = material.into_bounded_context(&mut self.oscore.provider)?;
                self.oscore.install_fresh(context)?;
                if entry.combined {
                    let mut protected = [0u8; DATAGRAM_BYTES];
                    let Prepared::Request { length, binding } = self
                        .oscore
                        .outgoing::<DATAGRAM_BYTES>(target, original, &mut protected)?
                    else {
                        return Err(Error::Edhoc);
                    };
                    let protected = MessageView::parse(&protected[..length])?;
                    match combine(protected, message_3.as_slice(), output) {
                        Ok(length) => return Ok(Prepared::Request { length, binding }),
                        Err(Error::Capacity) => {
                            if let Some(binding) = binding {
                                self.oscore.release(binding);
                            }
                        }
                        Err(error) => {
                            if let Some(binding) = binding {
                                self.oscore.release(binding);
                            }
                            return Err(error);
                        }
                    }
                }
                let id = lakers::ConnId::from_slice(&remote_id).ok_or(Error::Malformed)?;
                let mut payload = heapless::Vec::<u8, DATAGRAM_BYTES>::new();
                payload
                    .extend_from_slice(id.as_cbor())
                    .map_err(|_| Error::Capacity)?;
                payload
                    .extend_from_slice(message_3.as_slice())
                    .map_err(|_| Error::Capacity)?;
                let length = self.control_packet::<DATAGRAM_BYTES>(
                    original,
                    &payload,
                    ContentFormat::CID_EDHOC,
                    output,
                )?;
                self.sessions
                    .push(Session {
                        remote,
                        peer: Some(peer),
                        combined: false,
                        state: State::SequentialAcknowledgement,
                        started: now,
                        deadline: now
                            .after(self.timeout_ms.max(target.parameters.max_transmit_wait())),
                    })
                    .map_err(|_| Error::Capacity)?;
                Ok(Prepared::Handshake { length })
            }
            State::Responder(_) => Err(Error::Edhoc),
        }
    }
    fn recover<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        original: MessageView<'_>,
        now: Instant,
        output: &mut [u8],
    ) -> Result<Prepared<Binding>, Error> {
        self.now = now;
        if !target.recover {
            return Err(Error::ContextNotFound);
        }
        self.oscore
            .retire_unpinned(target.peer.ok_or(Error::ContextNotFound)?);
        self.begin::<DATAGRAM_BYTES>(target, original, output)
    }
    fn expire(&mut self, now: Instant) {
        self.now = now;
        self.sessions.retain(|s| s.deadline > now);
    }
    fn deadline(&self) -> Option<Instant> {
        self.sessions.iter().map(|s| s.deadline).min()
    }
    fn generation(&self, binding: &Binding) -> Option<u64> {
        self.oscore.generation(binding)
    }
}
fn combine(request: MessageView<'_>, message_3: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let mut b = MessageBuilder::new(
        output,
        request.message_type(),
        request.code(),
        request.message_id(),
        request.token(),
    )?;
    let mut inserted = false;
    for option in request.options() {
        if option.number > OptionNumber::EDHOC && !inserted {
            b.option(OptionNumber::EDHOC, &[])?;
            inserted = true;
        }
        b.option(option.number, option.value)?;
    }
    if !inserted {
        b.option(OptionNumber::EDHOC, &[])?;
    }
    b.finish_parts(&[message_3, request.payload()])
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::test_outgoing::PopOutgoing;
    use crate::{
        crypto::SoftwareCrypto,
        edhoc::tests::{CRED_I, CRED_R, M1, SK_I, SK_R, hex},
        endpoint::{Endpoint, Shared},
        security::PublicPaths,
        transport::Metadata,
    };
    use rand::{SeedableRng, rngs::StdRng};

    fn identity(ccs: &[u8], private: [u8; 32]) -> Identity {
        let mut provider = SoftwareCrypto::new(StdRng::from_seed([7; 32]));
        Identity::new(ccs, private, &mut provider).unwrap()
    }

    fn responder<const HANDSHAKES: usize>() -> Edhoc<SoftwareCrypto<StdRng>, 2, HANDSHAKES> {
        let identity = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap());
        let mut endpoint =
            Edhoc::new(SoftwareCrypto::new(StdRng::from_seed([8; 32])), identity).unwrap();
        endpoint
            .trust(TrustedPeer::new(PeerId(1), &hex(CRED_I)).unwrap())
            .unwrap();
        endpoint
    }
    fn first<const HANDSHAKES: usize>(
        endpoint: &mut Endpoint<'_, Edhoc<SoftwareCrypto<StdRng>, 2, HANDSHAKES>, 512, 2, 8>,
        remote: &str,
        mid: u16,
        now: u64,
    ) -> Code {
        let mut payload = std::vec![0xf5];
        payload.extend_from_slice(&hex(M1));
        let mut wire = [0; 512];
        let mut b =
            MessageBuilder::new(&mut wire, MessageType::Confirmable, Code::POST, mid, b"ed")
                .unwrap();
        crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
        b.uint_option(
            OptionNumber::CONTENT_FORMAT,
            ContentFormat::CID_EDHOC.0.into(),
        )
        .unwrap();
        let n = b.finish(&payload).unwrap();
        let metadata = Metadata {
            remote: remote.parse().unwrap(),
            local: "192.0.2.2".parse().unwrap(),
            interface: None,
            original_len: n,
        };
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| Err(Code::NOT_FOUND);
        endpoint
            .receive(
                &wire[..n],
                metadata,
                Instant(now),
                &mut unused,
                &PublicPaths(&[]),
            )
            .unwrap();
        let outgoing = endpoint.pop_outgoing().unwrap();
        MessageView::parse(outgoing.packet.as_slice())
            .unwrap()
            .code()
    }

    #[test]
    fn edh_8_context_pressure_preserves_sessions_for_new_mid_retries() {
        type Server<'a> = Endpoint<'a, Edhoc<SoftwareCrypto<StdRng>, 2, 2>, 512, 2, 8>;
        for combined in [false, true] {
            for expire in [false, true] {
                let shared = Shared::<512, 2>::new();
                let mut server = Server::new(&shared, responder::<2>()).unwrap();
                let handled = core::cell::Cell::new(0);
                let deliver = |server: &mut Server<'_>, bytes: &[u8], now| {
                    let mut app = |request: Request<'_>, response: &mut ResponseWriter<'_, 512>| {
                        assert_eq!(
                            request.security,
                            SecurityState::Protected { peer: PeerId(1) }
                        );
                        handled.set(handled.get() + 1);
                        response.set_payload(b"ok").unwrap();
                        Ok(crate::endpoint::Disposition::Complete)
                    };
                    server
                        .receive(
                            bytes,
                            Metadata::new(
                                "192.0.2.1:5683".parse().unwrap(),
                                "192.0.2.2".parse().unwrap(),
                                bytes.len(),
                            ),
                            Instant(now),
                            &mut app,
                            &PublicPaths(&[]),
                        )
                        .unwrap();
                    server.pop_outgoing().unwrap().packet
                };
                let mut crypto = SoftwareCrypto::new(StdRng::from_seed([9; 32]));
                let identity = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap());
                let peer = TrustedPeer::new(PeerId(2), &hex(CRED_R)).unwrap();
                let (initiator, m1) = Initiator::start::<512>(&mut crypto, &[0x37], &[2]).unwrap();
                let mut wire = [0; 512];
                let mut b =
                    MessageBuilder::new(&mut wire, MessageType::Confirmable, Code::POST, 1, b"m1")
                        .unwrap();
                crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
                b.uint_option(
                    OptionNumber::CONTENT_FORMAT,
                    ContentFormat::CID_EDHOC.0.into(),
                )
                .unwrap();
                let n = b.finish_parts(&[&[0xf5], m1.as_slice()]).unwrap();
                let response = deliver(&mut server, &wire[..n], 0);
                let response = MessageView::parse(response.as_slice()).unwrap();
                assert_eq!(response.code(), Code::CHANGED);
                let (m3, material) = initiator
                    .finish::<512>(&mut crypto, &identity, &peer, response.payload(), false)
                    .unwrap();
                let id = material.sender.clone();
                let mut context = material.into_context(&mut crypto).unwrap();
                let deadline = server.protection_mut().sessions[0].deadline;
                let mut generations = std::vec::Vec::new();
                for i in 0..2 {
                    let table = &mut server.protection_mut().oscore;
                    let context = crate::oscore::Context::derive(
                        &mut table.provider,
                        &[7; 16],
                        None,
                        &[9],
                        &[200 + i],
                        None,
                        PeerId(90 + u32::from(i)),
                    )
                    .unwrap();
                    let generation = table.install_epoch(context).unwrap();
                    table.pin(generation).unwrap();
                    generations.push(generation);
                }
                let mut b =
                    MessageBuilder::new(&mut wire, MessageType::Confirmable, Code::GET, 20, b"app")
                        .unwrap();
                crate::uri::path_options("/x", &mut b).unwrap();
                let n = b.finish(&[]).unwrap();
                let mut protected = [0; 512];
                let (protected_len, mut binding) = context
                    .protect_request::<512>(
                        &mut crypto,
                        MessageView::parse(&wire[..n]).unwrap(),
                        &mut protected,
                    )
                    .unwrap();
                let n = if combined {
                    combine(
                        MessageView::parse(&protected[..protected_len]).unwrap(),
                        m3.as_slice(),
                        &mut wire,
                    )
                    .unwrap()
                } else {
                    let mut b = MessageBuilder::new(
                        &mut wire,
                        MessageType::Confirmable,
                        Code::POST,
                        2,
                        b"m3",
                    )
                    .unwrap();
                    crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
                    b.uint_option(
                        OptionNumber::CONTENT_FORMAT,
                        ContentFormat::CID_EDHOC.0.into(),
                    )
                    .unwrap();
                    b.finish_parts(&[
                        lakers::ConnId::from_slice(&id).unwrap().as_cbor(),
                        m3.as_slice(),
                    ])
                    .unwrap()
                };
                for mid in [2u16, 3] {
                    wire[2..4].copy_from_slice(&mid.to_be_bytes());
                    let response = deliver(&mut server, &wire[..n], u64::from(mid - 2) * 1000);
                    let view = MessageView::parse(response.as_slice()).unwrap();
                    assert_eq!(view.code(), Code::UNAVAILABLE);
                    assert_eq!(view.option(OptionNumber::MAX_AGE).unwrap().uint(), Ok(1));
                    assert!(view.option(OptionNumber::CONTENT_FORMAT).is_none());
                    assert!(view.option(OptionNumber::OSCORE).is_none());
                    assert!(view.payload().is_empty());
                    assert_eq!(server.protection_mut().sessions.len(), 1);
                    assert_eq!(server.protection_mut().sessions[0].deadline, deadline);
                    assert_eq!(server.protection_mut().contexts(), 2);
                    assert_eq!(handled.get(), 0);
                    assert_eq!(server.counters().protection_failures, 0);
                    // Same-MID retries replay the cached refusal without touching the session.
                    assert_eq!(
                        deliver(&mut server, &wire[..n], u64::from(mid - 2) * 1000 + 1),
                        response
                    );
                    assert_eq!(server.counters().protection_failures, 0);
                }
                if expire {
                    server.protection_mut().expire(deadline);
                }
                server.protection_mut().oscore.unpin(generations[0]);
                wire[2..4].copy_from_slice(&4u16.to_be_bytes());
                let response = deliver(
                    &mut server,
                    &wire[..n],
                    if expire { deadline.0 } else { 2000 },
                );
                let view = MessageView::parse(response.as_slice()).unwrap();
                assert!(server.protection_mut().sessions.is_empty());
                if expire {
                    assert_eq!(view.code(), Code::BAD_REQUEST);
                    assert_eq!(view.payload(), &[1, 0x60]);
                    assert_eq!(server.protection_mut().contexts(), 2);
                    assert_eq!(handled.get(), 0);
                    assert_eq!(server.counters().protection_failures, u64::from(combined));
                    continue;
                }
                let response = if combined {
                    response
                } else {
                    assert_eq!(view.code(), Code::CHANGED);
                    deliver(&mut server, &protected[..protected_len], 2001)
                };
                let mut plain = [0; 512];
                let n = context
                    .unprotect_response::<512>(
                        &mut crypto,
                        MessageView::parse(response.as_slice()).unwrap(),
                        &mut binding,
                        &mut plain,
                    )
                    .unwrap();
                assert_eq!(MessageView::parse(&plain[..n]).unwrap().payload(), b"ok");
                assert_eq!(handled.get(), 1);
                assert_eq!(server.counters().protection_failures, 0);
            }
        }
    }
    #[test]
    fn edh_9_12_failed_message_3_releases_session_and_preserves_driver() {
        for (combined, bad_envelope) in [(false, false), (true, false), (true, true)] {
            let shared = Shared::<512, 2>::new();
            let mut server = Endpoint::<_, 512, 2, 8>::new(&shared, responder::<2>()).unwrap();
            assert_eq!(first(&mut server, "192.0.2.1:5683", 1, 0), Code::CHANGED);
            let id = match &server.protection_mut().sessions[0].state {
                State::Responder(state) => state.connection_id().to_vec(),
                _ => unreachable!(),
            };
            let mut wire = [0; 512];
            let mut b =
                MessageBuilder::new(&mut wire, MessageType::Confirmable, Code::POST, 2, b"ed")
                    .unwrap();
            let mut payload = std::vec::Vec::new();
            if combined {
                let mut option = std::vec![8]; // KID present, no Partial IV.
                option.extend_from_slice(&id);
                b.option(OptionNumber::OSCORE, &option).unwrap();
                b.option(OptionNumber::EDHOC, &[]).unwrap();
                if bad_envelope {
                    payload.push(0x41);
                } else {
                    payload.extend_from_slice(&[0x48, 0, 0, 0, 0, 0, 0, 0, 0]);
                    payload.extend_from_slice(b"opaque OSCORE body");
                }
            } else {
                crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
                b.uint_option(
                    OptionNumber::CONTENT_FORMAT,
                    ContentFormat::CID_EDHOC.0.into(),
                )
                .unwrap();
                payload.extend_from_slice(lakers::ConnId::from_slice(&id).unwrap().as_cbor());
                payload.push(0x41);
            }
            let n = b.finish(&payload).unwrap();
            let mut unused =
                |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| panic!("must not reach resource");
            server
                .receive(
                    &wire[..n],
                    Metadata::new(
                        "192.0.2.1:5683".parse().unwrap(),
                        "192.0.2.2".parse().unwrap(),
                        n,
                    ),
                    Instant(1),
                    &mut unused,
                    &PublicPaths(&[]),
                )
                .unwrap();
            let outgoing = server.pop_outgoing().unwrap();
            let reply = MessageView::parse(outgoing.packet.as_slice()).unwrap();
            assert_eq!(reply.code(), Code::BAD_REQUEST);
            if bad_envelope {
                assert!(reply.option(OptionNumber::CONTENT_FORMAT).is_none());
                assert!(reply.payload().is_empty());
            } else {
                assert_eq!(
                    reply.option(OptionNumber::CONTENT_FORMAT).unwrap().uint(),
                    Ok(64)
                );
                assert_eq!(reply.payload(), &[1, 0x60]);
            }
            assert!(reply.option(OptionNumber::OSCORE).is_none());
            assert_eq!(server.protection_mut().contexts(), 0);
            assert_eq!(server.counters().protection_failures, u64::from(combined));
            assert_eq!(
                server.protection_mut().sessions.len(),
                usize::from(bad_envelope)
            );
            assert_eq!(first(&mut server, "192.0.2.1:5683", 3, 2), Code::CHANGED);
        }
    }
    #[test]
    fn edh_11_source_limit_preserves_other_senders_and_ignores_port_rotation() {
        let shared = Shared::<512, 2>::new();
        let mut protection = responder::<4>();
        assert_eq!(protection.responder_limit, 2);
        assert_eq!(protection.set_responder_limit(0), Err(Error::Malformed));
        assert_eq!(protection.set_responder_limit(5), Err(Error::Malformed));
        let mut endpoint = Endpoint::<_, 512, 2, 8>::new(&shared, protection).unwrap();
        for (i, remote) in [
            "192.0.2.1:5683",
            "192.0.2.2:5683",
            "192.0.2.9:1000",
            "192.0.2.9:1001",
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(
                first(&mut endpoint, remote, i as u16, i as u64),
                Code::CHANGED
            );
        }
        let before: std::vec::Vec<_> = endpoint
            .protection_mut()
            .sessions
            .iter()
            .map(|session| (session.remote, session.started, session.deadline))
            .collect();
        for i in 4..8 {
            assert_eq!(
                first(&mut endpoint, "192.0.2.9:2000", i, i.into()),
                Code::TOO_MANY_REQUESTS
            );
        }
        let after: std::vec::Vec<_> = endpoint
            .protection_mut()
            .sessions
            .iter()
            .map(|session| (session.remote, session.started, session.deadline))
            .collect();
        assert_eq!(before, after);
        // Another source below its allowance still follows the documented oldest-responder policy.
        assert_eq!(first(&mut endpoint, "192.0.2.3:5683", 8, 8), Code::CHANGED);
        assert!(!endpoint.protection_mut().sessions.iter().any(
            |session| session.remote.ip() == "192.0.2.1".parse::<core::net::IpAddr>().unwrap()
        ));
        endpoint.protection_mut().expire(Instant(
            TransmissionParameters::default().max_transmit_wait() + 8,
        ));
        assert_eq!(
            first(&mut endpoint, "192.0.2.9:2000", 9, 100_000),
            Code::CHANGED
        );
    }

    #[test]
    fn edh_9_failed_initiation_releases_the_session_for_immediate_retry() {
        let mut endpoint = responder::<1>();
        let remote = "192.0.2.1:5683".parse().unwrap();
        let target = Target {
            peer: Some(PeerId(1)),
            combined_edhoc: true,
            recover: true,
            ..Target::new(remote)
        };
        let mut bytes = [0; 512];
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"x")
            .unwrap()
            .finish(&[])
            .unwrap();
        let original = MessageView::parse(&bytes[..n]).unwrap();
        let mut output = [0; 512];
        for code in [Code::TOO_MANY_REQUESTS, Code::BAD_REQUEST] {
            assert!(matches!(
                endpoint.outgoing::<512>(target, original, &mut output),
                Ok(Prepared::Handshake { .. })
            ));
            let mut reply = [0; 64];
            let n = MessageBuilder::new(&mut reply, MessageType::Acknowledgement, code, 1, b"x")
                .unwrap()
                .finish(&[])
                .unwrap();
            assert!(matches!(
                endpoint.handshake_response::<512>(
                    target,
                    MessageView::parse(&reply[..n]).unwrap(),
                    original,
                    Instant(1),
                    &mut output
                ),
                Err(Error::Edhoc)
            ));
            assert!(endpoint.sessions.is_empty());
        }
        assert!(matches!(
            endpoint.outgoing::<512>(target, original, &mut output),
            Ok(Prepared::Handshake { .. })
        ));
    }

    #[test]
    fn edh_11_shared_address_admission_pressure_and_expiry_are_bounded() {
        let shared = Shared::<512, 2>::new();
        let mut endpoint = Endpoint::<_, 512, 2, 8>::new(&shared, responder::<2>()).unwrap();
        assert_eq!(first(&mut endpoint, "192.0.2.1:5683", 1, 0), Code::CHANGED);
        assert_eq!(first(&mut endpoint, "192.0.2.1:5683", 2, 1), Code::CHANGED);
        assert_eq!(endpoint.protection_mut().sessions.len(), 2);
        assert_eq!(
            endpoint.protection_mut().deadline(),
            Some(Instant(
                TransmissionParameters::default().max_transmit_wait()
            ))
        );
        endpoint
            .protection_mut()
            .configure("/.well-known/edhoc", 1000)
            .unwrap();
        assert_eq!(first(&mut endpoint, "192.0.2.3:5683", 3, 2), Code::CHANGED);
        assert_eq!(first(&mut endpoint, "192.0.2.4:5683", 4, 3), Code::CHANGED);
        let protection = endpoint.protection_mut();
        assert_eq!(protection.sessions.len(), 2);
        assert!(
            protection
                .sessions
                .iter()
                .all(|session| session.remote != "192.0.2.1:5683".parse().unwrap())
        );
        assert_eq!(protection.deadline(), Some(Instant(1002)));
        protection.expire(Instant(1002));
        assert_eq!(protection.sessions.len(), 1);
        protection.expire(Instant(1003));
        assert!(protection.sessions.is_empty());
    }

    #[test]
    fn edh_11_same_proxy_clients_with_equal_initiator_ids_complete_in_reverse_order() {
        for combined in [false, true] {
            let shared = Shared::<512, 2>::new();
            let mut server = Endpoint::<_, 512, 2, 8>::new(&shared, responder::<2>()).unwrap();
            let proxy = "192.0.2.9:5683".parse().unwrap();
            let mut handled = 0;
            let mut deliver =
                |server: &mut Endpoint<'_, Edhoc<SoftwareCrypto<StdRng>, 2, 2>, 512, 2, 8>,
                 bytes: &[u8],
                 now| {
                    let mut application =
                        |request: Request<'_>, response: &mut ResponseWriter<'_, 512>| {
                            assert_eq!(
                                request.security,
                                SecurityState::Protected { peer: PeerId(1) }
                            );
                            handled += 1;
                            response.set_payload(b"ok").unwrap();
                            Ok(crate::endpoint::Disposition::Complete)
                        };
                    server
                        .receive(
                            bytes,
                            Metadata {
                                remote: proxy,
                                local: "192.0.2.2".parse().unwrap(),
                                interface: None,
                                original_len: bytes.len(),
                            },
                            Instant(now),
                            &mut application,
                            &PublicPaths(&[]),
                        )
                        .unwrap();
                    server.pop_outgoing().unwrap()
                };
            let mut clients = std::vec::Vec::new();
            for index in 0..2 {
                let mut provider = SoftwareCrypto::new(StdRng::from_seed([index + 1; 32]));
                let (initiator, message) =
                    Initiator::start::<512>(&mut provider, &[0x37], &[2]).unwrap();
                let mut bytes = [0; 512];
                let mut b = MessageBuilder::new(
                    &mut bytes,
                    MessageType::Confirmable,
                    Code::POST,
                    u16::from(index),
                    &[index],
                )
                .unwrap();
                crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
                b.uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::EDHOC.0.into())
                    .unwrap();
                let n = b.finish_parts(&[&[0xf5], message.as_slice()]).unwrap();
                let reply = deliver(&mut server, &bytes[..n], u64::from(index));
                let view = MessageView::parse(reply.packet.as_slice()).unwrap();
                assert_eq!(view.code(), Code::CHANGED);
                clients.push((
                    provider,
                    initiator,
                    crate::Packet::<512>::copy_from(view.payload()).unwrap(),
                ));
            }
            assert_eq!(server.protection_mut().sessions.len(), 2);
            let identity = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap());
            let peer = TrustedPeer::new(PeerId(2), &hex(CRED_R)).unwrap();
            for (index, (mut provider, initiator, message_2)) in
                clients.into_iter().rev().enumerate()
            {
                let (message_3, material) = initiator
                    .finish::<512>(&mut provider, &identity, &peer, message_2.as_slice(), false)
                    .unwrap();
                let responder_id = material.sender.clone();
                let mut context = material.into_context(&mut provider).unwrap();
                let mut bytes = [0; 512];
                if !combined {
                    let mut b = MessageBuilder::new(
                        &mut bytes,
                        MessageType::Confirmable,
                        Code::POST,
                        10 + index as u16,
                        b"m3",
                    )
                    .unwrap();
                    crate::uri::path_options("/.well-known/edhoc", &mut b).unwrap();
                    b.uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::EDHOC.0.into())
                        .unwrap();
                    let id = lakers::ConnId::from_slice(&responder_id).unwrap();
                    let n = b
                        .finish_parts(&[id.as_cbor(), message_3.as_slice()])
                        .unwrap();
                    let reply = deliver(&mut server, &bytes[..n], 10 + index as u64);
                    assert_eq!(
                        MessageView::parse(reply.packet.as_slice()).unwrap().code(),
                        Code::CHANGED
                    );
                }
                let mut b = MessageBuilder::new(
                    &mut bytes,
                    MessageType::Confirmable,
                    Code::GET,
                    20 + index as u16,
                    b"app",
                )
                .unwrap();
                crate::uri::path_options("/x", &mut b).unwrap();
                let n = b.finish(&[]).unwrap();
                let mut protected = [0; 512];
                let (n, mut binding) = context
                    .protect_request::<512>(
                        &mut provider,
                        MessageView::parse(&bytes[..n]).unwrap(),
                        &mut protected,
                    )
                    .unwrap();
                let reply = if combined {
                    let n = combine(
                        MessageView::parse(&protected[..n]).unwrap(),
                        message_3.as_slice(),
                        &mut bytes,
                    )
                    .unwrap();
                    deliver(&mut server, &bytes[..n], 20 + index as u64)
                } else {
                    deliver(&mut server, &protected[..n], 20 + index as u64)
                };
                let n = context
                    .unprotect_response::<512>(
                        &mut provider,
                        MessageView::parse(reply.packet.as_slice()).unwrap(),
                        &mut binding,
                        &mut bytes,
                    )
                    .unwrap();
                assert_eq!(MessageView::parse(&bytes[..n]).unwrap().payload(), b"ok");
            }
            assert_eq!(handled, 2);
            assert!(server.protection_mut().sessions.is_empty());
        }
    }

    #[test]
    fn edh_11_initiator_and_responder_can_share_one_address() {
        let mut protection = responder::<2>();
        let remote = "192.0.2.1:5683".parse().unwrap();
        let target = Target {
            peer: Some(PeerId(1)),
            combined_edhoc: true,
            recover: true,
            ..Target::new(remote)
        };
        let mut bytes = [0; 64];
        let n = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"x")
            .unwrap()
            .finish(&[])
            .unwrap();
        protection
            .outgoing::<512>(
                target,
                MessageView::parse(&bytes[..n]).unwrap(),
                &mut [0; 512],
            )
            .unwrap();
        let shared = Shared::<512, 2>::new();
        let mut endpoint = Endpoint::<_, 512, 2, 8>::new(&shared, protection).unwrap();
        assert_eq!(first(&mut endpoint, "192.0.2.1:5683", 2, 1), Code::CHANGED);
        assert_eq!(endpoint.protection_mut().sessions.len(), 2);
        assert_eq!(first(&mut endpoint, "192.0.2.3:5683", 3, 2), Code::CHANGED);
        assert!(
            endpoint
                .protection_mut()
                .sessions
                .iter()
                .any(|s| crate::transport::same_peer(s.remote, remote)
                    && matches!(s.state, State::Initiator(..)))
        );
        assert!(
            endpoint
                .protection_mut()
                .sessions
                .iter()
                .any(|s| s.remote == "192.0.2.3:5683".parse().unwrap()
                    && matches!(s.state, State::Responder(_)))
        );
    }

    #[test]
    fn edh_10_responder_pressure_preserves_initiator_work() {
        let mut protection = responder::<1>();
        let remote = "192.0.2.1:5683".parse().unwrap();
        let target = Target {
            peer: Some(PeerId(1)),
            combined_edhoc: true,
            recover: true,
            ..Target::new(remote)
        };
        let mut original = [0; 64];
        let n = MessageBuilder::new(&mut original, MessageType::Confirmable, Code::GET, 1, b"x")
            .unwrap()
            .finish(&[])
            .unwrap();
        protection
            .outgoing::<512>(
                target,
                MessageView::parse(&original[..n]).unwrap(),
                &mut [0; 512],
            )
            .unwrap();
        let shared = Shared::<512, 2>::new();
        let mut endpoint = Endpoint::<_, 512, 2, 8>::new(&shared, protection).unwrap();
        assert_eq!(
            first(&mut endpoint, "192.0.2.3:5683", 1, 1),
            Code::TOO_MANY_REQUESTS
        );
        assert!(matches!(
            endpoint.protection_mut().sessions[0].state,
            State::Initiator(..)
        ));
        let expiry = TransmissionParameters::default().max_transmit_wait();
        endpoint.protection_mut().expire(Instant(expiry));
        assert_eq!(
            first(&mut endpoint, "192.0.2.3:5683", 2, expiry + 1),
            Code::CHANGED
        );
    }

    #[test]
    fn edh_4_concurrent_initiators_keep_credential_snapshots_across_store_updates() {
        let mut client = responder::<2>();
        let mut original = [0; 64];
        let n = MessageBuilder::new(&mut original, MessageType::Confirmable, Code::GET, 1, b"x")
            .unwrap()
            .finish(&[])
            .unwrap();
        let original = MessageView::parse(&original[..n]).unwrap();
        let targets = ["192.0.2.1:5683", "192.0.2.3:5683"].map(|remote| Target {
            peer: Some(PeerId(1)),
            combined_edhoc: false,
            ..Target::new(remote.parse().unwrap())
        });
        let identity = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap());
        let mut remote_crypto = SoftwareCrypto::new(StdRng::from_seed([9; 32]));
        let mut replies = std::vec::Vec::new();
        for (i, target) in targets.iter().enumerate() {
            let mut output = [0; 512];
            let Prepared::Handshake { length } = client
                .outgoing::<512>(*target, original, &mut output)
                .unwrap()
            else {
                panic!("expected message_1");
            };
            let message = MessageView::parse(&output[..length]).unwrap();
            let State::Initiator(state, _) = &client.sessions[i].state else {
                panic!("expected initiator session");
            };
            let id = [if state.connection_id() != [i as u8] {
                i as u8
            } else {
                i as u8 + 2
            }];
            let (responder, message_2) = Responder::start::<512>(
                &mut remote_crypto,
                &identity,
                &id,
                &message.payload()[1..],
                false,
            )
            .unwrap();
            replies.push((responder, message_2));
        }
        assert_eq!(client.sessions.len(), 2);
        client
            .credentials_mut()
            .insert(TrustedPeer::new(PeerId(1), &hex(CRED_R)).unwrap())
            .unwrap();
        for (target, (responder, message_2)) in targets.into_iter().zip(replies) {
            let mut wire = [0; 512];
            let n = MessageBuilder::new(
                &mut wire,
                MessageType::Acknowledgement,
                Code::CHANGED,
                1,
                b"x",
            )
            .unwrap()
            .finish(message_2.as_slice())
            .unwrap();
            let mut output = [0; 512];
            let Prepared::Handshake { length } = client
                .handshake_response::<512>(
                    target,
                    MessageView::parse(&wire[..n]).unwrap(),
                    original,
                    Instant(1),
                    &mut output,
                )
                .unwrap()
            else {
                panic!("expected sequential message_3");
            };
            let message = MessageView::parse(&output[..length]).unwrap();
            let (_, message_3) = super::super::sequential_message_3(message.payload()).unwrap();
            let material = responder
                .finish(
                    &mut remote_crypto,
                    &[TrustedPeer::new(PeerId(2), &hex(CRED_R)).unwrap()],
                    message_3,
                )
                .unwrap();
            assert_eq!(material.peer, PeerId(2));
        }
        assert_eq!(client.contexts(), 2);
        assert_eq!(
            client.trusted.get(PeerId(1)).unwrap().credential_bytes(),
            hex(CRED_R)
        );
    }

    #[test]
    fn edh_10_message_3_survives_the_default_coap_retry_window() {
        let identity = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap());
        let mut client =
            Edhoc::<_, 2, 2>::new(SoftwareCrypto::new(StdRng::from_seed([9; 32])), identity)
                .unwrap();
        client
            .trust(TrustedPeer::new(PeerId(2), &hex(CRED_R)).unwrap())
            .unwrap();
        let remote = "192.0.2.2:5683".parse().unwrap();
        let target = Target {
            peer: Some(PeerId(2)),
            combined_edhoc: false,
            recover: false,
            ..Target::new(remote)
        };
        let shared = Shared::<512, 2>::new();
        let mut server = Endpoint::<_, 512, 2, 8>::new(&shared, responder::<2>()).unwrap();
        let mut original = [0; 512];
        let n = MessageBuilder::new(&mut original, MessageType::Confirmable, Code::GET, 1, b"ed")
            .unwrap()
            .finish(&[])
            .unwrap();
        let original = MessageView::parse(&original[..n]).unwrap();
        let mut output = [0; 512];
        let Prepared::Handshake { length } = client
            .outgoing::<512>(target, original, &mut output)
            .unwrap()
        else {
            panic!("expected message_1");
        };
        assert_eq!(
            MessageView::parse(&output[..length])
                .unwrap()
                .option(OptionNumber::CONTENT_FORMAT)
                .unwrap()
                .uint(),
            Ok(65),
        );
        let metadata = |n| Metadata {
            remote: "192.0.2.1:5683".parse().unwrap(),
            local: "192.0.2.2".parse().unwrap(),
            interface: None,
            original_len: n,
        };
        let policy = PublicPaths(&[]);
        let mut unused = |_: Request<'_>, _: &mut ResponseWriter<'_, 512>| Err(Code::NOT_FOUND);
        server
            .receive(
                &output[..length],
                metadata(length),
                Instant(0),
                &mut unused,
                &policy,
            )
            .unwrap();
        let reply = server.pop_outgoing().unwrap();
        let Prepared::Handshake { length } = client
            .handshake_response::<512>(
                target,
                MessageView::parse(reply.packet.as_slice()).unwrap(),
                original,
                Instant(0),
                &mut output,
            )
            .unwrap()
        else {
            panic!("expected sequential message_3");
        };
        output[2..4].copy_from_slice(&2u16.to_be_bytes());
        let now = Instant(90_000);
        client.expire(now);
        server
            .receive(
                &output[..length],
                metadata(length),
                now,
                &mut unused,
                &policy,
            )
            .unwrap();
        let reply = server.pop_outgoing().unwrap();
        let reply = MessageView::parse(reply.packet.as_slice()).unwrap();
        assert_eq!(reply.code(), Code::CHANGED);
        assert_eq!(server.protection_mut().contexts(), 1);
        let Prepared::Request { binding, .. } = client
            .handshake_response::<512>(target, reply, original, now, &mut output)
            .unwrap()
        else {
            panic!("expected protected application request");
        };
        if let Some(binding) = binding {
            client.release(binding);
        }
        assert_eq!(client.contexts(), 1);
    }

    #[test]
    fn edh_13_combined_payload_is_limited_only_by_output_capacity() {
        let mut request = [0; 6000];
        let mut b =
            MessageBuilder::new(&mut request, MessageType::Confirmable, Code::FETCH, 9, b"x")
                .unwrap();
        b.option(OptionNumber::OSCORE, b"\x09\x00\x01").unwrap();
        let n = b.finish(&[7; 5000]).unwrap();
        let request = MessageView::parse(&request[..n]).unwrap();
        let mut output = [0; 6000];
        let n = combine(request, &[5; 16], &mut output).unwrap();
        let combined = MessageView::parse(&output[..n]).unwrap();
        assert!(
            combined
                .option(OptionNumber::EDHOC)
                .unwrap()
                .value
                .is_empty()
        );
        assert_eq!(&combined.payload()[..16], &[5; 16]);
        assert_eq!(&combined.payload()[16..], &[7; 5000]);
        assert_eq!(
            combine(request, &[5; 16], &mut output[..n - 1]),
            Err(Error::Capacity)
        );
        assert_eq!(combine(request, &[5; 16], &mut output[..n]), Ok(n));
    }
}
