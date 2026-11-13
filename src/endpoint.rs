//! One bounded endpoint for simultaneous client and server work (API-4, TR-8).
use crate::{
    Error, Packet,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    messaging::{
        Deduplication, MessageIds, Retransmission, TransmissionParameters,
        internal::{CachedReply, ReplyReclaimMode},
    },
    packet_pool::{InlineStorage, OwnedPacketStorage, PacketPool, PacketRef, PacketStorage},
    security::{Policy, SecurityState},
    time::{Clock, Instant},
    transport::{
        DatagramReceiver, DatagramSender, Metadata, OwnedDatagramSender, ReceivedPacket,
        SendOutcome, Transport,
    },
};
use core::{
    cell::RefCell,
    future::{Future, poll_fn},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context as TaskContext, Poll, Waker},
};
use critical_section::Mutex;
mod delegate;
/// Compile-time endpoint request roles.
pub mod role;
mod writer;
use writer::ResponseArena;
pub use writer::ResponseWriter;

fn protected_response(binding: bool, state: SecurityState) -> bool {
    binding || !matches!(state, SecurityState::Unprotected)
}

fn trace_event(_event: &'static str) {
    #[cfg(feature = "log")]
    log::debug!("mai-coap: {}", _event);
    #[cfg(feature = "defmt")]
    defmt::debug!("mai-coap: {=str}", _event);
}
#[cfg(all(feature = "client", feature = "block"))]
pub mod client;
#[cfg(feature = "client")]
mod request;
#[cfg(feature = "client")]
pub use request::{Client, RawRequest, RequestBuilder};
#[cfg(feature = "observe")]
mod observing;
#[cfg(feature = "observe")]
pub use observing::Observation;
#[cfg(feature = "multicast")]
mod multicast;
#[cfg(feature = "multicast")]
pub use multicast::Collection;

/// Opaque deferred server exchange identifier; stale identifiers are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ticket(u64);
/// Default-capacity endpoint; use `Endpoint` directly for explicit memory budgets.
pub type DefaultEndpoint<
    'a,
    P,
    S = InlineStorage<{ crate::DEFAULT_DATAGRAM }, { crate::DEFAULT_PACKETS }>,
    Mode = role::Combined,
> = Endpoint<
    'a,
    P,
    { crate::DEFAULT_DATAGRAM },
    { crate::DEFAULT_OUTBOUND },
    { crate::DEFAULT_DEDUP },
    { crate::DEFAULT_OBSERVERS },
    { crate::DEFAULT_CACHED_REPLIES },
    { crate::DEFAULT_SEND_QUEUE },
    { crate::DEFAULT_OUTBOUND },
    { crate::DEFAULT_OUTBOUND },
    { crate::DEFAULT_BODY_CONTEXTS },
    { crate::DEFAULT_PACKETS },
    S,
    Mode,
>;
/// Default-capacity command and completion storage.
pub type DefaultShared = Shared;
/// Compact 1152-byte profile: four exchanges, sixteen duplicate records, four
/// observers, four full cached replies and four queued outgoing datagrams.
/// Pair with [`SmallShared`]; security storage is selected separately through `P`.
/// See the repository's `docs/sizes.md` for measurement boundaries.
///
/// ```
/// use mai_coap::endpoint::{Protection, SmallEndpoint, SmallShared};
/// fn setup<P: Protection>(protection: P) -> Result<(), mai_coap::Error> {
///     let shared = SmallShared::new();
///     let endpoint = SmallEndpoint::new(&shared, protection)?;
///     # let _ = endpoint;
///     Ok(())
/// }
/// ```
pub type SmallEndpoint<'a, P, S = InlineStorage<1152, 16>, Mode = role::Combined> =
    Endpoint<'a, P, 1152, 4, 16, 4, 4, 4, 4, 4, 4, 16, S, Mode>;
/// Command/completion storage matching [`SmallEndpoint`].
pub type SmallShared = Shared<1152, 4>;
/// Immediate server profile with no outbound or deferred application operations.
/// Two wire buffers are shared by queued sends and cached replies.
pub type ServerEndpoint<
    'a,
    P,
    const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM },
    S = InlineStorage<DATAGRAM_BYTES, 2>,
    Mode = role::Combined,
> = Endpoint<'a, P, DATAGRAM_BYTES, 0, 8, 0, 2, 2, 0, 0, 0, 2, S, Mode>;
/// Command-free storage matching [`ServerEndpoint`].
pub type ServerShared<const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM }> =
    Shared<DATAGRAM_BYTES, 0>;
/// Transport route and optional authenticated peer, independent of URI authority.
/// An explicit peer requires protection even if no context is currently present.
/// Construct with `Target::new` or `From<SocketAddr>`, then set public fields.
///
/// Exhaustive downstream construction is deliberately unavailable:
/// ```compile_fail
/// use mai_coap::endpoint::Target;
/// let remote = "192.0.2.1:5683".parse().unwrap();
/// let target = Target { remote, ..Target::new(remote) };
/// ```
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Target {
    /// UDP next hop; this may be a forward proxy.
    pub remote: SocketAddr,
    /// Expected application identity; URI names do not establish this identity.
    pub peer: Option<crate::security::PeerId>,
    /// Combines EDHOC message_3 with the first protected request (default true).
    /// Applies only when an authenticated peer is explicitly selected.
    pub combined_edhoc: bool,
    /// Allows one EDHOC recovery after an unprotected 4.01 (default true).
    pub recover: bool,
    /// Requested source address, or stack selection.
    pub source: Option<IpAddr>,
    /// Requested egress interface, or transport selection.
    pub interface: Option<u32>,
    /// Snapshot used for the complete operation and its internal handshakes.
    pub parameters: TransmissionParameters,
}
impl Target {
    /// Uses automatic source/interface selection and default transmission parameters.
    pub fn new(remote: SocketAddr) -> Self {
        Self {
            remote,
            peer: None,
            combined_edhoc: true,
            recover: true,
            source: None,
            interface: None,
            parameters: TransmissionParameters::default(),
        }
    }
}
impl From<SocketAddr> for Target {
    fn from(remote: SocketAddr) -> Self {
        Self::new(remote)
    }
}
/// Handler request, containing the authenticated inner message.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Request<'a> {
    /// Method, path, query, options and payload.
    pub message: MessageView<'a>,
    /// Incoming addressing.
    pub metadata: Metadata,
    /// Verified security state.
    pub security: SecurityState,
    /// Ticket usable by a deferred-response handle.
    pub(crate) ticket: Ticket,
    pub(crate) deferred_available: bool,
    /// Complete application body; buffered Block1 may exceed one datagram.
    pub body: &'a [u8],
    /// Security epoch generation for binding a Block1 body; never a peer identity.
    pub context: Option<u64>,
    /// Snapshot of the delivery grace retained with copied deferred work.
    #[cfg(feature = "server")]
    pub(crate) response_grace_ms: u64,
}
impl<'a> Request<'a> {
    /// Reserved deferred-response capacity, if available for this request.
    /// Obtain a ticket before accepting deferred work.
    pub const fn deferred_ticket(self) -> Option<Ticket> {
        if self.deferred_available {
            Some(self.ticket)
        } else {
            None
        }
    }
    /// Application payload, including a complete buffered upload where applicable.
    pub const fn payload(self) -> &'a [u8] {
        self.body
    }
}
/// Immediate or deferred application response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Response is ready now.
    Complete,
    /// Application will complete the ticket through its handle.
    /// Notification generation cannot be deferred; it terminates with 5.03.
    Deferred,
}
/// Owned application response for standalone construction and deferred submission.
/// Option values and payload have independent `DATAGRAM_BYTES` bounds. Synchronous
/// callbacks use [`ResponseWriter`], whose complete plaintext wire size shares one
/// datagram arena. Options are kept in ascending order.
#[derive(Clone, Debug)]
pub struct Response<const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM }> {
    code: Code,
    options: heapless::Vec<(OptionNumber, usize, usize), 16>,
    values: Packet<DATAGRAM_BYTES>,
    payload: Packet<DATAGRAM_BYTES>,
}
/// Failure while constructing local response content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum ResponseError {
    /// Options or payload exceed their bounded storage.
    Capacity,
    /// A deferred processing budget must be nonzero.
    InvalidTimeout,
    /// A Uri-Path or Location-Path value is `.` or `..` (RFC 7252 §§5.10.1, 5.10.7).
    InvalidOption,
}
impl core::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Capacity => "response capacity exhausted",
            Self::InvalidTimeout => "deferred response timeout must be nonzero",
            Self::InvalidOption => "path option value must not be a dot segment",
        })
    }
}
impl core::error::Error for ResponseError {}
impl From<ResponseError> for Error {
    fn from(error: ResponseError) -> Self {
        match error {
            ResponseError::Capacity => Self::Capacity,
            ResponseError::InvalidTimeout | ResponseError::InvalidOption => Self::Malformed,
        }
    }
}
impl From<ResponseError> for Code {
    fn from(_: ResponseError) -> Self {
        Self::INTERNAL_ERROR
    }
}
impl<const DATAGRAM_BYTES: usize> Response<DATAGRAM_BYTES> {
    /// Creates a response with no options or payload; implicit Max-Age is 60 seconds.
    pub const fn new(code: Code) -> Self {
        Self {
            code,
            options: heapless::Vec::new(),
            values: Packet::new(),
            payload: Packet::new(),
        }
    }
    /// Response status.
    pub const fn code(&self) -> Code {
        self.code
    }
    /// Replaces the status code.
    pub fn set_code(&mut self, code: Code) {
        self.code = code;
    }
    /// Replaces the body; overflow leaves the previous body unchanged.
    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), ResponseError> {
        if payload.len() > DATAGRAM_BYTES {
            return Err(ResponseError::Capacity);
        }
        self.payload.bytes.clear();
        self.payload
            .bytes
            .extend_from_slice(payload)
            .map_err(|_| ResponseError::Capacity)
    }
    /// Adds an option in numeric order, preserving the order of repeated options.
    pub fn option(&mut self, number: OptionNumber, value: &[u8]) -> Result<(), ResponseError> {
        if crate::codec::dot_segment(number, value) {
            return Err(ResponseError::InvalidOption);
        }
        if self.options.is_full() {
            return Err(ResponseError::Capacity);
        }
        let start = self.values.bytes.len();
        self.values
            .bytes
            .extend_from_slice(value)
            .map_err(|_| ResponseError::Capacity)?;
        let index = self.options.partition_point(|(n, _, _)| *n <= number);
        self.options
            .insert(index, (number, start, value.len()))
            .map_err(|_| ResponseError::Capacity)
    }
    /// Adds a minimal unsigned option.
    pub fn uint_option(&mut self, number: OptionNumber, value: u64) -> Result<(), ResponseError> {
        self.option(number, crate::codec::minimal_uint(&value.to_be_bytes()))
    }
    /// Inserts or replaces a singleton option without changing other option order.
    pub fn set_option(&mut self, number: OptionNumber, value: &[u8]) -> Result<(), ResponseError> {
        // Checked before removal so a rejected value leaves the content unchanged.
        if crate::codec::dot_segment(number, value) {
            return Err(ResponseError::InvalidOption);
        }
        let removed = self.options.iter().filter(|(n, _, _)| *n == number);
        let count = removed.clone().count();
        let bytes: usize = removed.map(|(_, _, len)| len).sum();
        if self.values.bytes.len() - bytes + value.len() > DATAGRAM_BYTES
            || count == 0 && self.options.is_full()
        {
            return Err(ResponseError::Capacity);
        }
        while let Some(index) = self.options.iter().position(|(n, _, _)| *n == number) {
            let (_, start, len) = self.options.remove(index);
            self.values.bytes.copy_within(start + len.., start);
            self.values.bytes.truncate(self.values.bytes.len() - len);
            for (_, other, _) in &mut self.options {
                if *other >= start + len {
                    *other -= len;
                }
            }
        }
        self.option(number, value)
    }
    /// Inserts or replaces a minimally encoded unsigned option.
    pub fn set_uint_option(
        &mut self,
        number: OptionNumber,
        value: u64,
    ) -> Result<(), ResponseError> {
        self.set_option(number, crate::codec::minimal_uint(&value.to_be_bytes()))
    }
    /// Serializes application content with supplied messaging fields.
    pub fn encode(
        &self,
        output: &mut [u8],
        ty: MessageType,
        mid: u16,
        token: &[u8],
    ) -> Result<usize, Error> {
        if !self.code.is_response() {
            return Err(Error::Malformed);
        }
        self.serialize(output, ty, mid, token)
    }
    fn serialize(
        &self,
        output: &mut [u8],
        ty: MessageType,
        mid: u16,
        token: &[u8],
    ) -> Result<usize, Error> {
        let mut b = MessageBuilder::new(output, ty, self.code, mid, token)?;
        for &(number, start, length) in &self.options {
            b.option(number, &self.values.as_slice()[start..start + length])?;
        }
        b.finish(self.payload.as_slice())
    }
}
/// Application resource dispatch; callbacks must return without awaiting slow work.
pub trait Application<const DATAGRAM_BYTES: usize> {
    /// Processes one inner request using the writer's shared plaintext wire bound.
    /// Failures map to the specified response code. An error discards any options
    /// and payload already written to `response`.
    /// Endpoint-owned protected response writes are erased when response processing
    /// finishes, including errors and unwinding. Unprotected responses are not erased.
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code>;
    /// Declares additional options recognized by this layer (MSG-5).
    fn recognizes(&self, number: OptionNumber) -> bool;
    /// Intercepts an opaque proxy request before endpoint security processing.
    /// `None` continues normal local resource processing. Wrappers must forward.
    #[cfg(feature = "proxy")]
    fn forward(
        &mut self,
        _: Request<'_>,
        _: Instant,
        _: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Option<Result<Disposition, Code>> {
        None
    }
    /// Polls worker operations with the driver's waker. Wrappers must forward.
    /// Custom drivers using cross-endpoint forwarding must call this method.
    fn poll(&mut self, _: Instant, _: &mut TaskContext<'_>) {}
    /// Earliest resource deadline; `None` means no scheduled application work.
    fn deadline(&self) -> Option<Instant> {
        None
    }
    /// Whether an unfinished application transfer still needs this security epoch.
    /// Wrappers must forward this method.
    fn uses_context(&self, _: u64) -> bool {
        false
    }
    /// Aborts unfinished transfers when their epoch cannot be retained.
    /// Wrappers must forward this method.
    fn abort_context(&mut self, _: u64) {}
    /// Observable resource settings; wrappers must forward this method.
    #[cfg(feature = "observe")]
    fn observable(&self, _: MessageView<'_>) -> Option<crate::observe::Settings> {
        None
    }
}
impl<const DATAGRAM_BYTES: usize, F> Application<DATAGRAM_BYTES> for F
where
    F: FnMut(Request<'_>, &mut ResponseWriter<'_, DATAGRAM_BYTES>) -> Result<Disposition, Code>,
{
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        self(request, response)
    }
    fn recognizes(&self, _: OptionNumber) -> bool {
        false
    }
}
/// Endpoint security layer; transport and resource APIs do not change with OSCORE.
pub trait Protection {
    /// Opaque authenticated request/response binding and context lease.
    type Binding;
    /// Uses the same secure entropy source as key establishment.
    fn random(&mut self, bytes: &mut [u8]);
    /// Whether handshake or recovery may need the original application request.
    /// Wrappers must forward this method. The conservative default retains it.
    fn requires_request_retention(&self, _: Target) -> bool {
        true
    }
    /// Protects a request for an explicit logical peer and transport route.
    /// Wrappers must forward this method. An explicit peer must fail closed.
    fn outgoing<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<Self::Binding>, Error>;
    /// Authenticates incoming requests before authorization or application dispatch.
    fn incoming<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: MessageView<'_>,
        metadata: Metadata,
        output: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<Self::Binding>), Error>;
    /// Produces a response bound to its authenticated request.
    /// A capacity failure may be retried with a smaller response; failed attempts
    /// must not make any nonce available for reuse.
    fn response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Self::Binding,
        output: &mut [u8],
    ) -> Result<usize, Error>;
    /// Authenticates a peer response using its original request binding.
    fn received_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Self::Binding,
        output: &mut [u8],
    ) -> Result<usize, Error>;
    /// Releases the binding's context pin when an exchange ends.
    fn release(&mut self, binding: Self::Binding);
    /// Handles an unprotected key-establishment endpoint before resource policy.
    /// On `Ok(false)`, the response must be left unmodified.
    /// An error discards the partial response: `Capacity` produces 5.03 Service
    /// Unavailable, and other errors produce 4.00 Bad Request.
    /// Wrappers must forward this method if their inner layer supports EDHOC.
    fn control<const DATAGRAM_BYTES: usize>(
        &mut self,
        _: Request<'_>,
        _: Instant,
        _: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<bool, Error> {
        Ok(false)
    }
    /// Advances a handshake for the same logical peer as the original request.
    /// Wrappers must forward this method.
    fn handshake_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        _: Target,
        _: MessageView<'_>,
        _: MessageView<'_>,
        _: Instant,
        _: &mut [u8],
    ) -> Result<Prepared<Self::Binding>, Error> {
        Err(Error::Edhoc)
    }
    /// Re-establishes keys for the original logical peer, preserving its route.
    /// Wrappers must forward this method.
    fn recover<const DATAGRAM_BYTES: usize>(
        &mut self,
        _: Target,
        _: MessageView<'_>,
        _: Instant,
        _: &mut [u8],
    ) -> Result<Prepared<Self::Binding>, Error> {
        Err(Error::ContextNotFound)
    }
    /// Expires half-finished control sessions. Wrappers must forward this method.
    fn expire(&mut self, _: Instant) {}
    /// Earliest security/control expiry, if any. Wrappers must forward this method.
    fn deadline(&self) -> Option<Instant> {
        None
    }
    /// Context generation associated with a live request binding.
    fn generation(&self, _: &Self::Binding) -> Option<u64> {
        None
    }
    /// Retains an epoch for a live Block1 body; wrappers must forward this method.
    fn pin_epoch(&mut self, _: u64) -> Result<(), Error> {
        Err(Error::ContextNotFound)
    }
    /// Releases a body epoch lease; wrappers must forward this method.
    fn unpin_epoch(&mut self, _: u64) {}
    /// Started EDHOC sessions; wrappers must forward this counter.
    fn handshake_runs(&self) -> u64 {
        0
    }
    /// Context-table evictions; wrappers must forward this counter.
    fn context_evictions(&self) -> u64 {
        0
    }
}
/// Outgoing application request or an internal EDHOC step.
pub enum Prepared<B> {
    /// Ready application request, optionally bound to a security epoch.
    Request {
        /// Used output length.
        length: usize,
        /// Context lease for authenticated response processing.
        binding: Option<B>,
    },
    /// Internal handshake; retain the original application request for retry.
    Handshake {
        /// Used output length.
        length: usize,
    },
}
impl<B> Prepared<B> {
    /// Output length, request binding and whether this is a handshake step.
    fn into_parts(self) -> (usize, Option<B>, bool) {
        match self {
            Self::Request { length, binding } => (length, binding, false),
            Self::Handshake { length } => (length, None, true),
        }
    }
}
/// Unsecured endpoint configuration using the caller's secure RNG.
#[derive(Debug)]
pub struct Unsecured<Rng>(pub Rng);
impl<Rng: rand_core::CryptoRng> Protection for Unsecured<Rng> {
    type Binding = ();
    fn random(&mut self, bytes: &mut [u8]) {
        self.0.fill_bytes(bytes);
    }
    fn requires_request_retention(&self, _: Target) -> bool {
        false
    }
    fn outgoing<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<()>, Error> {
        if target.peer.is_some() {
            return Err(Error::ContextNotFound);
        }
        Ok(Prepared::Request {
            length: copy(request.as_bytes(), output)?,
            binding: None,
        })
    }
    fn incoming<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: MessageView<'_>,
        _: Metadata,
        output: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<()>), Error> {
        if request.option(OptionNumber::OSCORE).is_some() {
            return Err(Error::BadOption(OptionNumber::OSCORE));
        }
        Ok((
            copy(request.as_bytes(), output)?,
            SecurityState::Unprotected,
            None,
        ))
    }
    fn response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        _: &mut (),
        output: &mut [u8],
    ) -> Result<usize, Error> {
        copy(response.as_bytes(), output)
    }
    fn received_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        _: &mut (),
        output: &mut [u8],
    ) -> Result<usize, Error> {
        copy(response.as_bytes(), output)
    }
    fn release(&mut self, _: ()) {}
}
fn copy(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    output
        .get_mut(..input.len())
        .ok_or(Error::Capacity)?
        .copy_from_slice(input);
    Ok(input.len())
}

/// A received response, retaining source information for multicast callers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Reply<const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM }> {
    /// Source endpoint.
    pub remote: SocketAddr,
    /// Validated CoAP bytes with any OSCORE protection removed.
    pub packet: Packet<DATAGRAM_BYTES>,
}
impl<const DATAGRAM_BYTES: usize> Reply<DATAGRAM_BYTES> {
    /// Borrowed decoded response.
    pub fn message(&self) -> Result<MessageView<'_>, Error> {
        MessageView::parse(self.packet.as_slice())
    }
}

enum Command<const DATAGRAM_BYTES: usize> {
    #[cfg(feature = "client")]
    Request {
        target: Target,
        packet: Packet<DATAGRAM_BYTES>,
        token_len: u8,
        wait: bool,
        raw: bool,
        #[cfg(feature = "multicast")]
        collect_until: Option<Instant>,
    },
    #[cfg(feature = "server")]
    Respond {
        ticket: Ticket,
        packet: Packet<DATAGRAM_BYTES>,
        queued: bool,
    },
}
#[cfg(feature = "client")]
struct RequestAdmission {
    target: Target,
    wait: bool,
    raw: bool,
    observe: bool,
    non_confirmable: bool,
}
#[cfg(feature = "client")]
impl RequestAdmission {
    fn new(target: Target, wait: bool, raw: bool, message: MessageView<'_>) -> Self {
        Self {
            target,
            wait,
            raw,
            observe: cfg!(feature = "observe")
                && message
                    .option(OptionNumber::OBSERVE)
                    .is_some_and(|o| o.uint() == Ok(0)),
            non_confirmable: message.message_type() == MessageType::NonConfirmable,
        }
    }
}
enum Admission {
    #[cfg(feature = "client")]
    Rejected(Error),
    #[cfg(feature = "client")]
    Request(RequestAdmission),
    #[cfg(feature = "server")]
    Respond(Ticket),
}
enum SlotData<const DATAGRAM_BYTES: usize> {
    Empty,
    Command(Command<DATAGRAM_BYTES>),
    Result(Result<Reply<DATAGRAM_BYTES>, Error>),
    #[cfg(feature = "server")]
    ResponsePending {
        remote: SocketAddr,
        mid: u16,
        confirmable: bool,
    },
    #[cfg(feature = "server")]
    ResponseResult(Result<(), Error>),
}
struct Slot<const DATAGRAM_BYTES: usize> {
    generation: u64,
    data: SlotData<DATAGRAM_BYTES>,
    active: bool,
    cancelled: bool,
    /// The observer waits for the Observe=1 exchange, unlike a dropped observation.
    #[cfg(feature = "observe")]
    deregister: bool,
    waker: Option<Waker>,
    #[cfg(feature = "multicast")]
    replies: heapless::Deque<Reply<DATAGRAM_BYTES>, 8>,
}
impl<const DATAGRAM_BYTES: usize> Slot<DATAGRAM_BYTES> {
    const fn new() -> Self {
        Self {
            generation: 0,
            data: SlotData::Empty,
            active: false,
            cancelled: false,
            #[cfg(feature = "observe")]
            deregister: false,
            waker: None,
            #[cfg(feature = "multicast")]
            replies: heapless::Deque::new(),
        }
    }
    fn command(&self) -> Option<&Command<DATAGRAM_BYTES>> {
        match &self.data {
            SlotData::Command(command) => Some(command),
            _ => None,
        }
    }
    fn take_command(&mut self) -> Option<Command<DATAGRAM_BYTES>> {
        if !matches!(self.data, SlotData::Command(_)) {
            return None;
        }
        match core::mem::replace(&mut self.data, SlotData::Empty) {
            SlotData::Command(command) => Some(command),
            _ => None,
        }
    }
    fn take_result(&mut self) -> Option<Result<Reply<DATAGRAM_BYTES>, Error>> {
        if !matches!(self.data, SlotData::Result(_)) {
            return None;
        }
        match core::mem::replace(&mut self.data, SlotData::Empty) {
            SlotData::Result(result) => Some(result),
            _ => None,
        }
    }
    #[cfg(feature = "server")]
    fn take_response_result(&mut self) -> Option<Result<(), Error>> {
        let result = match self.data {
            SlotData::ResponseResult(result) => result,
            SlotData::Result(Err(error)) => Err(error),
            _ => return None,
        };
        self.data = SlotData::Empty;
        Some(result)
    }
}
struct SharedState<const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    slots: [Slot<DATAGRAM_BYTES>; COMMANDS],
    #[cfg(feature = "shared-counters")]
    counters: Counters,
    driver: Option<Waker>,
    revision: u64,
    #[cfg(all(feature = "client", feature = "block1"))]
    body_sequence: u64,
    #[cfg(feature = "observe")]
    changes: heapless::Vec<u32, 16>,
}
/// Caller-owned command, completion and optional counter storage without atomic CAS (PLT-3).
pub struct Shared<
    const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM },
    const COMMANDS: usize = { crate::DEFAULT_COMMANDS },
> {
    state: Mutex<RefCell<SharedState<DATAGRAM_BYTES, COMMANDS>>>,
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Default
    for Shared<DATAGRAM_BYTES, COMMANDS>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Shared<DATAGRAM_BYTES, COMMANDS> {
    /// Constructs empty storage, usable in a static initializer.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(SharedState {
                slots: [const { Slot::new() }; COMMANDS],
                #[cfg(feature = "shared-counters")]
                counters: Counters::ZERO,
                driver: None,
                revision: 0,
                #[cfg(all(feature = "client", feature = "block1"))]
                body_sequence: 0,
                #[cfg(feature = "observe")]
                changes: heapless::Vec::new(),
            })),
        }
    }
    /// Creates a cheap cross-task handle.
    pub const fn handle(&self) -> Handle<'_, DATAGRAM_BYTES, COMMANDS> {
        Handle { shared: self }
    }
    /// Latest snapshot published at the start of an [`Endpoint::run`] pass,
    /// before it waits for input, or before it returns.
    ///
    /// Initially zero; it may lag current work and remains readable after the
    /// driver stops. Reads do not wake the driver or require command slots.
    /// Manual drivers read [`Endpoint::counters`] directly.
    #[cfg(feature = "shared-counters")]
    pub fn counters(&self) -> Counters {
        self.lock(|state| state.counters)
    }
    fn lock<T>(&self, f: impl FnOnce(&mut SharedState<DATAGRAM_BYTES, COMMANDS>) -> T) -> T {
        critical_section::with(|cs| f(&mut self.state.borrow(cs).borrow_mut()))
    }
    fn submit(
        &self,
        command: Command<DATAGRAM_BYTES>,
    ) -> Result<Operation<'_, DATAGRAM_BYTES, COMMANDS>, Error> {
        let (index, generation, waker) = self.lock(|s| {
            let index = s
                .slots
                .iter()
                .position(|slot| {
                    !slot.active && matches!(slot.data, SlotData::Empty) && !slot.cancelled
                })
                .ok_or(Error::Capacity)?;
            let slot = &mut s.slots[index];
            slot.generation = slot.generation.checked_add(1).ok_or(Error::Capacity)?;
            #[cfg(feature = "observe")]
            {
                slot.deregister = false;
            }
            slot.data = SlotData::Command(command);
            s.revision = s.revision.wrapping_add(1);
            Ok::<_, Error>((index, slot.generation, s.driver.take()))
        })?;
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(Operation {
            shared: self,
            index,
            generation,
            finished: false,
        })
    }
    fn complete(
        &self,
        index: usize,
        generation: u64,
        result: Result<Reply<DATAGRAM_BYTES>, Error>,
    ) {
        let waker = self.lock(|s| {
            let slot = &mut s.slots[index];
            if slot.generation != generation {
                return None;
            }
            slot.active = false;
            if slot.cancelled {
                slot.cancelled = false;
                slot.data = SlotData::Empty;
            } else {
                slot.data = SlotData::Result(result);
            }
            slot.waker.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn cancelled(&self, index: usize, generation: u64) -> bool {
        self.stopping(index, generation).0
    }
    #[cfg(feature = "observe")]
    fn deregistering(&self, index: usize, generation: u64) -> bool {
        self.stopping(index, generation).1
    }
    /// Whether the slot is cancelled, and whether its observer awaits deregistration.
    /// One lookup, since a critical section is costly to inline at each call site.
    fn stopping(&self, index: usize, generation: u64) -> (bool, bool) {
        self.lock(|s| {
            let slot = &s.slots[index];
            let cancelled = slot.generation != generation || slot.cancelled;
            #[cfg(feature = "observe")]
            let deregistering = slot.deregister && !cancelled;
            #[cfg(not(feature = "observe"))]
            let deregistering = false;
            (cancelled, deregistering)
        })
    }
    #[cfg(feature = "server")]
    fn response_handoff(
        &self,
        (index, generation): (usize, u64),
        remote: SocketAddr,
        mid: u16,
        confirmable: bool,
        queued: bool,
    ) -> bool {
        let (committed, waker) = self.lock(|s| {
            let slot = &mut s.slots[index];
            if slot.generation != generation || slot.cancelled {
                return (false, None);
            }
            slot.active = !queued;
            slot.data = if queued {
                SlotData::ResponseResult(Ok(()))
            } else {
                SlotData::ResponsePending {
                    remote,
                    mid,
                    confirmable,
                }
            };
            (true, queued.then(|| slot.waker.take()).flatten())
        });
        if let Some(waker) = waker {
            waker.wake();
        }
        committed
    }
    #[cfg(feature = "server")]
    fn complete_response(
        &self,
        remote: SocketAddr,
        mid: u16,
        local_only: bool,
        result: Result<(), Error>,
    ) {
        // Command-free profiles have no waiters and need no critical section.
        if COMMANDS == 0 {
            return;
        }
        let waker = self.lock(|s| {
            let slot = s.slots.iter_mut().find(|slot| {
                matches!(slot.data, SlotData::ResponsePending { remote: peer, mid: id, confirmable }
                    if crate::transport::same_peer(peer, remote) && id == mid
                        && (!local_only || !confirmable))
            })?;
            slot.active = false;
            slot.data = SlotData::ResponseResult(result);
            slot.waker.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn wake_driver(&self) {
        let waker = self.lock(|s| {
            s.revision = s.revision.wrapping_add(1);
            s.driver.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
    fn pending(&self, index: usize) -> Option<(u64, Admission)> {
        self.lock(|s| {
            let slot = &s.slots[index];
            let admission = match slot.command()? {
                #[cfg(feature = "client")]
                Command::Request {
                    target,
                    wait,
                    raw,
                    packet,
                    ..
                } => match MessageView::parse(packet.as_slice()) {
                    Ok(message) => {
                        Admission::Request(RequestAdmission::new(*target, *wait, *raw, message))
                    }
                    Err(error) => Admission::Rejected(error),
                },
                #[cfg(feature = "server")]
                Command::Respond { ticket, .. } => Admission::Respond(*ticket),
            };
            Some((slot.generation, admission))
        })
    }
    fn claim(&self, index: usize, generation: u64) -> Option<Command<DATAGRAM_BYTES>> {
        self.lock(|s| {
            let slot = &mut s.slots[index];
            if slot.generation != generation || slot.cancelled {
                return None;
            }
            let command = slot.take_command()?;
            slot.active = true;
            Some(command)
        })
    }
    async fn changed(&self, revision: u64) {
        poll_fn(|cx| {
            self.lock(|s| {
                if s.revision != revision {
                    Poll::Ready(())
                } else {
                    s.driver = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
        })
        .await
    }
}
/// Cross-task requests and deferred-response completion, borrowing bounded storage.
#[derive(Clone, Copy)]
pub struct Handle<
    'a,
    const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM },
    const COMMANDS: usize = { crate::DEFAULT_COMMANDS },
> {
    shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Handle<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Reads the driver's last published snapshot; see [`Shared::counters`].
    #[cfg(feature = "shared-counters")]
    pub fn counters(&self) -> Counters {
        self.shared.counters()
    }
    #[cfg(feature = "proxy")]
    pub(crate) fn forward_opaque(
        &self,
        remote: SocketAddr,
        packet: &[u8],
        parameters: TransmissionParameters,
    ) -> Result<Operation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.shared.submit(Command::Request {
            target: Target {
                parameters: parameters.validate()?,
                ..remote.into()
            },
            packet: Packet::copy_from(packet)?,
            token_len: 8,
            wait: true,
            raw: true,
            #[cfg(feature = "multicast")]
            collect_until: None,
        })
    }
    /// Queues a raw request with an explicit route, peer and reliability profile.
    #[cfg(feature = "client")]
    pub(crate) fn submit_request(
        &self,
        target: Target,
        packet: Packet<DATAGRAM_BYTES>,
        token_len: u8,
        wait_for_nstart: bool,
    ) -> Result<Operation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        let view = MessageView::parse(packet.as_slice())?;
        if !view.code().is_request()
            && !(view.code() == Code::EMPTY && view.message_type() == MessageType::Confirmable)
            || token_len > 8
        {
            return Err(Error::Malformed);
        }
        let target = Target {
            parameters: target.parameters.validate()?,
            ..target
        };
        self.shared.submit(Command::Request {
            target,
            packet,
            token_len,
            wait: wait_for_nstart,
            raw: false,
            #[cfg(feature = "multicast")]
            collect_until: None,
        })
    }
    /// Hands a deferred response to the endpoint's send queue.
    /// Completion reports queue handoff; later delivery failures are not returned.
    /// Dropping before handoff cancels submission; afterward transmission continues.
    /// The endpoint must be driven concurrently. Use [`Self::respond_confirmed`]
    /// to wait for the delivery outcome instead.
    #[cfg(feature = "server")]
    pub fn respond(
        &self,
        ticket: Ticket,
        response: &Response<DATAGRAM_BYTES>,
    ) -> Result<ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.submit_response(ticket, response, true)
    }
    /// Sends a deferred response, waiting for its delivery outcome.
    /// CON responses complete on ACK, RST or retransmission timeout. NON responses
    /// complete on local transport acceptance. A timeout leaves receipt unconfirmed;
    /// an ACK does not prove client application processing.
    /// This holds a command slot until the result is consumed or the future dropped.
    /// Dropping before queue handoff cancels submission; afterward it only detaches
    /// the waiter and transmission continues. The endpoint must be driven concurrently.
    #[cfg(feature = "server")]
    pub fn respond_confirmed(
        &self,
        ticket: Ticket,
        response: &Response<DATAGRAM_BYTES>,
    ) -> Result<ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.submit_response(ticket, response, false)
    }
    #[cfg(feature = "server")]
    fn submit_response(
        &self,
        ticket: Ticket,
        response: &Response<DATAGRAM_BYTES>,
        queued: bool,
    ) -> Result<ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        let packet =
            Packet::encoded(|bytes| response.encode(bytes, MessageType::NonConfirmable, 0, &[]))?;
        self.submit_serialized(ticket, packet, queued)
    }
    /// Hands an already serialized reply to the send queue; see [`Self::respond`].
    #[cfg(feature = "proxy")]
    pub(crate) fn respond_serialized(
        &self,
        ticket: Ticket,
        packet: &Packet<DATAGRAM_BYTES>,
    ) -> Result<ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.submit_serialized(ticket, packet.clone(), true)
    }
    #[cfg(feature = "server")]
    fn submit_serialized(
        &self,
        ticket: Ticket,
        packet: Packet<DATAGRAM_BYTES>,
        queued: bool,
    ) -> Result<ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        let operation = self.shared.submit(Command::Respond {
            ticket,
            packet,
            queued,
        })?;
        Ok(ResponseOperation { operation })
    }
}
/// Pending deferred-response completion; see [`Handle::respond`] and
/// [`Handle::respond_confirmed`] for the selected completion milestone.
/// Dropping after queue handoff releases the waiter while transmission continues.
#[cfg(feature = "server")]
#[must_use = "response operations must be awaited; dropping before handoff cancels submission"]
pub struct ResponseOperation<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    operation: Operation<'a, DATAGRAM_BYTES, COMMANDS>,
}
#[cfg(feature = "server")]
impl<const D: usize, const C: usize> Future for ResponseOperation<'_, D, C> {
    type Output = Result<(), Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let operation = &mut self.get_mut().operation;
        let result = operation.shared.lock(|s| {
            let slot = &mut s.slots[operation.index];
            if slot.generation != operation.generation {
                return Poll::Ready(Err(Error::Cancelled));
            }
            if let Some(result) = slot.take_response_result() {
                Poll::Ready(result)
            } else {
                slot.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        });
        if result.is_ready() {
            operation.finished = true;
            operation.shared.wake_driver();
        }
        result
    }
}
#[cfg(feature = "server")]
impl<const D: usize, const C: usize> Drop for ResponseOperation<'_, D, C> {
    fn drop(&mut self) {
        let operation = &mut self.operation;
        if operation.finished {
            return;
        }
        let waker = operation.shared.lock(|s| {
            let slot = &mut s.slots[operation.index];
            if slot.generation != operation.generation {
                return None;
            }
            let handed_off = matches!(
                slot.data,
                SlotData::ResponsePending { .. }
                    | SlotData::ResponseResult(_)
                    | SlotData::Result(_)
            );
            if handed_off {
                slot.active = false;
            }
            slot.cancelled = !handed_off;
            slot.data = SlotData::Empty;
            slot.waker = None;
            s.revision = s.revision.wrapping_add(1);
            s.driver.take()
        });
        // Cancellation and the handoff decision share one critical section.
        operation.finished = true;
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}
/// Pending operation. Dropping it cancels application delivery and wakes the driver.
#[must_use = "operations must be awaited; dropping cancels the operation"]
pub struct Operation<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
    index: usize,
    generation: u64,
    finished: bool,
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Future
    for Operation<'_, DATAGRAM_BYTES, COMMANDS>
{
    type Output = Result<Reply<DATAGRAM_BYTES>, Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let result = this.shared.lock(|s| {
            let slot = &mut s.slots[this.index];
            if slot.generation != this.generation {
                return Poll::Ready(Err(Error::Cancelled));
            }
            if let Some(result) = slot.take_result() {
                Poll::Ready(result)
            } else {
                slot.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        });
        if result.is_ready() {
            this.finished = true;
            // Consuming a completion frees command capacity needed by deferred replies.
            this.shared.wake_driver();
        }
        result
    }
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Drop
    for Operation<'_, DATAGRAM_BYTES, COMMANDS>
{
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let waker = self.shared.lock(|s| {
            let slot = &mut s.slots[self.index];
            if slot.generation == self.generation {
                slot.data = SlotData::Empty;
                slot.cancelled = true;
                #[cfg(feature = "multicast")]
                slot.replies.clear();
                slot.waker = None;
            }
            s.revision = s.revision.wrapping_add(1);
            s.driver.take()
        });
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// Cheap endpoint counters, containing no secret data (API-8).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub struct Counters {
    /// Requests dispatched to application code.
    pub requests: u64,
    /// Identical outgoing CON packets resent.
    pub retransmissions: u64,
    /// Incoming duplicate messages recognized (replayed, refused, or suppressed).
    pub duplicates: u64,
    /// Messages failing security processing, excluding incoming request capacity refusals.
    pub protection_failures: u64,
    /// Failed transport sends, including fatal socket errors.
    pub send_failures: u64,
    /// Datagrams that exceeded the local transport acceptance budget.
    pub local_send_timeouts: u64,
    /// Unauthenticated errors received for protected requests.
    pub unprotected_responses: u64,
    /// Messages discarded after serialization, capacity, protocol or metadata failure.
    /// Includes handshake/recovery processing failures that also complete an operation.
    pub dropped_messages: u64,
    /// Datagrams whose processing or response was suppressed by endpoint rate limits.
    /// Counts one rejection per datagram, separately from `dropped_messages`.
    pub rate_limited: u64,
    /// Live duplicate records evicted under metadata-table pressure.
    pub dedup_record_evictions: u64,
    /// Full replies discarded under pool pressure while retaining their duplicate records.
    pub dedup_reply_drops: u64,
    /// Rate-admitted duplicate CON requests whose cached reply was reclaimed.
    /// Counts refusal attempts even when no free packet slot is available.
    pub dedup_reply_misses: u64,
    /// Oversized datagrams discarded before parsing.
    pub oversized: u64,
    /// Started EDHOC handshakes.
    pub edhoc_runs: u64,
    /// Context-table pressure evictions.
    pub context_evictions: u64,
}
#[cfg(feature = "shared-counters")]
impl Counters {
    const ZERO: Self = Self {
        requests: 0,
        retransmissions: 0,
        duplicates: 0,
        protection_failures: 0,
        send_failures: 0,
        local_send_timeouts: 0,
        unprotected_responses: 0,
        dropped_messages: 0,
        rate_limited: 0,
        dedup_record_evictions: 0,
        dedup_reply_drops: 0,
        dedup_reply_misses: 0,
        oversized: 0,
        edhoc_runs: 0,
        context_evictions: 0,
    };
}
/// Bounded local transport acceptance, independent of CoAP retransmission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SendPolicy {
    /// Initial timed retry delay in milliseconds.
    pub initial_retry_ms: u64,
    /// Maximum timed retry delay in milliseconds.
    pub max_retry_ms: u64,
    /// Maximum time from enqueue to local acceptance in milliseconds.
    /// Run drivers and `Endpoint::with_send_window` exclude synchronous producer
    /// work; FIFO waiting counts.
    pub max_wait_ms: u64,
}
impl Default for SendPolicy {
    fn default() -> Self {
        Self {
            initial_retry_ms: 1,
            max_retry_ms: 64,
            max_wait_ms: 1000,
        }
    }
}
impl SendPolicy {
    fn unsent_lifetime(self, parameters: TransmissionParameters) -> u64 {
        parameters
            .exchange_lifetime()
            .saturating_add(self.max_wait_ms)
    }
    fn unsent_deadline(self, now: Instant, parameters: TransmissionParameters) -> Instant {
        now.after(self.unsent_lifetime(parameters))
    }
    /// Sets the initial timed retry delay.
    pub const fn with_initial_retry_ms(mut self, value: u64) -> Self {
        self.initial_retry_ms = value;
        self
    }
    /// Sets the maximum timed retry delay.
    pub const fn with_max_retry_ms(mut self, value: u64) -> Self {
        self.max_retry_ms = value;
        self
    }
    /// Sets the maximum local acceptance wait.
    pub const fn with_max_wait_ms(mut self, value: u64) -> Self {
        self.max_wait_ms = value;
        self
    }
    /// Rejects zero or inconsistent bounds.
    pub fn validate(self) -> Result<Self, Error> {
        if self.initial_retry_ms == 0
            || self.initial_retry_ms > self.max_retry_ms
            || self.max_retry_ms > self.max_wait_ms
        {
            Err(Error::Malformed)
        } else {
            Ok(self)
        }
    }
}
type Token = heapless::Vec<u8, 8, u8>;
// Parsed messages and local random arrays hold at most eight token bytes.
fn token(bytes: &[u8]) -> Token {
    Token::from_slice(bytes).unwrap_or_default()
}
struct Exchange<B> {
    slot: Option<(usize, u64)>,
    target: Target,
    mid: u16,
    token: Token,
    packet: Option<PacketRef>,
    retry: Option<Retransmission>,
    deadline: Instant,
    binding: Option<B>,
    original: Option<PacketRef>,
    handshaking: bool,
    recovered: bool,
    raw: bool,
    credit: bool,
    accepted: bool,
    #[cfg(feature = "observe")]
    refresh: Option<observing::PendingRefresh<B>>,
    #[cfg(feature = "multicast")]
    collection: Option<Instant>,
    #[cfg(feature = "observe")]
    observation: Option<crate::observe::Ordering>,
    #[cfg(feature = "observe")]
    observer: Option<u64>,
}
impl<B> Exchange<B> {
    fn collected(&self) -> bool {
        #[cfg(feature = "multicast")]
        {
            self.collection.is_some()
        }
        #[cfg(not(feature = "multicast"))]
        {
            false
        }
    }
}
#[cfg(feature = "server")]
struct Deferred<B> {
    ticket: Ticket,
    metadata: Metadata,
    token: Token,
    confirmable: bool,
    binding: Option<B>,
    deadline: Instant,
}
/// Borrowed serialized datagram at the front of the send queue.
#[derive(Debug)]
#[non_exhaustive]
pub struct Outgoing<'a> {
    /// Remote destination.
    pub remote: SocketAddr,
    /// Required local source, or automatic selection.
    pub source: Option<IpAddr>,
    /// Required interface when known.
    pub interface: Option<u32>,
    /// Exact serialized bytes, valid until this view is dropped.
    pub bytes: &'a [u8],
    /// Send-budget origin; `Endpoint::with_send_window` sets it after preparation.
    pub enqueued: Instant,
}
#[derive(Debug)]
enum SendPacket {
    Inline { bytes: [u8; 4], length: u8 },
    Pooled(PacketRef),
}
#[derive(Debug)]
struct Queued {
    remote: SocketAddr,
    source: Option<IpAddr>,
    // Keep presence separate so it can share descriptor padding; Some(0) is valid.
    interface: u32,
    has_interface: bool,
    packet: SendPacket,
    mid: QueuedMid,
    enqueued: Instant,
    pending_timestamp: bool,
}
#[derive(Clone, Copy, Debug)]
// Quarantine and exchange or response-completion ownership share one MID field.
enum QueuedMid {
    /// Peer-assigned ACK/RST MIDs, including cached replays. Locally allocated
    /// CON/NON MIDs must use Local or Owned to extend their quarantine.
    Peer,
    Local(u16),
    /// Local MID with exchange or deferred-response completion ownership.
    /// A separate NON response has a completion owner without an exchange.
    Owned(u16),
}
impl QueuedMid {
    fn owner(self) -> Option<u16> {
        match self {
            Self::Owned(mid) => Some(mid),
            _ => None,
        }
    }
    fn local(self) -> Option<u16> {
        match self {
            Self::Local(mid) | Self::Owned(mid) => Some(mid),
            Self::Peer => None,
        }
    }
}
impl Queued {
    fn new(
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        packet: SendPacket,
        mid: QueuedMid,
        now: Instant,
        pending_timestamp: bool,
    ) -> Self {
        Self {
            remote,
            source,
            interface: interface.unwrap_or(0),
            has_interface: interface.is_some(),
            packet,
            mid,
            enqueued: now,
            pending_timestamp,
        }
    }
    fn interface(&self) -> Option<u32> {
        self.has_interface.then_some(self.interface)
    }
    fn stamp<B>(
        &mut self,
        now: Instant,
        ids: &mut MessageIds,
        exchange: Option<&mut Exchange<B>>,
        parameters: &TransmissionParameters,
        policy: &SendPolicy,
    ) {
        if !self.pending_timestamp {
            return;
        }
        self.enqueued = now;
        self.pending_timestamp = false;
        let Some(mid) = self.mid.local() else {
            return;
        };
        let parameters = exchange
            .as_ref()
            .map_or(*parameters, |e| e.target.parameters);
        let until = policy.unsent_deadline(now, parameters);
        if let Some(exchange) = exchange {
            if exchange.accepted && self.mid.owner() == Some(exchange.mid) {
                return;
            }
            if !exchange.accepted && !exchange.collected() {
                exchange.deadline = exchange.deadline.max(until);
            }
        }
        ids.quarantine(mid, until);
    }
    fn bytes<'a, const D: usize, const N: usize, S: PacketStorage<D, N>>(
        &'a self,
        pool: &'a PacketPool<D, N, S>,
    ) -> Option<&'a [u8]> {
        match &self.packet {
            SendPacket::Inline { bytes, length } => Some(&bytes[..usize::from(*length)]),
            SendPacket::Pooled(packet) => pool.get(packet),
        }
    }
}
/// Synchronous producer access within [`Endpoint::with_send_window`].
///
/// Every operation uses the window's entry timestamp. Compose producer helpers
/// through this view; transmit and acknowledge local acceptance on the endpoint
/// after the window closes, using current time. Rate limits, storage/client backoff
/// and protection expiry also use entry time; storage/client retry deadlines may
/// already be due when a long window completes.
pub struct SendWindow<'e, E> {
    endpoint: &'e mut E,
    now: Instant,
}
impl<E> SendWindow<'_, E> {
    /// Logical timestamp shared by all producer steps in this window.
    pub fn now(&self) -> Instant {
        self.now
    }
}
struct SendWindowGuard<'a, E, F: FnMut(&mut E)> {
    endpoint: &'a mut E,
    complete: F,
}
impl<E, F: FnMut(&mut E)> Drop for SendWindowGuard<'_, E, F> {
    fn drop(&mut self) {
        (self.complete)(self.endpoint);
    }
}

trait PacketSender<T: DatagramSender, const D: usize, const N: usize, S: PacketStorage<D, N>> {
    fn poll_send(
        &self,
        transport: &mut T,
        pool: &mut PacketPool<D, N, S>,
        queued: &Queued,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<SendOutcome, RunError<T::Error>>>;
}
struct BorrowedSender;
impl<T: DatagramSender, const D: usize, const N: usize, S: PacketStorage<D, N>>
    PacketSender<T, D, N, S> for BorrowedSender
{
    fn poll_send(
        &self,
        transport: &mut T,
        pool: &mut PacketPool<D, N, S>,
        queued: &Queued,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<SendOutcome, RunError<T::Error>>> {
        let bytes = queued
            .bytes(pool)
            .ok_or(RunError::Protocol(Error::Cancelled))?;
        transport
            .poll_send(queued.remote, queued.source, queued.interface(), bytes, cx)
            .map(|result| result.map_err(RunError::Transport))
    }
}
struct OwnedSender;
impl<T: OwnedDatagramSender<S::Buffer>, const D: usize, const N: usize, S: OwnedPacketStorage<D, N>>
    PacketSender<T, D, N, S> for OwnedSender
{
    fn poll_send(
        &self,
        transport: &mut T,
        pool: &mut PacketPool<D, N, S>,
        queued: &Queued,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<SendOutcome, RunError<T::Error>>> {
        if let SendPacket::Pooled(packet) = &queued.packet
            && let Some(buffer) = pool.owned_buffer(packet)
        {
            return transport
                .poll_send_owned(queued.remote, queued.source, queued.interface(), buffer, cx)
                .map(|result| result.map_err(RunError::Transport));
        }
        BorrowedSender.poll_send(transport, pool, queued, cx)
    }
}
/// Protocol or transport failure from the async driver.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum RunError<TransportError> {
    /// Transport failed; the endpoint retains protocol state for restarting the driver.
    Transport(TransportError),
    /// A local configuration or capacity failure prevented progress.
    Protocol(Error),
}
impl<TransportError: core::fmt::Display> core::fmt::Display for RunError<TransportError> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(error) => write!(f, "transport: {error}"),
            Self::Protocol(error) => write!(f, "protocol: {error}"),
        }
    }
}
impl<TransportError: core::error::Error + 'static> core::error::Error for RunError<TransportError> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Protocol(error) => Some(error),
        }
    }
}
/// Endpoint state machine; storage is caller-owned and statically bounded.
///
/// After the lifetime and protection type, const arguments have this order:
///
/// | Position | Parameter | Default |
/// |---|---|---|
/// | 1 | `DATAGRAM_BYTES` | 1152 bytes |
/// | 2 | `OUTBOUND` | 8 |
/// | 3 | `DEDUP_ENTRIES` | 32 |
/// | 4 | `OBSERVERS` | 8 |
/// | 5 | `CACHED_REPLIES` | 8 |
/// | 6 | `SEND_QUEUE` | 16 descriptors |
/// | 7 | `COMMANDS` | `OUTBOUND` |
/// | 8 | `DEFERRED` | `OUTBOUND` |
/// | 9 | `BODY_CONTEXTS` | 8 |
/// | 10 | `PACKETS` | 40 buffers |
///
/// See the [crate-level capacity table](crate) for meanings, [`DefaultEndpoint`]
/// for the defaults, and [`SmallEndpoint`] for a compact profile.
/// `OUTBOUND` bounds all tracked exchanges, including deferred CON responses
/// and CON notifications on server-only endpoints.
/// Empty ACKs use only duplicate-record storage.
/// The final type arguments select packet storage and a fixed [`role::Role`].
/// Explicit roles use [`Self::new_with_role`] or [`Self::with_storage_and_role`].
///
/// # Custom drivers
///
/// [`with_send_window`](Self::with_send_window) and its restricted [`SendWindow`] view,
/// [`receive`](Self::receive), [`poll`](Self::poll),
/// [`front_outgoing`](Self::front_outgoing), [`complete_outgoing`](Self::complete_outgoing),
/// [`discard_outgoing`](Self::discard_outgoing), [`poll_resources`](Self::poll_resources)
/// and [`deadline`](Self::deadline) are supported driver APIs. With `observe`,
/// `poll_observations` is also supported and is already called by `poll_resources`.
///
/// Custom drivers poll protocol and resource work, preserve datagram metadata,
/// and complete a borrowed outgoing packet only after sending succeeds. Recoverable
/// send errors discard that packet; temporary backpressure retains it. Fatal
/// errors retain it for restart. Use `poll_transmit` for bounded local scheduling. Pass the driver's
/// task context to `poll_resources` and call it on every task wake, including wakes
/// with no new command or expired deadline. Wake for the earlier endpoint/application
/// deadline, treating `deadline(now) == now` as immediate work, and arrange
/// wakeups when commands are submitted. [`run`](Self::run) manages these wakeups
/// and transport cancellation automatically.
pub struct Endpoint<
    'a,
    P,
    const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM },
    const OUTBOUND: usize = { crate::DEFAULT_OUTBOUND },
    const DEDUP_ENTRIES: usize = { crate::DEFAULT_DEDUP },
    const OBSERVERS: usize = { crate::DEFAULT_OBSERVERS },
    const CACHED_REPLIES: usize = { crate::DEFAULT_CACHED_REPLIES },
    const SEND_QUEUE: usize = { crate::DEFAULT_SEND_QUEUE },
    const COMMANDS: usize = OUTBOUND,
    const DEFERRED: usize = OUTBOUND,
    const BODY_CONTEXTS: usize = { crate::DEFAULT_BODY_CONTEXTS },
    const PACKETS: usize = { crate::DEFAULT_PACKETS },
    S = InlineStorage<DATAGRAM_BYTES, PACKETS>,
    Mode = role::Combined,
> where
    P: Protection,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS>,
    Mode: role::Role,
{
    _role: core::marker::PhantomData<fn() -> Mode>,
    shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
    protection: P,
    ids: MessageIds,
    duplicates: Deduplication<DEDUP_ENTRIES, CACHED_REPLIES>,
    exchanges: heapless::Vec<Exchange<P::Binding>, OUTBOUND>,
    #[cfg(feature = "server")]
    deferred: heapless::Vec<Deferred<P::Binding>, DEFERRED>,
    outgoing: heapless::Deque<Queued, SEND_QUEUE>,
    in_send_window: bool,
    pool: PacketPool<DATAGRAM_BYTES, PACKETS, S>,
    // Backing pools have no portable allocation-ready waker. The positive retry
    // delay permits an optional deadline without enlarging its eight-byte storage.
    storage_retry: Option<core::num::NonZeroU64>,
    storage_backoff_ms: u16,
    send_policy: SendPolicy,
    send_retry: Option<Instant>,
    send_backoff_ms: u64,
    storage_reclaim_blocked: bool,
    next_ticket: u64,
    parameters: TransmissionParameters,
    counters: Counters,
    limiter: crate::rate::Limiter<16>,
    body_epochs: heapless::Vec<u64, BODY_CONTEXTS>,
    probes: crate::messaging::Probing<OUTBOUND>,
    backoff: heapless::Vec<(SocketAddr, Instant), OUTBOUND>,
    #[cfg(feature = "multicast")]
    leisure: heapless::Vec<multicast::Pending, SEND_QUEUE>,
    #[cfg(feature = "observe")]
    observers: heapless::Vec<observing::ServerObservation<P::Binding, DATAGRAM_BYTES>, OBSERVERS>,
}
impl<
    'a,
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS>,
    Mode: role::Role,
>
    SendWindow<
        '_,
        Endpoint<
            'a,
            P,
            DATAGRAM_BYTES,
            OUTBOUND,
            DEDUP_ENTRIES,
            OBSERVERS,
            CACHED_REPLIES,
            SEND_QUEUE,
            COMMANDS,
            DEFERRED,
            BODY_CONTEXTS,
            PACKETS,
            S,
            Mode,
        >,
    >
{
    /// Processes an incoming datagram at the window's logical timestamp.
    pub fn receive<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        bytes: &[u8],
        metadata: Metadata,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        self.endpoint
            .receive(bytes, metadata, self.now, application, policy)
    }
    /// Advances protocol work and eligible commands at the window's timestamp.
    pub fn poll(&mut self) -> Result<(), Error> {
        self.endpoint.poll(self.now)
    }
    /// Advances application work and registers worker wakeups.
    pub fn poll_resources<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
        cx: &mut TaskContext<'_>,
    ) -> Result<(), Error> {
        self.endpoint
            .poll_resources(self.now, application, policy, cx)
    }
    /// Delivers due notifications; already included in [`Self::poll_resources`].
    #[cfg(feature = "observe")]
    pub fn poll_observations<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        self.endpoint
            .poll_observations(self.now, application, policy)
    }
}
impl<
    'a,
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
>
    Endpoint<
        'a,
        P,
        DATAGRAM_BYTES,
        OUTBOUND,
        DEDUP_ENTRIES,
        OBSERVERS,
        CACHED_REPLIES,
        SEND_QUEUE,
        COMMANDS,
        DEFERRED,
        BODY_CONTEXTS,
        PACKETS,
        InlineStorage<DATAGRAM_BYTES, PACKETS>,
        role::Combined,
    >
{
    /// Constructs an endpoint with inline packet storage.
    /// Invalid zero/small capacities return [`Error::Capacity`].
    pub fn new(shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>, protection: P) -> Result<Self, Error> {
        Self::new_with_role(shared, protection)
    }
}
impl<
    'a,
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
    Mode: role::Role,
>
    Endpoint<
        'a,
        P,
        DATAGRAM_BYTES,
        OUTBOUND,
        DEDUP_ENTRIES,
        OBSERVERS,
        CACHED_REPLIES,
        SEND_QUEUE,
        COMMANDS,
        DEFERRED,
        BODY_CONTEXTS,
        PACKETS,
        InlineStorage<DATAGRAM_BYTES, PACKETS>,
        Mode,
    >
{
    /// Constructs inline packet storage with the role selected by the endpoint type.
    /// Invalid zero/small capacities return [`Error::Capacity`].
    pub fn new_with_role(
        shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
        protection: P,
    ) -> Result<Self, Error> {
        // Construct at the pool field rather than passing a second inline array.
        Self::initialize(shared, protection, || const { PacketPool::new() })
    }
}
impl<
    'a,
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS>,
>
    Endpoint<
        'a,
        P,
        DATAGRAM_BYTES,
        OUTBOUND,
        DEDUP_ENTRIES,
        OBSERVERS,
        CACHED_REPLIES,
        SEND_QUEUE,
        COMMANDS,
        DEFERRED,
        BODY_CONTEXTS,
        PACKETS,
        S,
        role::Combined,
    >
{
    /// Constructs an endpoint using caller-selected bounded packet storage.
    /// Invalid zero/small capacities return [`Error::Capacity`].
    pub fn with_storage(
        shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
        protection: P,
        storage: S,
    ) -> Result<Self, Error> {
        Self::with_storage_and_role(shared, protection, storage)
    }
}
impl<
    'a,
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS>,
    Mode: role::Role,
>
    Endpoint<
        'a,
        P,
        DATAGRAM_BYTES,
        OUTBOUND,
        DEDUP_ENTRIES,
        OBSERVERS,
        CACHED_REPLIES,
        SEND_QUEUE,
        COMMANDS,
        DEFERRED,
        BODY_CONTEXTS,
        PACKETS,
        S,
        Mode,
    >
{
    /// Constructs an endpoint using caller-selected bounded packet storage.
    /// Invalid zero/small capacities return [`Error::Capacity`].
    pub fn with_storage_and_role(
        shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
        protection: P,
        storage: S,
    ) -> Result<Self, Error> {
        Self::initialize(shared, protection, || PacketPool::with_storage(storage))
    }
    fn initialize(
        shared: &'a Shared<DATAGRAM_BYTES, COMMANDS>,
        mut protection: P,
        pool: impl FnOnce() -> PacketPool<DATAGRAM_BYTES, PACKETS, S>,
    ) -> Result<Self, Error> {
        if DATAGRAM_BYTES < 16
            || DEDUP_ENTRIES == 0
            || Mode::SERVE && CACHED_REPLIES == 0
            || SEND_QUEUE == 0
            || PACKETS == 0
        {
            return Err(Error::Capacity);
        }
        let mut seed = [0; 2];
        protection.random(&mut seed);
        Ok(Self {
            _role: core::marker::PhantomData,
            shared,
            protection,
            ids: MessageIds::new(u16::from_be_bytes(seed)),
            duplicates: Deduplication::new(),
            pool: pool(),
            exchanges: heapless::Vec::new(),
            #[cfg(feature = "server")]
            deferred: heapless::Vec::new(),
            // Avoid evaluating heapless's nonzero-only constructor for a rejected bound.
            outgoing: const {
                if SEND_QUEUE == 0 {
                    None
                } else {
                    Some(heapless::Deque::new())
                }
            }
            .ok_or(Error::Capacity)?,
            in_send_window: false,
            storage_retry: None,
            storage_backoff_ms: 1,
            send_policy: SendPolicy::default(),
            send_retry: None,
            send_backoff_ms: 1,
            storage_reclaim_blocked: false,
            next_ticket: 1,
            parameters: TransmissionParameters::default(),
            counters: Counters::default(),
            limiter: crate::rate::Limiter::new(crate::rate::Limits::default())?,
            body_epochs: heapless::Vec::new(),
            probes: crate::messaging::Probing::new(),
            backoff: heapless::Vec::new(),
            #[cfg(feature = "multicast")]
            leisure: heapless::Vec::new(),
            #[cfg(feature = "observe")]
            observers: heapless::Vec::new(),
        })
    }
    /// Configures defaults for incoming exchanges; outgoing commands carry their profile.
    pub fn set_parameters(&mut self, parameters: TransmissionParameters) -> Result<(), Error> {
        self.parameters = parameters.validate()?;
        Ok(())
    }
    /// Configures local send scheduling. Returns `Capacity` while datagrams are
    /// queued (including multicast leisure), preserving their MID quarantine bound.
    pub fn set_send_policy(&mut self, policy: SendPolicy) -> Result<(), Error> {
        let policy = policy.validate()?;
        #[cfg(feature = "multicast")]
        let pending_leisure = !self.leisure.is_empty();
        #[cfg(not(feature = "multicast"))]
        let pending_leisure = false;
        if !self.outgoing.is_empty() || pending_leisure {
            return Err(Error::Capacity);
        }
        self.send_policy = policy;
        self.send_retry = None;
        self.send_backoff_ms = policy.initial_retry_ms;
        Ok(())
    }
    /// Replaces unprotected response budgets and resets accumulated credit.
    pub fn set_rate_limits(&mut self, limits: crate::rate::Limits) -> Result<(), Error> {
        self.limiter = crate::rate::Limiter::new(limits)?;
        Ok(())
    }
    fn charge_response_budget(&mut self, source: IpAddr, now: Instant) -> bool {
        let allowed = self.limiter.allow(source, now);
        if !allowed {
            self.counters.rate_limited += 1;
        }
        allowed
    }
    /// Current counters, including statistics supplied by the protection layer.
    /// With `shared-counters`, use `Shared::counters` or `Handle::counters` while
    /// [`Self::run`] borrows this endpoint.
    pub fn counters(&self) -> Counters {
        Counters {
            edhoc_runs: self.protection.handshake_runs(),
            context_evictions: self.protection.context_evictions(),
            ..self.counters
        }
    }
    #[cfg(feature = "shared-counters")]
    fn publish_counters(&self) {
        // Providers may read Shared while reporting their statistics.
        let counters = self.counters();
        self.shared.lock(|state| state.counters = counters);
    }
    /// Security provider/context administration between driver polls.
    pub fn protection_mut(&mut self) -> &mut P {
        &mut self.protection
    }
    fn release_body_epochs(&mut self, application: &impl Application<DATAGRAM_BYTES>) {
        let mut i = 0;
        while i < self.body_epochs.len() {
            if !application.uses_context(self.body_epochs[i]) {
                let epoch = self.body_epochs.swap_remove(i);
                self.protection.unpin_epoch(epoch);
            } else {
                i += 1;
            }
        }
    }
    /// Advances resources and registers wakeups for external worker operations.
    /// For completion-based send budgets, use the corresponding [`SendWindow`]
    /// method through [`Self::with_send_window`].
    pub fn poll_resources<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
        cx: &mut TaskContext<'_>,
    ) -> Result<(), Error> {
        if self.storage_deadline().is_some_and(|retry| retry <= now) {
            self.storage_retry = None;
        }
        application.poll(now, cx);
        self.release_body_epochs(application);
        #[cfg(feature = "observe")]
        if let Err(error) = self.poll_observations(now, application, policy) {
            self.drop_message(error);
        }
        #[cfg(not(feature = "observe"))]
        let _ = policy;
        Ok(())
    }
    /// Borrows the next datagram without releasing its storage.
    /// Call `complete_outgoing` only after transport acceptance. Cancellation
    /// leaves the front packet available for a byte-exact retry.
    /// Use `with_send_window` around producer steps to exclude preparation time.
    pub fn front_outgoing(&self) -> Option<Outgoing<'_>> {
        let queued = self.outgoing.front()?;
        let bytes = queued.bytes(&self.pool)?;
        Some(Outgoing {
            remote: queued.remote,
            source: queued.source,
            interface: queued.interface(),
            bytes,
            enqueued: queued.enqueued,
        })
    }
    /// Releases the front datagram after the transport accepted it.
    /// This acknowledges local delivery, not a remote CoAP acknowledgement.
    /// Manual drivers must poll expiry immediately before attempting a send and
    /// honor `deadline`; `poll_transmit` enforces these bounds automatically.
    pub fn complete_outgoing(&mut self, now: Instant) {
        if let Some(queued) = self.outgoing.pop_front() {
            let index = self.queued_exchange(&queued);
            if let Some(index) = index {
                #[cfg(feature = "observe")]
                if let Err(error) = self.commit_refresh(index, now) {
                    self.drop_message(error);
                    self.finish(index, Err(error));
                    self.release_queued(queued);
                    self.send_progress();
                    return;
                }
                let exchange = &mut self.exchanges[index];
                if exchange.accepted {
                    self.counters.retransmissions += 1;
                } else {
                    if !exchange.collected() {
                        exchange.deadline =
                            now.after(exchange.target.parameters.exchange_lifetime());
                    }
                    if exchange.retry.is_none() {
                        self.probes
                            .accepted(exchange.target.remote, now.elapsed_since(queued.enqueued));
                    }
                    exchange.accepted = true;
                }
                if let Some(retry) = exchange.retry.as_mut() {
                    retry.accepted(now, exchange.target.parameters);
                }
                #[cfg(feature = "observe")]
                if let Some(ticket) = exchange.observer {
                    self.notification_accepted(ticket, now);
                }
            }
            #[cfg(feature = "server")]
            if let Some(mid) = queued.mid.owner() {
                self.shared
                    .complete_response(queued.remote, mid, true, Ok(()));
            }
            self.release_queued(queued);
            self.send_progress();
        }
    }
    /// Discards one datagram after a recoverable send failure and counts the drop.
    pub fn discard_outgoing(&mut self, now: Instant) {
        self.reject_outgoing(now, Error::LocalSendFailed);
    }
    fn send_progress(&mut self) {
        self.send_retry = None;
        self.send_backoff_ms = self.send_policy.initial_retry_ms;
    }
    fn queued_exchange(&self, queued: &Queued) -> Option<usize> {
        Self::find_queued_exchange(&self.exchanges, queued)
    }
    fn find_queued_exchange(exchanges: &[Exchange<P::Binding>], queued: &Queued) -> Option<usize> {
        // The shared exchange vector has zero capacity, including for server CONs.
        // Keep its bookkeeping out of zero-exchange monomorphizations.
        if OUTBOUND == 0 {
            return None;
        }

        let mid = queued.mid.owner()?;
        exchanges.iter().position(|e| {
            crate::transport::same_peer(e.target.remote, queued.remote)
                && ({
                    let matches = e.mid == mid;
                    #[cfg(feature = "observe")]
                    let matches = matches || e.refresh.as_ref().is_some_and(|r| r.mid == mid);
                    matches
                })
        })
    }
    /// Runs synchronous producer steps, starting new send budgets at completion.
    /// Existing queued datagrams retain their budgets.
    ///
    /// The restricted [`SendWindow`] uses one entry timestamp for all its steps,
    /// including calls through helpers. It exposes no transmission, acceptance or
    /// clock-boundary methods. After completion, use current time for transmission
    /// and expiry. Completion stamps new output even on errors or unwinding.
    /// `run` and `run_owned` use this boundary automatically.
    ///
    /// ```
    /// # use mai_coap::{Error, endpoint::{Application, Endpoint, Protection},
    /// #     security::Policy, time::Clock, transport::Metadata};
    /// # fn step<P: Protection, C: Clock, A: Application<1152>>(
    /// #     endpoint: &mut Endpoint<'_, P>, clock: &C, bytes: &[u8],
    /// #     metadata: Metadata, application: &mut A, policy: &impl Policy,
    /// # ) -> Result<(), Error> {
    /// endpoint.with_send_window(clock, |window| {
    ///     window.receive(bytes, metadata, application, policy)
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Local acceptance cannot occur through the producer view:
    /// ```compile_fail,E0599
    /// # use mai_coap::{endpoint::{Endpoint, Protection}, time::Clock};
    /// # fn step<P: Protection>(endpoint: &mut Endpoint<'_, P>, clock: &impl Clock) {
    /// endpoint.with_send_window(clock, |window| {
    ///     window.complete_outgoing(window.now());
    /// });
    /// # }
    /// ```
    /// Producer methods cannot be given a later timestamp:
    /// ```compile_fail,E0061
    /// # use mai_coap::{endpoint::{Endpoint, Protection}, time::{Clock, Instant}};
    /// # fn step<P: Protection>(endpoint: &mut Endpoint<'_, P>, clock: &impl Clock) {
    /// endpoint.with_send_window(clock, |window| window.poll(Instant(1000)));
    /// # }
    /// ```
    /// The view cannot escape into an asynchronous operation:
    /// ```compile_fail
    /// # use mai_coap::{endpoint::{Endpoint, Protection}, time::Clock};
    /// # fn step<P: Protection>(endpoint: &mut Endpoint<'_, P>, clock: &impl Clock) {
    /// let future = endpoint.with_send_window(clock, |window| async move { window.poll() });
    /// # }
    /// ```
    /// Endpoint access is restricted rather than provided through `DerefMut`:
    /// ```compile_fail,E0308
    /// # use mai_coap::{endpoint::{Endpoint, Protection}, time::Clock};
    /// # fn step<P: Protection>(endpoint: &mut Endpoint<'_, P>, clock: &impl Clock) {
    /// endpoint.with_send_window(clock, |window| {
    ///     let endpoint: &mut Endpoint<'_, P> = window;
    ///     endpoint.complete_outgoing(clock.now());
    /// });
    /// # }
    /// ```
    pub fn with_send_window<R>(
        &mut self,
        clock: &impl Clock,
        process: impl FnOnce(&mut SendWindow<'_, Self>) -> R,
    ) -> R {
        debug_assert!(!self.in_send_window, "send windows must not nest");
        let now = clock.now();
        self.in_send_window = true;
        // Unwinding must close the scope before the endpoint can be reused.
        let guard = SendWindowGuard {
            endpoint: self,
            complete: |endpoint: &mut Self| {
                endpoint.in_send_window = false;
                endpoint.stamp_enqueue_time(clock.now());
            },
        };
        process(&mut SendWindow {
            endpoint: &mut *guard.endpoint,
            now,
        })
    }
    // Keep timestamp/MID bookkeeping frames out of synchronous crypto processing.
    #[inline(never)]
    fn stamp_enqueue_time(&mut self, now: Instant) {
        for queued in &mut self.outgoing {
            if !queued.pending_timestamp {
                continue;
            }
            let index = Self::find_queued_exchange(&self.exchanges, queued);
            queued.stamp(
                now,
                &mut self.ids,
                index.map(|i| &mut self.exchanges[i]),
                &self.parameters,
                &self.send_policy,
            );
        }
    }
    fn send_expires(&self, queued: &Queued) -> Instant {
        let local = queued.enqueued.after(self.send_policy.max_wait_ms);
        let protocol = self.queued_exchange(queued).and_then(|index| {
            let e = &self.exchanges[index];
            if e.collected() {
                return Some(e.deadline);
            }
            (e.accepted && queued.mid.owner() == Some(e.mid))
                .then(|| {
                    e.retry
                        .map(|r| r.last_send_at(e.target.parameters).after(1))
                })
                .flatten()
        });
        protocol.map_or(local, |deadline| local.min(deadline))
    }
    fn reject_outgoing(&mut self, now: Instant, error: Error) {
        if let Some(queued) = self.outgoing.pop_front() {
            self.reject_queued(queued, now, error);
        }
        self.send_progress();
    }
    fn reject_queued(&mut self, queued: Queued, now: Instant, error: Error) {
        let index = self.queued_exchange(&queued);
        #[cfg(feature = "server")]
        if index.is_none()
            && let Some(mid) = queued.mid.owner()
        {
            self.shared
                .complete_response(queued.remote, mid, false, Err(error));
        }
        // A lost notification preserves both registration and a fresh-state retry.
        #[cfg(feature = "observe")]
        self.retry_notification(&queued, now);
        self.release_queued(queued);
        self.counters.dropped_messages += 1;
        if error == Error::LocalSendTimeout {
            self.counters.local_send_timeouts += 1;
        }
        if let Some(index) = index {
            #[cfg(feature = "observe")]
            if self.exchanges[index].refresh.is_some() {
                self.abort_refresh(index, now);
                return;
            }
            if !self.exchanges[index].accepted {
                self.finish(index, Err(error));
            } else if let Some(retry) = self.exchanges[index].retry.as_mut() {
                retry.skipped(now);
            }
        }
    }
    fn expire_outgoing(&mut self, now: Instant) {
        let count = self.outgoing.len();
        let mut expired = false;
        for _ in 0..count {
            let Some(queued) = self.outgoing.pop_front() else {
                break;
            };
            if now >= self.send_expires(&queued) {
                self.reject_queued(queued, now, Error::LocalSendTimeout);
                expired = true;
            } else {
                let _ = self.outgoing.push_back(queued);
            }
        }
        if expired {
            self.send_progress();
        }
    }
    fn release_queued(&mut self, queued: Queued) {
        if let SendPacket::Pooled(packet) = queued.packet {
            self.release_completed_packet(packet);
        }
    }
    // Queue/exchange completion and cache expiry establish protocol progress.
    // Admissions reset separately once all required buffers are reserved; raw
    // cleanup releases preserve any wait caused by a partial reservation failure.
    fn release_completed_packet(&mut self, packet: PacketRef) {
        let freed = self.pool.reference_count(&packet) == 1;
        self.pool.release(packet);
        if freed {
            self.storage_available();
        }
    }
    fn expire_cached_packets(&mut self, now: Instant) {
        let available = self.pool.available();
        self.duplicates.expire(&mut self.pool, now);
        if self.pool.available() > available {
            self.storage_available();
        }
    }
    fn storage_deadline(&self) -> Option<Instant> {
        self.storage_retry.map(|retry| Instant(retry.get()))
    }
    fn storage_ready(&self, now: Instant) -> bool {
        self.storage_deadline().is_none_or(|retry| retry <= now)
    }
    fn storage_shortage(&mut self, now: Instant) {
        if !self.storage_ready(now) {
            return;
        }
        self.storage_retry =
            core::num::NonZeroU64::new(now.after(u64::from(self.storage_backoff_ms)).0);
        self.storage_backoff_ms = self.storage_backoff_ms.saturating_mul(2).min(2000);
    }
    fn storage_available(&mut self) {
        // Complete admissions or released protocol storage establish progress;
        // partial two-buffer admissions must keep their growing retry delay.
        self.storage_retry = None;
        self.storage_backoff_ms = 1;
    }
    fn reserve_packet(
        &mut self,
        preferred: Option<(SocketAddr, IpAddr)>,
        now: Instant,
    ) -> Result<PacketRef, Error> {
        let result = (|| {
            self.expire_cached_packets(now);
            match self.pool.reserve() {
                Ok(packet) => return Ok(packet),
                Err(Error::Capacity) => {}
                Err(error) => return Err(error),
            }
            // Reclamation that cannot satisfy this allocator must not drain the
            // cache across repeated requests or retries. Successful allocation rearms it.
            if self.storage_reclaim_blocked
                || !self.duplicates.reclaim_reply(
                    &mut self.pool,
                    preferred,
                    ReplyReclaimMode::FreePacket,
                )
            {
                return Err(Error::Capacity);
            }
            self.counters.dedup_reply_drops += 1;
            let result = self.pool.reserve();
            if result.is_err() {
                self.storage_reclaim_blocked = true;
            }
            result
        })();
        match &result {
            Ok(_) => {
                self.storage_reclaim_blocked = false;
                // Partial admissions clear the wait, but keep the growing delay
                // until every required buffer has been acquired.
                self.storage_retry = None;
            }
            Err(Error::Capacity) if self.pool.available() != 0 => self.storage_shortage(now),
            _ => {}
        }
        result
    }

    fn replay_cached(
        &mut self,
        meta: Metadata,
        message: MessageView<'_>,
        now: Instant,
    ) -> Result<(), Error> {
        match self
            .duplicates
            .lookup(meta.remote, meta.local, message.message_id(), now)
        {
            Some(CachedReply::Full(packet)) => {
                let packet = self.pool.retain(packet)?;
                self.queue_ref(
                    meta.remote,
                    Some(meta.local),
                    meta.interface,
                    packet,
                    QueuedMid::Peer,
                    now,
                )
            }
            Some(&CachedReply::Inline { bytes, len }) => self.queue_inline(
                meta.remote,
                Some(meta.local),
                meta.interface,
                &bytes[..usize::from(len)],
                QueuedMid::Peer,
                now,
            ),
            Some(CachedReply::Dropped) if message.code().is_request() => {
                // OSCORE requests skip the earlier pre-lookup budget check,
                // so charge their duplicate refusal here.
                if message.option(OptionNumber::OSCORE).is_some()
                    && !self.charge_response_budget(meta.remote.ip(), now)
                {
                    return Ok(());
                }
                self.counters.dedup_reply_misses += 1;
                // The original operation may have succeeded; never dispatch or re-protect it.
                // Header, maximum token, and a two-byte Max-Age option:
                // extended delta with a zero-length value.
                let mut bytes = [0; 4 + 8 + 2];
                let mut builder = MessageBuilder::new(
                    &mut bytes,
                    MessageType::Acknowledgement,
                    Code::UNAVAILABLE,
                    message.message_id(),
                    message.token(),
                )?;
                builder.uint_option(OptionNumber::MAX_AGE, 0)?;
                let n = builder.finish(&[])?;
                // Speculative refusals must neither reclaim cached results nor
                // reset admission backoff before their queued send completes.
                self.expire_cached_packets(now);
                let Ok(packet) = self.pool.reserve() else {
                    return Ok(());
                };
                if let Err(error) = self.pool.write(&packet, &bytes[..n]) {
                    self.pool.release(packet);
                    return Err(error);
                }
                self.queue_ref(
                    meta.remote,
                    Some(meta.local),
                    meta.interface,
                    packet,
                    QueuedMid::Peer,
                    now,
                )
            }
            _ => Ok(()),
        }
    }
    fn queue_ref(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        packet: PacketRef,
        mid: QueuedMid,
        now: Instant,
    ) -> Result<(), Error> {
        if let Err(queued) = self.outgoing.push_back(Queued::new(
            remote,
            source,
            interface,
            SendPacket::Pooled(packet),
            mid,
            now,
            self.in_send_window,
        )) {
            self.release_queued(queued);
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn queue_inline(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        mid: QueuedMid,
        now: Instant,
    ) -> Result<(), Error> {
        let mut inline = [0; 4];
        inline
            .get_mut(..bytes.len())
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        self.outgoing
            .push_back(Queued::new(
                remote,
                source,
                interface,
                SendPacket::Inline {
                    bytes: inline,
                    length: bytes.len() as u8,
                },
                mid,
                now,
                self.in_send_window,
            ))
            .map_err(|_| Error::Capacity)
    }
    // Release the reservation on every exit, before its retained owners can outlive this call.
    fn with_packet<R>(
        &mut self,
        preferred: Option<(SocketAddr, IpAddr)>,
        now: Instant,
        use_packet: impl FnOnce(&mut Self, &PacketRef) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let packet = self.reserve_packet(preferred, now)?;
        let result = use_packet(self, &packet);
        if result.is_ok() {
            self.storage_available();
        }
        self.pool.release(packet);
        result
    }
    fn queue_reserved(
        &mut self,
        reservation: &PacketRef,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        mid: QueuedMid,
        now: Instant,
    ) -> Result<PacketRef, Error> {
        let retained = self.pool.retain(reservation)?;
        let result = self
            .pool
            .retain(reservation)
            .and_then(|queued| self.queue_ref(remote, source, interface, queued, mid, now));
        if let Err(error) = result {
            self.pool.release(retained);
            return Err(error);
        }
        Ok(retained)
    }
    fn drop_exchange_sends(&mut self, remote: SocketAddr, mid: u16) {
        let count = self.outgoing.len();
        for index in 0..count {
            if let Some(queued) = self.outgoing.pop_front() {
                if crate::transport::same_peer(queued.remote, remote)
                    && queued.mid.owner() == Some(mid)
                {
                    if index == 0 {
                        self.send_progress();
                    }
                    self.release_queued(queued);
                } else if let Err(queued) = self.outgoing.push_back(queued) {
                    self.release_queued(queued);
                }
            }
        }
    }
    fn drop_message(&mut self, error: Error) {
        self.counters.dropped_messages += 1;
        if matches!(
            error,
            Error::Protection | Error::SequenceExhausted | Error::ContextNotFound | Error::Edhoc
        ) {
            self.counters.protection_failures += 1;
        }
        trace_event("message dropped");
    }
    fn control(
        &mut self,
        meta: Metadata,
        ty: MessageType,
        mid: u16,
        now: Instant,
    ) -> Result<(), Error> {
        self.queue_inline(
            meta.remote,
            Some(meta.local),
            meta.interface,
            &empty_message(ty, mid),
            QueuedMid::Peer,
            now,
        )
    }
    fn acknowledge(
        &mut self,
        message: MessageView<'_>,
        meta: Metadata,
        now: Instant,
    ) -> Result<(), Error> {
        self.control(
            meta,
            MessageType::Acknowledgement,
            message.message_id(),
            now,
        )?;
        let ack = empty_message(MessageType::Acknowledgement, message.message_id());
        self.remember(message, meta, CachedReply::inline(&ack)?, now)
    }
    fn release(&mut self, binding: Option<P::Binding>) {
        if let Some(binding) = binding {
            self.protection.release(binding);
        }
    }
    // Intermediate failures still require provider cleanup for untransferred bindings.
    fn with_binding<R>(
        &mut self,
        mut binding: Option<P::Binding>,
        use_binding: impl FnOnce(&mut Self, &mut Option<P::Binding>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let result = use_binding(self, &mut binding);
        self.release(binding);
        result
    }
    fn deferred_available(&self, ty: MessageType) -> bool {
        #[cfg(feature = "server")]
        {
            Mode::SERVE
                && COMMANDS != 0
                && !self.deferred.is_full()
                && (ty != MessageType::Confirmable || OUTBOUND != 0)
        }
        #[cfg(not(feature = "server"))]
        {
            let _ = ty;
            false
        }
    }
    #[cfg(feature = "client")]
    fn destination_ready(&self, remote: SocketAddr, now: Instant) -> bool {
        !self
            .backoff
            .iter()
            .any(|(p, t)| crate::transport::same_peer(*p, remote) && *t > now)
    }
    fn credits_used(&self, remote: SocketAddr) -> usize {
        self.exchanges
            .iter()
            .filter(|e| crate::transport::same_peer(e.target.remote, remote) && e.credit)
            .count()
    }
    fn allocate_mid(
        &mut self,
        parameters: TransmissionParameters,
        now: Instant,
    ) -> Result<u16, Error> {
        self.ids
            .allocate(now, self.send_policy.unsent_lifetime(parameters))
    }
    fn random_u32(&mut self) -> u32 {
        let mut random = [0; 4];
        self.protection.random(&mut random);
        u32::from_ne_bytes(random)
    }
    fn stop_retransmission(&mut self, index: usize) {
        self.exchanges[index].retry = None;
        self.exchanges[index].credit = false;
        let (remote, mid) = (
            self.exchanges[index].target.remote,
            self.exchanges[index].mid,
        );
        self.drop_exchange_sends(remote, mid);
        if let Some(packet) = self.exchanges[index].packet.take() {
            self.release_completed_packet(packet);
        }
    }
    fn finish(&mut self, index: usize, result: Result<Reply<DATAGRAM_BYTES>, Error>) {
        let exchange = self.exchanges.swap_remove(index);
        if !exchange.accepted && exchange.retry.is_none() && exchange.slot.is_some() {
            self.probes.answered(exchange.target.remote);
        }
        self.drop_exchange_sends(exchange.target.remote, exchange.mid);
        if let Some(packet) = exchange.packet {
            self.release_completed_packet(packet);
        }
        if let Some(original) = exchange.original {
            self.release_completed_packet(original);
        }
        #[cfg(feature = "observe")]
        if result.is_err()
            && !matches!(
                result,
                Err(Error::LocalSendTimeout | Error::LocalSendFailed)
            )
            && let Some(ticket) = exchange.observer
        {
            self.remove_observer(ticket);
        }
        #[cfg(feature = "observe")]
        if let Some(ticket) = exchange.observer
            && let Some(observer) = self.observers.iter_mut().find(|o| o.ticket == ticket)
        {
            observer.pending = false;
        }
        #[cfg(feature = "observe")]
        if let Some(refresh) = exchange.refresh {
            self.drop_exchange_sends(exchange.target.remote, refresh.mid);
            self.release(refresh.binding);
            self.release_completed_packet(refresh.packet);
        }
        self.release(exchange.binding);
        if let Some((slot, generation)) = exchange.slot {
            self.shared.complete(slot, generation, result);
        } else {
            #[cfg(feature = "server")]
            self.shared.complete_response(
                exchange.target.remote,
                exchange.mid,
                false,
                result.map(|_| ()),
            );
        }
    }
    /// Processes one incoming whole datagram without depending on a runtime.
    /// Per-message failures are discarded and counted without stopping the driver.
    /// Manual drivers should use [`SendWindow::receive`] so synchronous
    /// application and crypto preparation do not consume newly queued send budgets.
    pub fn receive<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        bytes: &[u8],
        metadata: Metadata,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        self.poll_resources(
            now,
            application,
            policy,
            &mut TaskContext::from_waker(Waker::noop()),
        )?;
        let result = self.receive_one(bytes, metadata, now, application, policy);
        if let Err(error) = result {
            self.drop_message(error);
        }
        Ok(())
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn receive_one<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        bytes: &[u8],
        metadata: Metadata,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        if metadata.original_len > DATAGRAM_BYTES || metadata.original_len != bytes.len() {
            self.counters.oversized += 1;
            return Ok(());
        }
        let multicast = metadata.local.is_multicast();
        let message = match MessageView::parse(bytes) {
            Ok(m) => m,
            Err(_) => {
                if !multicast
                    && bytes.len() >= 4
                    && bytes[0] >> 6 == 1
                    && (bytes[0] >> 4) & 3 == 0
                    && self.charge_response_budget(metadata.remote.ip(), now)
                {
                    return self.control(
                        metadata,
                        MessageType::Reset,
                        u16::from_be_bytes([bytes[2], bytes[3]]),
                        now,
                    );
                }
                return Ok(());
            }
        };
        let ty = message.message_type();
        if multicast {
            #[cfg(feature = "multicast")]
            if Mode::SERVE {
                return self.receive_multicast(message, metadata, now, application, policy);
            }
            return Ok(());
        }
        if matches!(ty, MessageType::Acknowledgement | MessageType::Reset)
            && self.receive_acknowledgement(message, metadata)?
        {
            return Ok(());
        }
        if message.code().is_response() {
            if Mode::INITIATE {
                return self.receive_response(message, metadata, now, application);
            }
            if ty == MessageType::Confirmable
                && self.charge_response_budget(metadata.remote.ip(), now)
            {
                self.control(metadata, MessageType::Reset, message.message_id(), now)?;
            }
            return Ok(());
        }
        if message.code() == Code::EMPTY {
            if ty == MessageType::Confirmable
                && self.charge_response_budget(metadata.remote.ip(), now)
            {
                self.control(metadata, MessageType::Reset, message.message_id(), now)?;
            }
            return Ok(());
        }
        if !message.code().is_request()
            || !matches!(ty, MessageType::Confirmable | MessageType::NonConfirmable)
        {
            return Ok(());
        }
        if !Mode::SERVE {
            if ty == MessageType::Confirmable
                && self.charge_response_budget(metadata.remote.ip(), now)
            {
                if self
                    .duplicates
                    .lookup(metadata.remote, metadata.local, message.message_id(), now)
                    .is_some()
                {
                    self.counters.duplicates += 1;
                    return self.replay_cached(metadata, message, now);
                }
                let reset = empty_message(MessageType::Reset, message.message_id());
                self.control(metadata, MessageType::Reset, message.message_id(), now)?;
                self.remember(message, metadata, CachedReply::inline(&reset)?, now)?;
            }
            return Ok(());
        }
        if self.outgoing.is_full() || ty == MessageType::NonConfirmable && !self.ids.available(now)
        {
            return Err(Error::Capacity);
        }
        if message.option(OptionNumber::OSCORE).is_none()
            && !self.charge_response_budget(metadata.remote.ip(), now)
        {
            return Ok(());
        }
        if self
            .duplicates
            .lookup(metadata.remote, metadata.local, message.message_id(), now)
            .is_some()
        {
            self.counters.duplicates += 1;
            if ty == MessageType::Confirmable {
                self.replay_cached(metadata, message, now)?;
            }
            return Ok(());
        }
        self.with_packet(
            Some((metadata.remote, metadata.local)),
            now,
            |this, reservation| {
                this.receive_request(message, metadata, now, application, policy, reservation)
            },
        )
    }
    // Empty-ACK completion owns a Reply; requests must not reserve its packet storage.
    #[inline(never)]
    fn receive_acknowledgement(
        &mut self,
        message: MessageView<'_>,
        metadata: Metadata,
    ) -> Result<bool, Error> {
        let ty = message.message_type();
        if let Some(i) = self.exchanges.iter().position(|e| {
            crate::transport::same_peer(e.target.remote, metadata.remote)
                && e.mid == message.message_id()
        }) {
            if ty == MessageType::Reset {
                self.finish(i, Err(Error::Reset));
                return Ok(true);
            }
            // Dropped Observe cancellations lose their slot but retain the client request.
            let response = self.exchanges[i].slot.is_none() && self.exchanges[i].original.is_none();
            if message.code() == Code::EMPTY || response {
                if self.exchanges[i].slot.is_none() {
                    self.finish(
                        i,
                        Ok(Reply {
                            remote: metadata.remote,
                            packet: Packet::copy_from(message.as_bytes())?,
                        }),
                    );
                    return Ok(true);
                }
                self.stop_retransmission(i);
                return Ok(true);
            }
        } else {
            #[cfg(feature = "observe")]
            if ty == MessageType::Reset {
                self.reset_notification(metadata.remote, message.message_id());
            }
            return Ok(true);
        }
        Ok(false)
    }
    // Response decoding and handshake retries do not share the request call chain.
    #[inline(never)]
    fn receive_response<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        message: MessageView<'_>,
        metadata: Metadata,
        now: Instant,
        application: &mut A,
    ) -> Result<(), Error> {
        let ty = message.message_type();
        if ty == MessageType::Confirmable && self.outgoing.is_full() {
            return Err(Error::Capacity);
        }
        if self
            .duplicates
            .lookup(metadata.remote, metadata.local, message.message_id(), now)
            .is_some()
        {
            self.counters.duplicates += 1;
            if ty == MessageType::Confirmable {
                self.replay_cached(metadata, message, now)?;
            }
            return Ok(());
        }
        // Make the zero-capacity case constant so LLVM drops initiator code and scratch.
        let matched = if OUTBOUND == 0 {
            None
        } else {
            self.exchanges.iter().position(|e| {
                (crate::transport::same_peer(e.target.remote, metadata.remote) || {
                    #[cfg(feature = "multicast")]
                    {
                        e.collection.is_some()
                            && ty == MessageType::NonConfirmable
                            && e.target.remote.port() == metadata.remote.port()
                            && e.target.remote.is_ipv4() == metadata.remote.is_ipv4()
                    }
                    #[cfg(not(feature = "multicast"))]
                    {
                        false
                    }
                }) && e.token.as_slice() == message.token()
                    && (ty != MessageType::Acknowledgement || e.mid == message.message_id())
            })
        };
        let Some(index) = matched else {
            if ty == MessageType::Confirmable {
                self.control(metadata, MessageType::Reset, message.message_id(), now)?;
            }
            return Ok(());
        };
        let handshaking = self.exchanges[index].handshaking;
        let recovering = self.exchanges[index].binding.is_some()
            && message.option(OptionNumber::OSCORE).is_none()
            && message.code() == Code::UNAUTHORIZED
            && !self.exchanges[index].recovered
            && self.exchanges[index].target.recover;
        if handshaking || recovering {
            return self.receive_continuation(index, message, metadata, now);
        }
        self.receive_application_response(index, message, metadata, now, application)
    }
    // Keep continuation output and application-response scratch in separate frames.
    #[inline(never)]
    fn receive_continuation(
        &mut self,
        index: usize,
        message: MessageView<'_>,
        metadata: Metadata,
        now: Instant,
    ) -> Result<(), Error> {
        let ty = message.message_type();
        let handshaking = self.exchanges[index].handshaking;
        let descriptors = 1 + usize::from(ty == MessageType::Confirmable);
        if SEND_QUEUE < descriptors {
            self.finish(index, Err(Error::Capacity));
            return Err(Error::Capacity);
        }
        if self.outgoing.len().saturating_add(descriptors) > SEND_QUEUE || !self.ids.available(now)
        {
            return Err(Error::Capacity);
        }
        // Reuse uniquely owned retry storage so two-slot profiles need no
        // third buffer. Otherwise reserve before ACKs or protection state change.
        let reservation = if self.exchanges[index]
            .packet
            .as_ref()
            .is_some_and(|packet| self.pool.reference_count(packet) == 1)
        {
            self.exchanges[index].packet.take().ok_or(Error::Malformed)
        } else {
            self.reserve_packet(None, now)
        };
        let reservation = match reservation {
            Ok(packet) => packet,
            Err(Error::Capacity) => return Err(Error::Capacity),
            Err(error) => {
                self.finish(index, Err(error));
                return Err(error);
            }
        };
        self.storage_available();
        self.stop_retransmission(index);
        let result = (|| {
            if ty == MessageType::Confirmable {
                self.acknowledge(message, metadata, now)?;
            }
            if !handshaking {
                let binding = self.exchanges[index].binding.take();
                self.release(binding);
                self.exchanges[index].recovered = true;
            }
            let original = self.exchanges[index]
                .original
                .as_ref()
                .and_then(|packet| self.pool.get(packet))
                .ok_or(Error::Malformed)?;
            let original = MessageView::parse(original)?;
            let mut output = [0; DATAGRAM_BYTES];
            let target = self.exchanges[index].target;
            let prepared = if handshaking {
                self.protection.handshake_response::<DATAGRAM_BYTES>(
                    target,
                    message,
                    original,
                    now,
                    &mut output,
                )?
            } else {
                self.protection
                    .recover::<DATAGRAM_BYTES>(target, original, now, &mut output)?
            };
            self.continue_exchange(index, prepared, &mut output, now, &reservation)
        })();
        self.pool.release(reservation);
        if let Err(error) = result {
            self.finish(index, Err(error));
            self.drop_message(error);
        }
        Ok(())
    }
    #[inline(never)]
    fn receive_application_response<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        index: usize,
        message: MessageView<'_>,
        metadata: Metadata,
        now: Instant,
        application: &mut A,
    ) -> Result<(), Error> {
        let ty = message.message_type();
        if ty == MessageType::Acknowledgement {
            self.stop_retransmission(index);
        }
        if self.exchanges[index].binding.is_some()
            && message.option(OptionNumber::OSCORE).is_none()
            && matches!(message.code().0 >> 5, 4 | 5)
        {
            if ty == MessageType::Confirmable {
                self.acknowledge(message, metadata, now)?;
            }
            self.counters.unprotected_responses += 1;
            self.probes.answered(metadata.remote);
            self.finish(index, Err(Error::UnprotectedResponse(message.code())));
            return Ok(());
        }
        let mut decoded = [0; DATAGRAM_BYTES];
        let used = if let Some(binding) = self.exchanges[index].binding.as_mut() {
            match self.protection.received_response::<DATAGRAM_BYTES>(
                message,
                binding,
                &mut decoded,
            ) {
                Ok(n) => n,
                Err(_) => {
                    self.counters.protection_failures += 1;
                    return Ok(());
                }
            }
        } else {
            copy(message.as_bytes(), &mut decoded)?
        };
        let inner = MessageView::parse(&decoded[..used])?;
        if !self.exchanges[index].raw
            && let Err(error) =
                inner.check_options(|n| endpoint_option(n) || application.recognizes(n))
        {
            if ty == MessageType::NonConfirmable {
                return Ok(());
            }
            if ty == MessageType::Confirmable {
                self.control(metadata, MessageType::Reset, message.message_id(), now)?;
            }
            self.finish(index, Err(error));
            return Ok(());
        }
        let used = if self.exchanges[index].raw {
            used
        } else {
            MessageView::process_in_place(&mut decoded[..used], |n| {
                endpoint_option(n) || application.recognizes(n)
            })?
        };
        let inner = MessageView::parse(&decoded[..used])?;
        if ty == MessageType::Confirmable {
            self.acknowledge(message, metadata, now)?;
        } else if ty == MessageType::NonConfirmable {
            self.remember(message, metadata, CachedReply::Silent, now)?;
        }
        let result = Ok(Reply {
            remote: metadata.remote,
            packet: Packet::copy_from(inner.as_bytes())?,
        });
        self.probes.answered(metadata.remote);
        if inner.code() == Code::TOO_MANY_REQUESTS {
            let age = inner
                .option(OptionNumber::MAX_AGE)
                .map(|o| o.uint())
                .transpose()?
                .unwrap_or(60);
            let until = self
                .backoff
                .iter()
                .filter(|(peer, _)| crate::transport::same_peer(*peer, metadata.remote))
                .map(|(_, deadline)| *deadline)
                .chain(core::iter::once(now.after(age.saturating_mul(1000))))
                .max()
                .unwrap_or(now);
            self.backoff
                .retain(|(p, t)| !crate::transport::same_peer(*p, metadata.remote) && *t > now);
            if self.backoff.is_full()
                && let Some(index) = self
                    .backoff
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(i, _)| i)
            {
                // Forget one destination's delay rather than applying it to every peer.
                self.backoff.swap_remove(index);
            }
            self.backoff
                .push((metadata.remote, until))
                .map_err(|_| Error::Capacity)?;
        }
        #[cfg(feature = "multicast")]
        if self.client_multicast(index, inner, metadata.remote, inner.as_bytes())? {
            return Ok(());
        }
        #[cfg(feature = "observe")]
        if self.client_notification(index, inner, inner.as_bytes(), now)? {
            return Ok(());
        }
        self.finish(index, result);
        Ok(())
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn receive_request<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        message: MessageView<'_>,
        metadata: Metadata,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let ty = message.message_type();
        let ticket = Ticket(self.next_ticket);
        self.next_ticket = self.next_ticket.checked_add(1).ok_or(Error::Capacity)?;
        // The synchronous callback has exclusive access to the deferred table.
        let deferred_available = self.deferred_available(ty);
        // Keep one arena slot even if the binding closure is outlined.
        let mut response_bytes: [u8; DATAGRAM_BYTES];
        #[cfg(feature = "proxy")]
        {
            response_bytes = [0; DATAGRAM_BYTES];
            let mut response =
                ResponseWriter::new(&mut response_bytes, Code::CONTENT, message.token())?;
            let raw_request = Request {
                message,
                metadata,
                security: SecurityState::Unprotected,
                ticket,
                deferred_available,
                body: message.payload(),
                context: None,
                #[cfg(feature = "server")]
                response_grace_ms: self.parameters.exchange_lifetime(),
            };
            if let Some(result) = application.forward(raw_request, now, &mut response) {
                return match result {
                    Ok(Disposition::Deferred) => self.defer_request(
                        message,
                        metadata,
                        (ticket, response),
                        None,
                        now,
                        reservation,
                    ),
                    Ok(Disposition::Complete) => {
                        self.answer(message, metadata, response, None, now, reservation)
                    }
                    Err(code) => {
                        response.reset(code);
                        self.answer(message, metadata, response, None, now, reservation)
                    }
                };
            }
        }
        let mut decoded = [0; DATAGRAM_BYTES];
        let (used, state, binding) =
            match self
                .protection
                .incoming::<DATAGRAM_BYTES>(message, metadata, &mut decoded)
            {
                Ok(result) => result,
                Err(error) => {
                    if error != Error::Capacity {
                        self.counters.protection_failures += 1;
                    }
                    if message.option(OptionNumber::OSCORE).is_some()
                        && !self.charge_response_budget(metadata.remote.ip(), now)
                    {
                        return Ok(());
                    }
                    #[cfg(not(feature = "proxy"))]
                    {
                        response_bytes = [0; DATAGRAM_BYTES];
                    }
                    let mut response =
                        ResponseWriter::new(&mut response_bytes, Code::CONTENT, message.token())?;
                    let code = match error {
                        #[cfg(feature = "edhoc")]
                        Error::Capacity if message.option(OptionNumber::EDHOC).is_some() => {
                            Code::UNAVAILABLE
                        }
                        #[cfg(feature = "edhoc")]
                        Error::Malformed if message.option(OptionNumber::EDHOC).is_some() => {
                            Code::BAD_REQUEST
                        }
                        Error::BadOption(_) | Error::Malformed => Code::BAD_OPTION,
                        Error::Replay | Error::ContextNotFound => Code::UNAUTHORIZED,
                        _ => Code::BAD_REQUEST,
                    };
                    response.reset(code);
                    let populated = response
                        .uint_option(OptionNumber::MAX_AGE, u64::from(code == Code::UNAVAILABLE));
                    #[cfg(feature = "edhoc")]
                    let populated = populated.and_then(|()| {
                        if error == Error::Edhoc && message.option(OptionNumber::EDHOC).is_some() {
                            response.uint_option(
                                OptionNumber::CONTENT_FORMAT,
                                crate::codec::ContentFormat::EDHOC.0.into(),
                            )?;
                            response.set_payload(&[1, 0x60])?;
                        }
                        Ok(())
                    });
                    if populated.is_err() {
                        response.reset(Code::INTERNAL_ERROR);
                    }
                    return self.answer(message, metadata, response, None, now, reservation);
                }
            };
        #[cfg(not(feature = "proxy"))]
        {
            response_bytes = [0; DATAGRAM_BYTES];
        }
        self.with_binding(binding, |this, binding| {
            let mut arena = ResponseArena::new(&mut response_bytes);
            let protected = protected_response(binding.is_some(), state);
            let mut response = arena.writer(Code::CONTENT, message.token(), protected)?;
            let inner = MessageView::parse(decoded.get(..used).ok_or(Error::Malformed)?)?;
            if inner
                .check_options(|n| endpoint_option(n) || application.recognizes(n))
                .is_err()
            {
                if ty == MessageType::NonConfirmable {
                    this.remember(message, metadata, CachedReply::Silent, now)?;
                    return Ok(());
                }
                response.reset(Code::BAD_OPTION);
                return this.answer(
                    message,
                    metadata,
                    response,
                    binding.take(),
                    now,
                    reservation,
                );
            }
            let used = MessageView::process_in_place(&mut decoded[..used], |n| {
                endpoint_option(n) || application.recognizes(n)
            })?;
            let inner = MessageView::parse(decoded.get(..used).ok_or(Error::Malformed)?)?;

            let control_request = Request {
                message: inner,
                metadata,
                security: state,
                ticket,
                deferred_available,
                body: inner.payload(),
                context: binding.as_ref().and_then(|b| this.protection.generation(b)),
                #[cfg(feature = "server")]
                response_grace_ms: this.parameters.exchange_lifetime(),
            };
            let handled =
                this.protection
                    .control::<DATAGRAM_BYTES>(control_request, now, &mut response);
            #[cfg(feature = "observe")]
            this.cancel_observation(control_request);
            let disposition = if handled.as_ref().is_ok_and(|handled| *handled) {
                Disposition::Complete
            } else if let Err(error) = handled {
                response.reset(if error == Error::Capacity {
                    Code::UNAVAILABLE
                } else {
                    Code::BAD_REQUEST
                });
                Disposition::Complete
            } else if inner.option(OptionNumber::PROXY_URI).is_some()
                || inner.option(OptionNumber::PROXY_SCHEME).is_some()
            {
                response.set_code(Code::PROXY_UNSUPPORTED);
                Disposition::Complete
            } else if !policy.allow(state, inner) {
                response.set_code(if matches!(state, SecurityState::Unprotected) {
                    Code::UNAUTHORIZED
                } else {
                    Code::FORBIDDEN
                });
                Disposition::Complete
            } else {
                this.counters.requests += 1;
                match application.handle(control_request, &mut response) {
                    Ok(d) => d,
                    Err(code) => {
                        response.reset(if code.is_response() {
                            code
                        } else {
                            Code::INTERNAL_ERROR
                        });
                        Disposition::Complete
                    }
                }
            };
            this.release_body_epochs(application);
            if let Some(epoch) = binding.as_ref().and_then(|b| this.protection.generation(b))
                && application.uses_context(epoch)
                && !this.body_epochs.contains(&epoch)
            {
                if this.body_epochs.is_full() || this.protection.pin_epoch(epoch).is_err() {
                    application.abort_context(epoch);
                    response.reset(Code::UNAVAILABLE);
                    response.uint_option(OptionNumber::MAX_AGE, 1)?;
                    return this.answer(
                        message,
                        metadata,
                        response,
                        binding.take(),
                        now,
                        reservation,
                    );
                }
                if let Err(epoch) = this.body_epochs.push(epoch) {
                    this.protection.unpin_epoch(epoch);
                    application.abort_context(epoch);
                    return Err(Error::Capacity);
                }
            }
            if disposition == Disposition::Deferred {
                #[cfg(feature = "server")]
                {
                    this.defer_request(
                        message,
                        metadata,
                        (ticket, response),
                        binding.take(),
                        now,
                        reservation,
                    )
                }
                #[cfg(not(feature = "server"))]
                {
                    response.reset(Code::UNAVAILABLE);
                    this.answer(
                        message,
                        metadata,
                        response,
                        binding.take(),
                        now,
                        reservation,
                    )
                }
            } else {
                #[cfg(feature = "observe")]
                if inner
                    .option(OptionNumber::OBSERVE)
                    .is_some_and(|o| o.uint() == Ok(0))
                    && matches!(inner.code(), Code::GET | Code::FETCH)
                    && response.code().is_success()
                    && policy.allow(state, inner)
                    && let Some(settings) = application.observable(inner)
                {
                    return this.register_observer(
                        control_request,
                        message,
                        response,
                        binding.take(),
                        settings,
                        (now, reservation),
                    );
                }
                this.answer(
                    message,
                    metadata,
                    response,
                    binding.take(),
                    now,
                    reservation,
                )
            }
        })
    }
    #[cfg(feature = "server")]
    fn defer_request(
        &mut self,
        message: MessageView<'_>,
        metadata: Metadata,
        (ticket, mut response): (Ticket, ResponseWriter<'_, DATAGRAM_BYTES>),
        binding: Option<P::Binding>,
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let processing_timeout_ms = response.deferred_timeout_ms;
        self.with_binding(binding, |this, binding| {
            let ty = message.message_type();
            if !this.deferred_available(ty) {
                response.reset(Code::UNAVAILABLE);
                response.uint_option(OptionNumber::MAX_AGE, 1)?;
                return this.answer(
                    message,
                    metadata,
                    response,
                    binding.take(),
                    now,
                    reservation,
                );
            }
            if ty == MessageType::Confirmable {
                this.acknowledge(message, metadata, now)?;
            } else {
                this.remember(message, metadata, CachedReply::Silent, now)?;
            }
            let entry = Deferred {
                ticket,
                metadata,
                token: token(message.token()),
                confirmable: ty == MessageType::Confirmable,
                binding: binding.take(),
                deadline: now.after(processing_timeout_ms.map_or(
                    this.parameters.exchange_lifetime(),
                    |timeout| {
                        timeout
                            .get()
                            .saturating_add(this.parameters.exchange_lifetime())
                    },
                )),
            };
            if let Err(mut entry) = this.deferred.push(entry) {
                *binding = entry.binding.take();
                return Err(Error::Capacity);
            }
            Ok(())
        })
    }
    fn remember(
        &mut self,
        request: MessageView<'_>,
        meta: Metadata,
        reply: CachedReply,
        now: Instant,
    ) -> Result<(), Error> {
        let lifetime = if request.message_type() == MessageType::Confirmable {
            self.parameters.exchange_lifetime()
        } else {
            self.parameters.non_lifetime()
        };
        let pressure = self.duplicates.remember(
            &mut self.pool,
            meta.remote,
            meta.local,
            request.message_id(),
            now.after(lifetime),
            reply,
            now,
        )?;
        self.counters.dedup_record_evictions += u64::from(pressure.record_evicted);
        self.counters.dedup_reply_drops += u64::from(pressure.reply_dropped);
        Ok(())
    }
    fn answer(
        &mut self,
        request: MessageView<'_>,
        meta: Metadata,
        response: ResponseWriter<'_, DATAGRAM_BYTES>,
        mut binding: Option<P::Binding>,
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let result = self.answer_retained(request, meta, response, &mut binding, now, reservation);
        self.release(binding);
        result.map(|_| ())
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn answer_retained(
        &mut self,
        request: MessageView<'_>,
        meta: Metadata,
        response: ResponseWriter<'_, DATAGRAM_BYTES>,
        binding: &mut Option<P::Binding>,
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<bool, Error> {
        let ty = if request.message_type() == MessageType::Confirmable {
            MessageType::Acknowledgement
        } else {
            MessageType::NonConfirmable
        };
        let (mid, queued_mid) = if ty == MessageType::Acknowledgement {
            (request.message_id(), QueuedMid::Peer)
        } else {
            let mid = self.allocate_mid(self.parameters, now)?;
            (mid, QueuedMid::Local(mid))
        };
        let protection = &mut self.protection;
        let (n, success) = self.pool.encode(reservation, |wire| {
            let (n, success) = Self::serialize_response(
                protection,
                response,
                ty,
                mid,
                request.token(),
                binding,
                wire,
            )?;
            Ok((n, (n, success)))
        })?;
        let mut inline = [0; 4];
        if n <= inline.len() {
            inline[..n].copy_from_slice(self.pool.get(reservation).ok_or(Error::Cancelled)?);
        }
        let reply = if n <= 4 {
            self.queue_inline(
                meta.remote,
                Some(meta.local),
                meta.interface,
                &inline[..n],
                queued_mid,
                now,
            )?;
            if ty == MessageType::Acknowledgement {
                CachedReply::inline(&inline[..n])?
            } else {
                CachedReply::Silent
            }
        } else {
            let packet = self.queue_reserved(
                reservation,
                meta.remote,
                Some(meta.local),
                meta.interface,
                queued_mid,
                now,
            )?;
            if ty == MessageType::Acknowledgement {
                CachedReply::Full(packet)
            } else {
                self.pool.release(packet);
                CachedReply::Silent
            }
        };
        self.remember(request, meta, reply, now)?;
        Ok(success)
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn serialize_response(
        protection: &mut P,
        response: ResponseWriter<'_, DATAGRAM_BYTES>,
        ty: MessageType,
        mid: u16,
        token: &[u8],
        binding: &mut Option<P::Binding>,
        wire: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        let success = response.code().is_success();
        if let Ok(plain) = response.finish_bytes(ty, mid) {
            if let Some(binding) = binding.as_mut() {
                match protection.response::<DATAGRAM_BYTES>(
                    MessageView::parse(plain)?,
                    binding,
                    wire,
                ) {
                    Ok(n) => return Ok((n, success)),
                    Err(Error::Capacity) => {}
                    Err(error) => return Err(error),
                }
            } else {
                return Ok((copy(plain, wire)?, success));
            }
        }
        let mut fallback = [0; 12];
        let n =
            MessageBuilder::new(&mut fallback, ty, Code::INTERNAL_ERROR, mid, token)?.finish(&[])?;
        let n = if let Some(binding) = binding.as_mut() {
            protection.response::<DATAGRAM_BYTES>(
                MessageView::parse(&fallback[..n])?,
                binding,
                wire,
            )?
        } else {
            copy(&fallback[..n], wire)?
        };
        Ok((n, false))
    }
    /// Advances deadlines and drains eligible cross-task commands.
    /// For completion-based send budgets, use the corresponding [`SendWindow`]
    /// method through [`Self::with_send_window`].
    pub fn poll(&mut self, now: Instant) -> Result<(), Error> {
        self.expire_outgoing(now);
        if self.storage_deadline().is_some_and(|retry| retry <= now) {
            self.storage_retry = None;
        }
        self.expire_cached_packets(now);
        #[cfg(feature = "multicast")]
        if let Err(error) = self.poll_multicast(now) {
            self.drop_message(error);
        }
        self.protection.expire(now);
        let mut i = 0;
        while i < self.exchanges.len() {
            let stopping = self.exchanges[i]
                .slot
                .is_some_and(|(slot, generation)| self.shared.cancelled(slot, generation));
            #[cfg(feature = "observe")]
            let stopping = stopping || Mode::INITIATE && self.deregistration_due(i);
            if stopping {
                #[cfg(feature = "observe")]
                if Mode::INITIATE && self.exchanges[i].observation.is_some() {
                    if !self.observation_ready(i, now) {
                        i += 1;
                        continue;
                    }
                    if self.refresh_observation(i, true, now).is_ok() {
                        i += 1;
                        continue;
                    }
                }
                self.finish(i, Err(Error::Cancelled));
                continue;
            }
            if now >= self.exchanges[i].deadline {
                #[cfg(feature = "observe")]
                if Mode::INITIATE
                    && self.exchanges[i].retry.is_none()
                    && self.exchanges[i]
                        .observation
                        .is_some_and(|o| o.established())
                {
                    if !self.observation_ready(i, now) {
                        i += 1;
                        continue;
                    }
                    match self.refresh_observation(i, false, now) {
                        Ok(()) => {
                            i += 1;
                        }
                        Err(error) => self.finish(i, Err(error)),
                    }
                    continue;
                }
                self.finish(i, Err(Error::Timeout));
                continue;
            }
            let exchange = &self.exchanges[i];
            let queued = self.outgoing.iter().any(|q| {
                q.mid.owner() == Some(exchange.mid)
                    && crate::transport::same_peer(q.remote, exchange.target.remote)
            });
            #[cfg(feature = "observe")]
            let queued = queued || exchange.refresh.is_some();
            if !self.outgoing.is_full()
                && !queued
                && let Some(retry) = self.exchanges[i].retry.as_mut()
            {
                match retry.poll(now) {
                    Ok(true) => {
                        if now > retry.last_send_at(self.exchanges[i].target.parameters) {
                            self.exchanges[i].retry.as_mut().unwrap().skipped(now);
                            i += 1;
                            continue;
                        }
                        let exchange = &self.exchanges[i];
                        let packet = self
                            .pool
                            .retain(exchange.packet.as_ref().ok_or(Error::Malformed)?)?;
                        let (remote, local, interface, mid) = (
                            exchange.target.remote,
                            exchange.target.source,
                            exchange.target.interface,
                            exchange.mid,
                        );
                        if let Err(error) = self.queue_ref(
                            remote,
                            local,
                            interface,
                            packet,
                            QueuedMid::Owned(mid),
                            now,
                        ) {
                            self.drop_message(error);
                            i += 1;
                            continue;
                        }
                    }
                    Err(error) => {
                        self.finish(i, Err(error));
                        continue;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        #[cfg(feature = "server")]
        if Mode::SERVE && DEFERRED != 0 {
            self.expire_deferred(now);
        }
        for slot in 0..COMMANDS {
            let Some((generation, admission)) = self.shared.pending(slot) else {
                continue;
            };
            // Extension callbacks run without borrowing Shared or holding its critical section.
            #[cfg(feature = "client")]
            let mut retained = false;
            let ready = match admission {
                #[cfg(feature = "client")]
                Admission::Rejected(error) => Err(error),
                #[cfg(feature = "client")]
                Admission::Request(request) => {
                    if Mode::INITIATE {
                        self.request_ready(request, now).map(|ready| {
                            retained = ready.unwrap_or(false);
                            ready.is_some()
                        })
                    } else {
                        Err(Error::RoleDisabled)
                    }
                }
                #[cfg(feature = "server")]
                Admission::Respond(ticket) => {
                    if !Mode::SERVE {
                        Err(Error::RoleDisabled)
                    } else if let Some(entry) =
                        self.deferred.iter().find(|entry| entry.ticket == ticket)
                    {
                        Ok(!self.outgoing.is_full()
                            && self.ids.available(now)
                            && self.packet_capacity() > 0
                            && (!entry.confirmable
                                || (!self.exchanges.is_full()
                                    && self.credits_used(entry.metadata.remote)
                                        < self.parameters.nstart)))
                    } else {
                        Err(Error::Cancelled)
                    }
                }
            };
            if ready == Ok(false) {
                continue;
            }
            if let Err(error) = ready {
                if self.shared.claim(slot, generation).is_some() {
                    self.shared.complete(slot, generation, Err(error));
                }
                continue;
            }
            if !self.storage_ready(now) {
                continue;
            }
            let result = self.command(
                slot,
                generation,
                #[cfg(feature = "client")]
                retained,
                now,
            );
            if let Err(error) = result
                && error != Error::Capacity
                && self.shared.claim(slot, generation).is_some()
            {
                self.shared.complete(slot, generation, Err(error));
            }
        }
        self.shared.lock(|s| {
            for slot in &mut s.slots {
                if slot.cancelled && !slot.active {
                    slot.cancelled = false;
                }
            }
        });
        Ok(())
    }
    fn packet_capacity(&self) -> usize {
        self.pool.available() + self.duplicates.reclaimable_replies(&self.pool)
    }
    #[cfg(feature = "client")]
    // None waits; Some carries the original-request retention decision.
    fn request_ready(
        &self,
        request: RequestAdmission,
        now: Instant,
    ) -> Result<Option<bool>, Error> {
        let retained = !request.raw
            && (request.observe || self.protection.requires_request_retention(request.target));
        let needed = 1 + usize::from(retained);
        if OUTBOUND == 0 || needed > PACKETS {
            return Err(Error::Capacity);
        }
        if self.outgoing.is_full() || !self.ids.available(now) || self.packet_capacity() < needed {
            return Ok(None);
        }
        let target = request.target;
        if self.exchanges.is_full()
            || self.credits_used(target.remote) >= target.parameters.nstart
            || !self.destination_ready(target.remote, now)
            || request.non_confirmable
                && !target.remote.ip().is_multicast()
                && (!self.probes.allowed(target.remote, now)
                    || self.exchanges.iter().any(|e| {
                        !e.accepted
                            && e.retry.is_none()
                            && crate::transport::same_peer(e.target.remote, target.remote)
                    }))
        {
            return if request.wait {
                Ok(None)
            } else {
                Err(Error::Capacity)
            };
        }
        Ok(Some(retained))
    }
    fn command(
        &mut self,
        slot: usize,
        generation: u64,
        #[cfg(feature = "client")] retained: bool,
        now: Instant,
    ) -> Result<(), Error> {
        // Claim only after every backing allocation succeeds. Neither command
        // ownership nor protocol state may be consumed by transient exhaustion.
        self.with_packet(None, now, |this, reservation| {
            #[cfg(feature = "client")]
            let original = if retained {
                Some(this.reserve_packet(None, now)?)
            } else {
                None
            };
            this.storage_available();
            if let Some(command) = this.shared.claim(slot, generation) {
                let result = this.command_reserved(
                    (slot, generation),
                    command,
                    now,
                    reservation,
                    #[cfg(feature = "client")]
                    original.as_ref(),
                );
                if let Err(error) = result {
                    this.shared.complete(slot, generation, Err(error));
                }
            }
            #[cfg(feature = "client")]
            if let Some(original) = original {
                this.pool.release(original);
            }
            Ok(())
        })
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn command_reserved(
        &mut self,
        (slot, generation): (usize, u64),
        command: Command<DATAGRAM_BYTES>,
        now: Instant,
        reservation: &PacketRef,
        #[cfg(feature = "client")] original: Option<&PacketRef>,
    ) -> Result<(), Error> {
        match command {
            #[cfg(feature = "client")]
            Command::Request {
                target,
                mut packet,
                token_len,
                raw,
                #[cfg(feature = "multicast")]
                collect_until,
                ..
            } => {
                if !Mode::INITIATE {
                    return Err(Error::RoleDisabled);
                }
                self.command_request(
                    (slot, generation),
                    target,
                    &mut packet,
                    token_len,
                    raw,
                    #[cfg(feature = "multicast")]
                    collect_until,
                    now,
                    reservation,
                    original,
                )
            }
            #[cfg(feature = "server")]
            Command::Respond {
                ticket,
                packet,
                queued,
            } => {
                if Mode::SERVE {
                    self.command_respond(
                        (slot, generation),
                        ticket,
                        packet,
                        queued,
                        now,
                        reservation,
                    )
                } else {
                    Err(Error::RoleDisabled)
                }
            }
        }
    }
    #[cfg(feature = "client")]
    // Keep mutually exclusive request/response scratch in separate stack frames.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn command_request(
        &mut self,
        (slot, generation): (usize, u64),
        target: Target,
        packet: &mut Packet<DATAGRAM_BYTES>,
        token_len: u8,
        raw: bool,
        #[cfg(feature = "multicast")] collect_until: Option<Instant>,
        now: Instant,
        reservation: &PacketRef,
        original: Option<&PacketRef>,
    ) -> Result<(), Error> {
        let remote = target.remote;
        let parameters = target.parameters;
        let (code, ty) = {
            let message = MessageView::parse(packet.as_slice())?;
            (message.code(), message.message_type())
        };
        let mut token = [0; 8];
        self.protection.random(&mut token[..token_len.into()]);
        if self.exchanges.iter().any(|e| {
            crate::transport::same_peer(e.target.remote, remote)
                && e.token.as_slice() == &token[..token_len.into()]
        }) {
            return Err(Error::Capacity);
        }
        let mid = self.allocate_mid(parameters, now)?;
        let token = if code == Code::EMPTY {
            &[][..]
        } else {
            &token[..token_len.into()]
        };
        packet.reheader(ty, mid, token)?;
        let message = MessageView::parse(packet.as_slice())?;
        let retained = original.is_some();
        let mut original = if let Some(original) = original {
            self.pool.write(original, packet.as_slice())?;
            Some(self.pool.retain(original)?)
        } else {
            None
        };
        let mut binding = None;
        let mut stored = None;
        let result = (|| {
            let protection = &mut self.protection;
            let (n, handshaking) = self.pool.encode(reservation, |wire| {
                let prepared = if raw || message.code() == Code::EMPTY {
                    Prepared::Request {
                        length: copy(message.as_bytes(), wire)?,
                        binding: None,
                    }
                } else {
                    protection.outgoing::<DATAGRAM_BYTES>(target, message, wire)?
                };
                let (n, value, handshaking) = prepared.into_parts();
                binding = value;
                Ok((n, (n, handshaking)))
            })?;
            if handshaking && original.is_none() {
                return Err(Error::Malformed);
            }
            if message.message_type() == MessageType::NonConfirmable && !remote.ip().is_multicast()
            {
                self.probes.sent(remote, n, parameters.probing_rate, now)?;
            }
            let random = self.random_u32();
            let retry = (message.message_type() == MessageType::Confirmable)
                .then(|| Retransmission::pending(parameters, random));
            stored = Some(self.queue_reserved(
                reservation,
                remote,
                target.source,
                target.interface,
                QueuedMid::Owned(mid),
                now,
            )?);
            let packet = if retry.is_some() { stored.take() } else { None };
            let exchange = Exchange {
                slot: Some((slot, generation)),
                target: Target {
                    recover: target.recover && retained,
                    ..target
                },
                mid,
                token: self::token(token),
                packet,
                retry,
                deadline: {
                    #[cfg(feature = "multicast")]
                    {
                        collect_until.unwrap_or(self.send_policy.unsent_deadline(now, parameters))
                    }
                    #[cfg(not(feature = "multicast"))]
                    {
                        self.send_policy.unsent_deadline(now, parameters)
                    }
                },
                binding: binding.take(),
                original: original.take(),
                handshaking,
                recovered: false,
                raw,
                credit: !remote.ip().is_multicast(),
                accepted: false,
                #[cfg(feature = "observe")]
                refresh: None,
                #[cfg(feature = "multicast")]
                collection: collect_until,
                #[cfg(feature = "observe")]
                observation: message
                    .option(OptionNumber::OBSERVE)
                    .filter(|o| o.uint() == Ok(0))
                    .map(|_| crate::observe::Ordering::default()),
                #[cfg(feature = "observe")]
                observer: None,
            };
            if let Err(mut exchange) = self.exchanges.push(exchange) {
                binding = exchange.binding.take();
                original = exchange.original.take();
                if let Some(packet) = exchange.packet.take() {
                    self.pool.release(packet);
                }
                self.drop_exchange_sends(remote, mid);
                return Err(Error::Capacity);
            }
            Ok(())
        })();
        if let Some(packet) = original {
            self.pool.release(packet);
        }
        if let Some(packet) = stored {
            self.pool.release(packet);
        }
        self.release(binding);
        result
    }
    // Server-initiated CON: a deferred response or notification, with no retained request.
    #[cfg(any(feature = "server", feature = "observe"))]
    fn server_exchange(
        &mut self,
        metadata: Metadata,
        mid: u16,
        token: Token,
        packet: Option<PacketRef>,
        binding: Option<P::Binding>,
        now: Instant,
    ) -> Exchange<P::Binding> {
        Exchange {
            slot: None,
            target: Target {
                remote: metadata.remote,
                peer: None,
                combined_edhoc: false,
                recover: false,
                source: Some(metadata.local),
                interface: metadata.interface,
                parameters: self.parameters,
            },
            mid,
            token,
            packet,
            retry: Some(Retransmission::pending(self.parameters, self.random_u32())),
            deadline: self.send_policy.unsent_deadline(now, self.parameters),
            binding,
            original: None,
            handshaking: false,
            recovered: false,
            raw: false,
            credit: true,
            accepted: false,
            #[cfg(feature = "observe")]
            refresh: None,
            #[cfg(feature = "multicast")]
            collection: None,
            #[cfg(feature = "observe")]
            observation: None,
            #[cfg(feature = "observe")]
            observer: None,
        }
    }
    #[cfg(feature = "server")]
    // Keep mutually exclusive request/response scratch in separate stack frames.
    #[inline(never)]
    fn command_respond(
        &mut self,
        (slot, generation): (usize, u64),
        ticket: Ticket,
        mut packet: Packet<DATAGRAM_BYTES>,
        queued: bool,
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let i = self
            .deferred
            .iter()
            .position(|e| e.ticket == ticket)
            .ok_or(Error::Cancelled)?;
        if self.exchanges.is_full() && self.deferred[i].confirmable {
            return Err(Error::Capacity);
        }
        let mut entry = self.deferred.swap_remove(i);
        let mut stored = None;
        let result = (|| {
            let ty = if entry.confirmable {
                MessageType::Confirmable
            } else {
                MessageType::NonConfirmable
            };
            let mid = self.allocate_mid(self.parameters, now)?;
            packet.reheader(ty, mid, &entry.token)?;
            let protection = &mut self.protection;
            self.pool.encode(reservation, |wire| {
                let n = if let Some(binding) = entry.binding.as_mut() {
                    protection.response::<DATAGRAM_BYTES>(
                        MessageView::parse(packet.as_slice())?,
                        binding,
                        wire,
                    )?
                } else {
                    copy(packet.as_slice(), wire)?
                };
                Ok((n, ()))
            })?;
            stored = Some(self.queue_reserved(
                reservation,
                entry.metadata.remote,
                Some(entry.metadata.local),
                entry.metadata.interface,
                QueuedMid::Owned(mid),
                now,
            )?);
            let exchange_index = self.exchanges.len();
            if ty == MessageType::Confirmable {
                let exchange = self.server_exchange(
                    entry.metadata,
                    mid,
                    entry.token.clone(),
                    stored.take(),
                    entry.binding.take(),
                    now,
                );
                if let Err(mut exchange) = self.exchanges.push(exchange) {
                    entry.binding = exchange.binding.take();
                    if let Some(packet) = exchange.packet.take() {
                        self.pool.release(packet);
                    }
                    self.drop_exchange_sends(entry.metadata.remote, mid);
                    return Err(Error::Capacity);
                }
            }
            if !self.shared.response_handoff(
                (slot, generation),
                entry.metadata.remote,
                mid,
                ty == MessageType::Confirmable,
                queued,
            ) {
                // No transport poll can observe the queue before handoff commits.
                if ty == MessageType::Confirmable {
                    let mut exchange = self.exchanges.swap_remove(exchange_index);
                    entry.binding = exchange.binding.take();
                    stored = exchange.packet.take();
                }
                self.drop_exchange_sends(entry.metadata.remote, mid);
                return Err(Error::Cancelled);
            }
            self.release(entry.binding.take());
            Ok(())
        })();
        if let Some(packet) = stored {
            self.pool.release(packet);
        }
        if result.is_err()
            && let Err(entry) = self.deferred.push(entry)
        {
            self.release(entry.binding);
        }
        result
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn continue_exchange(
        &mut self,
        index: usize,
        prepared: Prepared<P::Binding>,
        bytes: &mut [u8],
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let (length, mut binding, handshaking) = prepared.into_parts();
        let result = (|| {
            let parameters = self.exchanges[index].target.parameters;
            let mid = self.allocate_mid(parameters, now)?;
            let mut token = [0; 8];
            self.protection.random(&mut token);
            let n = crate::codec::reheader(bytes, length, MessageType::Confirmable, mid, &token)?;
            let random = self.random_u32();
            let remote = self.exchanges[index].target.remote;
            self.pool.write(reservation, &bytes[..n])?;
            let stored = self.queue_reserved(
                reservation,
                remote,
                self.exchanges[index].target.source,
                self.exchanges[index].target.interface,
                QueuedMid::Owned(mid),
                now,
            )?;
            let old_mid = self.exchanges[index].mid;
            self.drop_exchange_sends(remote, old_mid);
            let old = self.exchanges[index].binding.take();
            self.release(old);
            if let Some(packet) = self.exchanges[index].packet.take() {
                self.pool.release(packet);
            }
            let exchange = &mut self.exchanges[index];
            exchange.accepted = false;
            exchange.mid = mid;
            exchange.token = self::token(&token);
            exchange.packet = Some(stored);
            exchange.retry = Some(Retransmission::pending(parameters, random));
            exchange.binding = binding.take();
            exchange.handshaking = handshaking;
            exchange.credit = true;
            exchange.deadline = self.send_policy.unsent_deadline(now, parameters);
            Ok(())
        })();
        self.release(binding);
        result
    }
    #[cfg(not(feature = "observe"))]
    fn observe_deadlines(&self) -> core::iter::Empty<Instant> {
        core::iter::empty()
    }
    /// Next driver wakeup: the earliest future deadline, or a distant idle wakeup.
    /// Returns `now` for due send expiry/retries, storage retries or ready observation work.
    /// Call outside producer windows, using current time. Explicit collection
    /// deadlines and accepted retransmission spans bound queued sends.
    pub fn deadline(&self, now: Instant) -> Instant {
        let send_deadline = self
            .outgoing
            .iter()
            .map(|q| self.send_expires(q))
            .chain(self.send_retry.filter(|_| !self.outgoing.is_empty()))
            .min();
        if send_deadline.is_some_and(|deadline| deadline <= now) {
            return now;
        }
        if self.storage_deadline().is_some_and(|retry| retry <= now) {
            return now;
        }
        #[cfg(feature = "observe")]
        if self.observation_due(now) {
            return now;
        }
        self.exchanges
            .iter()
            .map(|e| e.retry.map_or(e.deadline, |r| r.deadline().min(e.deadline)))
            .chain(self.deferred_deadlines())
            .chain(self.storage_deadline())
            .chain(send_deadline)
            .chain(self.protection.deadline())
            .chain(self.observe_deadlines())
            .chain(self.multicast_deadlines())
            .chain(self.probes.deadlines(now))
            .chain(self.ids.reusable_at())
            .chain(self.backoff.iter().map(|(_, t)| *t))
            .filter(|deadline| *deadline > now)
            .min()
            .unwrap_or(now.after(86_400_000))
    }
    // Keep datagram-sized removal temporaries out of the driver poll frame.
    #[cfg(feature = "server")]
    #[inline(never)]
    fn expire_deferred(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.deferred.len() {
            if now >= self.deferred[i].deadline {
                let binding = self.deferred[i].binding.take();
                self.deferred.swap_remove(i);
                self.release(binding);
            } else {
                i += 1;
            }
        }
    }
    fn deferred_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        #[cfg(feature = "server")]
        {
            self.deferred.iter().map(|e| e.deadline)
        }
        #[cfg(not(feature = "server"))]
        {
            core::iter::empty()
        }
    }
    #[cfg(not(feature = "multicast"))]
    fn multicast_deadlines(&self) -> core::iter::Empty<Instant> {
        core::iter::empty()
    }
    /// Drives socket I/O, timers and cross-task commands without spawning tasks.
    pub async fn run<T: Transport, C: Clock, A: Application<DATAGRAM_BYTES>>(
        &mut self,
        transport: &mut T,
        clock: &C,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), RunError<T::Error>> {
        let (receiver, transmitter) = transport.split();
        let result = self
            .run_loop(
                receiver,
                transmitter,
                clock,
                application,
                policy,
                BorrowedSender,
            )
            .await;
        #[cfg(feature = "shared-counters")]
        self.publish_counters();
        result
    }
    /// Drives socket I/O, transferring uniquely owned network buffers on acceptance.
    /// Retained packets use the copying path. Cancellation preserves queued bytes.
    pub async fn run_owned<'t, T: Transport, C: Clock, A: Application<DATAGRAM_BYTES>>(
        &mut self,
        transport: &'t mut T,
        clock: &C,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), RunError<T::Error>>
    where
        S: OwnedPacketStorage<DATAGRAM_BYTES, PACKETS>,
        T::Sender<'t>: OwnedDatagramSender<S::Buffer>,
    {
        let (receiver, transmitter) = transport.split();
        let result = self
            .run_loop(
                receiver,
                transmitter,
                clock,
                application,
                policy,
                OwnedSender,
            )
            .await;
        #[cfg(feature = "shared-counters")]
        self.publish_counters();
        result
    }
    /// Attempts the queued head without blocking reception or protocol work.
    /// `Ready(Ok(()))` means one datagram completed; `Pending` preserves the queue.
    /// `Pending` also covers an empty queue or a timed retry and does not guarantee
    /// a registered waker. Custom drivers must arrange command wakeups and re-poll
    /// at [`Self::deadline`] even without a transport wakeup.
    pub fn poll_transmit<T: DatagramSender>(
        &mut self,
        transport: &mut T,
        now: Instant,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), RunError<T::Error>>> {
        self.poll_transmit_with(transport, now, cx, &BorrowedSender)
    }
    /// As [`Self::poll_transmit`], with ownership transfer for unshared buffers.
    /// `Pending` does not guarantee a registered waker: arrange command wakeups
    /// and re-poll at [`Self::deadline`] even without a transport wakeup.
    pub fn poll_transmit_owned<T: OwnedDatagramSender<S::Buffer>>(
        &mut self,
        transport: &mut T,
        now: Instant,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), RunError<T::Error>>>
    where
        S: OwnedPacketStorage<DATAGRAM_BYTES, PACKETS>,
    {
        self.poll_transmit_with(transport, now, cx, &OwnedSender)
    }
    fn poll_transmit_with<T: DatagramSender>(
        &mut self,
        transport: &mut T,
        now: Instant,
        cx: &mut TaskContext<'_>,
        strategy: &impl PacketSender<T, DATAGRAM_BYTES, PACKETS, S>,
    ) -> Poll<Result<(), RunError<T::Error>>> {
        self.expire_outgoing(now);
        if self.send_retry.is_some_and(|deadline| now < deadline) {
            return Poll::Pending;
        }
        // Consume the due timer before readiness Pending, or deadline() would spin.
        self.send_retry = None;
        let Some(queued) = self.outgoing.front() else {
            return Poll::Pending;
        };
        match strategy.poll_send(transport, &mut self.pool, queued, cx) {
            Poll::Ready(Ok(SendOutcome::Accepted)) => {
                self.complete_outgoing(now);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(SendOutcome::RetryLater)) => {
                self.send_retry = Some(now.after(self.send_backoff_ms));
                self.send_backoff_ms = self
                    .send_backoff_ms
                    .saturating_mul(2)
                    .min(self.send_policy.max_retry_ms);
                Poll::Pending
            }
            Poll::Ready(Err(RunError::Transport(error))) => {
                self.counters.send_failures += 1;
                if T::discard_send_error(&error) {
                    self.reject_outgoing(now, Error::LocalSendFailed);
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Err(RunError::Transport(error)))
                }
            }
            other => other.map(|result| result.map(|_| ())),
        }
    }
    async fn run_loop<
        R: DatagramReceiver,
        T: DatagramSender<Error = R::Error>,
        C: Clock,
        A: Application<DATAGRAM_BYTES>,
    >(
        &mut self,
        mut receiver: R,
        mut transmitter: T,
        clock: &C,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
        sender: impl PacketSender<T, DATAGRAM_BYTES, PACKETS, S>,
    ) -> Result<(), RunError<R::Error>> {
        let mut scratch = R::receive_buffer::<DATAGRAM_BYTES>();
        let mut receive_first = true;
        loop {
            #[cfg(feature = "shared-counters")]
            self.publish_counters();
            poll_fn(|cx| {
                Poll::Ready(self.with_send_window(clock, |window| {
                    window.poll_resources(application, policy, cx)
                }))
            })
            .await
            .map_err(RunError::Protocol)?;
            for _ in 0..COMMANDS.saturating_mul(2).saturating_add(1) {
                let revision = self.shared.lock(|s| s.revision);
                self.with_send_window(clock, |window| window.poll())
                    .map_err(RunError::Protocol)?;
                poll_fn(|cx| {
                    application.poll(clock.now(), cx);
                    Poll::Ready(())
                })
                .await;
                if self.shared.lock(|s| s.revision) == revision {
                    break;
                }
            }
            #[cfg(feature = "shared-counters")]
            self.publish_counters();
            enum Event<T, E> {
                Receive(T),
                Transmit(Result<(), RunError<E>>),
                Wake,
            }
            let shared = self.shared;
            let revision = shared.lock(|s| s.revision);
            let deadline = self
                .deadline(clock.now())
                .min(application.deadline().unwrap_or(Instant(u64::MAX)));
            let event = {
                let mut receive = core::pin::pin!(receiver.receive(scratch.as_mut()));
                let mut wake =
                    core::pin::pin!(race(shared.changed(revision), clock.sleep_until(deadline)));
                poll_fn(|cx| {
                    if receive_first && let Poll::Ready(packet) = receive.as_mut().poll(cx) {
                        return Poll::Ready(Event::Receive(packet));
                    }
                    let previous_retry = self.send_retry;
                    if let Poll::Ready(result) =
                        self.poll_transmit_with(&mut transmitter, clock.now(), cx, &sender)
                    {
                        return Poll::Ready(Event::Transmit(result));
                    }
                    if self.send_retry != previous_retry {
                        return Poll::Ready(Event::Wake);
                    }
                    if !receive_first && let Poll::Ready(packet) = receive.as_mut().poll(cx) {
                        return Poll::Ready(Event::Receive(packet));
                    }
                    // External operations can wake this task without changing our revision.
                    application.poll(clock.now(), cx);
                    if application.deadline().is_some_and(|next| next < deadline) {
                        return Poll::Ready(Event::Wake);
                    }
                    wake.as_mut().poll(cx).map(|()| Event::Wake)
                })
                .await
            };
            receive_first = !receive_first;
            match event {
                Event::Receive(Ok(packet)) => self
                    .with_send_window(clock, |window| {
                        window.receive(packet.bytes(), packet.metadata(), application, policy)
                    })
                    .map_err(RunError::Protocol)?,
                Event::Receive(Err(error)) if R::discard_receive_error(&error) => {
                    self.counters.dropped_messages += 1
                }
                Event::Receive(Err(error)) => return Err(RunError::Transport(error)),
                Event::Transmit(result) => result?,
                Event::Wake => {}
            }
        }
    }
}
/// Races cancellation-safe futures without an executor dependency.
pub(crate) async fn race<A: Future<Output = T>, B: Future<Output = T>, T>(a: A, b: B) -> T {
    let mut a = core::pin::pin!(a);
    let mut b = core::pin::pin!(b);
    poll_fn(|cx| {
        if let Poll::Ready(value) = a.as_mut().poll(cx) {
            return Poll::Ready(value);
        }
        b.as_mut().poll(cx)
    })
    .await
}
fn empty_message(ty: MessageType, mid: u16) -> [u8; 4] {
    let mid = mid.to_be_bytes();
    [0x40 | ((ty as u8) << 4), Code::EMPTY.0, mid[0], mid[1]]
}
fn endpoint_option(number: OptionNumber) -> bool {
    matches!(
        number.0,
        1 | 3 | 4 | 5 | 7 | 8 | 11 | 12 | 14 | 15 | 16 | 17 | 20 | 35 | 39
    ) || cfg!(feature = "block") && matches!(number.0, 23 | 28)
        || cfg!(feature = "block1") && matches!(number.0, 27 | 60 | 292)
        || cfg!(feature = "observe") && number == OptionNumber::OBSERVE
}

#[cfg(all(test, feature = "server"))]
mod response_tests;
#[cfg(all(
    test,
    any(feature = "client", all(feature = "server", feature = "multicast"))
))]
mod tests;
