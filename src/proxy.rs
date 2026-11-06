//! Forwarding of opaque datagrams through the endpoint's bounded client machinery.
use crate::{
    Error, Packet,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    endpoint::{
        Application, Disposition, Handle, Operation, Reply, Request, ResponseOperation,
        ResponseWriter, Ticket,
    },
    messaging::TransmissionParameters,
    rate::{Limiter, Limits},
    time::Instant,
    uri::Uri,
};
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
};

/// Destination authorization and optional hostname resolution. Resolution should
/// consult an application cache; callbacks must not block the endpoint driver.
pub trait Routing {
    /// Explicit forwarding authorization, called before contacting the destination.
    fn allow(&self, requester: SocketAddr, host: &str, port: u16) -> bool;
    /// Resolves an address literal, or a hostname through an application override.
    fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        host.parse::<IpAddr>()
            .ok()
            .map(|ip| SocketAddr::new(ip, port))
    }
    /// Reliability profile for this outgoing destination.
    fn parameters(&self, _: SocketAddr) -> TransmissionParameters {
        TransmissionParameters::default()
    }
}
/// Safe default: proxy requests are denied until a routing policy is supplied.
pub struct Deny;
impl Routing for Deny {
    fn allow(&self, _: SocketAddr, _: &str, _: u16) -> bool {
        false
    }
}
#[allow(
    clippy::large_enum_variant,
    reason = "forwarding slots own one bounded serialized reply"
)]
enum State<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize, const OUTBOUND_COMMANDS: usize> {
    Waiting(Operation<'a, DATAGRAM_BYTES, OUTBOUND_COMMANDS>),
    Ready(Packet<DATAGRAM_BYTES>),
    Sending(
        ResponseOperation<'a, DATAGRAM_BYTES, COMMANDS>,
        Packet<DATAGRAM_BYTES>,
    ),
}
struct Forward<
    'a,
    const DATAGRAM_BYTES: usize,
    const COMMANDS: usize,
    const OUTBOUND_COMMANDS: usize,
> {
    ticket: Ticket,
    state: Option<State<'a, DATAGRAM_BYTES, COMMANDS, OUTBOUND_COMMANDS>>,
    deadline: Instant,
}
/// Application wrapper forwarding up to eight requests by default. It retains no
/// cache and never decrypts or reassembles payloads. Proxy Observe is unsupported.
pub struct ForwardProxy<
    'a,
    A,
    R,
    const DATAGRAM_BYTES: usize = 1152,
    const COMMANDS: usize = 8,
    const FORWARDS: usize = 8,
    const OUTBOUND_COMMANDS: usize = COMMANDS,
> {
    inner: A,
    routing: R,
    handle: Handle<'a, DATAGRAM_BYTES, COMMANDS>,
    outbound: Handle<'a, DATAGRAM_BYTES, OUTBOUND_COMMANDS>,
    forwards: heapless::Vec<Forward<'a, DATAGRAM_BYTES, COMMANDS, OUTBOUND_COMMANDS>, FORWARDS>,
    limiter: Limiter<16>,
}
impl<'a, A, R, const DATAGRAM_BYTES: usize, const COMMANDS: usize, const FORWARDS: usize>
    ForwardProxy<'a, A, R, DATAGRAM_BYTES, COMMANDS, FORWARDS>
{
    /// Wraps local resources; forwarding remains governed by `routing`.
    pub fn new(
        inner: A,
        routing: R,
        handle: Handle<'a, DATAGRAM_BYTES, COMMANDS>,
    ) -> Result<Self, Error> {
        Self::with_outbound(inner, routing, handle, handle)
    }
}
impl<
    'a,
    A,
    R,
    const DATAGRAM_BYTES: usize,
    const COMMANDS: usize,
    const FORWARDS: usize,
    const OUTBOUND_COMMANDS: usize,
> ForwardProxy<'a, A, R, DATAGRAM_BYTES, COMMANDS, FORWARDS, OUTBOUND_COMMANDS>
{
    /// Uses a separate endpoint for upstream traffic. Both endpoint drivers must run.
    /// Deferred replies are always completed through the receiving endpoint's handle.
    pub fn with_outbound(
        inner: A,
        routing: R,
        handle: Handle<'a, DATAGRAM_BYTES, COMMANDS>,
        outbound: Handle<'a, DATAGRAM_BYTES, OUTBOUND_COMMANDS>,
    ) -> Result<Self, Error> {
        if FORWARDS == 0 {
            return Err(Error::Capacity);
        }
        Ok(Self {
            inner,
            routing,
            handle,
            outbound,
            forwards: heapless::Vec::new(),
            limiter: Limiter::new(Limits::default())?,
        })
    }
    /// Replaces per-requester and aggregate forwarding budgets.
    pub fn set_rate_limits(&mut self, limits: Limits) -> Result<(), Error> {
        self.limiter = Limiter::new(limits)?;
        Ok(())
    }
    /// Accesses local application state.
    pub fn inner_mut(&mut self) -> &mut A {
        &mut self.inner
    }
}
impl<
    A: Application<DATAGRAM_BYTES>,
    R: Routing,
    const DATAGRAM_BYTES: usize,
    const COMMANDS: usize,
    const FORWARDS: usize,
    const OUTBOUND_COMMANDS: usize,
> Application<DATAGRAM_BYTES>
    for ForwardProxy<'_, A, R, DATAGRAM_BYTES, COMMANDS, FORWARDS, OUTBOUND_COMMANDS>
{
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        self.inner.handle(request, response)
    }
    fn recognizes(&self, option: OptionNumber) -> bool {
        self.inner.recognizes(option)
    }
    fn deadline(&self) -> Option<Instant> {
        self.inner
            .deadline()
            .into_iter()
            .chain(self.forwards.iter().filter_map(|forward| {
                matches!(forward.state, Some(State::Waiting(_))).then_some(forward.deadline)
            }))
            .min()
    }
    fn uses_context(&self, generation: u64) -> bool {
        self.inner.uses_context(generation)
    }
    fn abort_context(&mut self, generation: u64) {
        self.inner.abort_context(generation);
    }
    #[cfg(feature = "observe")]
    fn observable(&self, request: MessageView<'_>) -> Option<crate::observe::Settings> {
        self.inner.observable(request)
    }
    fn forward(
        &mut self,
        request: Request<'_>,
        now: Instant,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Option<Result<Disposition, Code>> {
        if request.message.option(OptionNumber::PROXY_URI).is_none()
            && request.message.option(OptionNumber::PROXY_SCHEME).is_none()
        {
            return self.inner.forward(request, now, response);
        }
        Some((|| {
            let Some(ticket) = request.deferred_ticket() else {
                response.set_unavailable()?;
                return Ok(Disposition::Complete);
            };
            if self.forwards.is_full() || !self.limiter.allow(request.metadata.remote.ip(), now) {
                response.set_code(Code::TOO_MANY_REQUESTS);
                response.uint_option(OptionNumber::MAX_AGE, 1)?;
                return Ok(Disposition::Complete);
            }
            let mut bytes = [0; DATAGRAM_BYTES];
            let (remote, n) = prepare(
                request.message,
                request.metadata.remote,
                &self.routing,
                &mut bytes,
            )?;
            let parameters = self.routing.parameters(remote);
            let timeout_ms = parameters.exchange_lifetime();
            response.set_deferred_timeout(timeout_ms)?;
            let operation = self
                .outbound
                .forward_opaque(remote, &bytes[..n], parameters)
                .map_err(|_| Code::TOO_MANY_REQUESTS)?;
            self.forwards
                .push(Forward {
                    ticket,
                    state: Some(State::Waiting(operation)),
                    deadline: now.after(timeout_ms),
                })
                .map_err(|_| Code::TOO_MANY_REQUESTS)?;
            Ok(Disposition::Deferred)
        })())
    }
    fn poll(&mut self, now: Instant, cx: &mut Context<'_>) {
        self.inner.poll(now, cx);
        let mut i = 0;
        while i < self.forwards.len() {
            let Some(state) = self.forwards[i].state.take() else {
                self.forwards.swap_remove(i);
                continue;
            };
            let next = match state {
                State::Waiting(mut operation) => match Pin::new(&mut operation).poll(cx) {
                    Poll::Pending if now >= self.forwards[i].deadline => {
                        drop(operation);
                        self.forwards[i].state = Some(State::Ready(status(Code::GATEWAY_TIMEOUT)));
                        continue;
                    }
                    Poll::Pending => State::Waiting(operation),
                    Poll::Ready(result) => {
                        self.forwards[i].state = Some(State::Ready(match result {
                            Ok(reply) => relay(reply),
                            Err(Error::Timeout) => status(Code::GATEWAY_TIMEOUT),
                            Err(_) => status(Code::BAD_GATEWAY),
                        }));
                        continue;
                    }
                },
                State::Ready(response) => {
                    match self
                        .handle
                        .respond_serialized(self.forwards[i].ticket, &response)
                    {
                        Ok(operation) => State::Sending(operation, response),
                        Err(Error::Capacity) => State::Ready(response),
                        Err(_) => {
                            self.forwards.swap_remove(i);
                            continue;
                        }
                    }
                }
                State::Sending(mut operation, response) => {
                    match Pin::new(&mut operation).poll(cx) {
                        Poll::Pending => State::Sending(operation, response),
                        Poll::Ready(Err(Error::Capacity)) => State::Ready(response),
                        Poll::Ready(_) => {
                            self.forwards.swap_remove(i);
                            continue;
                        }
                    }
                }
            };
            self.forwards[i].state = Some(next);
            i += 1;
        }
    }
}
/// A tokenless reply; the deferred completion binds the requester's type and token.
fn status<const DATAGRAM_BYTES: usize>(code: Code) -> Packet<DATAGRAM_BYTES> {
    Packet::encoded(|bytes| {
        MessageBuilder::new(bytes, MessageType::NonConfirmable, code, 0, &[])?.finish(&[])
    })
    .unwrap_or_default()
}
fn relayable(message: MessageView<'_>) -> bool {
    let mut previous = None;
    for (index, option) in message.options().enumerate() {
        let recognized =
            option.number.definition().is_some() && option.valid(previous, message.code());
        previous = Some(option.number);
        // Sixteen options is the bound on any locally constructed response.
        if index == 16
            || !recognized && option.number.unsafe_to_forward()
            || crate::codec::dot_segment(option.number, option.value)
        {
            return false;
        }
    }
    true
}
fn relay<const DATAGRAM_BYTES: usize>(mut reply: Reply<DATAGRAM_BYTES>) -> Packet<DATAGRAM_BYTES> {
    if reply.message().is_ok_and(relayable)
        && reply
            .packet
            .reheader(MessageType::NonConfirmable, 0, &[])
            .is_ok()
    {
        return reply.packet;
    }
    status(Code::BAD_GATEWAY)
}
/// Normalizes a forward request while preserving opaque option values and payload.
/// Errors are the response status the proxy should return to its requester.
pub(crate) fn prepare<const DATAGRAM_BYTES: usize>(
    request: MessageView<'_>,
    requester: SocketAddr,
    routing: &impl Routing,
    output: &mut [u8; DATAGRAM_BYTES],
) -> Result<(SocketAddr, usize), Code> {
    let mut previous = None;
    let mut hop = 16;
    let mut consume_hop = false;
    for option in request.options() {
        let valid = option.valid(previous, request.code());
        if option.number == OptionNumber::HOP_LIMIT
            && previous != Some(option.number)
            && option.value.len() <= 1
        {
            let value = option.uint().map_err(|_| Code::BAD_REQUEST)?;
            if value == 0 {
                return Err(Code::BAD_REQUEST);
            }
            if valid {
                if value == 1 {
                    return Err(Code::HOP_LIMIT_REACHED);
                }
                hop = value - 1;
                consume_hop = true;
            }
        }
        let recognized = valid && option.number.definition().is_some();
        if !recognized && option.number.unsafe_to_forward() {
            return Err(Code::BAD_OPTION);
        }
        previous = Some(option.number);
    }
    if request.option(OptionNumber::OBSERVE).is_some() {
        return Err(Code::PROXY_UNSUPPORTED);
    }
    let mut normalized = [0; DATAGRAM_BYTES];
    let mut normalized_builder = MessageBuilder::new(
        &mut normalized,
        MessageType::Confirmable,
        request.code(),
        0,
        &[],
    )
    .map_err(|_| Code::BAD_REQUEST)?;
    let proxy_uri = request.option(OptionNumber::PROXY_URI);
    let mut decoded_host = [0; 255];
    let (host, port) = if let Some(option) = proxy_uri {
        if request.options().any(|o| {
            matches!(
                o.number,
                OptionNumber::URI_HOST
                    | OptionNumber::URI_PORT
                    | OptionNumber::URI_PATH
                    | OptionNumber::URI_QUERY
                    | OptionNumber::PROXY_SCHEME
            )
        }) {
            return Err(Code::BAD_OPTION);
        }
        let text = core::str::from_utf8(option.value).map_err(|_| Code::BAD_REQUEST)?;
        let uri = Uri::parse(text).map_err(|e| {
            if e == Error::UnsupportedScheme {
                Code::PROXY_UNSUPPORTED
            } else {
                Code::BAD_REQUEST
            }
        })?;
        uri.options_with_scratch(&mut normalized_builder, &mut [0; DATAGRAM_BYTES])
            .map_err(|_| Code::BAD_REQUEST)?;
        let n = crate::uri::percent_decode(uri.host.as_bytes(), &mut decoded_host)
            .map_err(|_| Code::BAD_REQUEST)?;
        (
            core::str::from_utf8(&decoded_host[..n]).map_err(|_| Code::BAD_REQUEST)?,
            uri.port,
        )
    } else {
        let scheme = request
            .option(OptionNumber::PROXY_SCHEME)
            .ok_or(Code::BAD_REQUEST)?;
        if !scheme.value.eq_ignore_ascii_case(b"coap") {
            return Err(Code::PROXY_UNSUPPORTED);
        }
        let host = core::str::from_utf8(
            request
                .option(OptionNumber::URI_HOST)
                .ok_or(Code::BAD_OPTION)?
                .value,
        )
        .map_err(|_| Code::BAD_REQUEST)?;
        let port = request
            .option(OptionNumber::URI_PORT)
            .map(|o| o.uint().map_err(|_| Code::BAD_OPTION))
            .transpose()?
            .unwrap_or(5683);
        (host, u16::try_from(port).map_err(|_| Code::BAD_OPTION)?)
    };
    if !routing.allow(requester, host, port) {
        return Err(Code::FORBIDDEN);
    }
    let remote = routing.resolve(host, port).ok_or(Code::BAD_GATEWAY)?;
    if remote.ip().is_multicast() {
        return Err(Code::FORBIDDEN);
    }
    let n = normalized_builder
        .finish(&[])
        .map_err(|_| Code::BAD_REQUEST)?;
    let normal = MessageView::parse(&normalized[..n]).map_err(|_| Code::BAD_REQUEST)?;
    let mut extras = normal.options().peekable();
    let mut b = MessageBuilder::new(output, request.message_type(), request.code(), 0, &[])
        .map_err(|_| Code::BAD_REQUEST)?;
    let mut hop_inserted = false;
    for option in request.options() {
        if matches!(
            option.number,
            OptionNumber::PROXY_URI | OptionNumber::PROXY_SCHEME
        ) {
            continue;
        }
        if option.number == OptionNumber::HOP_LIMIT && consume_hop {
            consume_hop = false;
            continue;
        }
        while extras.peek().is_some_and(|o| o.number < option.number) {
            let extra = extras.next().ok_or(Code::INTERNAL_ERROR)?;
            if !hop_inserted && extra.number > OptionNumber::HOP_LIMIT {
                b.uint_option(OptionNumber::HOP_LIMIT, hop)
                    .map_err(|_| Code::BAD_REQUEST)?;
                hop_inserted = true;
            }
            b.option(extra.number, extra.value)
                .map_err(|_| Code::BAD_REQUEST)?;
        }
        if !hop_inserted && option.number >= OptionNumber::HOP_LIMIT {
            b.uint_option(OptionNumber::HOP_LIMIT, hop)
                .map_err(|_| Code::BAD_REQUEST)?;
            hop_inserted = true;
        }
        b.option(option.number, option.value)
            .map_err(|_| Code::BAD_REQUEST)?;
    }
    for extra in extras {
        if !hop_inserted && extra.number > OptionNumber::HOP_LIMIT {
            b.uint_option(OptionNumber::HOP_LIMIT, hop)
                .map_err(|_| Code::BAD_REQUEST)?;
            hop_inserted = true;
        }
        b.option(extra.number, extra.value)
            .map_err(|_| Code::BAD_REQUEST)?;
    }
    if !hop_inserted {
        b.uint_option(OptionNumber::HOP_LIMIT, hop)
            .map_err(|_| Code::BAD_REQUEST)?;
    }
    Ok((
        remote,
        b.finish(request.payload()).map_err(|_| Code::BAD_REQUEST)?,
    ))
}

#[cfg(test)]
#[path = "proxy/tests.rs"]
mod tests;
