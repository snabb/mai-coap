//! Configured client operations with independent routing and peer selection.
use super::{Handle, Operation, Reply, Response, Target};
use crate::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    messaging::TransmissionParameters,
    security::PeerId,
};

/// Cheap, caller-owned destination profile; each operation snapshots its settings.
#[derive(Clone, Copy)]
pub struct Client<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    pub(super) handle: Handle<'a, DATAGRAM_BYTES, COMMANDS>,
    pub(super) target: Target,
    pub(super) proxy: bool,
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Handle<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Configures operations with explicit source/interface, peer and reliability.
    pub fn client(&self, target: impl Into<Target>) -> Client<'a, DATAGRAM_BYTES, COMMANDS> {
        Client {
            handle: *self,
            target: target.into(),
            proxy: false,
        }
    }
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Client<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Requires this authenticated identity, independently of the next-hop address.
    pub fn peer(mut self, peer: PeerId) -> Self {
        self.target.peer = Some(peer);
        self
    }
    /// Chooses combined (`true`, default) or sequential EDHOC for an explicit peer.
    pub fn combined_edhoc(mut self, combined: bool) -> Self {
        self.target.combined_edhoc = combined;
        self
    }
    /// Enables one automatic EDHOC recovery after 4.01 (`true` by default).
    pub fn recovery(mut self, recover: bool) -> Self {
        self.target.recover = recover;
        self
    }
    /// Sets the profile used by all blocks, refreshes, retries and handshakes.
    pub fn parameters(mut self, parameters: TransmissionParameters) -> Result<Self, Error> {
        self.target.parameters = parameters.validate()?;
        Ok(self)
    }
    /// Uses Proxy-Scheme for absolute URI requests through the configured next hop.
    /// The URI authority must name the origin, not the proxy.
    pub fn through_proxy(mut self) -> Self {
        self.proxy = true;
        self
    }
    /// Builds a request from a method and escaped path or absolute `coap://` URI.
    /// URI authority is routing information; only `peer` selects a trusted identity.
    pub fn request(
        self,
        method: Code,
        uri: &str,
    ) -> Result<RequestBuilder<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        if !method.is_request() {
            return Err(Error::Malformed);
        }
        let mut bytes = [0; DATAGRAM_BYTES];
        let mut b = MessageBuilder::new(&mut bytes, MessageType::Confirmable, method, 0, &[])?;
        if uri.contains("://") {
            let destination = (!self.proxy).then_some(self.target.remote);
            crate::uri::Uri::parse(uri)?.request_options(
                &mut b,
                &mut [0; DATAGRAM_BYTES],
                destination,
            )?;
            if self.proxy {
                b.option(OptionNumber::PROXY_SCHEME, b"coap")?;
            }
        } else {
            if self.proxy {
                return Err(Error::Malformed);
            }
            crate::uri::resolved_path_query_options(uri, &mut b)?;
        }
        let n = b.finish(&[])?;
        let mut content = Response::new(method);
        for option in MessageView::parse(&bytes[..n])?.options() {
            content.option(option.number, option.value)?;
        }
        Ok(RequestBuilder {
            client: self,
            content,
            ty: MessageType::Confirmable,
            token_len: 8,
            wait: true,
        })
    }
    /// Borrows an encoded request; `send` copies it and replaces its MID and token.
    pub fn request_raw<'packet>(
        self,
        packet: &'packet [u8],
    ) -> Result<RawRequest<'a, 'packet, DATAGRAM_BYTES, COMMANDS>, Error> {
        let message = MessageView::parse(packet)?;
        if !message.code().is_request()
            && !(message.code() == Code::EMPTY
                && message.message_type() == MessageType::Confirmable)
        {
            return Err(Error::Malformed);
        }
        Ok(RawRequest {
            client: self,
            packet,
            token_len: 8,
            wait: true,
        })
    }
    /// Retrieves a GET response using this profile, including non-success replies.
    /// Inspect its code explicitly; options and diagnostic payload remain available.
    pub async fn get(self, uri: &str) -> Result<Reply<DATAGRAM_BYTES>, Error> {
        let operation = self.request(Code::GET, uri)?.send()?;
        operation.await
    }
}
/// Borrowed raw request with named submission controls; no packet buffer is allocated.
pub struct RawRequest<'a, 'packet, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    client: Client<'a, DATAGRAM_BYTES, COMMANDS>,
    packet: &'packet [u8],
    token_len: u8,
    wait: bool,
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize>
    RawRequest<'a, '_, DATAGRAM_BYTES, COMMANDS>
{
    /// Changes random token length; valid lengths are zero through eight.
    pub fn token_length(mut self, length: u8) -> Result<Self, Error> {
        if length > 8 {
            return Err(Error::Malformed);
        }
        self.token_len = length;
        Ok(self)
    }
    /// Waits for destination congestion credit instead of reporting capacity.
    pub fn wait_for_nstart(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }
    /// Copies and submits the request; dropping the operation cancels it.
    pub fn send(self) -> Result<Operation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.client.handle.submit_request(
            self.client.target,
            crate::Packet::copy_from(self.packet)?,
            self.token_len,
            self.wait,
        )
    }
}
/// Bounded request content with named reliability controls and generated MID/token.
pub struct RequestBuilder<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    client: Client<'a, DATAGRAM_BYTES, COMMANDS>,
    content: Response<DATAGRAM_BYTES>,
    ty: MessageType,
    token_len: u8,
    wait: bool,
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize>
    RequestBuilder<'a, DATAGRAM_BYTES, COMMANDS>
{
    /// Adds an option in numeric order, preserving repeated option order.
    pub fn option(mut self, number: OptionNumber, value: &[u8]) -> Result<Self, Error> {
        self.content.option(number, value)?;
        Ok(self)
    }
    /// Inserts or replaces a singleton option.
    pub fn set_option(mut self, number: OptionNumber, value: &[u8]) -> Result<Self, Error> {
        self.content.set_option(number, value)?;
        Ok(self)
    }
    /// Adds a minimally encoded unsigned option.
    pub fn uint_option(mut self, number: OptionNumber, value: u64) -> Result<Self, Error> {
        self.content.uint_option(number, value)?;
        Ok(self)
    }
    /// Sets the request body.
    pub fn payload(mut self, bytes: &[u8]) -> Result<Self, Error> {
        self.content.set_payload(bytes)?;
        Ok(self)
    }
    /// Chooses CON (`true`, default) or NON (`false`).
    pub fn confirmable(mut self, confirmable: bool) -> Self {
        self.ty = if confirmable {
            MessageType::Confirmable
        } else {
            MessageType::NonConfirmable
        };
        self
    }
    /// Changes random token length; valid lengths are zero through eight.
    pub fn token_length(mut self, length: u8) -> Result<Self, Error> {
        if length > 8 {
            return Err(Error::Malformed);
        }
        self.token_len = length;
        Ok(self)
    }
    /// Waits for destination congestion credit instead of reporting capacity.
    pub fn wait_for_nstart(mut self, wait: bool) -> Self {
        self.wait = wait;
        self
    }
    pub(super) fn encode(&self, bytes: &mut [u8]) -> Result<usize, Error> {
        self.content.serialize(bytes, self.ty, 0, &[])
    }
    /// Submits the request; dropping the returned operation cancels it.
    pub fn send(self) -> Result<Operation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        let packet = crate::Packet::encoded(|bytes| self.encode(bytes))?;
        self.client
            .handle
            .submit_request(self.client.target, packet, self.token_len, self.wait)
    }
    /// Registers a GET or FETCH observation, retaining its method and payload.
    #[cfg(feature = "observe")]
    pub fn observe(mut self) -> Result<super::Observation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        if !matches!(self.content.code, Code::GET | Code::FETCH) {
            return Err(Error::Malformed);
        }
        self.content.set_uint_option(OptionNumber::OBSERVE, 0)?;
        let packet: crate::Packet<DATAGRAM_BYTES> =
            crate::Packet::encoded(|bytes| self.encode(bytes))?;
        let operation = self.client.handle.submit_request(
            self.client.target,
            packet.clone(),
            self.token_len,
            self.wait,
        )?;
        super::Observation::start(operation, packet.as_slice(), self.client.target)
    }
}
