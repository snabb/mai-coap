//! Owned UDP integration with xarxa-backed Embassy (TR-6, TR-7).
use super::xarxa::{
    XarxaDatagram, XarxaError, receive_family, receive_metadata, send_metadata, validate_family,
    validate_payload_capacity,
};
use super::{DatagramReceiver, DatagramSender, OwnedDatagramSender, SendOutcome, Transport};
use core::net::{IpAddr, SocketAddr};
use core::task::{Context, Poll};
use embassy_net_xarxa::{
    TryError,
    udp::{IfaceHandle, RecvError, SendError, UdpSocket},
};
use xarxa::driver::PacketBuf;

static WARNED: critical_section::Mutex<core::cell::Cell<bool>> =
    critical_section::Mutex::new(core::cell::Cell::new(false));

/// Borrows an application-created, interface-bound xarxa-backed Embassy socket.
///
/// The application drives the Embassy runner. Temporary device or buffer
/// shortage returns [`SendOutcome::RetryLater`]; the endpoint schedules retries.
/// The socket's interface binding must remain unchanged while this adapter exists.
/// Owned sends need no replacement allocation.
pub struct EmbassyXarxaTransport<'s, 'd> {
    socket: &'s UdpSocket<'d>,
    iface: IfaceHandle,
    index: u32,
}
impl<'s, 'd> EmbassyXarxaTransport<'s, 'd> {
    /// Uses an open socket bound to `iface`, with a nonzero public interface ID.
    ///
    /// Returns an error for a closed socket, mismatched binding, or zero ID.
    pub fn new(
        socket: &'s UdpSocket<'d>,
        iface: IfaceHandle,
        index: u32,
    ) -> Result<Self, XarxaError> {
        if index == 0 {
            return Err(XarxaError::InvalidInterface);
        }
        if !socket.is_open() || socket.bound_iface() != Some(iface) {
            return Err(XarxaError::InvalidState);
        }
        Ok(Self {
            socket,
            iface,
            index,
        })
    }
    fn validate_socket(&self) -> Result<(), XarxaError> {
        if self.socket.is_open() && self.socket.bound_iface() == Some(self.iface) {
            Ok(())
        } else {
            Err(XarxaError::InvalidState)
        }
    }
    /// Returns the borrowed socket.
    pub fn into_inner(self) -> &'s UdpSocket<'d> {
        self.socket
    }
}
fn send_error(error: SendError) -> XarxaError {
    match error {
        SendError::InvalidState => XarxaError::InvalidState,
        SendError::Unaddressable => XarxaError::Unaddressable,
        SendError::BufferFull => XarxaError::BufferFull,
    }
}
impl Transport for EmbassyXarxaTransport<'_, '_> {
    type Error = XarxaError;
    type Receiver<'a>
        = &'a Self
    where
        Self: 'a;
    type Sender<'a>
        = &'a Self
    where
        Self: 'a;
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>) {
        (self, self)
    }
}
impl DatagramReceiver for &EmbassyXarxaTransport<'_, '_> {
    type Error = XarxaError;
    type Packet<'a>
        = XarxaDatagram
    where
        Self: 'a;
    fn receive_buffer<const D: usize>() -> impl AsMut<[u8]> {
        []
    }
    fn discard_receive_error(error: &Self::Error) -> bool {
        error.discard_receive()
    }
    async fn receive<'a>(&'a mut self, _: &'a mut [u8]) -> Result<Self::Packet<'a>, Self::Error> {
        self.validate_socket()?;
        let packet = self.socket.recv().await.map_err(|error| match error {
            RecvError::InvalidState => XarxaError::InvalidState,
            _ => XarxaError::ReceiveDropped,
        })?;
        let metadata = receive_metadata(&packet, self.index)?;
        receive_family(
            metadata,
            cfg!(feature = "embassy-net-xarxa-ipv4"),
            cfg!(feature = "embassy-net-xarxa-ipv6"),
        )?;
        Ok(XarxaDatagram { packet, metadata })
    }
}
impl DatagramSender for &EmbassyXarxaTransport<'_, '_> {
    type Error = XarxaError;
    fn discard_send_error(error: &Self::Error) -> bool {
        error.discard_send()
    }
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        _: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        validate_family(
            remote,
            cfg!(feature = "embassy-net-xarxa-ipv4"),
            cfg!(feature = "embassy-net-xarxa-ipv6"),
            "embassy-net-xarxa-ipv4",
            "embassy-net-xarxa-ipv6",
            &WARNED,
        )?;
        let meta = send_metadata(remote, source, interface, self.index)?;
        self.validate_socket()?;
        let Some(mut buffer) = self.socket.try_alloc() else {
            return Poll::Ready(Ok(SendOutcome::RetryLater));
        };
        validate_payload_capacity(&buffer, bytes.len())?;
        buffer.set_len(bytes.len());
        buffer.copy_from_slice(bytes);
        self.send_packet(meta, &mut Some(buffer))
    }
}
impl OwnedDatagramSender<PacketBuf> for &EmbassyXarxaTransport<'_, '_> {
    fn poll_send_owned(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        packet: &mut Option<PacketBuf>,
        _: &mut Context<'_>,
    ) -> Poll<Result<SendOutcome, Self::Error>> {
        validate_family(
            remote,
            cfg!(feature = "embassy-net-xarxa-ipv4"),
            cfg!(feature = "embassy-net-xarxa-ipv6"),
            "embassy-net-xarxa-ipv4",
            "embassy-net-xarxa-ipv6",
            &WARNED,
        )?;
        let meta = send_metadata(remote, source, interface, self.index)?;
        self.send_packet(meta, packet)
    }
}

impl EmbassyXarxaTransport<'_, '_> {
    fn send_packet(
        &self,
        meta: xarxa::udp::UdpMetadata,
        packet: &mut Option<PacketBuf>,
    ) -> Poll<Result<SendOutcome, XarxaError>> {
        self.validate_socket()?;
        let buffer = packet.take().ok_or(XarxaError::MissingPacket)?;
        Poll::Ready(match self.socket.try_send_packet_to(buffer, meta) {
            Ok(()) => Ok(SendOutcome::Accepted),
            Err((error, buffer)) => {
                *packet = Some(buffer);
                match error {
                    TryError::Other(error) => Err(send_error(error)),
                    TryError::WouldBlock => Ok(SendOutcome::RetryLater),
                }
            }
        })
    }
}
