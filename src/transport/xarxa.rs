//! Owned UDP packets and native xarxa stack integration (TR-6, TR-7).
use super::{Metadata, ReceivedPacket};
use core::net::{IpAddr, SocketAddr};
use xarxa::udp::UdpMetadata;

/// Invalid socket configuration, addressing, or datagram operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum XarxaError {
    /// The socket is closed, its binding changed, or a network buffer is invalid.
    InvalidState,
    /// Incoming metadata lacks an actual destination address.
    MissingDestination,
    /// The configured interface ID must be nonzero and match the socket binding.
    InvalidInterface,
    /// The requested interface or IPv6 zone conflicts with the socket binding.
    InterfaceMismatch,
    /// The adapter disables this address family, or source and destination differ.
    UnsupportedAddressFamily,
    /// The destination is unavailable or no suitable source address exists.
    Unaddressable,
    /// A complete datagram does not fit in a network buffer.
    BufferFull,
    /// The stack reported a recoverable receive error, including ICMP feedback.
    ReceiveDropped,
    /// An owned send was called without a packet.
    MissingPacket,
}
impl core::fmt::Display for XarxaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "xarxa UDP error: {self:?}")
    }
}
impl core::error::Error for XarxaError {}
impl XarxaError {
    pub(crate) fn discard_receive(self) -> bool {
        matches!(
            self,
            Self::MissingDestination | Self::ReceiveDropped | Self::UnsupportedAddressFamily
        )
    }
    pub(crate) fn discard_send(self) -> bool {
        matches!(
            self,
            Self::InterfaceMismatch
                | Self::UnsupportedAddressFamily
                | Self::Unaddressable
                | Self::BufferFull
        )
    }
}

pub(crate) fn ip_address(ip: IpAddr) -> Result<xarxa::wire::IpAddr, XarxaError> {
    match ip {
        IpAddr::V4(ip) => {
            #[cfg(any(feature = "xarxa-ipv4", feature = "embassy-net-xarxa-ipv4"))]
            {
                Ok(ip.into())
            }
            #[cfg(not(any(feature = "xarxa-ipv4", feature = "embassy-net-xarxa-ipv4")))]
            {
                let _ = ip;
                Err(XarxaError::UnsupportedAddressFamily)
            }
        }
        IpAddr::V6(ip) => {
            #[cfg(any(feature = "xarxa-ipv6", feature = "embassy-net-xarxa-ipv6"))]
            {
                Ok(ip.into())
            }
            #[cfg(not(any(feature = "xarxa-ipv6", feature = "embassy-net-xarxa-ipv6")))]
            {
                let _ = ip;
                Err(XarxaError::UnsupportedAddressFamily)
            }
        }
    }
}

pub(crate) fn receive_family(metadata: Metadata, ipv4: bool, ipv6: bool) -> Result<(), XarxaError> {
    if metadata.remote.is_ipv4() != metadata.local.is_ipv4()
        || !(if metadata.remote.is_ipv4() {
            ipv4
        } else {
            ipv6
        })
    {
        return Err(XarxaError::UnsupportedAddressFamily);
    }
    Ok(())
}

pub(crate) fn validate_family(
    remote: SocketAddr,
    ipv4: bool,
    ipv6: bool,
    ipv4_feature: &'static str,
    ipv6_feature: &'static str,
    warned: &critical_section::Mutex<core::cell::Cell<bool>>,
) -> Result<(), XarxaError> {
    let enabled = if remote.is_ipv4() { ipv4 } else { ipv6 };
    if enabled {
        return Ok(());
    }
    #[cfg(any(feature = "log", feature = "defmt"))]
    {
        super::warn_once(warned, || {
            let feature = if remote.is_ipv4() {
                ipv4_feature
            } else {
                ipv6_feature
            };
            #[cfg(feature = "log")]
            log::warn!(
                "mai-coap: xarxa adapter uses a disabled address family; enable mai-coap/{feature}"
            );
            #[cfg(feature = "defmt")]
            defmt::warn!(
                "mai-coap: xarxa adapter uses a disabled address family; enable mai-coap/{=str}",
                feature
            );
        });
    }
    #[cfg(not(any(feature = "log", feature = "defmt")))]
    let _ = (ipv4_feature, ipv6_feature, warned);
    Err(XarxaError::UnsupportedAddressFamily)
}

pub(crate) fn payload_capacity(buffer: &xarxa::driver::PacketBuf) -> Option<usize> {
    buffer.capacity().checked_sub(buffer.headroom())
}

pub(crate) fn validate_payload_capacity(
    buffer: &xarxa::driver::PacketBuf,
    length: usize,
) -> Result<(), XarxaError> {
    let capacity = payload_capacity(buffer).ok_or(XarxaError::InvalidState)?;
    if length > capacity {
        return Err(XarxaError::BufferFull);
    }
    Ok(())
}

pub(crate) fn send_metadata(
    remote: SocketAddr,
    source: Option<IpAddr>,
    interface: Option<u32>,
    index: u32,
) -> Result<UdpMetadata, XarxaError> {
    if interface.is_some_and(|id| id != index)
        || matches!(remote, SocketAddr::V6(addr) if addr.scope_id() != 0 && addr.scope_id() != index)
        // Receive metadata includes this zone; an unscoped exchange would never
        // match its scoped response's peer identity.
        || matches!(remote, SocketAddr::V6(addr) if addr.ip().is_unicast_link_local() && addr.scope_id() == 0)
    {
        return Err(XarxaError::InterfaceMismatch);
    }
    if source.is_some_and(|ip| ip.is_ipv4() != remote.is_ipv4()) {
        return Err(XarxaError::UnsupportedAddressFamily);
    }
    let remote = xarxa::wire::SocketAddr {
        addr: ip_address(remote.ip())?,
        port: remote.port(),
    };
    let mut meta = UdpMetadata::from(remote);
    meta.local_addr = source.map(ip_address).transpose()?;
    Ok(meta)
}

pub(crate) fn receive_metadata(
    packet: &xarxa::udp::RecvPacket,
    index: u32,
) -> Result<Metadata, XarxaError> {
    let meta = packet.meta();
    let local: IpAddr = meta
        .local_addr
        .ok_or(XarxaError::MissingDestination)?
        .into();
    if local.is_unspecified() {
        return Err(XarxaError::MissingDestination);
    }
    let mut remote: SocketAddr = meta.remote_addr.into();
    if let SocketAddr::V6(address) = &mut remote
        && (address.ip().is_unicast_link_local() || address.ip().is_multicast())
    {
        address.set_scope_id(index);
    }
    Ok(Metadata::new(remote, local, packet.payload().len()).with_interface(Some(index)))
}

/// A received datagram owning its network-pool buffer.
pub struct XarxaDatagram {
    pub(crate) packet: xarxa::udp::RecvPacket,
    pub(crate) metadata: Metadata,
}
impl ReceivedPacket for XarxaDatagram {
    fn bytes(&self) -> &[u8] {
        self.packet.payload()
    }
    fn metadata(&self) -> Metadata {
        self.metadata
    }
}

#[cfg(feature = "xarxa")]
mod native {
    use super::*;
    use crate::transport::{
        DatagramReceiver, DatagramSender, OwnedDatagramSender, SendOutcome, Transport,
    };
    use core::{future::poll_fn, task::Poll};
    use xarxa::{
        driver::PacketBuf,
        iface::IfaceHandle,
        udp::{RecvError, SendError, UdpHandle},
    };

    static WARNED: critical_section::Mutex<core::cell::Cell<bool>> =
        critical_section::Mutex::new(core::cell::Cell::new(false));

    /// Short stack access shared with an application-owned network runner.
    ///
    /// The implementation must release all stack borrows before returning from
    /// `with_stack`. `wake_runner` schedules the application task polling the stack.
    /// No callback may be retained or invoked inside an asynchronous wait.
    pub trait StackAccess<'d> {
        /// Runs a synchronous operation with exclusive stack access.
        fn with_stack<R>(&self, operation: impl FnOnce(&mut xarxa::Stack<'d>) -> R) -> R;
        /// Schedules stack progress after socket activity or buffer release.
        fn wake_runner(&self);
    }

    /// Native xarxa socket adapter; the application owns the stack and socket.
    ///
    /// Borrowed sends allocate a transmit copy and request a timed retry when
    /// the pool is exhausted. Device busy registers a readiness waker. Owned sends transfer
    /// their existing packet and need no replacement allocation.
    pub struct XarxaTransport<'d, A> {
        access: A,
        handle: UdpHandle,
        iface: IfaceHandle,
        index: u32,
        marker: core::marker::PhantomData<&'d ()>,
    }
    impl<'d, A: StackAccess<'d>> XarxaTransport<'d, A> {
        /// Uses an open socket already bound to `iface`, with a nonzero public ID.
        ///
        /// The application must not remove the socket or interface while this
        /// adapter exists. Returns an error for a closed socket, mismatched
        /// binding, or zero ID.
        ///
        /// # Panics
        /// Panics if `handle` no longer identifies a socket in the stack.
        pub fn new(
            access: A,
            handle: UdpHandle,
            iface: IfaceHandle,
            index: u32,
        ) -> Result<Self, XarxaError> {
            if index == 0 {
                return Err(XarxaError::InvalidInterface);
            }
            let valid = access.with_stack(|stack| {
                let socket = stack.udp_socket(handle);
                socket.is_open() && socket.bound_iface() == Some(iface)
            });
            if !valid {
                return Err(XarxaError::InvalidState);
            }
            Ok(Self {
                access,
                handle,
                iface,
                index,
                marker: core::marker::PhantomData,
            })
        }
        /// Returns the stack accessor.
        pub fn into_inner(self) -> A {
            self.access
        }
    }

    impl<'d, A: StackAccess<'d>> XarxaTransport<'d, A> {
        fn poll_send_packet(
            &self,
            meta: UdpMetadata,
            packet: &mut Option<PacketBuf>,
            cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<SendOutcome, XarxaError>> {
            let result = self.access.with_stack(|stack| {
                let mut socket = stack.udp_socket(self.handle);
                if socket.bound_iface() != Some(self.iface) {
                    return Poll::Ready(Err(XarxaError::InvalidState));
                }
                let Some(buffer) = packet.take() else {
                    return Poll::Ready(Err(XarxaError::MissingPacket));
                };
                match socket.send_packet(buffer, meta) {
                    Ok(()) => Poll::Ready(Ok(SendOutcome::Accepted)),
                    Err((error, buffer)) => {
                        *packet = Some(buffer);
                        match error {
                            SendError::DeviceBusy => {
                                socket.register_send_waker(cx.waker());
                                Poll::Pending
                            }
                            SendError::NoBuffer => Poll::Ready(Ok(SendOutcome::RetryLater)),
                            SendError::InvalidState => Poll::Ready(Err(XarxaError::InvalidState)),
                            SendError::Unaddressable => Poll::Ready(Err(XarxaError::Unaddressable)),
                            SendError::BufferFull => Poll::Ready(Err(XarxaError::BufferFull)),
                        }
                    }
                }
            });
            self.access.wake_runner();
            result
        }
    }

    /// Owned receive guard that notifies the runner when its buffer is released.
    pub struct NativeDatagram<'a, 'd, A: StackAccess<'d>> {
        packet: Option<xarxa::udp::RecvPacket>,
        metadata: Metadata,
        access: &'a A,
        marker: core::marker::PhantomData<&'d ()>,
    }
    impl<'d, A: StackAccess<'d>> ReceivedPacket for NativeDatagram<'_, 'd, A> {
        fn bytes(&self) -> &[u8] {
            self.packet
                .as_ref()
                .map_or(&[], xarxa::udp::RecvPacket::payload)
        }
        fn metadata(&self) -> Metadata {
            self.metadata
        }
    }
    impl<'d, A: StackAccess<'d>> Drop for NativeDatagram<'_, 'd, A> {
        fn drop(&mut self) {
            drop(self.packet.take());
            self.access.wake_runner();
        }
    }

    impl<'d, A: StackAccess<'d>> Transport for XarxaTransport<'d, A> {
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
    impl<'d, A: StackAccess<'d>> DatagramReceiver for &XarxaTransport<'d, A> {
        type Error = XarxaError;
        type Packet<'a>
            = NativeDatagram<'a, 'd, A>
        where
            Self: 'a;
        fn receive_buffer<const D: usize>() -> impl AsMut<[u8]> {
            []
        }
        fn discard_receive_error(error: &Self::Error) -> bool {
            error.discard_receive()
        }
        async fn receive<'a>(
            &'a mut self,
            _: &'a mut [u8],
        ) -> Result<Self::Packet<'a>, Self::Error> {
            let packet = poll_fn(|cx| {
                self.access.with_stack(|stack| {
                    let mut socket = stack.udp_socket(self.handle);
                    if socket.bound_iface() != Some(self.iface) {
                        return Poll::Ready(Err(XarxaError::InvalidState));
                    }
                    match socket.recv() {
                        Ok(packet) => Poll::Ready(Ok(packet)),
                        Err(RecvError::Exhausted) => {
                            socket.register_recv_waker(cx.waker());
                            Poll::Pending
                        }
                        Err(RecvError::InvalidState) => Poll::Ready(Err(XarxaError::InvalidState)),
                        Err(_) => Poll::Ready(Err(XarxaError::ReceiveDropped)),
                    }
                })
            })
            .await?;
            self.access.wake_runner();
            let metadata = match receive_metadata(&packet, self.index) {
                Ok(metadata) => metadata,
                Err(error) => {
                    drop(packet);
                    self.access.wake_runner();
                    return Err(error);
                }
            };
            if let Err(error) = receive_family(
                metadata,
                cfg!(feature = "xarxa-ipv4"),
                cfg!(feature = "xarxa-ipv6"),
            ) {
                drop(packet);
                self.access.wake_runner();
                return Err(error);
            }
            Ok(NativeDatagram {
                packet: Some(packet),
                metadata,
                access: &self.access,
                marker: core::marker::PhantomData,
            })
        }
    }
    impl<'d, A: StackAccess<'d>> DatagramSender for &XarxaTransport<'d, A> {
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
            cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<SendOutcome, Self::Error>> {
            validate_family(
                remote,
                cfg!(feature = "xarxa-ipv4"),
                cfg!(feature = "xarxa-ipv6"),
                "xarxa-ipv4",
                "xarxa-ipv6",
                &WARNED,
            )?;
            let meta = send_metadata(remote, source, interface, self.index)?;
            let buffer = self.access.with_stack(|stack| {
                let socket = stack.udp_socket(self.handle);
                if !socket.is_open() || socket.bound_iface() != Some(self.iface) {
                    return Err(XarxaError::InvalidState);
                }
                Ok(socket.alloc())
            })?;
            let Some(mut buffer) = buffer else {
                return Poll::Ready(Ok(SendOutcome::RetryLater));
            };
            validate_payload_capacity(&buffer, bytes.len())?;
            buffer.set_len(bytes.len());
            buffer.copy_from_slice(bytes);
            self.poll_send_packet(meta, &mut Some(buffer), cx)
        }
    }
    impl<'d, A: StackAccess<'d>> OwnedDatagramSender<PacketBuf> for &XarxaTransport<'d, A> {
        fn poll_send_owned(
            &mut self,
            remote: SocketAddr,
            source: Option<IpAddr>,
            interface: Option<u32>,
            packet: &mut Option<PacketBuf>,
            cx: &mut core::task::Context<'_>,
        ) -> Poll<Result<SendOutcome, Self::Error>> {
            validate_family(
                remote,
                cfg!(feature = "xarxa-ipv4"),
                cfg!(feature = "xarxa-ipv6"),
                "xarxa-ipv4",
                "xarxa-ipv6",
                &WARNED,
            )?;
            let meta = send_metadata(remote, source, interface, self.index)?;
            self.poll_send_packet(meta, packet, cx)
        }
    }
}
#[cfg(feature = "xarxa")]
pub use native::{NativeDatagram, StackAccess, XarxaTransport};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "log", feature = "defmt"))]
    #[test]
    fn tr_6_each_adapter_has_an_independent_warning_latch() {
        let native = critical_section::Mutex::new(core::cell::Cell::new(false));
        let embassy = critical_section::Mutex::new(core::cell::Cell::new(false));
        let remote = "192.0.2.1:5683".parse().unwrap();
        for latch in [&native, &embassy] {
            assert!(!critical_section::with(|cs| latch.borrow(cs).get()));
            assert_eq!(
                validate_family(remote, false, true, "v4", "v6", latch),
                Err(XarxaError::UnsupportedAddressFamily)
            );
            assert!(critical_section::with(|cs| latch.borrow(cs).get()));
        }
    }

    #[test]
    fn tr_1_link_local_requests_require_a_scoped_peer_identity() {
        let remote = "[fe80::1]:5683".parse().unwrap();
        assert_eq!(
            send_metadata(remote, None, Some(7), 7),
            Err(XarxaError::InterfaceMismatch)
        );
    }

    #[test]
    fn tr_6_conflicting_interface_and_scope_are_rejected() {
        let remote: SocketAddr = "[fe80::1%7]:5683".parse().unwrap();
        assert_eq!(
            send_metadata(remote, None, None, 8),
            Err(XarxaError::InterfaceMismatch)
        );
        assert_eq!(
            send_metadata(remote, None, Some(8), 7),
            Err(XarxaError::InterfaceMismatch)
        );
    }

    #[test]
    fn tr_6_source_and_destination_family_must_match() {
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let source: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(
            send_metadata(remote, Some(source), None, 7),
            Err(XarxaError::UnsupportedAddressFamily)
        );
    }

    #[test]
    fn tr_5_only_packet_specific_failures_are_discarded() {
        assert!(XarxaError::Unaddressable.discard_send());
        assert!(XarxaError::BufferFull.discard_send());
        assert!(XarxaError::InterfaceMismatch.discard_send());
        assert!(!XarxaError::InvalidState.discard_send());
        assert!(!XarxaError::MissingPacket.discard_send());
        assert!(XarxaError::MissingDestination.discard_receive());
        assert!(XarxaError::ReceiveDropped.discard_receive());
        assert!(!XarxaError::InvalidState.discard_receive());
    }

    #[cfg(any(feature = "xarxa-ipv4", feature = "embassy-net-xarxa-ipv4"))]
    #[test]
    fn tr_6_ipv4_metadata_preserves_explicit_source() {
        let remote: SocketAddr = "192.0.2.1:5683".parse().unwrap();
        let source: IpAddr = "192.0.2.2".parse().unwrap();
        let metadata = send_metadata(remote, Some(source), Some(7), 7).unwrap();
        assert_eq!(SocketAddr::from(metadata.remote_addr), remote);
        assert_eq!(metadata.local_addr.map(IpAddr::from), Some(source));
    }

    #[cfg(any(feature = "xarxa-ipv6", feature = "embassy-net-xarxa-ipv6"))]
    #[test]
    fn tr_6_ipv6_scope_matches_bound_interface() {
        let remote: SocketAddr = "[fe80::1%7]:5683".parse().unwrap();
        let metadata = send_metadata(remote, None, Some(7), 7).unwrap();
        assert_eq!(IpAddr::from(metadata.remote_addr.addr), remote.ip());
        assert_eq!(metadata.remote_addr.port, remote.port());
    }

    #[cfg(not(any(feature = "xarxa-ipv4", feature = "embassy-net-xarxa-ipv4")))]
    #[test]
    fn tr_6_disabled_ipv4_is_rejected() {
        assert_eq!(
            ip_address("192.0.2.1".parse().unwrap()),
            Err(XarxaError::UnsupportedAddressFamily)
        );
    }

    #[cfg(not(any(feature = "xarxa-ipv6", feature = "embassy-net-xarxa-ipv6")))]
    #[test]
    fn tr_6_disabled_ipv6_is_rejected() {
        assert_eq!(
            ip_address("2001:db8::1".parse().unwrap()),
            Err(XarxaError::UnsupportedAddressFamily)
        );
    }
}
