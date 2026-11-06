//! Whole-datagram transport contracts (TR-1–8).
use core::{
    future::Future,
    net::{IpAddr, SocketAddr},
};

#[cfg(any(test, feature = "server", feature = "client", feature = "block1"))]
pub(crate) fn peer_address(mut remote: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(address) = &mut remote {
        address.set_flowinfo(0);
        // Zones distinguish scoped peers, but are irrelevant for global unicast.
        if !address.ip().is_unicast_link_local() && !address.ip().is_multicast() {
            address.set_scope_id(0);
        }
    }
    remote
}

#[cfg(any(feature = "server", feature = "client"))]
pub(crate) fn same_peer(left: SocketAddr, right: SocketAddr) -> bool {
    peer_address(left) == peer_address(right)
}

/// Addresses and original length of a received datagram.
/// Use [`Metadata::new`] and [`Metadata::with_interface`] in transport adapters.
///
/// External exhaustive construction is intentionally unavailable:
/// ```compile_fail
/// use mai_coap::transport::Metadata;
/// let metadata = Metadata {
///     remote: "192.0.2.1:5683".parse().unwrap(),
///     local: "192.0.2.2".parse().unwrap(),
///     interface: None,
///     original_len: 4,
/// };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct Metadata {
    /// Remote source endpoint, including IPv6 scope when applicable.
    pub remote: SocketAddr,
    /// Destination address of the incoming datagram; never an unspecified address.
    pub local: IpAddr,
    /// Receiving interface index, when the network stack exposes it.
    pub interface: Option<u32>,
    /// Original length, allowing oversized datagrams to be discarded (TR-4).
    pub original_len: usize,
}
impl Metadata {
    /// Constructs destination metadata; `local` must be the actual destination.
    pub const fn new(remote: SocketAddr, local: IpAddr, original_len: usize) -> Self {
        Self {
            remote,
            local,
            interface: None,
            original_len,
        }
    }
    /// Sets the receiving interface when the transport exposes it.
    pub const fn with_interface(mut self, interface: Option<u32>) -> Self {
        self.interface = interface;
        self
    }
}
/// Borrowed or owned received packet, permitting transport-specific buffer guards.
pub trait ReceivedPacket {
    /// Accessible bytes; potentially shorter than the original datagram.
    fn bytes(&self) -> &[u8];
    /// Incoming addressing and original datagram length.
    fn metadata(&self) -> Metadata;
}
/// A packet borrowed from the receive scratch buffer.
#[derive(Debug)]
pub struct Datagram<'a> {
    /// Received bytes.
    pub bytes: &'a [u8],
    /// Original addressing and length.
    pub metadata: Metadata,
}
impl ReceivedPacket for Datagram<'_> {
    fn bytes(&self) -> &[u8] {
        self.bytes
    }
    fn metadata(&self) -> Metadata {
        self.metadata
    }
}
/// Independently borrowable receive and send halves of one datagram socket.
///
/// Splitting must preserve addressing, error classification and readiness hooks.
/// The application drives the network stack; the adapter owns no protocol tasks.
pub trait Transport {
    /// Transport-specific I/O or ICMP error.
    type Error;
    /// Cancellation-safe receiver.
    type Receiver<'a>: DatagramReceiver<Error = Self::Error>
    where
        Self: 'a;
    /// Nonblocking sender.
    type Sender<'a>: DatagramSender<Error = Self::Error>
    where
        Self: 'a;
    /// Borrows both directions without serializing reception behind transmission.
    fn split(&mut self) -> (Self::Receiver<'_>, Self::Sender<'_>);
}

/// Cancellation-safe whole-datagram reception.
/// Cancelling a pending receive must not consume a datagram.
pub trait DatagramReceiver {
    /// Transport-specific receive error.
    type Error;
    /// Transport-owned packet guard or scratch-buffer view.
    type Packet<'a>: ReceivedPacket
    where
        Self: 'a;
    /// Scratch storage; owned-packet receivers may return an empty array.
    /// Wrappers must forward this hook to preserve the driver's memory bound.
    fn receive_buffer<const DATAGRAM_BYTES: usize>() -> impl AsMut<[u8]> {
        [0; DATAGRAM_BYTES]
    }
    /// Whether an error discards only one datagram and permits another read.
    fn discard_receive_error(_: &Self::Error) -> bool {
        false
    }
    /// Receives one datagram, reporting its original size even if scratch is small.
    fn receive<'a>(
        &'a mut self,
        scratch: &'a mut [u8],
    ) -> impl Future<Output = Result<Self::Packet<'a>, Self::Error>>;
}

/// Result of one nonblocking whole-datagram send attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendOutcome {
    /// The network stack accepted the complete datagram.
    Accepted,
    /// Nothing was accepted, and no reliable readiness wakeup is available.
    /// The endpoint schedules a bounded exponential retry.
    RetryLater,
}

/// Nonblocking local datagram acceptance.
///
/// `Pending` means nothing was accepted and a readiness waker was registered.
/// `RetryLater` means nothing was accepted and the caller must schedule a retry.
/// Neither may self-wake merely because storage or the device is still busy.
/// Errors must leave the datagram unsent. Wrappers forward error classification.
pub trait DatagramSender {
    /// Transport-specific send error.
    type Error;
    /// Whether an error affects only this datagram. Socket failures remain fatal.
    fn discard_send_error(_: &Self::Error) -> bool {
        false
    }
    /// Attempts one datagram; `None` permits automatic source selection.
    fn poll_send(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        bytes: &[u8],
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<SendOutcome, Self::Error>>;
}

/// Optional ownership transfer for network-stack packet buffers.
///
/// `Pending`, `RetryLater` and errors must leave the original buffer in `packet`,
/// with identical bytes and metadata. Only acceptance consumes it. Retained
/// packets use [`DatagramSender::poll_send`] to preserve exact retry bytes.
pub trait OwnedDatagramSender<Buffer>: DatagramSender {
    /// Attempts to transfer one uniquely owned serialized datagram.
    fn poll_send_owned(
        &mut self,
        remote: SocketAddr,
        source: Option<IpAddr>,
        interface: Option<u32>,
        packet: &mut Option<Buffer>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<SendOutcome, Self::Error>>;
}

#[cfg(feature = "embassy-net")]
pub mod embassy;
#[cfg(feature = "embassy-net-xarxa")]
pub mod embassy_xarxa;
#[cfg(all(feature = "std", target_os = "linux"))]
pub mod linux;
#[cfg(feature = "_xarxa")]
pub mod xarxa;

#[cfg(all(
    any(feature = "log", feature = "defmt"),
    any(
        feature = "_xarxa",
        all(
            feature = "embassy-net",
            not(all(feature = "embassy-net-ipv4", feature = "embassy-net-ipv6"))
        )
    )
))]
fn warn_once(latch: &critical_section::Mutex<core::cell::Cell<bool>>, warning: impl FnOnce()) {
    let first = critical_section::with(|cs| !latch.borrow(cs).replace(true));
    // A logger may re-enter transport code.
    if first {
        warning();
    }
}

#[cfg(test)]
mod peer_tests {
    use super::*;
    use core::net::SocketAddrV6;

    #[test]
    fn multicast_zones_remain_part_of_peer_identity() {
        let address = |scope, flow| {
            SocketAddr::V6(SocketAddrV6::new(
                "ff02::fd".parse().unwrap(),
                5683,
                flow,
                scope,
            ))
        };
        assert_eq!(peer_address(address(2, 0)), peer_address(address(2, 7)));
        assert_ne!(peer_address(address(2, 0)), peer_address(address(3, 0)));
    }
}
