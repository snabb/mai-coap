//! Heap-free CoAP layers, implemented from the RFCs listed in `docs/requirements.md`.
//!
//! [`codec`] provides borrowed messages and ordered, caller-buffer serialization
//! (MSG). [`messaging`] provides per-destination transmission profiles (REL).
//! [`transport`] and [`time`] are executor-independent extension points (TR, PLT).
//! Optional protocol modules are available only with their corresponding features.
//!
//! All protocol storage is bounded. Applications supply a critical-section
//! implementation on bare-metal targets and a cryptographically secure RNG.
//!
//! [`security`] defines authorization; [`crypto`] exposes the shared provider
//! contract and optional software implementation (AUT, CRY).
//! [`uri`] handles URI decomposition/composition; [`rate`] configures response budgets.
//!
//! Handlers and crypto calls run synchronously on the socket driver. Slow
//! application I/O uses deferred workers; the library does not spawn tasks.
//! The `std` transport and clock adapters require Linux; other hosts supply
//! [`transport::Transport`] and [`time::Clock`].
//!
//! Capacity names use bytes for buffers and entry counts for tables:
//!
//! | Const parameter | Meaning |
//! |---|---|
//! | `DATAGRAM_BYTES` | Maximum encoded datagram bytes |
//! | `OUTBOUND` | Shared exchange slots (client requests, deferred CON responses, CON notifications) |
//! | `COMMANDS`, `OUTBOUND_COMMANDS` | Shared command/result slots |
//! | `DEFERRED`, `BODY_CONTEXTS` | Deferred tickets and body epoch leases |
//! | `PACKETS` | Immutable datagram buffers shared by sends, retries and cached replies; below 65,535 |
//! | `DEDUP_ENTRIES`, `CACHED_REPLIES` | Duplicate records and references to full replies |
//! | `OBSERVERS`, `SEND_QUEUE` | Server observers and queued outgoing datagrams |
//! | `ROUTES`, `UPLOADS`, `UPLOAD_BYTES` | Router routes, live uploads and buffered body bytes |
//! | `JOBS`, `BODY_BYTES` | Deferred jobs and owned body bytes |
//! | `CONTEXTS`, `HANDSHAKES`, `CREDENTIALS` | Security and credential table entries |
//! | `FORWARDS` | Proxy forwarding entries |
//! | `MESSAGE_BYTES`, `BLOCK_BYTES`, `CAPACITY` | EDHOC message, saved block, or general buffer bytes |
//!
//! Supported lower layers include codec/URI, block-transfer primitives, standalone
//! OSCORE/EDHOC roles, Endpoint's `with_send_window` producer boundary and its
//! restricted `SendWindow` view, and manual receive/poll/send/deadline methods.
//! Endpoint reliability tables and Observe ordering/scheduling state are internal.
//! The hidden `_test-support` feature is unstable and intended only for repository
//! harnesses.
//!
//! Implementation tables cannot be imported through the application API:
//! ```compile_fail
//! use mai_coap::messaging::MessageIds;
//! ```
#![cfg_attr(
    feature = "server",
    doc = "Server routing and deferred work (SRV, API-7): [`server`]."
)]
#![cfg_attr(
    any(feature = "server", feature = "client"),
    doc = "The socket driver, supported manual-driver methods and cross-task handles (REL, API-4): [`endpoint`]."
)]
#![cfg_attr(
    feature = "block",
    doc = "Supported standalone Block2 downloads (`block`) and transactional uploads (`block1`) (BLK): [`block`]."
)]
#![cfg_attr(
    feature = "observe",
    doc = "Notification scheduling and ordering (OBS): [`observe`]."
)]
#![cfg_attr(
    feature = "link-format",
    doc = "Discovery representations (DSC): [`link_format`]."
)]
#![cfg_attr(
    feature = "proxy",
    doc = "Default-deny forward proxy (PRX): [`proxy`]."
)]
#![cfg_attr(
    feature = "oscore",
    doc = "End-to-end message protection (OSC): [`oscore`]."
)]
#![cfg_attr(
    feature = "edhoc",
    doc = "Key establishment through Lakers (EDH): [`edhoc`]."
)]
#![cfg_attr(
    feature = "software-crypto",
    doc = "Optional RustCrypto provider (CRY): [`crypto`]."
)]
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate self as mai_coap;
#[cfg(all(test, any(feature = "server", feature = "client")))]
#[path = "../tests/support/outgoing.rs"]
pub(crate) mod test_outgoing;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("log and defmt are mutually exclusive (PLT-8)");

#[cfg(all(
    feature = "embassy-net",
    not(any(feature = "embassy-net-ipv4", feature = "embassy-net-ipv6"))
))]
compile_error!("embassy-net requires embassy-net-ipv4 or embassy-net-ipv6 (TR-6)");

#[cfg(all(
    feature = "xarxa",
    not(any(feature = "xarxa-ipv4", feature = "xarxa-ipv6"))
))]
compile_error!("xarxa requires xarxa-ipv4 or xarxa-ipv6 (TR-6)");

#[cfg(all(
    feature = "embassy-net-xarxa",
    not(any(feature = "embassy-net-xarxa-ipv4", feature = "embassy-net-xarxa-ipv6"))
))]
compile_error!(
    "embassy-net-xarxa requires embassy-net-xarxa-ipv4 or embassy-net-xarxa-ipv6 (TR-6)"
);

#[cfg(feature = "_test-support")]
#[doc(hidden)]
#[path = "test_support.rs"]
pub mod __test_support;
#[cfg(feature = "block")]
pub mod block;
pub mod codec;
pub mod crypto;
#[cfg(feature = "edhoc")]
pub mod edhoc;
#[cfg(any(feature = "server", feature = "client"))]
pub mod endpoint;
#[cfg(feature = "link-format")]
pub mod link_format;
#[cfg(any(feature = "link-format", feature = "server"))]
mod link_format_validation;
pub mod messaging;
#[cfg(feature = "observe")]
pub mod observe;
#[cfg(feature = "oscore")]
pub mod oscore;
#[cfg(any(test, feature = "server", feature = "client"))]
mod packet_pool;
#[cfg(all(feature = "_xarxa", any(test, feature = "server", feature = "client")))]
pub use packet_pool::XarxaStorage;
#[cfg(any(test, feature = "server", feature = "client"))]
pub use packet_pool::{InlineStorage, OwnedPacketStorage, PacketStorage};
#[cfg(feature = "proxy")]
pub mod proxy;
pub mod rate;
pub mod security;
#[cfg(feature = "server")]
pub mod server;
pub mod time;
pub mod transport;
pub mod uri;

/// Default maximum UDP datagram length, in bytes (PLT-7).
pub const DEFAULT_DATAGRAM: usize = 1152;
/// Default number of cross-task command/result slots (PLT-7).
pub const DEFAULT_COMMANDS: usize = 8;
/// Default number of shared exchange slots for client requests, deferred CON
/// responses and CON notifications.
pub const DEFAULT_OUTBOUND: usize = 8;
/// Default number of incoming deduplication entries (PLT-7).
pub const DEFAULT_DEDUP: usize = 32;
/// Default number of server observers.
pub const DEFAULT_OBSERVERS: usize = 8;
/// Default number of full cached replies.
pub const DEFAULT_CACHED_REPLIES: usize = 8;
/// Default number of body epoch leases.
pub const DEFAULT_BODY_CONTEXTS: usize = 8;
/// Default number of queued outgoing datagrams, independent of exchange storage.
pub const DEFAULT_SEND_QUEUE: usize = 16;
/// Default total number of immutable serialized packet buffers.
pub const DEFAULT_PACKETS: usize = 40;

/// Protocol or application failure; transport errors retain their own type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[non_exhaustive]
pub enum Error {
    /// Malformed wire encoding.
    Malformed,
    /// Caller-provided buffer or compile-time capacity is exhausted.
    Capacity,
    /// Packet storage cannot accommodate the configured datagram size.
    InvalidStorage,
    /// Options were supplied in decreasing numeric order.
    OptionOrder,
    /// An exchange exhausted its retransmissions or response deadline.
    Timeout,
    /// A datagram was never accepted before its local send deadline.
    LocalSendTimeout,
    /// A datagram was rejected before its first local acceptance.
    LocalSendFailed,
    /// The peer rejected an exchange with RST.
    Reset,
    /// A peer returned an unsuccessful response.
    Response(codec::Code),
    /// Unauthenticated error received for a protected request; diagnostic only.
    UnprotectedResponse(codec::Code),
    /// An option is unrecognized at the receiving layer.
    BadOption(codec::OptionNumber),
    /// A message could not be authenticated or decrypted.
    Protection,
    /// A protected request was replayed.
    Replay,
    /// No matching security context exists.
    ContextNotFound,
    /// The sender sequence space is exhausted; rekeying is required.
    SequenceExhausted,
    /// Key establishment failed.
    Edhoc,
    /// A representation changed too often during a block transfer.
    RepresentationChanged,
    /// The operation was cancelled.
    Cancelled,
    /// An address scheme is unsupported.
    UnsupportedScheme,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Response(code) => write!(f, "peer response {}.{:02}", code.0 >> 5, code.0 & 31),
            Self::UnprotectedResponse(code) => {
                write!(f, "unprotected response {}.{:02}", code.0 >> 5, code.0 & 31)
            }
            Self::BadOption(number) => write!(f, "unrecognized option {}", number.0),
            Self::Malformed => f.write_str("malformed message"),
            Self::Capacity => f.write_str("capacity exhausted"),
            Self::InvalidStorage => f.write_str("invalid packet storage"),
            Self::OptionOrder => f.write_str("options out of order"),
            Self::LocalSendTimeout => f.write_str("local send timeout"),
            Self::LocalSendFailed => f.write_str("local send failed"),
            Self::Timeout => f.write_str("exchange timed out"),
            Self::Reset => f.write_str("exchange reset by peer"),
            Self::Protection => f.write_str("message protection failed"),
            Self::Replay => f.write_str("replayed request"),
            Self::ContextNotFound => f.write_str("security context not found"),
            Self::SequenceExhausted => f.write_str("sender sequence exhausted"),
            Self::Edhoc => f.write_str("key establishment failed"),
            Self::RepresentationChanged => f.write_str("representation changed"),
            Self::Cancelled => f.write_str("operation cancelled"),
            Self::UnsupportedScheme => f.write_str("unsupported URI scheme"),
        }
    }
}
impl core::error::Error for Error {}

/// Bounded packet storage shared by protocol layers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet<const CAPACITY: usize = DEFAULT_DATAGRAM> {
    bytes: heapless::Vec<u8, CAPACITY>,
}

impl<const CAPACITY: usize> Default for Packet<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> Packet<CAPACITY> {
    /// Creates an empty packet without allocating.
    pub const fn new() -> Self {
        Self {
            bytes: heapless::Vec::new(),
        }
    }
    /// Copies bytes into bounded storage, rejecting oversize input.
    pub fn copy_from(bytes: &[u8]) -> Result<Self, Error> {
        let mut packet = Self::new();
        packet
            .bytes
            .extend_from_slice(bytes)
            .map_err(|_| Error::Capacity)?;
        Ok(packet)
    }
    /// Returns the packet bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    /// Serializes directly into a new packet, without a separate scratch array.
    #[cfg(any(feature = "server", feature = "client"))]
    pub(crate) fn encoded(
        encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<Self, Error> {
        let mut packet = Self::new();
        packet
            .bytes
            .resize(CAPACITY, 0)
            .map_err(|_| Error::Capacity)?;
        let length = encode(&mut packet.bytes)?;
        packet.bytes.truncate(length);
        Ok(packet)
    }
    /// Replaces the messaging header in place; options and payload are unchanged.
    #[cfg(any(feature = "server", feature = "client"))]
    pub(crate) fn reheader(
        &mut self,
        ty: codec::MessageType,
        mid: u16,
        token: &[u8],
    ) -> Result<(), Error> {
        let length = self.bytes.len();
        // The old token length is known only after parsing; the rewrite reports overflow.
        let grown = length + token.len();
        self.bytes
            .resize(grown.min(CAPACITY), 0)
            .map_err(|_| Error::Capacity)?;
        let n = codec::reheader(&mut self.bytes, length, ty, mid, token)?;
        self.bytes.truncate(n);
        Ok(())
    }
}
