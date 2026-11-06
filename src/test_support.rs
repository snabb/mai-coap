//! Unstable access for this repository's fuzz and target harnesses.
//! This feature is outside the supported public API and may change without notice.

#[cfg(feature = "observe")]
pub use crate::observe::internal::Ordering;
pub use crate::{
    messaging::internal::{CachedReply, Deduplication},
    packet_pool::{PacketPool, PacketRef},
};

pub fn reheader(
    bytes: &mut [u8],
    length: usize,
    ty: crate::codec::MessageType,
    mid: u16,
    token: &[u8],
) -> Result<usize, crate::Error> {
    crate::codec::reheader(bytes, length, ty, mid, token)
}

#[cfg(feature = "edhoc")]
pub fn combined_message_3_length(payload: &[u8]) -> Result<usize, crate::Error> {
    crate::edhoc::combined_message_3_length(payload)
}
#[cfg(feature = "edhoc")]
pub fn sequential_message_3(payload: &[u8]) -> Result<(lakers::ConnId, &[u8]), crate::Error> {
    crate::edhoc::sequential_message_3(payload)
}
#[cfg(feature = "proxy")]
pub fn prepare<const DATAGRAM_BYTES: usize>(
    request: crate::codec::MessageView<'_>,
    requester: core::net::SocketAddr,
    routing: &impl crate::proxy::Routing,
    output: &mut [u8; DATAGRAM_BYTES],
) -> Result<(core::net::SocketAddr, usize), crate::codec::Code> {
    crate::proxy::prepare(request, requester, routing, output)
}
