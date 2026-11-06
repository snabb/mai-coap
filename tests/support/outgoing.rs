#![allow(dead_code)]

use core::net::{IpAddr, SocketAddr};
use mai_coap::{
    Packet,
    endpoint::{Endpoint, Protection},
};

/// Owned snapshot of one outgoing datagram for protocol assertions.
#[derive(Debug)]
pub struct Outgoing<const DATAGRAM_BYTES: usize> {
    /// Remote destination.
    pub remote: SocketAddr,
    /// Selected local source address.
    pub source: Option<IpAddr>,
    /// Selected egress interface.
    pub interface: Option<u32>,
    /// Owned serialized bytes.
    pub packet: Packet<DATAGRAM_BYTES>,
}

/// Test adapter that copies the public borrowed outgoing view before completing it.
pub trait PopOutgoing<const DATAGRAM_BYTES: usize> {
    fn pop_outgoing(&mut self) -> Option<Outgoing<DATAGRAM_BYTES>>;
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
> PopOutgoing<DATAGRAM_BYTES>
    for Endpoint<
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
    >
{
    fn pop_outgoing(&mut self) -> Option<Outgoing<DATAGRAM_BYTES>> {
        let front = self.front_outgoing()?;
        let outgoing = Outgoing {
            remote: front.remote,
            source: front.source,
            interface: front.interface,
            packet: Packet::copy_from(front.bytes).ok()?,
        };
        self.complete_outgoing(
            self.front_outgoing()
                .map_or(mai_coap::time::Instant(0), |p| p.enqueued),
        );
        Some(outgoing)
    }
}
