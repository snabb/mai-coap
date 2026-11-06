//! Bounded reliability primitives and deadline arithmetic (RFC 7252 §4).
use crate::Error;

/// Per-destination transmission parameters (REL-2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct TransmissionParameters {
    /// Base ACK timeout in milliseconds.
    pub ack_timeout_ms: u64,
    /// Randomization factor in thousandths; at least 1000.
    pub ack_random_factor: u32,
    /// Maximum number of retransmissions after the original send.
    pub max_retransmit: u8,
    /// Maximum simultaneous outstanding interactions with one destination.
    pub nstart: usize,
    /// Multicast leisure in milliseconds.
    pub leisure_ms: u64,
    /// Bytes per second for NON traffic without replies.
    pub probing_rate: u32,
    /// Maximum assumed one-way latency in milliseconds.
    pub max_latency_ms: u64,
}
impl Default for TransmissionParameters {
    fn default() -> Self {
        Self {
            ack_timeout_ms: 2000,
            ack_random_factor: 1500,
            max_retransmit: 4,
            nstart: 1,
            leisure_ms: 5000,
            probing_rate: 1,
            max_latency_ms: 100_000,
        }
    }
}
impl TransmissionParameters {
    /// Sets the base ACK timeout in milliseconds.
    pub const fn with_ack_timeout_ms(mut self, value: u64) -> Self {
        self.ack_timeout_ms = value;
        self
    }
    /// Sets the ACK randomization factor in thousandths.
    pub const fn with_ack_random_factor(mut self, value: u32) -> Self {
        self.ack_random_factor = value;
        self
    }
    /// Sets the maximum retransmission count.
    pub const fn with_max_retransmit(mut self, value: u8) -> Self {
        self.max_retransmit = value;
        self
    }
    /// Sets the per-destination concurrency limit.
    pub const fn with_nstart(mut self, value: usize) -> Self {
        self.nstart = value;
        self
    }
    /// Sets the multicast leisure in milliseconds.
    pub const fn with_leisure_ms(mut self, value: u64) -> Self {
        self.leisure_ms = value;
        self
    }
    /// Sets the NON probing rate in bytes per second.
    pub const fn with_probing_rate(mut self, value: u32) -> Self {
        self.probing_rate = value;
        self
    }
    /// Sets the assumed one-way latency in milliseconds.
    pub const fn with_max_latency_ms(mut self, value: u64) -> Self {
        self.max_latency_ms = value;
        self
    }
    /// Checks construction-time constraints and overflow of derived lifetimes.
    pub fn validate(self) -> Result<Self, Error> {
        if self.ack_timeout_ms == 0
            || self.ack_random_factor < 1000
            || self.max_retransmit > 30
            || self.nstart == 0
            || self.probing_rate == 0
        {
            return Err(Error::Malformed);
        }
        let factor = (1u64 << (self.max_retransmit + 1)) - 1;
        self.ack_timeout_ms
            .checked_mul(factor)
            .and_then(|n| n.checked_mul(self.ack_random_factor.into()))
            .and_then(|n| n.checked_add(self.max_latency_ms.checked_mul(2000)?))
            .ok_or(Error::Malformed)?;
        Ok(self)
    }
    /// Upper bound on the time between initial transmission and last retry.
    pub fn max_transmit_span(self) -> u64 {
        self.ack_timeout_ms
            .saturating_mul((1u64 << self.max_retransmit.min(30)) - 1)
            .saturating_mul(self.ack_random_factor.into())
            / 1000
    }
    /// Upper bound on the total retransmission waiting period.
    pub fn max_transmit_wait(self) -> u64 {
        self.ack_timeout_ms
            .saturating_mul((1u64 << (self.max_retransmit.min(30) + 1)) - 1)
            .saturating_mul(self.ack_random_factor.into())
            / 1000
    }
    /// Derived CON duplicate and message-ID lifetime.
    pub fn exchange_lifetime(self) -> u64 {
        self.max_transmit_span()
            .saturating_add(self.max_latency_ms.saturating_mul(2))
            .saturating_add(self.ack_timeout_ms)
    }
    /// Derived NON duplicate lifetime.
    pub fn non_lifetime(self) -> u64 {
        self.max_transmit_span().saturating_add(self.max_latency_ms)
    }
    /// Random initial timeout from a uniformly distributed RNG word.
    pub fn initial_timeout(self, random: u32) -> u64 {
        let extra = self
            .ack_timeout_ms
            .saturating_mul(u64::from(self.ack_random_factor.saturating_sub(1000)))
            / 1000;
        self.ack_timeout_ms
            .saturating_add(((u128::from(random) * u128::from(extra + 1)) >> 32) as u64)
    }
}

#[cfg(any(test, feature = "server", feature = "client"))]
pub(crate) mod internal {
    use crate::{
        Error,
        packet_pool::{PacketPool, PacketRef, PacketStorage},
        time::Instant,
    };
    use core::net::SocketAddr;

    /// Bounded pacing of NON requests until a destination answers (REL-5).
    /// A destination's first datagram is admitted; unanswered bytes delay later sends.
    #[cfg(any(feature = "server", feature = "client"))]
    pub struct Probing<const DESTINATIONS: usize> {
        destinations: heapless::Vec<(SocketAddr, Instant), DESTINATIONS>,
    }
    #[cfg(any(feature = "server", feature = "client"))]
    impl<const DESTINATIONS: usize> Probing<DESTINATIONS> {
        /// Starts with no unanswered destinations.
        pub const fn new() -> Self {
            Self {
                destinations: heapless::Vec::new(),
            }
        }
        /// Whether this destination can send now, including table admission.
        #[cfg(feature = "client")]
        pub fn allowed(&self, remote: SocketAddr, now: Instant) -> bool {
            self.destinations
                .iter()
                .find(|(p, _)| crate::transport::same_peer(*p, remote))
                .map_or_else(
                    || {
                        !self.destinations.is_full()
                            || self.destinations.iter().any(|(_, t)| *t <= now)
                    },
                    |(_, t)| *t <= now,
                )
        }
        /// Records an admitted datagram at the configured byte rate.
        #[cfg(feature = "client")]
        pub fn sent(
            &mut self,
            remote: SocketAddr,
            bytes: usize,
            rate: u32,
            now: Instant,
        ) -> Result<(), Error> {
            if rate == 0 || !self.allowed(remote, now) {
                return Err(Error::Capacity);
            }
            self.answered(remote);
            if self.destinations.is_full() {
                let index = self
                    .destinations
                    .iter()
                    .position(|(_, t)| *t <= now)
                    .ok_or(Error::Capacity)?;
                self.destinations.swap_remove(index);
            }
            let delay = (bytes as u64)
                .saturating_mul(1000)
                .div_ceil(u64::from(rate));
            self.destinations
                .push((remote, now.after(delay)))
                .map_err(|_| Error::Capacity)
        }
        /// Shifts reserved NON pacing to the actual first transport acceptance.
        pub(crate) fn accepted(&mut self, remote: SocketAddr, delay: u64) {
            if let Some((_, until)) = self
                .destinations
                .iter_mut()
                .find(|(p, _)| crate::transport::same_peer(*p, remote))
            {
                *until = until.after(delay);
            }
        }
        /// A matched response restores the destination's normal request admission.
        pub fn answered(&mut self, remote: SocketAddr) {
            if let Some(i) = self
                .destinations
                .iter()
                .position(|(p, _)| crate::transport::same_peer(*p, remote))
            {
                self.destinations.swap_remove(i);
            }
        }
        /// Future pacing deadlines, for an executor-independent timer.
        pub fn deadlines(&self, now: Instant) -> impl Iterator<Item = Instant> + '_ {
            self.destinations
                .iter()
                .map(|(_, t)| *t)
                .filter(move |t| *t > now)
        }
    }

    /// Reply state of a duplicate record.
    #[derive(Debug)]
    pub enum CachedReply {
        /// The request was processed without a reply.
        Silent,
        /// Reply bytes were reclaimed while the duplicate record remains live.
        Dropped,
        /// A reply of up to four bytes, including an empty ACK.
        Inline {
            /// Reply storage; bytes past `len` are unused.
            bytes: [u8; 4],
            /// Reply length.
            len: u8,
        },
        /// A cache-owned reference to a full serialized reply in the packet pool.
        Full(PacketRef),
    }
    impl CachedReply {
        /// Stores a reply of at most four bytes inline.
        pub fn inline(reply: &[u8]) -> Result<Self, Error> {
            let mut bytes = [0; 4];
            bytes
                .get_mut(..reply.len())
                .ok_or(Error::Capacity)?
                .copy_from_slice(reply);
            Ok(Self::Inline {
                bytes,
                len: reply.len() as u8,
            })
        }
    }
    // Cache identity already discards flow information; keep only canonical
    // address/port/zone fields rather than SocketAddr's full transport layout.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct DuplicatePeer {
        address: core::net::IpAddr,
        port: u16,
        zone: u32,
    }
    impl From<SocketAddr> for DuplicatePeer {
        fn from(peer: SocketAddr) -> Self {
            let peer = crate::transport::peer_address(peer);
            Self {
                address: peer.ip(),
                port: peer.port(),
                zone: match peer {
                    SocketAddr::V4(_) => 0,
                    SocketAddr::V6(address) => address.scope_id(),
                },
            }
        }
    }
    #[derive(Debug)]
    struct Duplicate {
        peer: DuplicatePeer,
        local: core::net::IpAddr,
        id: u16,
        until: Instant,
        reply: CachedReply,
    }
    /// Live cache state reclaimed during one successful admission.
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct CachePressure {
        /// A duplicate record was evicted, releasing any associated reply.
        pub record_evicted: bool,
        /// Reply bytes were discarded while their duplicate record was retained.
        pub reply_dropped: bool,
    }
    /// Selects which cached replies may be discarded during reclamation.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum ReplyReclaimMode {
        /// Any cached reply can be dropped to satisfy the configured reply count.
        CacheBudget,
        /// Only an unshared reply can be dropped to free a packet-pool slot.
        FreePacket,
    }
    /// Incoming CON/NON duplicate table with bounded records and full-reply references.
    /// Replies of up to four bytes are stored inline, including empty ACKs. Record
    /// pressure evicts the oldest record. Full-reply pressure prefers the oldest
    /// reply from the same remote/local endpoint, then the oldest globally, while
    /// retaining its duplicate record. Expiry releases cache-owned references.
    #[derive(Debug)]
    pub struct Deduplication<
        const DEDUP_ENTRIES: usize,
        const CACHED_REPLIES: usize = DEDUP_ENTRIES,
    > {
        entries: heapless::Vec<Duplicate, DEDUP_ENTRIES>,
    }
    impl<const DEDUP_ENTRIES: usize, const CACHED_REPLIES: usize> Default
        for Deduplication<DEDUP_ENTRIES, CACHED_REPLIES>
    {
        fn default() -> Self {
            Self::new()
        }
    }
    impl<const DEDUP_ENTRIES: usize, const CACHED_REPLIES: usize>
        Deduplication<DEDUP_ENTRIES, CACHED_REPLIES>
    {
        /// Empty bounded duplicate table.
        pub const fn new() -> Self {
            Self {
                entries: heapless::Vec::new(),
            }
        }
        /// Distinguishes live replies, reclaimed replies, intentional silence and a miss.
        // Share canonicalization and cache search across receive/replay paths.
        #[inline(never)]
        pub fn lookup(
            &self,
            peer: SocketAddr,
            local: core::net::IpAddr,
            id: u16,
            now: Instant,
        ) -> Option<&CachedReply> {
            let peer = DuplicatePeer::from(peer);
            self.entries
                .iter()
                .find(|e| e.peer == peer && e.local == local && e.id == id && e.until > now)
                .map(|e| &e.reply)
        }
        /// Releases all records whose duplicate lifetime has ended.
        pub fn expire<const D: usize, const PACKETS: usize, S: PacketStorage<D, PACKETS>>(
            &mut self,
            pool: &mut PacketPool<D, PACKETS, S>,
            now: Instant,
        ) {
            let mut i = 0;
            while i < self.entries.len() {
                if self.entries[i].until <= now {
                    Self::release_reply(pool, self.entries.remove(i).reply);
                } else {
                    i += 1;
                }
            }
        }
        fn release_reply<const D: usize, const PACKETS: usize, S: PacketStorage<D, PACKETS>>(
            pool: &mut PacketPool<D, PACKETS, S>,
            reply: CachedReply,
        ) {
            if let CachedReply::Full(packet) = reply {
                pool.release(packet);
            }
        }
        /// Drops an eligible full reply, preferring a matching peer and local address.
        pub fn reclaim_reply<const D: usize, const PACKETS: usize, S: PacketStorage<D, PACKETS>>(
            &mut self,
            pool: &mut PacketPool<D, PACKETS, S>,
            preferred: Option<(SocketAddr, core::net::IpAddr)>,
            mode: ReplyReclaimMode,
        ) -> bool {
            let eligible = |entry: &Duplicate| match &entry.reply {
                CachedReply::Full(packet) => match mode {
                    ReplyReclaimMode::CacheBudget => true,
                    ReplyReclaimMode::FreePacket => pool.reference_count(packet) == 1,
                },
                _ => false,
            };
            let preferred = preferred.map(|(peer, local)| (DuplicatePeer::from(peer), local));
            let candidate = preferred
                .and_then(|(peer, local)| {
                    self.entries.iter().position(|entry| {
                        entry.peer == peer && entry.local == local && eligible(entry)
                    })
                })
                .or_else(|| self.entries.iter().position(eligible));
            let Some(index) = candidate else {
                return false;
            };
            let reply = core::mem::replace(&mut self.entries[index].reply, CachedReply::Dropped);
            Self::release_reply(pool, reply);
            true
        }
        /// Counts cached replies whose sole reference can be reclaimed for admission.
        #[cfg(any(feature = "server", feature = "client"))]
        pub(crate) fn reclaimable_replies<
            const D: usize,
            const PACKETS: usize,
            S: PacketStorage<D, PACKETS>,
        >(
            &self,
            pool: &PacketPool<D, PACKETS, S>,
        ) -> usize {
            self.entries
                .iter()
                .filter(|entry| match &entry.reply {
                    CachedReply::Full(packet) => pool.reference_count(packet) == 1,
                    _ => false,
                })
                .count()
        }

        /// Records an incoming message and transfers any full-reply reference to the cache.
        ///
        /// A full-reply reference is released on every error, and failed admission leaves
        /// records unchanged. Expiry is applied only after admission checks succeed.
        #[expect(
            clippy::too_many_arguments,
            reason = "cache identity, lifetime and pool ownership are explicit"
        )]
        pub fn remember<const D: usize, const PACKETS: usize, S: PacketStorage<D, PACKETS>>(
            &mut self,
            pool: &mut PacketPool<D, PACKETS, S>,
            peer: SocketAddr,
            local: core::net::IpAddr,
            id: u16,
            until: Instant,
            reply: CachedReply,
            now: Instant,
        ) -> Result<CachePressure, Error> {
            if DEDUP_ENTRIES == 0 || CACHED_REPLIES == 0 && matches!(reply, CachedReply::Full(_)) {
                Self::release_reply(pool, reply);
                return Err(Error::Capacity);
            }
            let canonical_peer = DuplicatePeer::from(peer);
            self.expire(pool, now);
            let existing = self
                .entries
                .iter()
                .position(|e| e.peer == canonical_peer && e.local == local && e.id == id);
            let mut pressure = CachePressure::default();
            if existing.is_none() && self.entries.is_full() {
                Self::release_reply(pool, self.entries.remove(0).reply);
                pressure.record_evicted = true;
            }
            if matches!(reply, CachedReply::Full(_)) {
                let replaces_full =
                    existing.is_some_and(|i| matches!(self.entries[i].reply, CachedReply::Full(_)));
                let full_count = self
                    .entries
                    .iter()
                    .filter(|entry| matches!(entry.reply, CachedReply::Full(_)))
                    .count();
                if !replaces_full && full_count >= CACHED_REPLIES {
                    if !self.reclaim_reply(pool, Some((peer, local)), ReplyReclaimMode::CacheBudget)
                    {
                        Self::release_reply(pool, reply);
                        return Err(Error::Capacity);
                    }
                    pressure.reply_dropped = true;
                }
            }
            let entry = Duplicate {
                peer: canonical_peer,
                local,
                id,
                until,
                reply,
            };
            if let Some(i) = existing {
                let old = core::mem::replace(&mut self.entries[i], entry);
                Self::release_reply(pool, old.reply);
            } else {
                self.entries.push(entry).map_err(|_| Error::Capacity)?;
            }
            Ok(pressure)
        }
    }
}
#[cfg(any(feature = "server", feature = "client"))]
pub(crate) use internal::{Deduplication, Probing};

#[cfg(test)]
#[path = "messaging/tests.rs"]
mod tests;

#[cfg(kani)]
mod proofs;

#[cfg(any(test, feature = "server", feature = "client", kani))]
mod retransmission;
#[cfg(any(feature = "server", feature = "client"))]
pub(crate) use {ids::MessageIds, retransmission::Retransmission};

#[cfg(any(test, feature = "server", feature = "client", kani))]
mod ids;
