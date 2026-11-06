//! Bounded storage for serialized datagrams shared by endpoint state.
use crate::{Error, Packet};
use core::num::NonZeroU16;

use zeroize::Zeroize;

/// Owns one reference to a packet-pool slot; release it through [`PacketPool::release`].
///
/// The handle is deliberately neither `Copy` nor `Clone`; another owner must be
/// acquired through [`PacketPool::retain`].
#[must_use = "packet references must be transferred or released through their pool"]
#[derive(Debug, Eq, PartialEq)]
pub struct PacketRef {
    // One-based slots provide the niche. The linear, non-Clone handle keeps a slot's
    // reference count nonzero, so it cannot observe a later reuse of that slot.
    slot: NonZeroU16,
}
impl PacketRef {
    fn slot(&self) -> usize {
        usize::from(self.slot.get() - 1)
    }
}

/// Bounded backing storage for a packet pool.
///
/// Slots are indexed below `PACKETS`. An allocated slot must expose at most
/// `DATAGRAM_BYTES` initialized payload bytes. Encoding receives exactly that
/// much writable space and commits only the returned length. Failed encoding
/// leaves an empty packet. Oversized writes leave existing bytes unchanged.
/// Release must tolerate an empty slot. Erase previous payload bytes before
/// overwriting or releasing storage, including failed encodes and unused suffixes.
pub trait PacketStorage<const DATAGRAM_BYTES: usize, const PACKETS: usize> {
    /// Allocates one empty slot; failure must leave it empty without an allocation.
    /// `Capacity` means temporary exhaustion; other errors
    /// describe invalid storage and must not invite cache reclamation or retry.
    fn allocate(&mut self, slot: usize) -> Result<(), Error>;
    /// Borrows an allocated slot's serialized payload.
    fn bytes(&self, slot: usize) -> Option<&[u8]>;
    /// Replaces an allocated slot's payload.
    fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Serializes directly into an allocated slot.
    fn encode<R>(
        &mut self,
        slot: usize,
        encode: impl FnOnce(&mut [u8]) -> Result<(usize, R), Error>,
    ) -> Result<R, Error>;
    /// Releases a slot and any backing allocation.
    fn release(&mut self, slot: usize);
}

/// Storage whose uniquely owned buffers can be transferred to a transport.
pub trait OwnedPacketStorage<const DATAGRAM_BYTES: usize, const PACKETS: usize>:
    PacketStorage<DATAGRAM_BYTES, PACKETS>
{
    /// The network stack's owned transmit buffer.
    type Buffer;
    /// Borrows a slot's ownership cell; failed or pending sends must restore it.
    fn buffer_mut(&mut self, slot: usize) -> Option<&mut Option<Self::Buffer>>;
}

/// Inline backing storage used by default, without network-pool dependencies.
#[derive(Debug)]
pub struct InlineStorage<const DATAGRAM_BYTES: usize, const PACKETS: usize> {
    packets: [Packet<DATAGRAM_BYTES>; PACKETS],
}

impl<const D: usize, const N: usize> InlineStorage<D, N> {
    /// Creates empty bounded storage without allocating.
    pub const fn new() -> Self {
        Self {
            packets: [const { Packet::new() }; N],
        }
    }

    fn clear(packet: &mut Packet<D>) {
        packet.bytes.as_mut_slice().zeroize();
        packet.bytes.clear();
    }
}

impl<const D: usize, const N: usize> Default for InlineStorage<D, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize, const N: usize> PacketStorage<D, N> for InlineStorage<D, N> {
    fn allocate(&mut self, slot: usize) -> Result<(), Error> {
        let packet = self.packets.get_mut(slot).ok_or(Error::InvalidStorage)?;
        Self::clear(packet);
        Ok(())
    }

    fn bytes(&self, slot: usize) -> Option<&[u8]> {
        self.packets.get(slot).map(Packet::as_slice)
    }

    fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > D {
            return Err(Error::Capacity);
        }
        let packet = self.packets.get_mut(slot).ok_or(Error::Cancelled)?;
        Self::clear(packet);
        packet
            .bytes
            .extend_from_slice(bytes)
            .map_err(|_| Error::Capacity)
    }

    fn encode<R>(
        &mut self,
        slot: usize,
        encode: impl FnOnce(&mut [u8]) -> Result<(usize, R), Error>,
    ) -> Result<R, Error> {
        let packet = self.packets.get_mut(slot).ok_or(Error::Cancelled)?;
        Self::clear(packet);
        packet.bytes.resize(D, 0).map_err(|_| Error::Capacity)?;
        match encode(packet.bytes.as_mut_slice()) {
            Ok((len, result)) if len <= D => {
                packet.bytes[len..].zeroize();
                packet.bytes.truncate(len);
                Ok(result)
            }
            result => {
                Self::clear(packet);
                Err(result.err().unwrap_or(Error::Capacity))
            }
        }
    }

    fn release(&mut self, slot: usize) {
        if let Some(packet) = self.packets.get_mut(slot) {
            Self::clear(packet);
        }
    }
}

/// Fixed-capacity packet storage with reference-counted shared handles.
#[derive(Debug)]
pub struct PacketPool<
    const DATAGRAM_BYTES: usize,
    const PACKETS: usize,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS> = InlineStorage<DATAGRAM_BYTES, PACKETS>,
> {
    references: [u16; PACKETS],
    storage: S,
}

impl<const D: usize, const N: usize> Default for PacketPool<D, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize, const N: usize> PacketPool<D, N> {
    /// Creates an empty inline pool without allocating.
    pub const fn new() -> Self {
        Self::with_storage(InlineStorage::new())
    }
}

impl<const D: usize, const N: usize, S: PacketStorage<D, N>> PacketPool<D, N, S> {
    /// Creates an empty pool using caller-provided backing storage.
    pub const fn with_storage(storage: S) -> Self {
        const { assert!(N < u16::MAX as usize) };
        Self {
            references: [0; N],
            storage,
        }
    }

    /// Number of unused logical slots; backing allocation can still fail.
    pub fn available(&self) -> usize {
        self.references.iter().filter(|count| **count == 0).count()
    }

    /// Reserves an empty packet slot for one owner.
    pub fn reserve(&mut self) -> Result<PacketRef, Error> {
        let index = self
            .references
            .iter()
            .position(|count| *count == 0)
            .ok_or(Error::Capacity)?;
        self.storage.allocate(index)?;
        self.references[index] = 1;
        Ok(PacketRef {
            slot: NonZeroU16::MIN.saturating_add(index as u16),
        })
    }

    /// Writes bytes into a uniquely owned reservation.
    pub fn write(&mut self, packet: &PacketRef, bytes: &[u8]) -> Result<(), Error> {
        let slot = packet.slot();
        if self.references[slot] != 1 || bytes.len() > D {
            return Err(Error::Capacity);
        }
        self.storage.write(slot, bytes)
    }

    /// Serializes directly into a uniquely owned reservation.
    ///
    /// A failed encoder or invalid returned length clears the slot's payload.
    pub fn encode<R>(
        &mut self,
        packet: &PacketRef,
        encode: impl FnOnce(&mut [u8]) -> Result<(usize, R), Error>,
    ) -> Result<R, Error> {
        let slot = packet.slot();
        if self.references[slot] != 1 {
            return Err(Error::Capacity);
        }
        self.storage.encode(slot, encode)
    }

    /// Borrows bytes while the caller holds a live reference.
    pub fn get(&self, packet: &PacketRef) -> Option<&[u8]> {
        self.storage.bytes(packet.slot())
    }

    /// Returns the current owner count for a live reference.
    pub fn reference_count(&self, packet: &PacketRef) -> usize {
        self.references[packet.slot()].into()
    }

    /// Acquires another owner of a live packet.
    pub fn retain(&mut self, packet: &PacketRef) -> Result<PacketRef, Error> {
        let slot = packet.slot();
        self.references[slot] = self.references[slot]
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        Ok(PacketRef { slot: packet.slot })
    }

    /// Releases one owner.
    pub fn release(&mut self, packet: PacketRef) {
        let slot = packet.slot();
        self.references[slot] -= 1;
        if self.references[slot] == 0 {
            self.storage.release(slot);
        }
    }
}

impl<const D: usize, const N: usize, S: OwnedPacketStorage<D, N>> PacketPool<D, N, S> {
    /// Borrows transport ownership only when no cache or exchange shares the packet.
    #[cfg(any(feature = "server", feature = "client", feature = "_xarxa"))]
    pub fn owned_buffer(&mut self, packet: &PacketRef) -> Option<&mut Option<S::Buffer>> {
        if self.reference_count(packet) != 1 {
            return None;
        }
        self.storage.buffer_mut(packet.slot())
    }
}

impl<const D: usize, const N: usize, S: PacketStorage<D, N>> Drop for PacketPool<D, N, S> {
    fn drop(&mut self) {
        for index in 0..N {
            self.storage.release(index);
        }
    }
}

#[cfg(feature = "_xarxa")]
#[path = "packet_pool/xarxa.rs"]
mod xarxa;
#[cfg(feature = "_xarxa")]
pub use xarxa::XarxaStorage;

#[cfg(test)]
#[path = "packet_pool/tests.rs"]
mod tests;
