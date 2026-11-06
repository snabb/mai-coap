use super::{OwnedPacketStorage, PacketStorage};
use crate::Error;
use crate::transport::xarxa::payload_capacity;
use ::xarxa::driver::PacketBuf;
use zeroize::Zeroize;

/// Bounded packet storage backed by the xarxa network pool.
///
/// The allocator must return empty transmit buffers with the UDP socket's required
/// headroom already reserved. It must release any network-stack borrow before
/// returning. Buffers must accommodate `DATAGRAM_BYTES` after their headroom;
/// an undersized buffer is released and reported as [`Error::InvalidStorage`].
pub struct XarxaStorage<F, const PACKETS: usize> {
    allocate: F,
    buffers: [Option<PacketBuf>; PACKETS],
}

impl<F, const N: usize> core::fmt::Debug for XarxaStorage<F, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("XarxaStorage")
            .field(
                "allocated",
                &self
                    .buffers
                    .iter()
                    .filter(|buffer| buffer.is_some())
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

impl<F, const N: usize> XarxaStorage<F, N> {
    /// Creates storage without allocating any packet buffers.
    pub const fn new(allocate: F) -> Self {
        Self {
            allocate,
            buffers: [const { None }; N],
        }
    }

    fn clear(buffer: &mut PacketBuf) {
        buffer.iter_mut().for_each(Zeroize::zeroize);
        buffer.set_len(0);
    }
}

impl<F: FnMut() -> Option<PacketBuf>, const D: usize, const N: usize> PacketStorage<D, N>
    for XarxaStorage<F, N>
{
    fn allocate(&mut self, slot: usize) -> Result<(), Error> {
        let cell = self.buffers.get_mut(slot).ok_or(Error::InvalidStorage)?;
        if cell.is_some() {
            return Err(Error::InvalidStorage);
        }
        let mut buffer = (self.allocate)().ok_or(Error::Capacity)?;
        let capacity = payload_capacity(&buffer).ok_or(Error::InvalidStorage)?;
        Self::clear(&mut buffer);
        if capacity < D {
            return Err(Error::InvalidStorage);
        }
        *cell = Some(buffer);
        Ok(())
    }

    fn bytes(&self, slot: usize) -> Option<&[u8]> {
        self.buffers.get(slot)?.as_deref()
    }

    fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > D {
            return Err(Error::Capacity);
        }
        let buffer = self
            .buffers
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Cancelled)?;
        let capacity = payload_capacity(buffer).ok_or(Error::InvalidStorage)?;
        if bytes.len() > capacity {
            return Err(Error::Capacity);
        }
        Self::clear(buffer);
        buffer.set_len(bytes.len());
        buffer.copy_from_slice(bytes);
        Ok(())
    }

    fn encode<R>(
        &mut self,
        slot: usize,
        encode: impl FnOnce(&mut [u8]) -> Result<(usize, R), Error>,
    ) -> Result<R, Error> {
        let buffer = self
            .buffers
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Cancelled)?;
        let capacity = payload_capacity(buffer).ok_or(Error::InvalidStorage)?;
        if capacity < D {
            return Err(Error::InvalidStorage);
        }
        Self::clear(buffer);
        buffer.set_len(D);
        match encode(buffer) {
            Ok((len, result)) if len <= D => {
                buffer[len..].zeroize();
                buffer.set_len(len);
                Ok(result)
            }
            result => {
                Self::clear(buffer);
                Err(result.err().unwrap_or(Error::Capacity))
            }
        }
    }

    fn release(&mut self, slot: usize) {
        if let Some(mut buffer) = self.buffers.get_mut(slot).and_then(Option::take) {
            Self::clear(&mut buffer);
        }
    }
}

impl<F: FnMut() -> Option<PacketBuf>, const D: usize, const N: usize> OwnedPacketStorage<D, N>
    for XarxaStorage<F, N>
{
    type Buffer = PacketBuf;

    fn buffer_mut(&mut self, slot: usize) -> Option<&mut Option<Self::Buffer>> {
        self.buffers.get_mut(slot)
    }
}

impl<F, const N: usize> Drop for XarxaStorage<F, N> {
    fn drop(&mut self) {
        for cell in &mut self.buffers {
            if let Some(mut buffer) = cell.take() {
                Self::clear(&mut buffer);
            }
        }
    }
}
