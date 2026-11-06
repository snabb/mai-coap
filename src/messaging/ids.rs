//! Bounded message-ID reuse quarantine (REL-1).
use crate::{Error, time::Instant};

/// Message-ID generator with bounded reuse quarantine (REL-1).
#[derive(Debug)]
pub struct MessageIds {
    next: u16,
    seed: u16,
    reusable: [Instant; 16],
}
impl MessageIds {
    /// Seeds the endpoint's monotonically increasing identifier sequence.
    pub const fn new(random: u16) -> Self {
        Self {
            next: random,
            seed: random,
            reusable: [Instant(0); 16],
        }
    }
    /// Allocates an ID or reports capacity until rollover is safe.
    pub fn allocate(&mut self, now: Instant, lifetime: u64) -> Result<u16, Error> {
        if !self.available(now) {
            return Err(Error::Capacity);
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        self.quarantine(id, now.after(lifetime));
        Ok(id)
    }
    /// Extends an issued ID's hold when preparation postpones its send window.
    pub(crate) fn quarantine(&mut self, id: u16, until: Instant) {
        // Blocks are relative to the seed, so every seed permits a full first cycle.
        let block = usize::from(id.wrapping_sub(self.seed) >> 12);
        self.reusable[block] = self.reusable[block].max(until);
    }
    pub(crate) fn available(&self, now: Instant) -> bool {
        self.reusable_at().is_none_or(|deadline| now >= deadline)
    }
    pub(crate) fn reusable_at(&self) -> Option<Instant> {
        let offset = self.next.wrapping_sub(self.seed);
        (offset & 0xfff == 0).then_some(self.reusable[usize::from(offset >> 12)])
    }
    #[cfg(any(test, kani))]
    pub(super) fn reentering_block(seed: u16, id: u16) -> Self {
        // Use wider modular arithmetic as an independent model of the block cursor.
        let offset = (65536 + u32::from(id) - u32::from(seed)) % 65536;
        let start = (u32::from(seed) + offset / 4096 * 4096) % 65536;
        Self {
            next: start as u16,
            ..Self::new(seed)
        }
    }
}
