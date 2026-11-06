//! Bounded per-IP and aggregate token buckets for unprotected response work.
use crate::Error;

/// Unprotected request budgets. Limits count responses, independent of UDP source port.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// Sustained responses per second from one source IP.
    pub per_source: u32,
    /// Maximum accumulated source credit.
    pub source_burst: u32,
    /// Sustained responses per second across all sources.
    pub overall: u32,
    /// Maximum accumulated aggregate credit.
    pub overall_burst: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            per_source: 4,
            source_burst: 128,
            overall: 32,
            overall_burst: 512,
        }
    }
}
impl Limits {
    /// Sets the sustained responses per second per IP.
    pub const fn with_per_source(mut self, value: u32) -> Self {
        self.per_source = value;
        self
    }
    /// Sets the per-IP burst credit.
    pub const fn with_source_burst(mut self, value: u32) -> Self {
        self.source_burst = value;
        self
    }
    /// Sets the aggregate sustained responses per second.
    pub const fn with_overall(mut self, value: u32) -> Self {
        self.overall = value;
        self
    }
    /// Sets the aggregate burst credit.
    pub const fn with_overall_burst(mut self, value: u32) -> Self {
        self.overall_burst = value;
        self
    }
    /// Rejects budgets that could never admit a response.
    pub fn validate(self) -> Result<Self, Error> {
        if self.per_source == 0
            || self.source_burst == 0
            || self.overall == 0
            || self.overall_burst == 0
        {
            return Err(Error::Malformed);
        }
        Ok(self)
    }
}
#[cfg(any(test, feature = "server", feature = "client"))]
pub(crate) mod internal {
    use super::Limits;
    use crate::{Error, time::Instant};
    use core::net::IpAddr;
    #[derive(Clone, Copy)]
    struct Bucket {
        credit: u64,
    }
    impl Bucket {
        fn new(burst: u32) -> Self {
            Self {
                credit: u64::from(burst) * 1000,
            }
        }
        fn refill(&mut self, elapsed: u64, rate: u32, burst: u32) {
            self.credit = self
                .credit
                .saturating_add(elapsed.saturating_mul(rate.into()))
                .min(u64::from(burst) * 1000);
        }
    }
    /// Admission state with bounded per-IP credit and an aggregate response budget.
    /// Table pressure evicts the source with the most credit; the aggregate budget
    /// remains enforced when sources rotate.
    /// IPv6 neighbors keep independent source credit rather than sharing a /64 bucket.
    pub struct Limiter<const SOURCES: usize = 16> {
        limits: Limits,
        total: Bucket,
        updated: Instant,
        sources: heapless::Vec<(IpAddr, Bucket), SOURCES>,
    }
    impl<const SOURCES: usize> Limiter<SOURCES> {
        /// Creates an empty limiter with full initial burst credit.
        pub fn new(limits: Limits) -> Result<Self, Error> {
            const { assert!(SOURCES > 0) };
            let limits = limits.validate()?;
            Ok(Self {
                limits,
                total: Bucket::new(limits.overall_burst),
                updated: Instant(0),
                sources: heapless::Vec::new(),
            })
        }
        /// Charges one response opportunity, returning false when it must be dropped.
        pub fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
            // Every admission refills all buckets, so their timestamps are identical.
            let elapsed = now.elapsed_since(self.updated);
            self.updated = now;
            self.total
                .refill(elapsed, self.limits.overall, self.limits.overall_burst);
            for (_, bucket) in &mut self.sources {
                bucket.refill(elapsed, self.limits.per_source, self.limits.source_burst);
            }
            if self.total.credit < 1000 {
                return false;
            }
            let index = if let Some(index) = self.sources.iter().position(|(ip, _)| *ip == source) {
                index
            } else {
                if self.sources.is_full()
                    && let Some((index, _)) = self
                        .sources
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, (_, b))| b.credit)
                {
                    self.sources.swap_remove(index);
                }
                let _ = self
                    .sources
                    .push((source, Bucket::new(self.limits.source_burst)));
                self.sources.len() - 1
            };
            if self.sources[index].1.credit < 1000 {
                return false;
            }
            self.sources[index].1.credit -= 1000;
            self.total.credit -= 1000;
            true
        }
    }
}
#[cfg(any(test, feature = "server", feature = "client"))]
pub(crate) use internal::Limiter;

#[cfg(test)]
#[path = "rate/tests.rs"]
mod tests;
