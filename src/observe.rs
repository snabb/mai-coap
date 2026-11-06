//! Observe serial arithmetic and interval scheduling (RFC 7641).

/// Registered resource identity within one application's routing tree.
/// Use it with the handle driving that tree. Custom applications may continue
/// assigning raw IDs; IDs must be unique within the same endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceId(pub(crate) u32);
impl From<u32> for ResourceId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

/// Resource identity and notification intervals, all durations in milliseconds.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Settings {
    /// Stable application resource identifier used with `Handle::notify`.
    pub resource: u32,
    /// Minimum interval between updates.
    pub minimum_ms: u64,
    /// Maximum interval without an update, also advertised as Max-Age.
    pub maximum_ms: u64,
    /// Maximum interval between confirmable notifications, capped at 24 hours.
    pub confirmable_ms: u64,
}

impl Settings {
    /// Uses no minimum delay, a 60-second maximum, and CON at least every 60 seconds.
    pub const fn new(resource: u32) -> Self {
        Self {
            resource,
            minimum_ms: 0,
            maximum_ms: 60_000,
            confirmable_ms: 60_000,
        }
    }
    /// Sets the minimum update interval in milliseconds.
    pub const fn with_minimum_ms(mut self, value: u64) -> Self {
        self.minimum_ms = value;
        self
    }
    /// Sets the maximum update interval in milliseconds.
    pub const fn with_maximum_ms(mut self, value: u64) -> Self {
        self.maximum_ms = value;
        self
    }
    /// Sets the confirmable notification interval in milliseconds.
    pub const fn with_confirmable_ms(mut self, value: u64) -> Self {
        self.confirmable_ms = value;
        self
    }
}
#[cfg(any(feature = "server", feature = "client"))]
pub(crate) mod internal {
    use crate::time::Instant;
    /// Client-side ordering state for a single observation (OBS-5).
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Ordering {
        last: Option<(u32, Instant)>,
    }
    impl Ordering {
        /// Whether at least one notification has been accepted.
        pub const fn established(self) -> bool {
            self.last.is_some()
        }
        /// Accepts newer 24-bit values, including the RFC's 128-second rule.
        pub fn accept(&mut self, sequence: u32, now: Instant) -> bool {
            if sequence > 0xffffff {
                return false;
            }
            let newer = self.last.is_none_or(|(last, time)| {
                let difference = sequence.wrapping_sub(last) & 0xffffff;
                difference != 0 && difference < 0x800000 || now.elapsed_since(time) > 128000
            });
            if newer {
                self.last = Some((sequence, now));
            }
            newer
        }
    }
    /// Notification scheduling for a resource (OBS-3–4).
    #[derive(Clone, Copy, Debug)]
    pub struct Schedule {
        last: Instant,
        last_confirmable: Instant,
        minimum: u64,
        maximum: u64,
        confirmable_interval: u64,
        changed: bool,
    }
    impl Schedule {
        /// Creates a schedule, rejecting zero maximum or reversed intervals.
        pub fn new(
            now: Instant,
            minimum_ms: u64,
            maximum_ms: u64,
            confirmable_interval_ms: u64,
        ) -> Result<Self, crate::Error> {
            if maximum_ms == 0 || minimum_ms > maximum_ms {
                return Err(crate::Error::Malformed);
            }
            Ok(Self {
                last: now,
                last_confirmable: now,
                minimum: minimum_ms,
                maximum: maximum_ms,
                confirmable_interval: confirmable_interval_ms.clamp(1, 86_400_000),
                changed: false,
            })
        }
        /// Coalesces a resource change without blocking.
        pub fn changed(&mut self) {
            self.changed = true;
        }
        /// Earliest deadline for the next notification.
        pub fn deadline(self) -> Instant {
            self.last.after(if self.changed {
                self.minimum
            } else {
                self.maximum
            })
        }
        /// Selects NON (`Some(false)`) or CON (`Some(true)`) when a notification is due.
        pub fn poll(&mut self, now: Instant) -> Option<bool> {
            if now < self.deadline() {
                return None;
            }
            let con = now.elapsed_since(self.last_confirmable) >= self.confirmable_interval;
            self.last = now;
            self.changed = false;
            Some(con)
        }
        /// Keeps the latest value pending without spinning on local send errors.
        #[cfg(any(feature = "server", feature = "client"))]
        pub(crate) fn retry_after(&mut self, now: Instant, delay: u64) {
            self.changed = true;
            self.last = self
                .last
                .max(Instant(now.after(delay).0.saturating_sub(self.minimum)));
        }
        /// Records an actually accepted CON, independently of queued notifications.
        #[cfg(any(feature = "server", feature = "client"))]
        pub(crate) fn confirmable_accepted(&mut self, now: Instant) {
            self.last_confirmable = now;
        }
        /// Max-Age corresponding to the maximum interval, rounded up to seconds.
        pub fn max_age(self) -> u64 {
            self.maximum.div_ceil(1000)
        }
    }
}
#[cfg(any(feature = "server", feature = "client"))]
pub(crate) use internal::{Ordering, Schedule};
