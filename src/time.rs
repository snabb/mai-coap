//! Monotonic time without an executor dependency (PLT-6).
use core::future::Future;

/// Milliseconds since an implementation-defined monotonic origin.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct Instant(pub u64);
impl Instant {
    /// Adds milliseconds, saturating at the maximum representable instant.
    pub const fn after(self, milliseconds: u64) -> Self {
        Self(self.0.saturating_add(milliseconds))
    }
    /// Elapsed milliseconds, saturating if the other instant is in the future.
    pub const fn elapsed_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}
/// Monotonic clock and cancellation-safe timer.
pub trait Clock {
    /// Returns the current monotonic instant.
    fn now(&self) -> Instant;
    /// Waits until a deadline; dropping this future cancels only the wait.
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()>;
}

#[cfg(feature = "embassy-time")]
/// Adapter for an application-provided Embassy time driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmbassyClock;
#[cfg(feature = "embassy-time")]
impl Clock for EmbassyClock {
    fn now(&self) -> Instant {
        Instant(embassy_time::Instant::now().as_millis())
    }
    async fn sleep_until(&self, deadline: Instant) {
        embassy_time::Timer::at(embassy_time::Instant::from_millis(deadline.0)).await;
    }
}

#[cfg(all(feature = "std", target_os = "linux"))]
/// Host clock using the same readiness reactor as the std transport.
#[derive(Clone, Debug)]
pub struct StdClock {
    origin: std::time::Instant,
}
#[cfg(all(feature = "std", target_os = "linux"))]
impl Default for StdClock {
    fn default() -> Self {
        Self {
            origin: std::time::Instant::now(),
        }
    }
}
#[cfg(all(feature = "std", target_os = "linux"))]
impl Clock for StdClock {
    fn now(&self) -> Instant {
        Instant(self.origin.elapsed().as_millis().min(u64::MAX.into()) as u64)
    }
    async fn sleep_until(&self, deadline: Instant) {
        async_io::Timer::at(self.origin + std::time::Duration::from_millis(deadline.0)).await;
    }
}
