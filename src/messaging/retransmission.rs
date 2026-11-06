use super::TransmissionParameters;
use crate::{Error, time::Instant};
#[derive(Clone, Copy, Debug)]
pub struct Retransmission {
    deadline: Instant,
    interval: u64,
    until: Instant,
    retries: u8,
    max: u8,
    started: bool,
}
impl Retransmission {
    /// Starts after an accepted original send.
    #[cfg(test)]
    pub fn new(now: Instant, parameters: TransmissionParameters, random: u32) -> Self {
        let mut retry = Self::pending(parameters, random);
        retry.accepted(now, parameters);
        retry
    }
    /// Prepares a random interval without starting the ACK timer.
    pub fn pending(parameters: TransmissionParameters, random: u32) -> Self {
        Self {
            deadline: Instant(u64::MAX),
            interval: parameters.initial_timeout(random),
            until: Instant(u64::MAX),
            retries: 0,
            max: parameters.max_retransmit,
            started: false,
        }
    }
    pub const fn deadline(self) -> Instant {
        self.deadline
    }
    #[cfg(any(feature = "server", feature = "client"))]
    pub(crate) fn last_send_at(self, parameters: TransmissionParameters) -> Instant {
        Instant(
            self.until.0.saturating_sub(
                parameters
                    .max_transmit_wait()
                    .saturating_sub(parameters.max_transmit_span()),
            ),
        )
    }
    pub(crate) fn accepted(&mut self, now: Instant, parameters: TransmissionParameters) {
        if self.started {
            self.retries = self.retries.saturating_add(1);
            self.interval = self.interval.saturating_mul(2);
        } else {
            self.started = true;
            self.until = now.after(parameters.max_transmit_wait());
        }
        self.deadline = now.after(self.interval).min(self.until);
    }
    #[cfg(any(feature = "server", feature = "client", kani))]
    pub(crate) fn skipped(&mut self, now: Instant) {
        self.deadline = now.after(self.interval).min(self.until);
    }
    /// A due retry does not advance the timer until acceptance or local expiry.
    pub fn poll(&mut self, now: Instant) -> Result<bool, Error> {
        if now < self.deadline {
            return Ok(false);
        }
        if self.retries == self.max || now >= self.until {
            return Err(Error::Timeout);
        }
        Ok(true)
    }
}
