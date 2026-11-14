//! Driver-owned handoff of serialized deferred replies.
use super::{Error, Ticket};

/// Bounded synchronous delivery through the receiving endpoint's packet pool.
/// Handoff needs no free command slot; the sink retains no reply buffer or callback.
/// Ticket admission still obeys the endpoint's deferred-work capacity requirements.
/// A successful call reports queue handoff, as [`super::Handle::respond`] does.
pub trait DeferredResponses<const DATAGRAM_BYTES: usize> {
    /// Queues a response for an admitted ticket.
    ///
    /// `writer` writes one complete serialized response and returns its length.
    /// Its type, MID and token are replaced with those for the deferred request.
    /// The writer runs only after protocol and packet capacity are available,
    /// without a critical section. It must return synchronously.
    ///
    /// Keep the original reply until this call succeeds: preparation can fail
    /// after writing. `Capacity` is retryable; `Cancelled` means the ticket is
    /// absent or expired. Invalid output, including an oversized returned length,
    /// returns its codec error or `Malformed`.
    /// Later transport or peer delivery failures are not reported to the caller.
    fn respond(
        &mut self,
        ticket: Ticket,
        writer: &mut dyn FnMut(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error>;
}

pub(super) struct Sink<F>(pub F);
impl<const D: usize, F> DeferredResponses<D> for Sink<F>
where
    F: FnMut(Ticket, &mut dyn FnMut(&mut [u8]) -> Result<usize, Error>) -> Result<(), Error>,
{
    fn respond(
        &mut self,
        ticket: Ticket,
        writer: &mut dyn FnMut(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<(), Error> {
        self.0(ticket, writer)
    }
}
