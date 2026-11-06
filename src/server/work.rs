//! Bounded deferred work for I/O in an application task (SRV-3, API-7).
use crate::{
    Error, Packet,
    codec::{Code, MessageView, OptionNumber},
    endpoint::{Application, Disposition, Request, ResponseWriter, Ticket},
    security::SecurityState,
    time::Instant,
    transport::Metadata,
};
use core::{
    cell::RefCell,
    future::poll_fn,
    task::{Poll, Waker},
};
use critical_section::Mutex;
#[cfg(feature = "block1")]
pub mod upload;

/// Owned request handed to an application worker after the endpoint sends its ACK.
pub struct Job<const DATAGRAM_BYTES: usize, const BODY_BYTES: usize> {
    packet: Packet<DATAGRAM_BYTES>,
    body: Packet<BODY_BYTES>,
    metadata: Metadata,
    security: SecurityState,
    context: Option<u64>,
    ticket: Ticket,
    deadline: Instant,
    response_grace_ms: u64,
}
impl<const DATAGRAM_BYTES: usize, const BODY_BYTES: usize> Job<DATAGRAM_BYTES, BODY_BYTES> {
    /// Borrows the copied request and its complete body for worker-side processing.
    pub fn request(&self) -> Result<Request<'_>, Error> {
        Ok(Request {
            message: MessageView::parse(self.packet.as_slice())?,
            body: self.body.as_slice(),
            metadata: self.metadata,
            security: self.security,
            context: self.context,
            ticket: self.ticket,
            deferred_available: true,
            response_grace_ms: self.response_grace_ms,
        })
    }
    /// Ticket to complete through the endpoint handle after the I/O finishes.
    pub const fn ticket(&self) -> Ticket {
        self.ticket
    }
    /// Processing deadline. Once dequeued, the worker must enforce this deadline;
    /// queue expiry cannot cancel I/O already running in an application task.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
    /// Processing deadline plus the receiving endpoint's response-delivery grace.
    /// Cancellation or security-context removal can invalidate the ticket earlier.
    pub const fn delivery_deadline(&self) -> Instant {
        self.deadline.after(self.response_grace_ms)
    }
}
struct State<const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize> {
    jobs: heapless::Deque<Job<DATAGRAM_BYTES, BODY_BYTES>, JOBS>,
    epochs: heapless::Vec<(u64, Instant), JOBS>,
    waker: Option<Waker>,
    now: Instant,
}
/// Caller-owned queue. One worker may await [`Self::next`] while the endpoint runs.
/// Epochs remain retained between Block1 jobs until completion or inactivity expiry.
pub struct WorkQueue<
    const DATAGRAM_BYTES: usize = 1152,
    const JOBS: usize = 2,
    const BODY_BYTES: usize = 1152,
> {
    state: Mutex<RefCell<State<DATAGRAM_BYTES, JOBS, BODY_BYTES>>>,
}
impl<const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize> Default
    for WorkQueue<DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize>
    WorkQueue<DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    /// Creates empty bounded storage; zero capacity rejects every job with 5.03.
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(RefCell::new(State {
                jobs: heapless::Deque::new(),
                epochs: heapless::Vec::new(),
                waker: None,
                now: Instant(0),
            })),
        }
    }
    fn lock<R>(&self, f: impl FnOnce(&mut State<DATAGRAM_BYTES, JOBS, BODY_BYTES>) -> R) -> R {
        critical_section::with(|cs| f(&mut self.state.borrow(cs).borrow_mut()))
    }
    /// Creates a resource handler using an application-selected inactivity timeout.
    /// Queued jobs expire automatically; workers enforce [`Job::deadline`] after
    /// dequeueing. [`Job::delivery_deadline`] includes the receiving endpoint's
    /// response-delivery grace.
    pub fn handler(
        &self,
        timeout_ms: u64,
    ) -> Result<Handler<'_, DATAGRAM_BYTES, JOBS, BODY_BYTES>, Error> {
        if timeout_ms == 0 {
            return Err(Error::Malformed);
        }
        Ok(Handler {
            queue: self,
            timeout_ms,
        })
    }
    /// Waits for one job. Only one application task should consume a queue.
    pub async fn next(&self) -> Job<DATAGRAM_BYTES, BODY_BYTES> {
        poll_fn(|cx| {
            self.lock(|s| {
                if let Some(job) = s.jobs.pop_front() {
                    Poll::Ready(job)
                } else {
                    s.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
        })
        .await
    }
    /// Releases a body's epoch after commit or abort. Other bodies using the same
    /// epoch must finish first; use separate queues for independently live bodies.
    pub fn finish_context(&self, generation: u64) {
        self.lock(|s| s.epochs.retain(|(g, _)| *g != generation));
    }
    /// Whether an epoch remains usable by an active worker after timeout/abort.
    pub fn contains_context(&self, generation: u64) -> bool {
        self.lock(|s| s.epochs.iter().any(|(g, _)| *g == generation))
    }
}
/// Resource handler that copies requests into a [`WorkQueue`] and defers replies.
pub struct Handler<'a, const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize> {
    queue: &'a WorkQueue<DATAGRAM_BYTES, JOBS, BODY_BYTES>,
    timeout_ms: u64,
}
impl<const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize>
    Application<DATAGRAM_BYTES> for Handler<'_, DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    fn handle(
        &mut self,
        request: Request<'_>,
        response: &mut ResponseWriter<'_, DATAGRAM_BYTES>,
    ) -> Result<Disposition, Code> {
        let Some(ticket) = request.deferred_ticket() else {
            response.set_unavailable()?;
            return Ok(Disposition::Complete);
        };
        let packet = Packet::copy_from(request.message.as_bytes()).map_err(|_| Code::TOO_LARGE)?;
        let body = Packet::copy_from(request.payload()).map_err(|_| Code::TOO_LARGE)?;
        let result = self.queue.lock(|s| {
            if s.jobs.is_full()
                || request
                    .context
                    .is_some_and(|g| s.epochs.is_full() && !s.epochs.iter().any(|(e, _)| *e == g))
            {
                return Err(());
            }
            let deadline = s.now.after(self.timeout_ms);
            if let Some(generation) = request.context {
                if let Some((_, t)) = s.epochs.iter_mut().find(|(g, _)| *g == generation) {
                    *t = deadline;
                } else {
                    s.epochs.push((generation, deadline)).map_err(|_| ())?;
                }
            }
            s.jobs
                .push_back(Job {
                    packet,
                    body,
                    metadata: request.metadata,
                    security: request.security,
                    context: request.context,
                    ticket,
                    deadline,
                    response_grace_ms: request.response_grace_ms,
                })
                .map_err(|_| ())?;
            Ok(s.waker.take())
        });
        match result {
            Ok(waker) => {
                response.set_deferred_timeout(self.timeout_ms)?;
                if let Some(waker) = waker {
                    waker.wake();
                }
                Ok(Disposition::Deferred)
            }
            Err(()) => {
                response.set_unavailable()?;
                Ok(Disposition::Complete)
            }
        }
    }
    fn recognizes(&self, _: OptionNumber) -> bool {
        false
    }
    fn uses_context(&self, generation: u64) -> bool {
        self.queue.contains_context(generation)
    }
    fn abort_context(&mut self, generation: u64) {
        self.queue.lock(|s| {
            s.epochs.retain(|(g, _)| *g != generation);
            let count = s.jobs.len();
            for _ in 0..count {
                if let Some(job) = s.jobs.pop_front()
                    && job.context != Some(generation)
                {
                    let _ = s.jobs.push_back(job);
                }
            }
        });
    }
    fn poll(&mut self, now: Instant, _: &mut core::task::Context<'_>) {
        self.queue.lock(|s| {
            s.now = now;
            s.epochs.retain(|(_, t)| *t > now);
            let count = s.jobs.len();
            for _ in 0..count {
                if let Some(job) = s.jobs.pop_front()
                    && job.deadline > now
                {
                    let _ = s.jobs.push_back(job);
                }
            }
        });
    }
    fn deadline(&self) -> Option<Instant> {
        self.queue.lock(|s| {
            s.epochs
                .iter()
                .map(|(_, t)| *t)
                .chain(s.jobs.iter().map(|j| j.deadline))
                .min()
        })
    }
}
