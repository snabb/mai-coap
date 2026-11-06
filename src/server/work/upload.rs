//! Worker-side transactional Block1 uploads to asynchronous storage.
use super::{Job, WorkQueue};
use crate::{
    Error,
    block::{Block, BodyKey, Progress, StreamingUpload, UploadSink},
    codec::{Code, OptionNumber},
    endpoint::{Handle, Response, race},
    time::{Clock, Instant},
};

/// Storage transactions driven outside the endpoint task.
/// Async methods must be cancellation-safe. `abort` synchronously invalidates
/// staging state; delayed physical cleanup may run in the next `begin`.
/// Committing is atomic, and aborting must never remove an already active image.
#[allow(async_fn_in_trait)]
pub trait AsyncUploadSink {
    /// Starts an inactive transaction.
    async fn begin(&mut self, key: &BodyKey, size: Option<u64>) -> Result<(), Error>;
    /// Persists ordered bytes before the worker acknowledges the block.
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Atomically activates a complete body before its final response.
    async fn commit(&mut self) -> Result<(), Error>;
    /// Invalidates an incomplete transaction, including after cancellation.
    fn abort(&mut self);
}
#[derive(Default)]
struct Plan {
    write: bool,
    commit: bool,
    abort: bool,
}
impl UploadSink for Plan {
    fn begin(&mut self, _: &BodyKey, _: Option<u64>) -> Result<(), Error> {
        Ok(())
    }
    fn write(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
        self.write = true;
        Ok(())
    }
    fn commit(&mut self) -> Result<(), Error> {
        self.commit = true;
        Ok(())
    }
    fn abort(&mut self) {
        self.abort = true;
    }
}
/// One transactional route and sink, backed by an existing deferred-work queue.
/// Use a separate queue for each independently live upload sink. State is bounded
/// by one body and one cached block; other active remotes receive 5.03.
pub struct UploadWorker<
    'a,
    S: AsyncUploadSink,
    const DATAGRAM_BYTES: usize = 1152,
    const JOBS: usize = 2,
    const BODY_BYTES: usize = 1152,
> {
    queue: &'a WorkQueue<DATAGRAM_BYTES, JOBS, BODY_BYTES>,
    sink: S,
    active: Option<(BodyKey, StreamingUpload<DATAGRAM_BYTES>, Instant)>,
    limit: usize,
    timeout_ms: u64,
    dirty: bool,
}
struct UploadGuard<
    'w,
    'q,
    S: AsyncUploadSink,
    const DATAGRAM_BYTES: usize,
    const JOBS: usize,
    const BODY_BYTES: usize,
>(&'w mut UploadWorker<'q, S, DATAGRAM_BYTES, JOBS, BODY_BYTES>);
impl<S: AsyncUploadSink, const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize>
    Drop for UploadGuard<'_, '_, S, DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    fn drop(&mut self) {
        // A processing future can be cancelled while its worker remains alive.
        if self.0.dirty {
            self.0.abort();
        }
    }
}
impl<
    'a,
    S: AsyncUploadSink,
    const DATAGRAM_BYTES: usize,
    const JOBS: usize,
    const BODY_BYTES: usize,
> UploadWorker<'a, S, DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    /// Creates a worker. Register `queue.handler(timeout_ms)` on one upload route.
    pub fn new(
        queue: &'a WorkQueue<DATAGRAM_BYTES, JOBS, BODY_BYTES>,
        sink: S,
        limit: usize,
        timeout_ms: u64,
    ) -> Result<Self, Error> {
        if timeout_ms == 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            queue,
            sink,
            active: None,
            limit,
            timeout_ms,
            dirty: false,
        })
    }
    fn abort(&mut self) {
        self.abort_retaining(None);
    }
    fn abort_retaining(&mut self, keep: Option<u64>) {
        self.sink.abort();
        if let Some((key, _, _)) = self.active.take()
            && let Some(epoch) = key.context
            && Some(epoch) != keep
        {
            self.queue.finish_context(epoch);
        }
        self.dirty = false;
    }
    /// Aborts expired staging state; call from custom worker scheduling.
    pub fn expire(&mut self, now: Instant) {
        if self.dirty
            || self
                .active
                .as_ref()
                .is_some_and(|(_, state, deadline)| !state.closed() && now >= *deadline)
        {
            self.abort();
        }
    }
    /// Processes one queued block. Errors become contextual CoAP responses.
    /// Cancelling the future synchronously invalidates pending staging writes.
    pub async fn process(
        &mut self,
        job: &Job<DATAGRAM_BYTES, BODY_BYTES>,
        clock: &impl Clock,
    ) -> Response<DATAGRAM_BYTES> {
        let guard = UploadGuard(self);
        guard.0.process_inner(job, clock).await
    }
    async fn process_inner(
        &mut self,
        job: &Job<DATAGRAM_BYTES, BODY_BYTES>,
        clock: &impl Clock,
    ) -> Response<DATAGRAM_BYTES> {
        if self.dirty
            || self
                .active
                .as_ref()
                .is_some_and(|(_, state, deadline)| !state.closed() && clock.now() >= *deadline)
        {
            // The handler may already have renewed this epoch for the new job.
            self.abort_retaining(job.request().ok().and_then(|request| request.context));
        }
        let result = race(self.accept(job, clock), async {
            clock.sleep_until(job.deadline()).await;
            Err(Error::Timeout)
        })
        .await;
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                if self.dirty {
                    self.abort();
                }
                let code = match error {
                    Error::Response(code) => code,
                    Error::Timeout | Error::Cancelled => Code::UNAVAILABLE,
                    Error::Malformed | Error::BadOption(_) => Code::BAD_REQUEST,
                    _ => Code::INTERNAL_ERROR,
                };
                let mut response = Response::new(code);
                let option = match code {
                    Code::TOO_LARGE => Some((OptionNumber::SIZE1, self.limit as u64)),
                    Code::UNAVAILABLE => Some((OptionNumber::MAX_AGE, 1)),
                    _ => None,
                };
                if let Some((number, value)) = option
                    && response.uint_option(number, value).is_err()
                {
                    response = Response::new(Code::INTERNAL_ERROR);
                }
                response
            }
        };
        if let Some(epoch) = job.request().ok().and_then(|request| request.context)
            && self
                .active
                .as_ref()
                .is_none_or(|(key, state, _)| key.context != Some(epoch) || state.closed())
        {
            self.queue.finish_context(epoch);
        }
        response
    }
    async fn accept(
        &mut self,
        job: &Job<DATAGRAM_BYTES, BODY_BYTES>,
        clock: &impl Clock,
    ) -> Result<Response<DATAGRAM_BYTES>, Error> {
        if clock.now() >= job.deadline() {
            return Err(Error::Timeout);
        }
        let request = job.request()?;
        if request
            .context
            .is_some_and(|epoch| !self.queue.contains_context(epoch))
        {
            return Err(Error::Cancelled);
        }
        let block = Block::decode(
            request
                .message
                .option(OptionNumber::BLOCK1)
                .ok_or(Error::Malformed)?
                .uint()?,
        )?;
        let size = request
            .message
            .option(OptionNumber::SIZE1)
            .map(|o| o.uint())
            .transpose()?;
        let key =
            BodyKey::from_request(request.metadata.remote, 0, request.context, request.message)?;
        let duplicate = self.active.as_ref().is_some_and(|(active, state, _)| {
            *active == key && state.is_duplicate(block, request.payload())
        });
        if block.number == 0 && !duplicate {
            if self.active.as_ref().is_some_and(|(active, state, _)| {
                !crate::transport::same_peer(active.remote, key.remote) && !state.closed()
            }) {
                let mut response = Response::new(Code::UNAVAILABLE);
                response.uint_option(OptionNumber::MAX_AGE, 1)?;
                return Ok(response);
            }
            self.abort_retaining(key.context);
            let deadline = clock.now().after(self.timeout_ms);
            let state =
                StreamingUpload::begin(&key, size, self.limit, deadline, &mut Plan::default())?;
            self.active = Some((key.clone(), state, deadline));
            self.dirty = true;
            self.sink.begin(&key, size).await?;
            self.dirty = false;
        }
        let (active, state, deadline) = self
            .active
            .as_mut()
            .ok_or(Error::Response(Code::INCOMPLETE))?;
        if *active != key {
            return Err(Error::Response(Code::INCOMPLETE));
        }
        let mut plan = Plan::default();
        let next_deadline = clock.now().after(self.timeout_ms);
        let progress = state.push(
            block,
            request.payload(),
            clock.now(),
            next_deadline,
            &mut plan,
        );
        if matches!(progress, Err(Error::Response(Code::TOO_LARGE))) {
            plan.abort = true;
        }
        if plan.abort {
            self.dirty = true;
        }
        let progress = progress?;
        if progress != Progress::Duplicate {
            self.dirty = true;
            if plan.write {
                self.sink.write(block.offset()?, request.payload()).await?;
            }
            if request
                .context
                .is_some_and(|epoch| !self.queue.contains_context(epoch))
            {
                return Err(Error::Cancelled);
            }
            if plan.commit {
                self.sink.commit().await?;
            }
            self.dirty = false;
            *deadline = next_deadline;
        }
        let mut response = Response::new(if block.more {
            Code::CONTINUE
        } else {
            Code::CHANGED
        });
        response.uint_option(OptionNumber::BLOCK1, block.encode()?)?;
        Ok(response)
    }
    /// Runs indefinitely without spawning tasks; the caller concurrently drives
    /// the endpoint. Waiting for the next job enforces upload inactivity expiry.
    /// Response capacity failures retry after 100 ms, 250 ms, then every 500 ms.
    /// Queue handoff, including commands waiting for NSTART, is bounded by
    /// [`Job::delivery_deadline`]. Transmission continues after handoff. Other
    /// submission errors or expiry discard only that reply. Use
    /// [`Self::process`] for application-managed delivery retries.
    /// While handoff waits, this worker does not expire its unfinished upload or
    /// process another job. Expiry is checked again after handoff.
    pub async fn run<const COMMANDS: usize>(
        &mut self,
        handle: Handle<'_, DATAGRAM_BYTES, COMMANDS>,
        clock: &impl Clock,
    ) -> core::convert::Infallible {
        loop {
            let deadline = self
                .active
                .as_ref()
                .filter(|(_, state, _)| !state.closed())
                .map(|(_, _, deadline)| *deadline);
            let job = if let Some(deadline) = deadline {
                race(async { Some(self.queue.next().await) }, async {
                    clock.sleep_until(deadline).await;
                    None
                })
                .await
            } else {
                Some(self.queue.next().await)
            };
            let Some(job) = job else {
                self.expire(clock.now());
                continue;
            };
            let response = self.process(&job, clock).await;
            let deadline = job.delivery_deadline();
            let deliver = async {
                for delay in [0, 100, 250].into_iter().chain(core::iter::repeat(500)) {
                    let next = clock.now().after(delay).min(deadline);
                    clock.sleep_until(next).await;
                    if clock.now() >= deadline {
                        break;
                    }
                    let result = match handle.respond(job.ticket(), &response) {
                        Ok(operation) => operation.await,
                        Err(error) => Err(error),
                    };
                    if result != Err(Error::Capacity) {
                        break;
                    }
                }
            };
            // NSTART waiting is normal congestion control and can span retransmissions.
            race(deliver, clock.sleep_until(deadline)).await;
        }
    }
}
impl<S: AsyncUploadSink, const DATAGRAM_BYTES: usize, const JOBS: usize, const BODY_BYTES: usize>
    Drop for UploadWorker<'_, S, DATAGRAM_BYTES, JOBS, BODY_BYTES>
{
    fn drop(&mut self) {
        if self.dirty
            || self
                .active
                .as_ref()
                .is_some_and(|(_, state, _)| !state.closed())
        {
            self.abort();
        }
    }
}
