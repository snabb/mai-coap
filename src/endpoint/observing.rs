use super::*;
use crate::observe::{Schedule, Settings};

pub(super) struct PendingRefresh<B> {
    pub mid: u16,
    pub binding: Option<B>,
    pub packet: PacketRef,
    handshaking: bool,
    random: u32,
    cancel: bool,
}

pub(super) struct ServerObservation<B, const DATAGRAM_BYTES: usize> {
    pub ticket: u64,
    resource: u32,
    request: Packet<DATAGRAM_BYTES>,
    metadata: Metadata,
    security: SecurityState,
    binding: Option<B>,
    schedule: Schedule,
    sequence: u32,
    pub pending: bool,
    recent: heapless::Deque<u16, 4>,
}

/// A bounded observation stream. Delivery coalesces to the latest notification
/// while the caller is busy. Dropping it queues cancellation and releases its slot.
#[must_use = "dropping cancels the observation"]
pub struct Observation<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    operation: Operation<'a, DATAGRAM_BYTES, COMMANDS>,
    ended: bool,
    #[cfg(all(feature = "client", feature = "block"))]
    follow_up: Packet<DATAGRAM_BYTES>,
    #[cfg(all(feature = "client", feature = "block"))]
    target: Target,
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Observation<'_, DATAGRAM_BYTES, COMMANDS> {
    /// Waits for the next notification; `None` follows the final response.
    pub async fn next(&mut self) -> Option<Result<Reply<DATAGRAM_BYTES>, Error>> {
        if self.ended {
            return None;
        }
        let operation = &mut self.operation;
        let (result, active) = poll_fn(|cx| {
            operation.shared.lock(|s| {
                let slot = &mut s.slots[operation.index];
                if slot.generation != operation.generation {
                    return Poll::Ready((Err(Error::Cancelled), false));
                }
                if let Some(result) = slot.take_result() {
                    Poll::Ready((result, slot.active))
                } else {
                    slot.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            })
        })
        .await;
        if !active {
            self.ended = true;
            operation.finished = true;
            operation.shared.wake_driver();
        }
        Some(result)
    }
    /// Queues an explicit Observe cancellation; the endpoint sends it on its next poll.
    /// The driver must keep running for that; [`Self::deregister`] reports when it did.
    pub fn cancel(self) {
        drop(self);
    }
    /// Sends the Observe=1 request and waits for that exchange to end, so the driver can
    /// stop afterwards. Later notifications are discarded. `Ok(None)` means the observation
    /// had already ended, and errors such as [`Error::Timeout`] mean the server may still
    /// list this client. Dropping the future stops retransmitting a request already sent.
    pub async fn deregister(self) -> Result<Option<Reply<DATAGRAM_BYTES>>, Error> {
        if self.ended {
            return Ok(None);
        }
        let mut operation = self.operation;
        operation.shared.lock(|s| {
            let slot = &mut s.slots[operation.index];
            if slot.generation == operation.generation {
                slot.deregister = true;
            }
        });
        operation.shared.wake_driver();
        let result = poll_fn(|cx| {
            operation.shared.lock(|s| {
                let slot = &mut s.slots[operation.index];
                if slot.generation != operation.generation {
                    return Poll::Ready(Err(Error::Cancelled));
                }
                match slot.take_result() {
                    Some(result) if !slot.active => Poll::Ready(result),
                    _ => {
                        slot.waker = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }
            })
        })
        .await;
        operation.finished = true;
        operation.shared.wake_driver();
        result.map(Some)
    }
    /// Streams a complete notification body, fetching later blocks without Observe.
    /// `RepresentationChanged` discards a notification whose ETag changed (OBS-6).
    /// A non-success final response is delivered as for [`RequestBuilder::transfer`].
    #[cfg(all(feature = "client", feature = "block"))]
    pub async fn next_into(
        &mut self,
        sink: &mut impl super::client::DownloadSink,
    ) -> Option<Result<super::client::Transfer<DATAGRAM_BYTES>, Error>> {
        let first = match self.next().await? {
            Ok(reply) => reply,
            Err(error) => return Some(Err(error)),
        };
        let client = self.operation.shared.handle().client(self.target);
        Some(
            client
                .complete_notification(self.follow_up.as_slice(), first, sink)
                .await,
        )
    }
    /// As [`Self::next_into`], reassembling the body into caller storage.
    #[cfg(all(feature = "client", feature = "block"))]
    pub async fn next_blocks(
        &mut self,
        output: &mut [u8],
    ) -> Option<Result<super::client::Transfer<DATAGRAM_BYTES>, Error>> {
        self.next_into(&mut super::client::Buffer(output)).await
    }
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Handle<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Coalesces an observable resource change and wakes the endpoint without waiting.
    /// A full change mailbox returns `Capacity`; existing resource changes still coalesce.
    pub fn notify(&self, resource: impl Into<crate::observe::ResourceId>) -> Result<(), Error> {
        let resource = resource.into().0;
        let waker = self.shared.lock(|s| {
            if !s.changes.contains(&resource) {
                s.changes.push(resource).map_err(|_| Error::Capacity)?;
            }
            s.revision = s.revision.wrapping_add(1);
            Ok::<_, Error>(s.driver.take())
        })?;
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
}
#[cfg(feature = "client")]
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Client<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Registers GET Observe with this route, peer and transmission profile.
    pub fn observe(self, uri: &str) -> Result<Observation<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        self.request(Code::GET, uri)?.observe()
    }
}
#[cfg(feature = "client")]
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize>
    Observation<'a, DATAGRAM_BYTES, COMMANDS>
{
    pub(super) fn start(
        operation: Operation<'a, DATAGRAM_BYTES, COMMANDS>,
        packet: &[u8],
        target: Target,
    ) -> Result<Self, Error> {
        #[cfg(not(feature = "block"))]
        let _ = (packet, target);
        Ok(Self {
            operation,
            ended: false,
            #[cfg(feature = "block")]
            follow_up: Packet::copy_from(packet)?,
            #[cfg(feature = "block")]
            target,
        })
    }
}

impl<
    P: Protection,
    const DATAGRAM_BYTES: usize,
    const OUTBOUND: usize,
    const DEDUP_ENTRIES: usize,
    const OBSERVERS: usize,
    const CACHED_REPLIES: usize,
    const SEND_QUEUE: usize,
    const COMMANDS: usize,
    const DEFERRED: usize,
    const BODY_CONTEXTS: usize,
    const PACKETS: usize,
    S: PacketStorage<DATAGRAM_BYTES, PACKETS>,
>
    Endpoint<
        '_,
        P,
        DATAGRAM_BYTES,
        OUTBOUND,
        DEDUP_ENTRIES,
        OBSERVERS,
        CACHED_REPLIES,
        SEND_QUEUE,
        COMMANDS,
        DEFERRED,
        BODY_CONTEXTS,
        PACKETS,
        S,
    >
{
    pub(super) fn observation_ready(&self, index: usize, now: Instant) -> bool {
        let exchange = &self.exchanges[index];
        exchange.refresh.is_none()
            && self.storage_ready(now)
            && !self.outgoing.is_full()
            && self.ids.available(now)
            && self.packet_capacity() >= 1
            && (exchange.credit
                || self.credits_used(exchange.target.remote) < exchange.target.parameters.nstart)
    }

    pub(super) fn observation_due(&self, now: Instant) -> bool {
        if (0..self.observers.len()).any(|index| self.notification_ready(index, now).is_some()) {
            return true;
        }
        self.exchanges.iter().enumerate().any(|(index, exchange)| {
            exchange.observation.is_some()
                && (exchange
                    .slot
                    .is_some_and(|(slot, generation)| self.shared.cancelled(slot, generation))
                    || self.deregistration_due(index)
                    || exchange.retry.is_none() && exchange.deadline <= now)
                && self.observation_ready(index, now)
        })
    }

    /// The Observe=1 request is still to be sent for an explicit deregistration.
    pub(super) fn deregistration_due(&self, index: usize) -> bool {
        let exchange = &self.exchanges[index];
        exchange.observation.is_some()
            && exchange
                .slot
                .is_some_and(|(slot, generation)| self.shared.deregistering(slot, generation))
    }

    pub(super) fn refresh_observation(
        &mut self,
        index: usize,
        cancel: bool,
        now: Instant,
    ) -> Result<(), Error> {
        let exchange = &self.exchanges[index];
        if exchange.handshaking {
            return Err(Error::Cancelled);
        }
        let preferred = exchange
            .target
            .source
            .map(|local| (exchange.target.remote, local));
        let packet = match self.reserve_packet(preferred, now) {
            Ok(packet) => packet,
            Err(Error::Capacity) => return Ok(()),
            Err(error) => return Err(error),
        };
        self.storage_available();
        let result = self.refresh_observation_reserved(index, cancel, now, &packet);
        self.pool.release(packet);
        result
    }

    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    fn refresh_observation_reserved(
        &mut self,
        index: usize,
        cancel: bool,
        now: Instant,
        reservation: &PacketRef,
    ) -> Result<(), Error> {
        let exchange = &self.exchanges[index];
        let target = exchange.target;
        let remote = target.remote;
        let token = exchange.token.clone();
        let parameters = exchange.target.parameters;
        let original = exchange.original.as_ref().ok_or(Error::Malformed)?;
        if self.pool.reference_count(original) != 1 {
            return Err(Error::Capacity);
        }
        let message = MessageView::parse(self.pool.get(original).ok_or(Error::Malformed)?)?;
        let mid = self
            .ids
            .allocate(now, self.send_policy.unsent_lifetime(parameters))?;
        let mut plain = [0; DATAGRAM_BYTES];
        let plain_length = Self::encode_refresh(message, mid, &token, cancel, &mut plain)?;
        let plain_message = MessageView::parse(&plain[..plain_length])?;
        let mut binding = None;
        let mut handshaking = false;
        let result = (|| {
            let protection = &mut self.protection;
            self.pool.encode(reservation, |wire| {
                let prepared =
                    protection.outgoing::<DATAGRAM_BYTES>(target, plain_message, wire)?;
                let (length, new_binding, is_handshaking) = prepared.into_parts();
                binding = new_binding;
                handshaking = is_handshaking;
                Ok((length, ()))
            })?;
            let packet = self.queue_reserved(
                reservation,
                remote,
                target.source,
                target.interface,
                QueuedMid::Owned(mid),
                now,
            )?;
            Ok(packet)
        })();
        let packet = match result {
            Ok(packet) => packet,
            Err(error) => {
                self.release(binding);
                return Err(error);
            }
        };
        let random = self.random_u32();
        self.exchanges[index].refresh = Some(PendingRefresh {
            mid,
            binding,
            packet,
            handshaking,
            random,
            cancel,
        });
        Ok(())
    }
    fn encode_refresh(
        message: MessageView<'_>,
        mid: u16,
        token: &[u8],
        cancel: bool,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let mut b =
            MessageBuilder::new(output, MessageType::Confirmable, message.code(), mid, token)?;
        for option in message.options() {
            if option.number == OptionNumber::OBSERVE {
                b.uint_option(option.number, u64::from(cancel))?;
            } else {
                b.option(option.number, option.value)?;
            }
        }
        b.finish(message.payload())
    }
    // Commit plaintext separately so EDHOC continuations retain Observe cancellation.
    #[inline(never)]
    fn commit_refresh_original(
        &mut self,
        index: usize,
        mid: u16,
        cancel: bool,
    ) -> Result<(), Error> {
        let exchange = &self.exchanges[index];
        let original = exchange.original.as_ref().ok_or(Error::Malformed)?;
        let message = MessageView::parse(self.pool.get(original).ok_or(Error::Malformed)?)?;
        let mut plain = [0; DATAGRAM_BYTES];
        let n = Self::encode_refresh(message, mid, &exchange.token, cancel, &mut plain)?;
        self.pool.write(original, &plain[..n])
    }
    pub(super) fn commit_refresh(&mut self, index: usize, now: Instant) -> Result<(), Error> {
        let Some(refresh) = self.exchanges[index].refresh.as_ref() else {
            return Ok(());
        };
        self.commit_refresh_original(index, refresh.mid, refresh.cancel)?;
        let Some(refresh) = self.exchanges[index].refresh.take() else {
            return Err(Error::Malformed);
        };
        let (remote, old_mid) = (
            self.exchanges[index].target.remote,
            self.exchanges[index].mid,
        );
        self.drop_exchange_sends(remote, old_mid);
        let old = self.exchanges[index].binding.take();
        self.release(old);
        if let Some(packet) = self.exchanges[index].packet.take() {
            self.release_completed_packet(packet);
        }
        let exchange = &mut self.exchanges[index];
        exchange.mid = refresh.mid;
        exchange.binding = refresh.binding;
        exchange.packet = Some(refresh.packet);
        exchange.handshaking = refresh.handshaking;
        exchange.recovered = false;
        exchange.credit = true;
        exchange.accepted = false;
        exchange.observation = (!refresh.cancel).then(crate::observe::Ordering::default);
        exchange.retry = Some(Retransmission::pending(
            exchange.target.parameters,
            refresh.random,
        ));
        exchange.deadline = now.after(exchange.target.parameters.exchange_lifetime());
        if refresh.cancel
            && let Some((slot, generation)) = exchange.slot
            && !self.shared.deregistering(slot, generation)
        {
            exchange.slot = None;
            self.shared
                .complete(slot, generation, Err(Error::Cancelled));
        }
        Ok(())
    }
    pub(super) fn abort_refresh(&mut self, index: usize, now: Instant) {
        let Some(refresh) = self.exchanges[index].refresh.take() else {
            return;
        };
        self.release(refresh.binding);
        self.release_completed_packet(refresh.packet);
        if refresh.cancel {
            self.finish(index, Err(Error::Cancelled));
        } else {
            self.exchanges[index].deadline = now.after(self.send_policy.max_retry_ms);
        }
    }
    pub(super) fn notification_accepted(&mut self, ticket: u64, now: Instant) {
        if let Some(observer) = self.observers.iter_mut().find(|o| o.ticket == ticket) {
            observer.schedule.confirmable_accepted(now);
        }
    }
    pub(super) fn retry_notification(&mut self, queued: &Queued, now: Instant) {
        let Some(id) = queued.mid.local() else {
            return;
        };
        for observer in &mut self.observers {
            if crate::transport::same_peer(observer.metadata.remote, queued.remote)
                && observer.recent.iter().any(|mid| *mid == id)
            {
                observer
                    .schedule
                    .retry_after(now, self.send_policy.max_retry_ms);
            }
        }
    }
    pub(super) fn remove_observer(&mut self, ticket: u64) {
        if let Some(i) = self.observers.iter().position(|o| o.ticket == ticket) {
            let observer = self.observers.swap_remove(i);
            self.release(observer.binding);
        }
    }
    pub(super) fn cancel_observation(&mut self, request: Request<'_>) {
        if !matches!(request.message.code(), Code::GET | Code::FETCH) {
            return;
        }
        let ticket = self
            .observers
            .iter()
            .find(|o| {
                crate::transport::same_peer(o.metadata.remote, request.metadata.remote)
                    && o.security == request.security
                    && MessageView::parse(o.request.as_slice())
                        .is_ok_and(|m| m.token() == request.message.token())
            })
            .map(|o| o.ticket);
        if let Some(ticket) = ticket {
            self.remove_observer(ticket);
        }
    }
    pub(super) fn register_observer(
        &mut self,
        request: Request<'_>,
        outer: MessageView<'_>,
        mut response: ResponseWriter<'_, DATAGRAM_BYTES>,
        binding: Option<P::Binding>,
        settings: Settings,
        packet_context: (Instant, &PacketRef),
    ) -> Result<(), Error> {
        self.with_binding(binding, |this, binding| {
            let (now, reservation) = packet_context;
            // An observation needs an exchange slot for its eventual CON notification.
            if OUTBOUND == 0 || this.observers.is_full() {
                return this.answer(
                    outer,
                    request.metadata,
                    response,
                    binding.take(),
                    now,
                    reservation,
                );
            }
            let schedule = Schedule::new(
                now,
                settings.minimum_ms,
                settings.maximum_ms,
                settings.confirmable_ms,
            )?;
            let sequence = now.0 as u32 & 0xffffff;
            if response
                .set_uint_option(OptionNumber::OBSERVE, sequence.into())
                .and_then(|_| response.set_uint_option(OptionNumber::MAX_AGE, schedule.max_age()))
                .is_err()
            {
                response.reset(Code::INTERNAL_ERROR);
                return this.answer(
                    outer,
                    request.metadata,
                    response,
                    binding.take(),
                    now,
                    reservation,
                );
            }
            let saved_request = Packet::copy_from(request.message.as_bytes())?;
            if !this.answer_retained(
                outer,
                request.metadata,
                response,
                binding,
                now,
                reservation,
            )? {
                return Ok(());
            }
            let entry = ServerObservation {
                ticket: request.ticket.0,
                resource: settings.resource,
                request: saved_request,
                metadata: request.metadata,
                security: request.security,
                binding: binding.take(),
                schedule,
                sequence,
                pending: false,
                recent: heapless::Deque::new(),
            };
            if let Err(mut entry) = this.observers.push(entry) {
                *binding = entry.binding.take();
                return Err(Error::Capacity);
            }
            Ok(())
        })
    }
    pub(super) fn client_notification(
        &mut self,
        index: usize,
        message: MessageView<'_>,
        bytes: &[u8],
        now: Instant,
    ) -> Result<bool, Error> {
        let exchange = &mut self.exchanges[index];
        let Some(ordering) = exchange.observation.as_mut() else {
            return Ok(false);
        };
        let Some(observe) = message.option(OptionNumber::OBSERVE) else {
            return Ok(false);
        };
        if !message.code().is_success() {
            return Ok(false);
        }
        let sequence = u32::try_from(observe.uint()?).map_err(|_| Error::Malformed)?;
        if !ordering.accept(sequence, now) {
            return Ok(true);
        }
        exchange.retry = None;
        exchange.credit = false;
        let max_age = message
            .option(OptionNumber::MAX_AGE)
            .map(|o| o.uint())
            .transpose()?
            .unwrap_or(60);
        exchange.deadline = now.after(
            max_age
                .saturating_mul(1000)
                .saturating_add(exchange.target.parameters.ack_timeout_ms),
        );
        if let Some((slot, generation)) = exchange.slot {
            let reply = Reply {
                remote: exchange.target.remote,
                packet: Packet::copy_from(bytes)?,
            };
            let waker = self.shared.lock(|s| {
                let entry = &mut s.slots[slot];
                if entry.generation != generation || entry.cancelled {
                    return None;
                }
                entry.data = SlotData::Result(Ok(reply));
                entry.waker.take()
            });
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        Ok(true)
    }
    fn notification_ready(&self, index: usize, now: Instant) -> Option<(Schedule, bool)> {
        let observer = &self.observers[index];
        if !self.storage_ready(now)
            || observer.pending
            || self.outgoing.is_full()
            || self.packet_capacity() == 0
            || !self.ids.available(now)
        {
            return None;
        }
        let mut schedule = observer.schedule;
        let con = schedule.poll(now)?;
        if con
            && (self.exchanges.is_full()
                || self.credits_used(observer.metadata.remote) >= self.parameters.nstart)
        {
            return None;
        }
        Some((schedule, con))
    }
    pub(super) fn observe_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        self.observers.iter().filter(|o| !o.pending).map(|o| {
            let deadline = o.schedule.deadline();
            self.storage_deadline()
                .map_or(deadline, |retry| deadline.max(retry))
        })
    }
    /// Delivers due notifications through normal retransmission.
    /// `poll_resources` already calls this method and also advances application
    /// timers and security body leases; custom drivers normally use that method.
    /// For completion-based send budgets, call [`SendWindow::poll_observations`]
    /// through [`Self::with_send_window`].
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    pub fn poll_observations<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        let changes = self.shared.lock(|s| core::mem::take(&mut s.changes));
        for observer in &mut self.observers {
            if changes.contains(&observer.resource) {
                observer.schedule.changed();
            }
        }
        if !self.storage_ready(now) {
            return Ok(());
        }
        // Descending indices keep swap_remove from moving an unvisited observer.
        let mut i = self.observers.len();
        while i != 0 {
            i -= 1;
            let Some((schedule, con)) = self.notification_ready(i, now) else {
                continue;
            };
            let mut observer = self.observers.swap_remove(i);
            let message = match MessageView::parse(observer.request.as_slice()) {
                Ok(message) => message,
                Err(error) => {
                    self.release(observer.binding);
                    self.drop_message(error);
                    continue;
                }
            };
            let request = Request {
                message,
                metadata: observer.metadata,
                security: observer.security,
                ticket: Ticket(observer.ticket),
                deferred_available: false,
                body: message.payload(),
                context: observer
                    .binding
                    .as_ref()
                    .and_then(|b| self.protection.generation(b)),
                #[cfg(feature = "server")]
                response_grace_ms: self.parameters.exchange_lifetime(),
            };
            let ty = if con {
                MessageType::Confirmable
            } else {
                MessageType::NonConfirmable
            };
            let mut attempted = false;
            let prepared = self.with_packet(
                Some((observer.metadata.remote, observer.metadata.local)),
                now,
                |this, reservation| {
                    attempted = true;
                    this.storage_available();
                    let mut bytes = [0; DATAGRAM_BYTES];
                    let mut arena = ResponseArena::new(&mut bytes);
                    let protected =
                        protected_response(observer.binding.is_some(), observer.security);
                    let mut response = arena.writer(Code::CONTENT, message.token(), protected)?;
                    let mut ended = !policy.allow(observer.security, message);
                    if ended {
                        response.set_code(Code::FORBIDDEN);
                    } else {
                        match application.handle(request, &mut response) {
                            Ok(Disposition::Complete) => ended = !response.code().is_success(),
                            Ok(Disposition::Deferred) => {
                                response.reset(Code::UNAVAILABLE);
                                ended = true;
                            }
                            Err(code) => {
                                response.reset(if code.is_response() {
                                    code
                                } else {
                                    Code::INTERNAL_ERROR
                                });
                                ended = true;
                            }
                        }
                    }
                    let sequence = observer.sequence.wrapping_add(1) & 0xffffff;
                    if !ended
                        && (response
                            .set_uint_option(OptionNumber::OBSERVE, sequence.into())
                            .and_then(|_| {
                                response.set_uint_option(OptionNumber::MAX_AGE, schedule.max_age())
                            })
                            .is_err())
                    {
                        response.reset(Code::INTERNAL_ERROR);
                        ended = true;
                    }
                    let mid = this.allocate_mid(this.parameters, now)?;
                    let protection = &mut this.protection;
                    let success = this.pool.encode(reservation, |wire| {
                        Self::serialize_response(
                            protection,
                            response,
                            ty,
                            mid,
                            message.token(),
                            &mut observer.binding,
                            wire,
                        )
                    })?;
                    let packet = this.queue_reserved(
                        reservation,
                        observer.metadata.remote,
                        Some(observer.metadata.local),
                        observer.metadata.interface,
                        if ty == MessageType::Confirmable {
                            QueuedMid::Owned(mid)
                        } else {
                            QueuedMid::Local(mid)
                        },
                        now,
                    )?;
                    Ok((mid, success, packet, ended, sequence))
                },
            );
            let (mid, success, packet, mut ended, sequence) = match prepared {
                Ok(prepared) => prepared,
                Err(Error::Capacity) if !attempted => {
                    if let Err(observer) = self.observers.push(observer) {
                        self.release(observer.binding);
                        self.drop_message(Error::Capacity);
                    }
                    break;
                }
                Err(error) => {
                    self.release(observer.binding);
                    self.drop_message(error);
                    continue;
                }
            };
            observer.schedule = schedule;
            observer.sequence = sequence;
            ended |= !success;
            if observer.recent.is_full() {
                observer.recent.pop_front();
            }
            let _ = observer.recent.push_back(mid);
            if ty == MessageType::Confirmable {
                let mut exchange = self.server_exchange(
                    observer.metadata,
                    mid,
                    token(message.token()),
                    Some(packet),
                    None,
                    now,
                );
                exchange.observer = Some(observer.ticket);
                if let Err(exchange) = self.exchanges.push(exchange) {
                    self.drop_exchange_sends(observer.metadata.remote, mid);
                    if let Some(packet) = exchange.packet {
                        self.pool.release(packet);
                    }
                    self.release(observer.binding);
                    self.drop_message(Error::Capacity);
                    continue;
                }
                observer.pending = true;
            } else {
                self.pool.release(packet);
            }
            if ended {
                self.release(observer.binding);
            } else if let Err(observer) = self.observers.push(observer) {
                self.release(observer.binding);
                self.drop_message(Error::Capacity);
            }
        }
        Ok(())
    }
    pub(super) fn reset_notification(&mut self, remote: SocketAddr, mid: u16) {
        if let Some(ticket) = self
            .observers
            .iter()
            .find(|o| {
                crate::transport::same_peer(o.metadata.remote, remote)
                    && o.recent.iter().any(|&id| id == mid)
            })
            .map(|o| o.ticket)
        {
            self.remove_observer(ticket);
        }
    }
}
