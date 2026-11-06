use super::*;

pub(super) struct Pending {
    pub(super) deadline: Instant,
    pub(super) outgoing: Queued,
}

/// Multicast discovery replies, retaining their unicast source addresses. Up to
/// eight unread responses are buffered; excess responses are dropped. `None`
/// marks the caller's deadline after local acceptance, even when no server answered.
/// Expiry before local acceptance instead yields [`Error::LocalSendTimeout`].
#[must_use = "dropping ends response collection"]
pub struct Collection<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> {
    operation: Operation<'a, DATAGRAM_BYTES, COMMANDS>,
    ended: bool,
}
impl<const DATAGRAM_BYTES: usize, const COMMANDS: usize> Collection<'_, DATAGRAM_BYTES, COMMANDS> {
    /// Waits for another reply or the collection deadline.
    pub async fn next(&mut self) -> Option<Result<Reply<DATAGRAM_BYTES>, Error>> {
        if self.ended {
            return None;
        }
        let operation = &mut self.operation;
        let result = poll_fn(|cx| {
            operation.shared.lock(|s| {
                let slot = &mut s.slots[operation.index];
                if slot.generation != operation.generation {
                    return Poll::Ready(Some(Err(Error::Cancelled)));
                }
                if let Some(reply) = slot.replies.pop_front() {
                    return Poll::Ready(Some(Ok(reply)));
                }
                if let Some(result) = slot.take_result() {
                    return Poll::Ready(match result {
                        Err(Error::Timeout) => None,
                        result => Some(result),
                    });
                }
                slot.waker = Some(cx.waker().clone());
                Poll::Pending
            })
        })
        .await;
        if result.is_none() || result.as_ref().is_some_and(Result::is_err) {
            self.ended = true;
            operation.finished = true;
        }
        result
    }
}
impl<'a, const DATAGRAM_BYTES: usize, const COMMANDS: usize> Handle<'a, DATAGRAM_BYTES, COMMANDS> {
    /// Sends public, unprotected NON discovery and collects replies until `deadline`.
    /// The transport must already have the required multicast interface configured.
    #[cfg(feature = "client")]
    pub fn discover_multicast(
        &self,
        remote: SocketAddr,
        deadline: Instant,
    ) -> Result<Collection<'a, DATAGRAM_BYTES, COMMANDS>, Error> {
        if !remote.ip().is_multicast() {
            return Err(Error::Malformed);
        }
        let packet = Packet::encoded(|bytes| {
            let mut b = MessageBuilder::new(bytes, MessageType::NonConfirmable, Code::GET, 0, &[])?;
            crate::uri::path_options("/.well-known/core", &mut b)?;
            b.finish(&[])
        })?;
        let operation = self.shared.submit(Command::Request {
            target: remote.into(),
            packet,
            token_len: 8,
            wait: false,
            raw: true,
            collect_until: Some(deadline),
        })?;
        Ok(Collection {
            operation,
            ended: false,
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
    pub(super) fn multicast_deadlines(&self) -> impl Iterator<Item = Instant> + '_ {
        self.leisure.iter().map(|p| p.deadline)
    }
    pub(super) fn poll_multicast(&mut self, now: Instant) -> Result<(), Error> {
        let mut i = 0;
        while i < self.leisure.len() {
            if self.leisure[i].deadline <= now && !self.outgoing.is_full() {
                let mut pending = self.leisure.swap_remove(i);
                pending.outgoing.enqueued = now;
                // Promotion starts the send window. The driver conservatively extends
                // this MID through EXCHANGE_LIFETIME, including after a slow handler.
                pending.outgoing.pending_timestamp = self.in_send_window;
                if let Err(queued) = self.outgoing.push_back(pending.outgoing) {
                    self.release_queued(queued);
                    return Err(Error::Capacity);
                }
            } else {
                i += 1;
            }
        }
        Ok(())
    }
    pub(super) fn client_multicast(
        &mut self,
        index: usize,
        message: MessageView<'_>,
        remote: SocketAddr,
        bytes: &[u8],
    ) -> Result<bool, Error> {
        let exchange = &self.exchanges[index];
        if exchange.collection.is_none() {
            return Ok(false);
        }
        if !message.code().is_success()
            || message.message_type() != MessageType::NonConfirmable
            || message.check_options(endpoint_option).is_err()
        {
            return Ok(true);
        }
        if let Some((slot, generation)) = exchange.slot {
            let reply = Reply {
                remote,
                packet: Packet::copy_from(bytes)?,
            };
            let waker = self.shared.lock(|s| {
                let entry = &mut s.slots[slot];
                if entry.generation != generation || entry.cancelled {
                    return None;
                }
                if entry.replies.push_back(reply).is_err() {
                    return None;
                }
                entry.waker.take()
            });
            if let Some(waker) = waker {
                waker.wake();
            }
        }
        Ok(true)
    }
    // Keep datagram scratch out of the caller's driver poll frame.
    #[inline(never)]
    pub(super) fn receive_multicast<A: Application<DATAGRAM_BYTES>>(
        &mut self,
        message: MessageView<'_>,
        metadata: Metadata,
        now: Instant,
        application: &mut A,
        policy: &(impl Policy + ?Sized),
    ) -> Result<(), Error> {
        if message.message_type() != MessageType::NonConfirmable
            || message.code() != Code::GET
            || !crate::security::path_matches(message, "/.well-known/core")
            || message.option(OptionNumber::OSCORE).is_some()
            || !policy.allow(SecurityState::Unprotected, message)
            || message
                .check_options(|n| endpoint_option(n) || application.recognizes(n))
                .is_err()
            || self.leisure.is_full()
        {
            return Ok(());
        }
        if self
            .duplicates
            .lookup(metadata.remote, metadata.local, message.message_id(), now)
            .is_some()
        {
            self.counters.duplicates += 1;
            return Ok(());
        }
        if !self.charge_response_budget(metadata.remote.ip(), now) {
            return Ok(());
        }
        self.with_packet(
            Some((metadata.remote, metadata.local)),
            now,
            |this, reservation| {
                let ticket = Ticket(this.next_ticket);
                let Some(next_ticket) = this.next_ticket.checked_add(1) else {
                    return Err(Error::Capacity);
                };
                this.next_ticket = next_ticket;
                let mut arena = [0; DATAGRAM_BYTES];
                let mut response = ResponseWriter::new(&mut arena, Code::CONTENT, message.token())?;
                this.counters.requests += 1;
                let request = Request {
                    message,
                    metadata,
                    security: SecurityState::Unprotected,
                    ticket,
                    deferred_available: false,
                    body: message.payload(),
                    context: None,
                    #[cfg(feature = "server")]
                    response_grace_ms: this.parameters.exchange_lifetime(),
                };
                if application.handle(request, &mut response) != Ok(Disposition::Complete)
                    || !response.code().is_success()
                {
                    return Ok(());
                }
                let mid = this.ids.allocate(
                    now,
                    this.parameters
                        .non_lifetime()
                        .saturating_add(this.parameters.leisure_ms)
                        .saturating_add(this.send_policy.max_wait_ms),
                )?;
                let wire = match response.finish(MessageType::NonConfirmable, mid) {
                    Ok(wire) => wire,
                    Err(_) => return Ok(()),
                };
                if wire.payload().is_empty() {
                    return Ok(());
                }
                this.pool.write(reservation, wire.as_bytes())?;
                let packet = this.pool.retain(reservation)?;
                let mut random = [0; 4];
                this.protection.random(&mut random);
                let delay = u64::from(u32::from_ne_bytes(random))
                    % this.parameters.leisure_ms.saturating_add(1);
                let pending = Pending {
                    deadline: now.after(delay),
                    outgoing: Queued::new(
                        metadata.remote,
                        None,
                        metadata.interface,
                        SendPacket::Pooled(packet),
                        QueuedMid::Local(mid),
                        now,
                        false,
                    ),
                };
                if let Err(pending) = this.leisure.push(pending) {
                    this.release_queued(pending.outgoing);
                    return Err(Error::Capacity);
                }
                this.remember(
                    message,
                    metadata,
                    crate::messaging::internal::CachedReply::Silent,
                    now,
                )
            },
        )
    }
}
