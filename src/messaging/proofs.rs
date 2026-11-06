//! REL-2/4: local waiting does not start ACK timers or extend their hard envelope.
use super::{TransmissionParameters, ids::MessageIds, retransmission::Retransmission};
use crate::time::Instant;

/// REL-1 / RFC 7252 section 4.4: later preparation cannot shorten a live ID hold.
#[kani::proof]
#[kani::unwind(3)]
fn later_preparation_preserves_message_id_quarantine() {
    let seed: u16 = kani::any();
    let id: u16 = kani::any();
    let other_block: u8 = kani::any();
    kani::assume((1..16).contains(&other_block));
    let other = id.wrapping_add(u16::from(other_block) * 4096);
    let prior: u64 = kani::any();
    let other_hold: u64 = kani::any();
    let completion: u64 = kani::any();
    let lifetime: u64 = kani::any();
    let now: u64 = kani::any();
    let until = completion.saturating_add(lifetime);
    let mut ids = MessageIds::reentering_block(seed, id);
    let mut different = MessageIds::reentering_block(seed, other);
    for state in [&mut ids, &mut different] {
        state.quarantine(id, Instant(prior));
        state.quarantine(other, Instant(other_hold));
        state.quarantine(id, Instant(completion).after(lifetime));
    }
    assert_eq!(ids.available(Instant(now)), now >= prior.max(until));
    assert_eq!(different.available(Instant(now)), now >= other_hold);
    assert_eq!(
        ids.allocate(Instant(now), 0).is_ok(),
        now >= prior.max(until)
    );
    assert_eq!(
        different.allocate(Instant(now), 0).is_ok(),
        now >= other_hold
    );
    kani::cover!(completion > 1000 && now >= completion && now < until);
    kani::cover!(id.wrapping_sub(seed) >= 4096 && now < until);
    kani::cover!(id < seed && id.wrapping_sub(seed) >= 4096 && now < until);
    kani::cover!(prior > until && now < prior);
    kani::cover!(completion.checked_add(lifetime).is_none() && now < u64::MAX);
}

#[kani::proof]
fn local_wait_does_not_start_ack_timer() {
    let now: u64 = kani::any();
    kani::assume(now < u64::MAX);
    let mut retry = Retransmission::pending(TransmissionParameters::default(), kani::any());
    assert_eq!(retry.poll(Instant(now)), Ok(false));
    assert_eq!(retry.deadline(), Instant(u64::MAX));
    kani::cover!(now > 3000);
}

#[kani::proof]
fn skipped_retry_cannot_extend_protocol_wait() {
    let parameters = TransmissionParameters::default();
    let start: u64 = kani::any();
    let now: u64 = kani::any();
    kani::assume(now >= start);
    let mut retry = Retransmission::pending(parameters, kani::any());
    retry.accepted(Instant(start), parameters);
    let until = Instant(start).after(parameters.max_transmit_wait());
    retry.skipped(Instant(now));
    assert!(retry.deadline() <= until);
    if now < until.0 {
        assert!(retry.deadline() > Instant(now));
    }
    kani::cover!(now > until.0);
}

#[kani::proof]
#[kani::unwind(5)]
fn only_accepted_sends_advance_retransmission_attempts() {
    let parameters = TransmissionParameters::default();
    let start: u64 = kani::any();
    kani::assume(start <= u64::MAX - 1_000_000);
    let mut retry = Retransmission::pending(parameters, kani::any());
    retry.accepted(Instant(start), parameters);
    assert!((start + 2000..=start + 3000).contains(&retry.deadline().0));
    for _ in 0..4 {
        let due = retry.deadline();
        assert_eq!(retry.poll(Instant(due.0 - 1)), Ok(false));
        assert_eq!(retry.poll(due), Ok(true));
        assert_eq!(retry.poll(due), Ok(true));
        assert_eq!(retry.deadline(), due);
        retry.accepted(due, parameters);
        assert!(retry.deadline() <= Instant(start).after(parameters.max_transmit_wait()));
    }
    assert_eq!(retry.poll(retry.deadline()), Err(crate::Error::Timeout));
    kani::cover!(retry.deadline() > Instant(start + 60_000));
}
