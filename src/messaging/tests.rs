//! Reliability timing and duplicate-cache lifetime tests (REL).
use super::{
    ids::MessageIds,
    internal::{CachePressure, CachedReply, Deduplication, ReplyReclaimMode},
    retransmission::Retransmission,
};
use crate::{Error, messaging::TransmissionParameters, packet_pool::PacketPool, time::Instant};
use std::{format, vec, vec::Vec};

fn cache_input<const DATAGRAM_BYTES: usize, const PACKETS: usize>(
    pool: &mut PacketPool<DATAGRAM_BYTES, PACKETS>,
    reply: Option<&[u8]>,
) -> CachedReply {
    match reply {
        None => CachedReply::Silent,
        Some(bytes) if bytes.len() <= 4 => CachedReply::inline(bytes).unwrap(),
        Some(bytes) => {
            let packet = pool.reserve().unwrap();
            pool.write(&packet, bytes).unwrap();
            CachedReply::Full(packet)
        }
    }
}

fn cached<
    'a,
    const DATAGRAM_BYTES: usize,
    const DEDUP_ENTRIES: usize,
    const CACHED_REPLIES: usize,
    const PACKETS: usize,
>(
    table: &'a Deduplication<DEDUP_ENTRIES, CACHED_REPLIES>,
    pool: &'a PacketPool<DATAGRAM_BYTES, PACKETS>,
    peer: core::net::SocketAddr,
    local: core::net::IpAddr,
    id: u16,
    now: Instant,
) -> Option<Option<&'a [u8]>> {
    match table.lookup(peer, local, id, now)? {
        CachedReply::Silent | CachedReply::Dropped => Some(None),
        CachedReply::Inline { bytes, len } => Some(Some(&bytes[..usize::from(*len)])),
        CachedReply::Full(packet) => Some(Some(pool.get(packet)?)),
    }
}

#[test]
fn rel_2_4_default_deadlines_and_backoff() {
    let p = TransmissionParameters::default().validate().unwrap();
    assert_eq!(p.max_transmit_span(), 45_000);
    assert_eq!(p.max_transmit_wait(), 93_000);
    assert_eq!(p.exchange_lifetime(), 247_000);
    assert_eq!(p.non_lifetime(), 145_000);
    let mut r = Retransmission::new(Instant(0), p, 0);
    for deadline in [2000, 6000, 14000, 30000] {
        assert_eq!(r.deadline(), Instant(deadline));
        assert_eq!(r.poll(Instant(deadline - 1)), Ok(false));
        assert_eq!(r.poll(Instant(deadline)), Ok(true));
        r.accepted(Instant(deadline), p);
    }
    assert_eq!(r.deadline(), Instant(62000));
    assert_eq!(r.poll(Instant(62000)), Err(Error::Timeout));
    assert_eq!(p.initial_timeout(u32::MAX), 3000);
}

#[test]
fn rel_1_rollover_never_reuses_live_ids() {
    let mut ids = MessageIds::new(300);
    for _ in 0..65536 {
        ids.allocate(Instant(0), 247000).unwrap();
    }
    assert_eq!(ids.allocate(Instant(246999), 247000), Err(Error::Capacity));
    assert_eq!(ids.allocate(Instant(247000), 247000), Ok(300));
}

#[test]
fn rel_1_slow_preparation_extends_id_quarantine_through_the_send_window() {
    let mut ids = MessageIds::new(300);
    let first = ids.allocate(Instant(0), 248_000).unwrap();
    ids.quarantine(first, Instant(250_000));
    for _ in 1..65536 {
        ids.allocate(Instant(0), 248_000).unwrap();
    }
    assert_eq!(
        ids.allocate(Instant(249_999), 248_000),
        Err(Error::Capacity)
    );
    assert_eq!(ids.allocate(Instant(250_000), 248_000), Ok(first));
}

#[test]
fn rel_1_quarantine_follows_wrapping_seed_relative_blocks() {
    for seed in [0u16, 300, 0xf800, u16::MAX] {
        for block in 0..16u16 {
            for within in [0, 1, 4095] {
                let start = seed.wrapping_add(block * 4096);
                let id = start.wrapping_add(within);
                let other_id = id.wrapping_add(4096);
                let mut ids = MessageIds::reentering_block(seed, id);
                let mut other = MessageIds::reentering_block(seed, other_id);
                for state in [&mut ids, &mut other] {
                    state.quarantine(id, Instant(20));
                    state.quarantine(other_id, Instant(12));
                    state.quarantine(id, Instant(5));
                }
                assert!(!other.available(Instant(11)));
                assert!(other.available(Instant(12)));
                assert_eq!(ids.allocate(Instant(19), 0), Err(Error::Capacity));
                assert_eq!(ids.allocate(Instant(20), 0), Ok(start));
            }
        }
    }
}

#[test]
fn rel_1_rollover_quarantines_only_the_block_being_reused() {
    let mut ids = MessageIds::new(300);
    for _ in 0..4096 {
        ids.allocate(Instant(0), 10_000).unwrap();
    }
    for _ in 4096..65536 {
        ids.allocate(Instant(20_000), 10_000).unwrap();
    }
    for i in 0..4096u16 {
        assert_eq!(ids.allocate(Instant(20_000), 10_000), Ok(300 + i));
    }
    assert_eq!(ids.allocate(Instant(29_999), 10_000), Err(Error::Capacity));
    assert_eq!(ids.allocate(Instant(30_000), 10_000), Ok(4396));
}

#[test]
fn rel_3_byte_exact_cached_reply_and_expiry_release_the_cache_reference() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<64, 2>::new();
    let mut table = Deduplication::<1>::new();
    let queue_ref = pool.reserve().unwrap();
    pool.write(&queue_ref, b"exact protected bytes").unwrap();
    let cache_ref = pool.retain(&queue_ref).unwrap();
    assert_eq!(
        table.remember(
            &mut pool,
            peer,
            local,
            1,
            Instant(20),
            CachedReply::Full(cache_ref),
            Instant(0),
        ),
        Ok(CachePressure::default())
    );
    assert_eq!(
        cached(&table, &pool, peer, local, 1, Instant(19)),
        Some(Some(&b"exact protected bytes"[..]))
    );
    pool.release(queue_ref);
    assert_eq!(pool.available(), 1);
    table.expire(&mut pool, Instant(20));
    assert_eq!(cached(&table, &pool, peer, local, 1, Instant(20)), None);
    assert_eq!(pool.available(), 2);
}

#[test]
fn rel_3_reply_reclamation_prefers_same_remote_and_local_and_keeps_queued_bytes() {
    let a = "127.0.0.1:5683".parse().unwrap();
    let b = "127.0.0.1:5684".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let other_local = "127.0.0.2".parse().unwrap();
    for candidate_local in [local, other_local] {
        let mut pool = PacketPool::<32, 4>::new();
        let mut table = Deduplication::<4, 2>::new();
        let mut queued_old = None;
        for (peer, destination, id) in [(b, local, 1), (a, candidate_local, 2)] {
            let reply = [id as u8; 8];
            let input = cache_input(&mut pool, Some(&reply));
            let queue_ref = match &input {
                CachedReply::Full(packet) => Some(pool.retain(packet).unwrap()),
                _ => None,
            };
            if id == 2 {
                queued_old = queue_ref;
            }
            assert_eq!(
                table.remember(
                    &mut pool,
                    peer,
                    destination,
                    id,
                    Instant(100),
                    input,
                    Instant(0),
                ),
                Ok(CachePressure::default())
            );
        }
        let incoming = cache_input(&mut pool, Some(b"new reply"));
        assert_eq!(
            table.remember(&mut pool, a, local, 3, Instant(100), incoming, Instant(1),),
            Ok(CachePressure {
                reply_dropped: true,
                ..CachePressure::default()
            })
        );
        if candidate_local == local {
            assert_eq!(
                cached(&table, &pool, b, local, 1, Instant(2)),
                Some(Some(&[1; 8][..]))
            );
            assert_eq!(cached(&table, &pool, a, local, 2, Instant(2)), Some(None));
            assert_eq!(pool.get(queued_old.as_ref().unwrap()), Some(&[2; 8][..]));
        } else {
            assert_eq!(cached(&table, &pool, b, local, 1, Instant(2)), Some(None));
            assert_eq!(
                cached(&table, &pool, a, other_local, 2, Instant(2)),
                Some(Some(&[2; 8][..]))
            );
        }
        assert_eq!(
            cached(&table, &pool, a, local, 3, Instant(2)),
            Some(Some(b"new reply".as_slice()))
        );
        if let Some(packet) = queued_old {
            pool.release(packet);
        }
    }
}

#[test]
fn pool_pressure_reclaims_oldest_unshared_reply_with_same_sender_preference() {
    let preferred = "127.0.0.1:5683".parse().unwrap();
    let other = "127.0.0.1:5684".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<32, 4>::new();
    let mut table = Deduplication::<4, 3>::new();

    let pinned = cache_input(&mut pool, Some(b"pinned reply"));
    let queue_ref = match &pinned {
        CachedReply::Full(packet) => Some(pool.retain(packet).unwrap()),
        _ => None,
    };
    table
        .remember(
            &mut pool,
            preferred,
            local,
            1,
            Instant(100),
            pinned,
            Instant(0),
        )
        .unwrap();
    for (peer, id, bytes) in [
        (preferred, 2, b"same sender".as_slice()),
        (other, 3, b"other sender".as_slice()),
    ] {
        let input = cache_input(&mut pool, Some(bytes));
        table
            .remember(&mut pool, peer, local, id, Instant(100), input, Instant(0))
            .unwrap();
    }

    let available = pool.available();
    assert!(table.reclaim_reply(
        &mut pool,
        Some((preferred, local)),
        ReplyReclaimMode::FreePacket,
    ));
    assert_eq!(
        cached(&table, &pool, preferred, local, 1, Instant(1)),
        Some(Some(&b"pinned reply"[..]))
    );
    assert_eq!(
        cached(&table, &pool, preferred, local, 2, Instant(1)),
        Some(None)
    );
    assert_eq!(
        cached(&table, &pool, other, local, 3, Instant(1)),
        Some(Some(&b"other sender"[..]))
    );
    assert_eq!(pool.available(), available + 1);
    pool.release(queue_ref.unwrap());
}

#[test]
fn rel_3_record_and_reply_pressure_are_independent() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<16, 4>::new();
    let mut table = Deduplication::<2, 1>::new();
    for (id, reply) in [(1, None), (2, Some(b"old reply".as_slice()))] {
        let input = cache_input(&mut pool, reply);
        assert_eq!(
            table.remember(&mut pool, peer, local, id, Instant(10), input, Instant(0),),
            Ok(CachePressure::default())
        );
    }
    let input = cache_input(&mut pool, Some(b"new reply"));
    assert_eq!(
        table.remember(&mut pool, peer, local, 3, Instant(10), input, Instant(0),),
        Ok(CachePressure {
            record_evicted: true,
            reply_dropped: true,
        })
    );
    assert_eq!(cached(&table, &pool, peer, local, 1, Instant(0)), None);
    assert_eq!(
        cached(&table, &pool, peer, local, 2, Instant(0)),
        Some(None)
    );
    assert_eq!(
        cached(&table, &pool, peer, local, 3, Instant(0)),
        Some(Some(b"new reply".as_slice()))
    );
}

#[test]
fn rel_3_expiry_precedes_live_reply_budget_reclamation() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<32, 4>::new();
    let mut table = Deduplication::<3, 2>::new();
    for (id, until, reply) in [
        (1, 5, Some(b"expired full".as_slice())),
        (2, 100, Some(b"live full".as_slice())),
    ] {
        let input = cache_input(&mut pool, reply);
        assert_eq!(
            table.remember(
                &mut pool,
                peer,
                local,
                id,
                Instant(until),
                input,
                Instant(0),
            ),
            Ok(CachePressure::default())
        );
    }
    let input = cache_input(&mut pool, Some(b"replacement"));
    assert_eq!(
        table.remember(&mut pool, peer, local, 3, Instant(200), input, Instant(5),),
        Ok(CachePressure::default())
    );
    assert_eq!(cached(&table, &pool, peer, local, 1, Instant(5)), None);
    assert_eq!(
        cached(&table, &pool, peer, local, 2, Instant(5)),
        Some(Some(&b"live full"[..]))
    );
}

#[test]
fn rel_3_inline_cache_distinguishes_silence_and_empty_reply_per_endpoint() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let other_peer = "127.0.0.1:5684".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let other_local = "127.0.0.2".parse().unwrap();
    let mut pool = PacketPool::<4, 0>::new();
    let mut table = Deduplication::<3, 0>::new();
    for (peer, local, reply) in [
        (peer, local, None),
        (other_peer, local, Some(&b""[..])),
        (peer, other_local, Some(&b"ack!"[..])),
    ] {
        let input = cache_input(&mut pool, reply);
        assert_eq!(
            table.remember(&mut pool, peer, local, 7, Instant(10), input, Instant(0),),
            Ok(CachePressure::default())
        );
    }
    assert_eq!(
        cached(&table, &pool, peer, local, 7, Instant(1)),
        Some(None)
    );
    assert_eq!(
        cached(&table, &pool, other_peer, local, 7, Instant(1)),
        Some(Some(&b""[..]))
    );
    assert_eq!(
        cached(&table, &pool, peer, other_local, 7, Instant(1)),
        Some(Some(&b"ack!"[..]))
    );
    assert_eq!(
        cached(&table, &pool, other_peer, other_local, 7, Instant(1)),
        None
    );
    let mut zero = Deduplication::<0, 0>::new();
    assert_eq!(
        zero.remember(
            &mut pool,
            peer,
            local,
            7,
            Instant(10),
            CachedReply::Silent,
            Instant(0)
        ),
        Err(Error::Capacity)
    );
}

#[test]
fn rel_3_cache_identity_preserves_families_ports_destinations_and_zones() {
    use core::net::{IpAddr, SocketAddr, SocketAddrV6};
    let v6 = |ip: &str, port, flow, zone| {
        SocketAddr::V6(SocketAddrV6::new(ip.parse().unwrap(), port, flow, zone))
    };
    let ipv4: SocketAddr = "192.0.2.1:5683".parse().unwrap();
    let global = v6("2001:db8::1", 5683, 1, 3);
    let link = v6("fe80::1", 5683, 1, 3);
    let group = v6("ff02::1", 5683, 1, 3);
    let local: IpAddr = "2001:db8::2".parse().unwrap();
    for (stored, query, same) in [
        (ipv4, ipv4, true),
        (ipv4, "192.0.2.1:5684".parse().unwrap(), false),
        (ipv4, v6("::ffff:192.0.2.1", 5683, 0, 0), false),
        (global, v6("2001:db8::1", 5683, 2, 4), true),
        (link, v6("fe80::1", 5683, 2, 3), true),
        (link, v6("fe80::1", 5683, 1, 4), false),
        (group, v6("ff02::1", 5683, 2, 3), true),
        (group, v6("ff02::1", 5683, 1, 4), false),
    ] {
        let mut pool = PacketPool::<4, 0>::new();
        let mut table = Deduplication::<1, 0>::new();
        table
            .remember(
                &mut pool,
                stored,
                local,
                7,
                Instant(10),
                CachedReply::inline(b"ack!").unwrap(),
                Instant(0),
            )
            .unwrap();
        assert_eq!(table.lookup(query, local, 7, Instant(1)).is_some(), same);
        assert!(
            table
                .lookup(query, "2001:db8::3".parse().unwrap(), 7, Instant(1))
                .is_none()
        );
        assert!(table.lookup(query, local, 8, Instant(1)).is_none());
    }
}

#[test]
fn rel_3_inline_replacement_preserves_all_lengths_and_queued_ownership() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let bytes = [0x60, 0, 0x12, 0x34];
    for length in 0..=bytes.len() {
        let mut pool = PacketPool::<16, 2>::new();
        let mut table = Deduplication::<1, 1>::new();
        let packet = pool.reserve().unwrap();
        pool.write(&packet, b"full response").unwrap();
        let queued = pool.retain(&packet).unwrap();
        table
            .remember(
                &mut pool,
                peer,
                local,
                7,
                Instant(10),
                CachedReply::Full(packet),
                Instant(0),
            )
            .unwrap();
        table
            .remember(
                &mut pool,
                peer,
                local,
                7,
                Instant(10),
                CachedReply::inline(&bytes[..length]).unwrap(),
                Instant(1),
            )
            .unwrap();
        assert_eq!(
            cached(&table, &pool, peer, local, 7, Instant(1)),
            Some(Some(&bytes[..length]))
        );
        assert_eq!(pool.get(&queued), Some(b"full response".as_slice()));
        assert_eq!(pool.reference_count(&queued), 1);
        pool.release(queued);
        assert_eq!(pool.available(), 2);
        table.expire(&mut pool, Instant(10));
        assert!(table.lookup(peer, local, 7, Instant(10)).is_none());
    }
}

#[test]
fn rel_3_reclaimed_reply_remains_distinct_from_intentional_silence_until_expiry() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<16, 2>::new();
    let mut table = Deduplication::<3, 1>::new();
    for (id, bytes) in [
        (1, None),
        (2, Some(&b"reply"[..])),
        (3, Some(&b"new reply"[..])),
    ] {
        let input = cache_input(&mut pool, bytes);
        table
            .remember(&mut pool, peer, local, id, Instant(10), input, Instant(0))
            .unwrap();
    }
    assert!(matches!(
        table.lookup(peer, local, 1, Instant(9)),
        Some(CachedReply::Silent)
    ));
    assert!(matches!(
        table.lookup(peer, local, 2, Instant(9)),
        Some(CachedReply::Dropped)
    ));
    assert!(matches!(
        table.lookup(peer, local, 3, Instant(9)),
        Some(CachedReply::Full(_))
    ));
    assert!(table.lookup(peer, local, 2, Instant(10)).is_none());
    table.expire(&mut pool, Instant(10));
    assert_eq!(pool.available(), 2);
}

#[test]
fn plt_7_failed_cache_admission_leaves_records_unchanged_and_releases_input() {
    let peer = "127.0.0.1:5683".parse().unwrap();
    let local = "127.0.0.1".parse().unwrap();
    let mut pool = PacketPool::<16, 2>::new();
    let mut table = Deduplication::<2, 0>::new();
    table
        .remember(
            &mut pool,
            peer,
            local,
            1,
            Instant(1),
            CachedReply::inline(b"ack").unwrap(),
            Instant(0),
        )
        .unwrap();
    let before = format!("{table:?}");
    let input = cache_input(&mut pool, Some(b"full reply"));
    assert_eq!(
        table.remember(&mut pool, peer, local, 2, Instant(20), input, Instant(10)),
        Err(Error::Capacity)
    );
    assert_eq!(format!("{table:?}"), before);
    assert_eq!(pool.available(), 2);

    let mut zero = Deduplication::<0, 1>::new();
    assert_eq!(
        zero.remember(
            &mut pool,
            peer,
            local,
            1,
            Instant(10),
            CachedReply::Silent,
            Instant(0)
        ),
        Err(Error::Capacity)
    );
}

#[test]
fn plt_7_oversized_inline_reply_is_refused() {
    assert!(matches!(
        CachedReply::inline(&[0; 4]),
        Ok(CachedReply::Inline { len: 4, .. })
    ));
    assert!(matches!(CachedReply::inline(&[0; 5]), Err(Error::Capacity)));
}

proptest::proptest! {
    #[test]
    fn rel_3_bounded_cache_matches_a_record_and_reply_budget_model(
        operations in proptest::collection::vec((0u8..8, 0u8..5, 0u8..4, 1u8..15, 0u8..3, 0u8..2), 1..100)
    ) {
        use proptest::prelude::*;
        let peers: [core::net::SocketAddr; 3] = core::array::from_fn(|i| format!("127.0.0.1:{}", 5683+i).parse().unwrap());
        let locals: [core::net::IpAddr; 2] = ["127.0.0.1".parse().unwrap(), "127.0.0.2".parse().unwrap()];
        let mut pool = PacketPool::<16, 8>::new();
        let mut table = Deduplication::<3, 2>::new();
        type ModelEntry = ((u8, u8, u16), Instant, Option<Vec<u8>>, bool);
        let mut model: Vec<ModelEntry> = Vec::new();
        let mut now = Instant(0);
        for (id, kind, step, lifetime, peer, local) in operations {
            now = now.after(u64::from(step));
            let id = u16::from(id);
            let key = (peer, local, id);
            let reply = match kind {
                0 => None,
                1 => Some(vec![id as u8; 4]),
                2 => Some(vec![id as u8; 8]),
                3 => Some(vec![id as u8; 16]),
                _ => Some(vec![id as u8; 17]),
            };
            let until = now.after(u64::from(lifetime));
            let expected = if kind == 4 {
                Err(Error::Capacity)
            } else {
                model.retain(|(_, expiry, _, _)| *expiry > now);
                let mut pressure = CachePressure::default();
                if !model.iter().any(|(old, _, _, _)| *old == key) && model.len() == 3 {
                    model.remove(0);
                    pressure.record_evicted = true;
                }
                let replaces_full = model.iter().any(|(old, _, bytes, _)| *old == key && bytes.as_ref().is_some_and(|b| b.len() > 4));
                if reply.as_ref().is_some_and(|b| b.len() > 4) && !replaces_full
                    && model.iter().filter(|(_, _, bytes, _)| bytes.as_ref().is_some_and(|b| b.len() > 4)).count() == 2
                {
                    let full = |bytes: &Option<Vec<u8>>| bytes.as_ref().is_some_and(|b| b.len() > 4);
                    let victim = model.iter().position(|((p,l,_), _, bytes, _)| *p == peer && *l == local && full(bytes))
                        .or_else(|| model.iter().position(|(_, _, bytes, _)| full(bytes))).unwrap();
                    model[victim].2 = None;
                    model[victim].3 = true;
                    pressure.reply_dropped = true;
                }
                if let Some(existing) = model.iter_mut().find(|(old, _, _, _)| *old == key) {
                    *existing = (key, until, reply.clone(), false);
                } else {
                    model.push((key, until, reply.clone(), false));
                }
                Ok(pressure)
            };
            if kind == 4 {
                prop_assert!(CachedReply::inline(&[0; 17]).is_err());
            } else {
                let input = cache_input(&mut pool, reply.as_deref());
                prop_assert_eq!(table.remember(&mut pool, peers[usize::from(peer)], locals[usize::from(local)], id, until, input, now), expected);
            }
            for p in 0..3 {
                for l in 0..2 {
                    for id in 0..8 {
                        let entry = model.iter().find(|(old, expiry, _, _)| *old == (p, l, id) && *expiry > now);
                        let expected = entry.map(|(_, _, bytes, _)| bytes.as_deref());
                        let dropped = matches!(table.lookup(peers[usize::from(p)], locals[usize::from(l)], id, now), Some(CachedReply::Dropped));
                        prop_assert_eq!(dropped, entry.is_some_and(|(_, _, _, dropped)| *dropped));
                        prop_assert_eq!(cached(&table, &pool, peers[usize::from(p)], locals[usize::from(l)], id, now), expected);
                    }
                }
            }
        }
    }
}
