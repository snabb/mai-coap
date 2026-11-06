//! Source-table pressure and aggregate response budget regressions (DOS-1).
use crate::{
    rate::{Limiter, Limits},
    time::Instant,
};

#[test]
fn dos_1_new_sources_can_replace_partly_refilled_buckets() {
    let mut limiter = Limiter::<2>::new(Limits {
        per_source: 1,
        source_burst: 3,
        overall: 100,
        overall_burst: 100,
    })
    .unwrap();
    let a = "192.0.2.1".parse().unwrap();
    let b = "192.0.2.2".parse().unwrap();
    let c = "192.0.2.3".parse().unwrap();
    assert!(limiter.allow(a, Instant(0)));
    for _ in 0..3 {
        assert!(limiter.allow(b, Instant(0)));
    }
    assert!(limiter.allow(c, Instant(500)));
    // B has less credit and must remain tracked rather than receiving a fresh burst.
    assert!(!limiter.allow(b, Instant(500)));
}

#[test]
fn dos_1_source_churn_keeps_the_aggregate_limit() {
    let mut limiter = Limiter::<2>::new(Limits {
        per_source: 1,
        source_burst: 3,
        overall: 1,
        overall_burst: 3,
    })
    .unwrap();
    for i in 1..=3 {
        assert!(limiter.allow(core::net::Ipv4Addr::new(192, 0, 2, i).into(), Instant(0)));
    }
    assert!(!limiter.allow("192.0.2.9".parse().unwrap(), Instant(999)));
    assert!(limiter.allow("192.0.2.9".parse().unwrap(), Instant(1000)));
}

#[test]
fn dos_1_late_source_admission_does_not_refill_twice() {
    let mut limiter = Limiter::<2>::new(Limits {
        per_source: 1,
        source_burst: 1,
        overall: 100,
        overall_burst: 100,
    })
    .unwrap();
    let source = "2001:db8::1".parse().unwrap();
    assert!(limiter.allow(source, Instant(50_000)));
    assert!(!limiter.allow(source, Instant(50_000)));
    assert!(!limiter.allow(source, Instant(50_999)));
    assert!(limiter.allow(source, Instant(51_000)));
}

#[test]
fn dos_1_source_and_overall_budgets_age_and_do_not_reset_on_source_port_changes() {
    use crate::rate::{Limiter, Limits};
    let mut limiter = Limiter::<2>::new(Limits {
        per_source: 1,
        source_burst: 2,
        overall: 2,
        overall_burst: 3,
    })
    .unwrap();
    let a = "192.0.2.1".parse().unwrap();
    let b = "192.0.2.2".parse().unwrap();
    assert!(limiter.allow(a, Instant(0)));
    assert!(limiter.allow(a, Instant(0)));
    assert!(!limiter.allow(a, Instant(999)));
    assert!(limiter.allow(b, Instant(999)));
    assert!(limiter.allow(a, Instant(1000)));
    assert!(!limiter.allow(a, Instant(1000)));
    assert!(limiter.allow(a, Instant(2000)));
}

proptest::proptest! {
    #[test]
    fn dos_1_admission_matches_independent_lazy_refill_model(
        rates in proptest::array::uniform4(proptest::prop_oneof![1u32..16, proptest::strategy::Just(u32::MAX)]),
        steps in proptest::collection::vec(
            (0usize..4, proptest::prop_oneof![proptest::strategy::Just(0u64), 1u64..1001, proptest::num::u64::ANY]),
            1..128,
        ),
    ) {
        let limits = Limits {
            per_source: rates[0],
            source_burst: rates[1],
            overall: rates[2],
            overall_burst: rates[3],
        };
        let mut limiter = Limiter::<4>::new(limits).unwrap();
        // DOS-1: refill sources lazily with independent timestamps and exact
        // u128 arithmetic. Four identities avoid mixing refill with eviction policy.
        let mut sources: [Option<(u128, u64)>; 4] = [None; 4];
        let mut total = u128::from(limits.overall_burst) * 1000;
        let mut updated = 0;
        let mut now = 0u64;
        for (source, advance) in steps {
            now = now.saturating_add(advance);
            total = (total + u128::from(now - updated) * u128::from(limits.overall))
                .min(u128::from(limits.overall_burst) * 1000);
            updated = now;
            let expected = if total < 1000 {
                false
            } else {
                let (credit, updated) = sources[source]
                    .get_or_insert((u128::from(limits.source_burst) * 1000, now));
                *credit = (*credit + u128::from(now - *updated) * u128::from(limits.per_source))
                    .min(u128::from(limits.source_burst) * 1000);
                *updated = now;
                if *credit < 1000 {
                    false
                } else {
                    *credit -= 1000;
                    total -= 1000;
                    true
                }
            };
            let address = if source % 2 == 0 {
                core::net::Ipv4Addr::new(192, 0, 2, source as u8).into()
            } else {
                core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, source as u16).into()
            };
            proptest::prop_assert_eq!(limiter.allow(address, Instant(now)), expected, "now={}, source={}", now, source);
        }
    }
}
