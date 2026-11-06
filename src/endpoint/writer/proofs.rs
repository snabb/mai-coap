use super::*;

/// API-1 / BLK-1: preserve the rendered prefix and erase the full offered window.
#[kani::proof]
#[kani::unwind(17)]
fn response_render_bounds_and_cleanup() {
    let wanted = usize::from(kani::any::<u8>());
    let reported = usize::from(kani::any::<u8>());
    let mut bytes = [0x55; 16];
    {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        let result = writer.fill_payload(wanted, |out| {
            assert_eq!(out.len(), wanted);
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = 0x70 + index as u8;
            }
            Ok((reported, ()))
        });
        let fits = wanted <= 11;
        assert_eq!(result.is_ok(), fits && reported <= wanted);
        assert_eq!(
            writer.payload().len(),
            if result.is_ok() { reported } else { 0 }
        );
        for (index, &byte) in writer.payload().iter().enumerate() {
            assert_eq!(byte, 0x70 + index as u8);
        }
    }
    for (index, byte) in bytes.into_iter().enumerate() {
        assert_eq!(
            byte,
            if wanted <= 11 && index >= 16 - wanted {
                0
            } else {
                0x55
            }
        );
    }
    kani::cover!(wanted == 8 && reported == 8, "complete render");
    kani::cover!(wanted == 8 && reported == 3, "short render");
    kani::cover!(wanted == 8 && reported == 9, "excess reported length");
    kani::cover!(wanted == 12, "insufficient wire space");
}

/// MSG-4 / API-1: exact RFC 7252 section 3 wire accounting has no wrapping path.
#[kani::proof]
#[kani::unwind(3)]
fn response_wire_size_is_exact_or_rejects_overflow() {
    let token: usize = kani::any_where(|&n| n <= 8);
    let payload: usize = kani::any();
    let first: u32 = kani::any_where(|&n| n <= 65804);
    let second: u32 = kani::any_where(|&n| n >= first && n - first <= 65804);
    let a: usize = kani::any_where(|&n| n <= 65804);
    let b: usize = kani::any_where(|&n| n <= 65804);
    let extension = |n: u64| {
        if n <= 12 {
            0u128
        } else if n <= 268 {
            1
        } else {
            2
        }
    };
    let expected = 4u128
        + token as u128
        + 1
        + extension(first.into())
        + extension(a as u64)
        + a as u128
        + 1
        + extension((second - first).into())
        + extension(b as u64)
        + b as u128
        + if payload == 0 { 0 } else { 1 + payload as u128 };
    let result = wire_size(
        &[(OptionNumber(first), a), (OptionNumber(second), b)],
        payload,
        token,
    );
    if expected <= usize::MAX as u128 {
        assert_eq!(result, Some(expected as usize));
    } else {
        assert_eq!(result, None);
    }
    kani::cover!(a == 13 && b == 269, "both extension thresholds");
    kani::cover!(payload == 0, "no payload marker");
    kani::cover!(expected > usize::MAX as u128, "overflow refused");
}
