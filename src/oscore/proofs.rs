use super::*;

const OPTION_BYTES: usize = 20;

/// OSC-2/15: bounded context IDs preserve RFC 8613 section 3.2.1 bstr/nil inputs.
#[kani::proof]
#[kani::unwind(10)]
fn context_id_storage_preserves_presence_and_capacity() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any_where(|&len| len <= bytes.len());
    let present: bool = kani::any();
    let input = present.then_some(&bytes[..len]);
    let zero = store_context_id::<0>(input);
    let seven = store_context_id::<7>(input);
    assert_eq!(zero.is_ok(), !present || len == 0);
    assert_eq!(seven.is_ok(), !present || len <= 7);
    if let Ok(stored) = zero {
        assert_eq!(stored.as_deref(), input);
    }
    if let Ok(stored) = seven {
        assert_eq!(stored.as_deref(), input);
    }
    kani::cover!(!present, "absent ID Context");
    kani::cover!(present && len == 0, "present empty ID Context");
    kani::cover!(present && len == 7, "exact capacity");
    kani::cover!(present && len == 8, "capacity exceeded");
}

fn window() -> ReplayWindow {
    ReplayWindow {
        highest: kani::any(),
        bitmap: kani::any(),
    }
}

/// OSC-6: compressed COSE header parsing is panic-free.
#[kani::proof]
#[kani::unwind(22)]
fn option_parse_never_panics() {
    let bytes: [u8; OPTION_BYTES] = kani::any();
    let len: usize = kani::any_where(|&len| len <= OPTION_BYTES);
    if let Ok(option) = OscoreOption::parse(&bytes[..len]) {
        let _ = option.sequence();
        kani::cover!(option.kid_context.is_some(), "kid context");
    }
}

/// OSC-6: an accepted option value is the unique encoding of its fields.
#[kani::proof]
#[kani::unwind(22)]
fn option_parse_encode_round_trip() {
    let bytes: [u8; OPTION_BYTES] = kani::any();
    let len: usize = kani::any_where(|&len| len <= OPTION_BYTES);
    let input = &bytes[..len];
    if let Ok(option) = OscoreOption::parse(input) {
        let mut out = [0; 32];
        let used = option.encode(&mut out).unwrap();
        assert_eq!(&out[..used], input);
        kani::cover!(
            option.partial_iv.is_some() && option.kid.is_some() && option.kid_context.is_some(),
            "all fields present"
        );
    }
}

/// OSC-8: an accepted sequence number is never accepted again.
#[kani::proof]
fn replay_accept_then_reject() {
    let mut window = window();
    let sequence = kani::any();
    if window.accept(sequence).is_ok() {
        assert_eq!(window.check(sequence), Err(Error::Replay));
        kani::cover!(window.bitmap.count_ones() > 1, "older entries retained");
    }
}

/// OSC-8: once rejected as a replay, a sequence number stays rejected after any
/// further update. With `replay_accept_then_reject` this covers every sequence of
/// accepts by induction, since the starting window is arbitrary.
#[kani::proof]
fn replay_rejection_is_preserved() {
    let mut window = window();
    let replayed = kani::any();
    kani::assume(window.check(replayed) == Err(Error::Replay));
    let advanced = window.highest;
    let accepted = window.accept(kani::any()).is_ok();
    assert_eq!(window.check(replayed), Err(Error::Replay));
    kani::cover!(accepted && window.highest != advanced, "window advanced");
}

/// OSC-8: numbers above the highest seen, and unseen numbers inside the
/// 32-entry window, are accepted; without this a reject-everything window would
/// satisfy the other replay harnesses.
#[kani::proof]
fn replay_accepts_fresh_numbers() {
    let mut window = window();
    let sequence = kani::any_where(|&s: &u64| s <= MAX_SEQUENCE);
    let fresh = match window.highest {
        None => true,
        Some(highest) if sequence > highest => true,
        Some(highest) => {
            highest - sequence < 32 && window.bitmap & (1 << (highest - sequence)) == 0
        }
    };
    if fresh {
        assert_eq!(window.accept(sequence), Ok(()));
        kani::cover!(
            window.highest != Some(sequence),
            "unseen number inside the window"
        );
    }
}

/// OSC-8: rejection leaves the window unchanged.
#[kani::proof]
fn replay_failed_accept_is_noop() {
    let mut window = window();
    let before = (window.highest, window.bitmap);
    if window.accept(kani::any()).is_err() {
        assert_eq!((window.highest, window.bitmap), before);
        kani::cover!(before.0.is_some(), "rejected by a non-empty window");
    }
}

/// OSC-8: `check` predicts `accept` exactly.
#[kani::proof]
fn replay_accept_agrees_with_check() {
    let mut window = window();
    let sequence = kani::any();
    let checked = window.check(sequence);
    assert_eq!(window.accept(sequence), checked);
    kani::cover!(checked == Err(Error::Replay), "replay rejected");
}

/// OSC-7: reservation advances by one, is never rolled back, and yields the
/// minimal Partial IV of the reserved number.
#[kani::proof]
#[kani::unwind(17)]
fn reserve_monotonic_and_minimal() {
    let mut context = Context {
        sender: heapless::Vec::new(),
        recipient: heapless::Vec::new(),
        id_context: None,
        sender_key: [0; 16],
        recipient_key: [0; 16],
        common_iv: [0; 13],
        next_sequence: kani::any(),
        replay: ReplayWindow::default(),
        peer: PeerId(0),
    };
    let before = context.next_sequence;
    match context.reserve() {
        Ok(piv) => {
            assert!(before <= MAX_SEQUENCE);
            assert_eq!(context.next_sequence, before + 1);
            assert!((1..=5).contains(&piv.len()));
            assert!(piv.len() == 1 || piv[0] != 0);
            let option = OscoreOption {
                partial_iv: Some(&piv),
                kid: None,
                kid_context: None,
            };
            assert_eq!(option.sequence(), Ok(before));
            kani::cover!(piv.len() == 5, "five-byte Partial IV");
        }
        Err(error) => {
            assert_eq!(error, Error::SequenceExhausted);
            assert!(before > MAX_SEQUENCE);
            assert_eq!(context.next_sequence, before);
            kani::cover!(true, "sequence space exhausted");
        }
    }
}

/// OSC-5: the nonce is the common IV XORed with the padded ID length, ID and
/// Partial IV at their fixed positions.
#[kani::proof]
#[kani::unwind(14)]
fn nonce_layout() {
    let common_iv: [u8; 13] = kani::any();
    let id_bytes: [u8; 8] = kani::any();
    let id = &id_bytes[..kani::any_where(|&n: &usize| n <= 8)];
    let piv_bytes: [u8; 6] = kani::any();
    let piv = &piv_bytes[..kani::any_where(|&n: &usize| n <= 6)];
    let result = nonce(&common_iv, id, piv);
    if id.len() > 7 || piv.is_empty() || piv.len() > 5 {
        assert_eq!(result, Err(Error::Malformed));
        return;
    }
    let nonce = result.unwrap();
    let id_start = 8 - id.len();
    let piv_start = 13 - piv.len();
    for i in 0..13 {
        let mut expected = common_iv[i];
        if i == 0 {
            expected ^= id.len() as u8;
        }
        if (id_start..8).contains(&i) {
            expected ^= id[i - id_start];
        }
        if i >= piv_start {
            expected ^= piv[i - piv_start];
        }
        assert_eq!(nonce[i], expected);
    }
    kani::cover!(id.len() == 7 && piv.len() == 5, "longest ID and Partial IV");
}
