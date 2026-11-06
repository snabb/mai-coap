use super::*;

const PARSE_BYTES: usize = 12;

fn message_type(bits: u8) -> MessageType {
    match bits & 3 {
        0 => MessageType::Confirmable,
        1 => MessageType::NonConfirmable,
        2 => MessageType::Acknowledgement,
        _ => MessageType::Reset,
    }
}

/// MSG-1–3, TST-2: parsing any datagram up to `PARSE_BYTES` is panic-free, as are
/// the header, token, payload, option iteration and `uint` accessors of an
/// accepted one. The bound excludes two-byte length extensions (values of 269+
/// bytes); `check_options` and `process_in_place` are covered by the codec fuzz
/// target instead.
#[kani::proof]
#[kani::unwind(10)]
fn parse_never_panics() {
    let bytes: [u8; PARSE_BYTES] = kani::any();
    let len: usize = kani::any_where(|&len| len <= PARSE_BYTES);
    if let Ok(view) = MessageView::parse(&bytes[..len]) {
        let _ = (view.message_type(), view.code(), view.message_id());
        assert!(view.token().len() <= 8);
        let payload = view.payload();
        let mut previous = 0;
        let mut count = 0;
        for option in view.options() {
            assert!(option.number.0 >= previous);
            previous = option.number.0;
            let _ = option.uint();
            count += 1;
        }
        assert!(view.option_end <= len);
        assert!(payload.is_empty() || view.payload_start == view.option_end + 1);
        kani::cover!(count >= 2 && !payload.is_empty(), "options and payload");
    }
}

/// Option delta and length nibbles round-trip for every value.
#[kani::proof]
fn extension_round_trip() {
    let n: usize = kani::any();
    match encode_extension(n) {
        Ok((encoded, bytes, len)) => {
            assert!(n <= 65804);
            kani::cover!(len == 2, "two-byte extension");
            let mut offset = 0;
            assert_eq!(extension(&bytes[..len], &mut offset, encoded), Ok(n));
            assert_eq!(offset, len);
        }
        Err(error) => {
            assert!(n > 65804);
            assert_eq!(error, Error::Capacity);
        }
    }
}

/// MSG-7: an encoded message parses back to the same fields.
#[kani::proof]
#[kani::unwind(10)]
fn builder_round_trip_single_option() {
    let ty = message_type(kani::any());
    let code = Code(kani::any());
    let mid: u16 = kani::any();
    let token_bytes: [u8; 8] = kani::any();
    let token = &token_bytes[..kani::any_where(|&n: &usize| n <= 8)];
    let number = OptionNumber(kani::any());
    let value_bytes: [u8; 4] = kani::any();
    let value = &value_bytes[..kani::any_where(|&n: &usize| n <= 4)];
    let payload_bytes: [u8; 2] = kani::any();
    let payload = &payload_bytes[..kani::any_where(|&n: &usize| n <= 2)];
    let with_option: bool = kani::any();

    let mut buffer = [0; 24];
    let Ok(mut builder) = MessageBuilder::new(&mut buffer, ty, code, mid, token) else {
        return;
    };
    if with_option && builder.option(number, value).is_err() {
        return;
    }
    let Ok(used) = builder.finish(payload) else {
        return;
    };

    let view = MessageView::parse(&buffer[..used]).unwrap();
    assert_eq!(view.message_type(), ty);
    assert_eq!(view.code(), code);
    assert_eq!(view.message_id(), mid);
    assert_eq!(view.token(), token);
    assert_eq!(view.payload(), payload);
    let mut options = view.options();
    if with_option {
        assert_eq!(options.next(), Some(MessageOption { number, value }));
    }
    assert_eq!(options.next(), None);
    kani::cover!(
        with_option && number.0 >= 269 && !token.is_empty() && !payload.is_empty(),
        "two-byte extension with token and payload"
    );
}

/// MSG-1, MSG-7: rewriting type, MID and token keeps the code and the exact option
/// and payload bytes.
#[kani::proof]
#[kani::unwind(10)]
fn reheader_preserves_content() {
    let original: [u8; 6] = kani::any();
    let length: usize = kani::any_where(|&length| length <= original.len());
    let Ok(view) = MessageView::parse(&original[..length]) else {
        return;
    };
    let token: [u8; 8] = kani::any();
    let token_length: usize = kani::any_where(|&n| n <= token.len());
    let token = &token[..token_length];
    if view.code() == Code::EMPTY && !token.is_empty() {
        return;
    }
    let (ty, mid) = (message_type(kani::any()), kani::any());
    // Fits the longest token with the longest tail of this bounded message.
    let mut bytes = [0; 16];
    bytes[..length].copy_from_slice(&original[..length]);
    let n = reheader(&mut bytes, length, ty, mid, token).unwrap();
    let tail = &original[view.option_start..length];
    assert_eq!(n, 4 + token.len() + tail.len());
    assert_eq!(&bytes[4 + token.len()..n], tail);
    let rewritten = MessageView::parse(&bytes[..n]).unwrap();
    assert!(rewritten.message_type() == ty);
    assert_eq!(rewritten.message_id(), mid);
    assert_eq!(rewritten.code(), view.code());
    assert_eq!(rewritten.token(), token);
    kani::cover!(view.token().len() > token.len(), "shrinking token");
    kani::cover!(
        view.token().len() < token.len() && !tail.is_empty(),
        "growing token"
    );
}
