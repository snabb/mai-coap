//! Codec conformance and property tests (MSG, TST-2).
use mai_coap::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn msg_4_6_filtering_matches_explicit_expected_options_with_tight_output(
        response in any::<bool>(),
        tag in proptest::collection::vec(any::<u8>(), 1..9),
        payload in proptest::collection::vec(any::<u8>(), 0..200),
    ) {
        let code = if response { Code::CONTENT } else { Code::GET };
        let mut input = [0; 512];
        let mut b = MessageBuilder::new(&mut input, MessageType::Confirmable, code, 7, b"token").unwrap();
        b.option(OptionNumber::ETAG, &tag).unwrap();
        b.option(OptionNumber::ETAG, b"second").unwrap();
        b.option(OptionNumber::URI_PATH, b"first").unwrap();
        b.option(OptionNumber::URI_PATH, b"second").unwrap();
        b.option(OptionNumber::CONTENT_FORMAT, &[]).unwrap();
        b.uint_option(OptionNumber::CONTENT_FORMAT, 60).unwrap();
        b.option(OptionNumber(280), &[9; 100]).unwrap();
        let n = b.finish(&payload).unwrap();
        let saved = input;
        let mut expected = [0; 512];
        let mut b = MessageBuilder::new(&mut expected, MessageType::Confirmable, code, 7, b"token").unwrap();
        b.option(OptionNumber::ETAG, &tag).unwrap();
        if !response { b.option(OptionNumber::ETAG, b"second").unwrap(); }
        b.option(OptionNumber::URI_PATH, b"first").unwrap();
        b.option(OptionNumber::URI_PATH, b"second").unwrap();
        b.option(OptionNumber::CONTENT_FORMAT, &[]).unwrap();
        let wanted = b.finish(&payload).unwrap();
        let recognized = |number: OptionNumber| number.definition().is_some();
        let message = MessageView::parse(&input[..n]).unwrap();
        let mut output = vec![0; wanted];
        prop_assert_eq!(message.processed(recognized, &mut output), Ok(wanted));
        prop_assert_eq!(output.as_slice(), &expected[..wanted]);
        prop_assert_eq!(message.processed(recognized, &mut output[..wanted - 1]), Err(Error::Capacity));
        prop_assert_eq!(input, saved);
        prop_assert_eq!(MessageView::process_in_place(&mut input[..n], recognized), Ok(wanted));
        prop_assert_eq!(&input[..wanted], &expected[..wanted]);
        prop_assert_eq!(MessageView::process_in_place(&mut input[..wanted], recognized), Ok(wanted));
        prop_assert_eq!(&input[..wanted], &expected[..wanted]);
    }
}

#[test]
fn msg_3_4_filtering_reports_unencodable_merged_option_deltas() {
    let mut input = [0; 32];
    let mut builder = MessageBuilder::new(
        &mut input,
        MessageType::Acknowledgement,
        Code::CONTENT,
        1,
        &[],
    )
    .unwrap();
    for number in [4, 8, 12, 16, 65_820] {
        builder.option(OptionNumber(number), &[]).unwrap();
    }
    let length = builder.finish(&[]).unwrap();
    let saved = input;
    let message = MessageView::parse(&input[..length]).unwrap();
    assert_eq!(message.check_options(|_| true), Ok(()));
    assert_eq!(
        message.processed(|_| true, &mut [0; 32]),
        Err(Error::Capacity)
    );
    assert_eq!(input, saved);
    // Dropping the invalid Hop-Limit merges two deltas beyond the wire range.
    assert_eq!(
        MessageView::process_in_place(&mut input[..length], |_| true),
        Err(Error::Capacity)
    );
}

#[test]
fn msg_4_6_in_place_filtering_matches_the_borrowed_codec() {
    for code in [Code::GET, Code::CONTENT] {
        let mut bytes = [0; 1024];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, code, 77, b"token").unwrap();
        b.option(OptionNumber::ETAG, b"first").unwrap();
        b.option(OptionNumber::ETAG, b"second").unwrap();
        b.option(OptionNumber(10), &[1; 300]).unwrap();
        b.option(OptionNumber::URI_PATH, b"x").unwrap();
        b.option(OptionNumber::CONTENT_FORMAT, &[0; 3]).unwrap();
        b.uint_option(OptionNumber::MAX_AGE, 100).unwrap();
        b.option(OptionNumber(280), b"drop").unwrap();
        b.option(OptionNumber(300), b"keep").unwrap();
        let n = b.finish(b"unchanged payload").unwrap();
        let recognizes =
            |number: OptionNumber| number.definition().is_some() || number == OptionNumber(300);
        let mut expected = [0; 1024];
        let used = MessageView::parse(&bytes[..n])
            .unwrap()
            .processed(recognizes, &mut expected)
            .unwrap();
        let compacted = MessageView::process_in_place(&mut bytes[..n], recognizes).unwrap();
        assert_eq!(&bytes[..compacted], &expected[..used]);
        assert_eq!(
            MessageView::parse(&bytes[..compacted]).unwrap().payload(),
            b"unchanged payload"
        );
        assert_eq!(
            MessageView::process_in_place(&mut bytes[..compacted], recognizes),
            Ok(compacted)
        );
    }
    let mut bytes = [0; 32];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, b"").unwrap();
    b.option(OptionNumber(99), b"critical").unwrap();
    let n = b.finish(&[]).unwrap();
    let saved = bytes;
    assert_eq!(
        MessageView::process_in_place(&mut bytes[..n], |_| false),
        Err(Error::BadOption(OptionNumber(99)))
    );
    assert_eq!(bytes, saved);
}

#[test]
fn msg_4_integer_encoders_and_split_payloads_preserve_wire_bytes() {
    for value in [0, 1, 255, 256, 65535, 65536, u64::MAX] {
        let mut bytes = [0; 64];
        let mut b = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            2,
            b"x",
        )
        .unwrap();
        b.uint_option(OptionNumber(300), value).unwrap();
        let n = b.finish_parts(&[b"first", b"", b"last"]).unwrap();
        let message = MessageView::parse(&bytes[..n]).unwrap();
        let option = message.option(OptionNumber(300)).unwrap();
        assert_eq!(option.uint(), Ok(value));
        assert_eq!(
            option.value.len(),
            (64 - value.leading_zeros()).div_ceil(8) as usize
        );
        assert_eq!(message.payload(), b"firstlast");
        #[cfg(any(feature = "client", feature = "server"))]
        {
            let mut response = mai_coap::endpoint::Response::<64>::new(Code::CONTENT);
            response.uint_option(OptionNumber(300), value).unwrap();
            response.set_uint_option(OptionNumber(300), value).unwrap();
            response.set_payload(b"firstlast").unwrap();
            let mut output = [0; 64];
            let used = response
                .encode(&mut output, MessageType::Acknowledgement, 2, b"x")
                .unwrap();
            assert_eq!(&output[..used], &bytes[..n]);
        }
        let mut short = [0; 64];
        let mut b = MessageBuilder::new(
            &mut short[..n - 1],
            MessageType::Acknowledgement,
            Code::CONTENT,
            2,
            b"x",
        )
        .unwrap();
        b.uint_option(OptionNumber(300), value).unwrap();
        assert_eq!(b.finish_parts(&[b"first", b"last"]), Err(Error::Capacity));
    }
    let mut empty = [0; 4];
    let b = MessageBuilder::new(
        &mut empty,
        MessageType::Acknowledgement,
        Code::EMPTY,
        3,
        b"",
    )
    .unwrap();
    assert_eq!(b.finish_parts(&[b"", b""]), Ok(4));
}

#[test]
fn msg_1_2_empty_and_token_bounds() {
    let mut bytes = [0; 32];
    for n in 0..=8 {
        let token = [42; 8];
        let len = MessageBuilder::new(
            &mut bytes,
            MessageType::Confirmable,
            Code::GET,
            0xabcd,
            &token[..n],
        )
        .unwrap()
        .finish(b"hi")
        .unwrap();
        let view = MessageView::parse(&bytes[..len]).unwrap();
        assert_eq!(view.token(), &token[..n]);
        assert_eq!(view.message_id(), 0xabcd);
        assert_eq!(view.payload(), b"hi");
    }
    for malformed in [
        &[0x00, 1, 0, 0][..],
        &[0x49, 1, 0, 0],
        &[0x40, 0, 0, 0, 255, 1],
        &[0x40, 1, 0, 0, 255],
        &[0x40, 1, 0, 0, 0xf0],
        &[0x40, 1, 0, 0, 0x0f],
        &[0x40, 1, 0, 0, 0xdd],
        &[0x40, 1, 0, 0, 0x01],
    ] {
        assert!(MessageView::parse(malformed).is_err(), "{malformed:x?}");
    }
    assert_eq!(
        MessageView::parse(&[0x40, 0, 0, 0]).unwrap().code(),
        Code::EMPTY
    );
}

#[test]
fn msg_3_7_extended_options_and_failed_insert_are_atomic() {
    let mut bytes = vec![0; 70000];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::NonConfirmable, Code::POST, 2, &[]).unwrap();
    for number in [12, 25, 293, 562, 66366] {
        builder.option(OptionNumber(number), b"").unwrap();
    }
    assert_eq!(
        builder.option(OptionNumber(1), b"").unwrap_err(),
        Error::OptionOrder
    );
    builder
        .option(OptionNumber(66366), &vec![7; 65804])
        .unwrap();
    let len = builder.finish(&[]).unwrap();
    let options: Vec<_> = MessageView::parse(&bytes[..len])
        .unwrap()
        .options()
        .collect();
    assert_eq!(options.len(), 6);
    assert_eq!(options[5].value.len(), 65804);
}

#[test]
fn msg_4_5_6_recognition_lengths_and_duplicate_singletons() {
    let mut bytes = [0; 256];
    let mut b =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 0, &[]).unwrap();
    b.option(OptionNumber::URI_HOST, b"host").unwrap();
    b.option(OptionNumber::URI_PORT, &[0, 80]).unwrap();
    b.option(OptionNumber::URI_PORT, &[80]).unwrap();
    let n = b.finish(&[]).unwrap();
    let v = MessageView::parse(&bytes[..n]).unwrap();
    assert_eq!(v.option(OptionNumber::URI_PORT).unwrap().uint(), Ok(80));
    assert_eq!(
        v.check_options(|_| true),
        Err(Error::BadOption(OptionNumber::URI_PORT))
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]
    #[test]
    fn tst_2_network_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        if let Ok(view) = MessageView::parse(&bytes) {
            for option in view.options() { let _ = option.uint(); }
            let _ = view.check_options(|_| false);
        }
    }
    #[test]
    fn tst_2_valid_raw_messages_round_trip(token in prop::collection::vec(any::<u8>(), 0..=8), payload in prop::collection::vec(any::<u8>(), 0..128), values in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..12), mid in any::<u16>()) {
        let mut input = [0; 2048];
        let mut builder = MessageBuilder::new(&mut input, MessageType::Confirmable, Code::POST, mid, &token).unwrap();
        for value in &values { builder.option(OptionNumber::URI_PATH, value).unwrap(); }
        let length = builder.finish(&payload).unwrap();
        let view = MessageView::parse(&input[..length]).unwrap();
        let mut output = [0; 2048];
        let mut builder = MessageBuilder::new(&mut output, view.message_type(), view.code(), view.message_id(), view.token()).unwrap();
        for option in view.options() { builder.option(option.number, option.value).unwrap(); }
        let other = builder.finish(view.payload()).unwrap();
        prop_assert_eq!(&input[..length], &output[..other]);
    }
}

#[test]
fn msg_5_location_extensions_follow_verified_erratum_4949() {
    for number in [128, 132, 136, 140] {
        let mut bytes = [0; 64];
        let mut b =
            MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::CREATED, 1, b"t")
                .unwrap();
        b.option(OptionNumber::LOCATION_PATH, b"new").unwrap();
        b.option(OptionNumber(number), b"extension").unwrap();
        let n = b.finish(&[]).unwrap();
        let m = MessageView::parse(&bytes[..n]).unwrap();
        assert_eq!(
            m.check_options(|o| o == OptionNumber::LOCATION_PATH),
            Err(Error::BadOption(OptionNumber(number)))
        );
        assert!(m.check_options(|_| true).is_ok());
    }
}
