use super::*;

#[test]
fn owned_and_borrowed_responses_share_ordering_and_refusal_policy() {
    let mut arena = [0; 1024];
    let mut writer = ResponseWriter::<1024>::new(&mut arena, Code::CONTENT, b"token").unwrap();
    let mut owned = Response::<1024>::new(Code::CONTENT);
    writer.set_payload(b"body").unwrap();
    owned.set_payload(b"body").unwrap();
    let mut operations = std::vec![
        (false, 15, &b"a"[..], Ok(())),
        (false, 4, &b"tag"[..], Ok(())),
        (false, 15, &b"b"[..], Ok(())),
        (false, 11, &b"path"[..], Ok(())),
        (true, 15, &b"new"[..], Ok(())),
        (false, 8, &b"."[..], Err(ResponseError::InvalidOption)),
        (true, 11, &b".."[..], Err(ResponseError::InvalidOption)),
    ];
    operations.extend((0..13).map(|_| (false, 15, &b"repeat"[..], Ok(()))));
    operations.extend([
        (false, 15, &b"full"[..], Err(ResponseError::Capacity)),
        (true, 12, &b"absent"[..], Err(ResponseError::Capacity)),
        (true, 11, &b"."[..], Err(ResponseError::InvalidOption)),
        (true, 15, &b"replacement"[..], Ok(())),
        (false, 0, &b"first"[..], Ok(())),
    ]);
    // The large arena keeps wire capacity out of this option-policy comparison.
    for (replace, number, value, expected) in operations {
        let number = OptionNumber(number);
        let (a, b) = if replace {
            (
                writer.set_option(number, value),
                owned.set_option(number, value),
            )
        } else {
            (writer.option(number, value), owned.option(number, value))
        };
        assert_eq!(a, expected);
        assert_eq!(b, expected);
        let mut a = [0; 1024];
        let mut b = [0; 1024];
        let na = writer
            .encode(&mut a, MessageType::Acknowledgement, 7)
            .unwrap();
        let nb = owned
            .encode(&mut b, MessageType::Acknowledgement, 7, b"token")
            .unwrap();
        assert_eq!(&a[..na], &b[..nb]);
    }
    let message = writer.finish(MessageType::Acknowledgement, 7).unwrap();
    assert_eq!(
        message
            .options()
            .map(|o| (o.number.0, o.value))
            .collect::<std::vec::Vec<_>>(),
        [
            (0, &b"first"[..]),
            (4, &b"tag"[..]),
            (11, &b"path"[..]),
            (15, &b"replacement"[..])
        ]
    );
}

#[test]
fn writer_snapshot_and_finish_use_the_same_reserved_token() {
    let mut arena = [0; 24];
    let mut writer = ResponseWriter::<24>::new(&mut arena, Code::CONTENT, b"token123").unwrap();
    writer.set_payload(b"elevenbytes").unwrap();
    let mut snapshot = [0; 24];
    let n = writer
        .encode(&mut snapshot, MessageType::Acknowledgement, 7)
        .unwrap();
    let message = writer.finish(MessageType::Acknowledgement, 7).unwrap();
    assert_eq!(message.token(), b"token123");
    assert_eq!(n, 24);
    assert_eq!(message.as_bytes(), &snapshot[..n]);
}

#[test]
fn deferred_processing_budget_is_not_owned_response_content() {
    let mut arena = [0; 64];
    let mut writer = ResponseWriter::<64>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.set_deferred_timeout(250).unwrap();
    let owned = writer.to_owned().unwrap();
    assert_eq!(writer.deferred_timeout_ms.unwrap().get(), 250);
    writer.copy_from(&owned).unwrap();
    assert_eq!(writer.deferred_timeout_ms.unwrap().get(), 250);
}

#[cfg(feature = "server")]
#[test]
fn rendering_clears_previous_body_on_capacity_and_callback_errors() {
    for capacity_failure in [false, true] {
        let mut bytes = [0; 32];
        let mut writer = ResponseWriter::<32>::new(&mut bytes, Code::CONTENT, &[]).unwrap();
        writer.set_payload(b"old body").unwrap();
        let mut attempted = false;
        let result = writer.fill_payload(if capacity_failure { 32 } else { 8 }, |out| {
            attempted = true;
            out.fill(0x70);
            Err::<(usize, ()), _>(Code::BAD_REQUEST)
        });
        assert_eq!(
            result,
            Err(if capacity_failure {
                Code::INTERNAL_ERROR
            } else {
                Code::BAD_REQUEST
            })
        );
        assert_eq!(attempted, !capacity_failure);
        assert!(writer.payload().is_empty());
    }
}

#[cfg(feature = "discovery")]
#[test]
fn scratch_clears_previous_body_even_on_error() {
    let mut bytes = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut bytes, Code::CONTENT, &[]).unwrap();
    writer.set_payload(b"old body").unwrap();
    let result = writer.with_scratch::<()>(|out| {
        out.fill(0x70);
        Err(Code::BAD_REQUEST)
    });
    assert_eq!(result, Err(Code::BAD_REQUEST));
    assert!(writer.payload().is_empty());
}

#[cfg(feature = "server")]
proptest::proptest! {
    /// API-1 / OSC-18: no potentially written response plaintext survives cleanup.
    #[test]
    fn protected_arena_cleanup_preserves_no_sequence_data(
        operations in proptest::collection::vec(
            (0u8..9, proptest::collection::vec(1u8..0x80, 0..80)), 0..64,
        ),
    ) {
        let mut bytes = [0xcc; 64];
        {
            let mut arena = ResponseArena::new(&mut bytes);
            let mut writer = arena.writer(Code::CONTENT, b"t", true).unwrap();
            for (op, data) in operations {
                match op {
                    0 => { let _ = writer.option(OptionNumber(15), &data); }
                    1 => { let _ = writer.set_option(OptionNumber(15), &data); }
                    2 => { let _ = writer.set_payload(&data); }
                    3 => writer.reset(Code::CONTENT),
                    4 => {
                        let mut owned = Response::<64>::new(Code::CONTENT);
                        if owned.set_payload(&data).is_ok() {
                            let _ = writer.copy_from(&owned);
                        }
                    }
                    5 | 6 => {
                        let reported = usize::from(data.first().copied().unwrap_or(0))
                            % (data.len() + 2);
                        let _ = writer.fill_payload(data.len(), |out| {
                            out.copy_from_slice(&data);
                            if op == 5 { Ok((reported, ())) } else { Err(Code::BAD_REQUEST) }
                        });
                    }
                    7 => {
                        #[cfg(feature = "discovery")]
                        let _ = writer.with_scratch::<()>(|out| {
                            let length = out.len().min(data.len());
                            out[..length].copy_from_slice(&data[..length]);
                            Err(Code::BAD_REQUEST)
                        });
                    }
                    _ => {
                        let _ = writer.finish(MessageType::Acknowledgement, 7);
                        break;
                    }
                }
            }
        }
        // Data excludes zero and the sentinel; abandoned bytes must also be erased.
        proptest::prop_assert!(bytes.into_iter().all(|b| b == 0 || b == 0xcc));
    }
}

#[test]
fn protected_arena_erases_old_values_and_moved_payload_without_wiping_gaps() {
    for protected in [false, true] {
        let mut bytes = [0xcc; 128];
        {
            let mut arena = ResponseArena::new(&mut bytes);
            let mut writer = arena.writer(Code::CONTENT, b"t", protected).unwrap();
            writer.option(OptionNumber(4), &[0x51; 12]).unwrap();
            writer.set_payload(&[0x61; 16]).unwrap();
            writer.set_option(OptionNumber(4), b"x").unwrap();
            writer.set_payload(b"x").unwrap();
            writer.reset(Code::CONTENT);
            assert_eq!(
                writer.set_payload(&[0x71; 128]),
                Err(ResponseError::Capacity)
            );
            writer.set_payload(b"end").unwrap();
            let message = writer.finish(MessageType::Acknowledgement, 7).unwrap();
            assert_eq!(message.payload(), b"end");
        }
        assert!(bytes[12..112].iter().all(|&b| b == 0xcc));
        if protected {
            assert!(bytes[..12].iter().all(|&b| b == 0));
            assert!(bytes[112..].iter().all(|&b| b == 0));
        } else {
            assert_eq!(&bytes[125..], b"end");
            assert!(bytes[..12].contains(&0x51));
        }
    }
}

#[test]
fn overlapping_protected_write_regions_erase_the_whole_arena() {
    let mut bytes = [0xcc; 32];
    {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        writer.option(OptionNumber(4), &[0x51; 12]).unwrap();
        writer.set_payload(&[0x61; 8]).unwrap();
        assert_eq!(
            writer
                .finish(MessageType::Acknowledgement, 1)
                .unwrap()
                .payload(),
            &[0x61; 8]
        );
    }
    assert_eq!(bytes, [0; 32]);
}

#[cfg(feature = "server")]
#[test]
fn render_short_success_and_errors_erase_the_entire_offered_window() {
    for mode in 0..3 {
        let mut bytes = [0xcc; 64];
        {
            let mut arena = ResponseArena::new(&mut bytes);
            let mut writer = arena.writer(Code::CONTENT, b"t", true).unwrap();
            let result = writer.fill_payload(8, |out| {
                assert_eq!(out.len(), 8);
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte = 0x70 + index as u8;
                }
                match mode {
                    0 => Ok((3, ())),
                    1 => Err(Code::BAD_REQUEST),
                    _ => Ok((9, ())),
                }
            });
            if mode == 0 {
                result.unwrap();
                assert_eq!(writer.payload(), &[0x70, 0x71, 0x72]);
                let message = writer.finish(MessageType::Acknowledgement, 1).unwrap();
                assert_eq!(message.payload(), &[0x70, 0x71, 0x72]);
            } else {
                assert!(result.is_err());
                assert!(writer.payload().is_empty());
            }
        }
        let prefix = if mode == 0 { 9 } else { 0 };
        assert!(bytes[..prefix].iter().all(|&b| b == 0));
        assert!(bytes[prefix..56].iter().all(|&b| b == 0xcc));
        assert_eq!(&bytes[56..], &[0; 8]);
    }
}

#[cfg(feature = "server")]
#[test]
fn protected_render_cleanup_runs_on_unwind() {
    let mut bytes = [0xcc; 64];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        let _ = writer.fill_payload::<()>(8, |out| {
            out.fill(0x71);
            panic!("render failed after writing")
        });
    }));
    assert!(result.is_err());
    assert_eq!(&bytes[..56], &[0xcc; 56]);
    assert_eq!(&bytes[56..], &[0; 8]);
}

#[test]
fn protected_option_and_payload_cleanup_runs_on_unwind() {
    let mut bytes = [0xcc; 64];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        writer.option(OptionNumber(4), &[0x51; 8]).unwrap();
        writer.set_payload(&[0x61; 12]).unwrap();
        writer.reset(Code::CONTENT);
        panic!("handler failed after reset")
    }));
    assert!(result.is_err());
    assert_eq!(&bytes[..8], &[0; 8]);
    assert_eq!(&bytes[8..52], &[0xcc; 44]);
    assert_eq!(&bytes[52..], &[0; 12]);
}

#[cfg(feature = "discovery")]
#[test]
fn protected_scratch_errors_erase_all_exposed_bytes() {
    let mut bytes = [0xcc; 64];
    {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        writer.option(OptionNumber(4), b"tag").unwrap();
        assert_eq!(
            writer.with_scratch::<()>(|out| {
                out.fill(0x71);
                Err(Code::BAD_REQUEST)
            }),
            Err(Code::BAD_REQUEST)
        );
    }
    assert_eq!(bytes, [0; 64]);
}

#[cfg(feature = "discovery")]
#[test]
fn protected_scratch_cleanup_runs_on_unwind() {
    let mut bytes = [0xcc; 64];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut arena = ResponseArena::new(&mut bytes);
        let mut writer = arena.writer(Code::CONTENT, &[], true).unwrap();
        let _ = writer.with_scratch::<()>(|out| {
            out.fill(0x71);
            panic!("scratch failed after writing")
        });
    }));
    assert!(result.is_err());
    assert_eq!(bytes, [0; 64]);
}

#[test]
fn msg_4_writer_stably_orders_values_and_rebases_repeated_options() {
    let mut arena = [0; 128];
    let mut writer = ResponseWriter::<128>::new(&mut arena, Code::CONTENT, b"token").unwrap();
    for (n, value) in [
        (15, &b"a"[..]),
        (4, &b"tag"[..]),
        (15, &b"b"[..]),
        (12, &b""[..]),
    ] {
        writer.option(OptionNumber(n), value).unwrap();
    }
    writer.set_payload(b"body").unwrap();
    let expected = writer.to_owned().unwrap();
    let mut encoded = [0; 128];
    let n = expected
        .encode(&mut encoded, MessageType::Acknowledgement, 123, b"token")
        .unwrap();
    let message = writer.finish(MessageType::Acknowledgement, 123).unwrap();
    assert_eq!(message.as_bytes(), &encoded[..n]);
    assert_eq!(
        message
            .options()
            .map(|o| o.number.0)
            .collect::<std::vec::Vec<_>>(),
        [4, 12, 15, 15]
    );
    assert_eq!(
        message
            .values(OptionNumber(15))
            .collect::<std::vec::Vec<_>>(),
        [b"a", b"b"]
    );
    assert_eq!(message.payload(), b"body");
    assert_eq!(message.as_bytes()[n - 5], 0xff);
}

#[test]
fn msg_4_writer_extension_thresholds_match_literal_wire_headers() {
    for (delta, header) in [
        (12, &b"\xc0"[..]),
        (13, &b"\xd0\x00"[..]),
        (268, &b"\xd0\xff"[..]),
        (269, &b"\xe0\x00\x00"[..]),
        (65804, &b"\xe0\xff\xff"[..]),
    ] {
        let mut arena = [0; 32];
        let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, &[]).unwrap();
        writer.option(OptionNumber(delta), &[]).unwrap();
        let message = writer.finish(MessageType::NonConfirmable, 1).unwrap();
        assert_eq!(&message.as_bytes()[4..], header);
    }
    for (length, header) in [
        (0, &b"\x00"[..]),
        (12, &b"\x0c"[..]),
        (13, &b"\x0d\x00"[..]),
        (268, &b"\x0d\xff"[..]),
        (269, &b"\x0e\x00\x00"[..]),
    ] {
        let mut arena = [0; 512];
        let mut writer = ResponseWriter::<512>::new(&mut arena, Code::CONTENT, &[]).unwrap();
        writer
            .option(OptionNumber(0), &std::vec![0x5a; length])
            .unwrap();
        let message = writer.finish(MessageType::NonConfirmable, 1).unwrap();
        assert_eq!(&message.as_bytes()[4..4 + header.len()], header);
        assert_eq!(
            message.option(OptionNumber(0)).unwrap().value,
            &std::vec![0x5a; length]
        );
    }
}

#[test]
fn api_1_writer_replacements_and_refusals_preserve_previous_content() {
    let mut arena = [0; 48];
    let mut writer = ResponseWriter::<48>::new(&mut arena, Code::CONTENT, &[1; 8]).unwrap();
    writer.option(OptionNumber(15), b"first").unwrap();
    writer.option(OptionNumber(4), b"tag").unwrap();
    writer.option(OptionNumber(15), b"second").unwrap();
    writer.set_payload(b"payload").unwrap();
    writer.set_option(OptionNumber(15), b"new").unwrap();
    writer.set_option(OptionNumber(4), b"longer-tag").unwrap();
    let before = writer.to_owned().unwrap();
    assert_eq!(
        writer.set_option(OptionNumber(4), &[0; 48]),
        Err(ResponseError::Capacity)
    );
    assert_eq!(writer.set_payload(&[0; 48]), Err(ResponseError::Capacity));
    assert_eq!(
        writer.option(OptionNumber::URI_PATH, b".."),
        Err(ResponseError::InvalidOption)
    );
    assert_eq!(
        writer.option(OptionNumber(u32::MAX), b""),
        Err(ResponseError::Capacity)
    );
    let mut expected = [0; 48];
    let n = before
        .encode(&mut expected, MessageType::Acknowledgement, 9, &[1; 8])
        .unwrap();
    let message = writer.finish(MessageType::Acknowledgement, 9).unwrap();
    assert_eq!(message.as_bytes(), &expected[..n]);
    assert_eq!(
        message
            .values(OptionNumber(15))
            .collect::<std::vec::Vec<_>>(),
        [b"new"]
    );
}

#[test]
fn api_1_writer_counts_header_marker_and_option_slots_exactly() {
    for token in [&[][..], &[1; 8][..]] {
        let mut arena = [0; 32];
        let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, token).unwrap();
        assert_eq!(writer.remaining_payload(), 32 - 4 - token.len() - 1);
        writer
            .set_payload(&[0xff; 32][..writer.remaining_payload()])
            .unwrap();
        assert_eq!(
            writer.option(OptionNumber(0), &[]),
            Err(ResponseError::Capacity)
        );
        let message = writer.finish(MessageType::NonConfirmable, 1).unwrap();
        assert_eq!(message.as_bytes().len(), 32);
        assert_eq!(message.payload(), &[0xff; 32][..32 - 4 - token.len() - 1]);
    }
    let mut arena = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    for _ in 0..16 {
        writer.option(OptionNumber(0), &[]).unwrap();
    }
    let before = writer.to_owned().unwrap();
    assert_eq!(
        writer.option(OptionNumber(0), &[]),
        Err(ResponseError::Capacity)
    );
    let mut before_bytes = [0; 32];
    let mut after_bytes = [0; 32];
    let n = before
        .encode(&mut before_bytes, MessageType::NonConfirmable, 1, &[])
        .unwrap();
    let m = writer
        .encode(&mut after_bytes, MessageType::NonConfirmable, 1)
        .unwrap();
    assert_eq!(&before_bytes[..n], &after_bytes[..m]);
    writer.set_option(OptionNumber(0), &[]).unwrap();
    assert_eq!(
        writer
            .finish(MessageType::NonConfirmable, 1)
            .unwrap()
            .as_bytes()
            .len(),
        5
    );
    assert_eq!(
        ResponseWriter::<3>::new(&mut [0; 3], Code::CONTENT, &[]).unwrap_err(),
        Error::Capacity
    );
    assert_eq!(
        ResponseWriter::<16>::new(&mut [0; 16], Code::CONTENT, &[1; 9]).unwrap_err(),
        Error::Malformed
    );
}

#[test]
fn msg_4_writer_preserves_marker_bytes_in_options_and_emits_none_for_empty_body() {
    let mut arena = [0; 16];
    let mut writer = ResponseWriter::<16>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.option(OptionNumber(4), &[0xff]).unwrap();
    let message = writer.finish(MessageType::NonConfirmable, 1).unwrap();
    assert_eq!(
        message.as_bytes(),
        &[0x50, Code::CONTENT.0, 0, 1, 0x41, 0xff]
    );
    assert!(message.payload().is_empty());
}

#[test]
fn msg_4_writer_maximum_length_and_one_byte_over_extension() {
    let mut arena = std::vec![0; 70_000];
    let mut writer = ResponseWriter::<70_000>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer
        .option(OptionNumber(0), &std::vec![0x5a; 65_804])
        .unwrap();
    assert_eq!(
        writer.set_option(OptionNumber(0), &std::vec![0; 65_805]),
        Err(ResponseError::Capacity)
    );
    let message = writer.finish(MessageType::NonConfirmable, 1).unwrap();
    assert_eq!(&message.as_bytes()[4..7], &[0x0e, 0xff, 0xff]);
    assert_eq!(message.option(OptionNumber(0)).unwrap().value.len(), 65_804);
    assert!(
        message
            .option(OptionNumber(0))
            .unwrap()
            .value
            .iter()
            .all(|b| *b == 0x5a)
    );
    let mut arena = [0; 20];
    let mut writer = ResponseWriter::<20>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.option(OptionNumber(269), &[1; 12]).unwrap();
    // One unused byte fits the extra value byte but not its new length extension.
    assert_eq!(
        writer.set_option(OptionNumber(269), &[1; 13]),
        Err(ResponseError::Capacity)
    );
    writer.set_payload(&[]).unwrap();
    assert_eq!(
        writer
            .finish(MessageType::NonConfirmable, 1)
            .unwrap()
            .as_bytes()
            .len(),
        19
    );
    let mut arena = [0; 8];
    let mut writer = ResponseWriter::<8>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.option(OptionNumber(13), &[]).unwrap();
    writer.set_payload(&[0xff]).unwrap();
    assert_eq!(writer.set_payload(&[0xff; 2]), Err(ResponseError::Capacity));
    assert_eq!(
        writer
            .finish(MessageType::NonConfirmable, 1)
            .unwrap()
            .as_bytes(),
        &[0x50, Code::CONTENT.0, 0, 1, 0xd0, 0, 0xff, 0xff]
    );
}

#[test]
fn api_1_writer_owned_bridge_is_transactional() {
    let mut arena = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.set_payload(b"old").unwrap();
    writer.set_deferred_timeout(10).unwrap();
    let mut owned = Response::<32>::new(Code::CHANGED);
    owned.option(OptionNumber(4), &[1; 32]).unwrap();
    owned.set_payload(&[2; 32]).unwrap();
    assert_eq!(writer.copy_from(&owned), Err(ResponseError::Capacity));
    assert_eq!(writer.code(), Code::CONTENT);
    assert_eq!(writer.payload(), b"old");
    assert_eq!(writer.deferred_timeout_ms.unwrap().get(), 10);
    let mut owned = Response::<32>::new(Code::CHANGED);
    owned.option(OptionNumber(4), b"tag").unwrap();
    owned.set_payload(b"new").unwrap();
    writer.copy_from(&owned).unwrap();
    assert_eq!(writer.deferred_timeout_ms.unwrap().get(), 10);
    assert_eq!(writer.code(), Code::CHANGED);
    let message = writer.finish(MessageType::Acknowledgement, 1).unwrap();
    assert_eq!(message.payload(), b"new");
    assert_eq!(message.option(OptionNumber(4)).unwrap().value, b"tag");
}

#[cfg(feature = "server")]
#[test]
fn api_1_writer_fill_exposes_remaining_space_and_clears_failed_body() {
    let mut arena = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, &[1; 8]).unwrap();
    writer.option(OptionNumber(4), b"tag").unwrap();
    let available = writer.remaining_payload();
    assert_eq!(
        writer.fill_payload(available, |out| {
            assert_eq!(out.len(), available);
            out.fill(0x5a);
            Ok((out.len(), 7))
        }),
        Ok(7)
    );
    assert_eq!(writer.payload(), &std::vec![0x5a; available]);
    assert_eq!(
        writer.fill_payload::<()>(available, |_| Err(Code::INTERNAL_ERROR)),
        Err(Code::INTERNAL_ERROR)
    );
    assert!(writer.payload().is_empty());
    assert!(
        writer
            .finish(MessageType::Acknowledgement, 1)
            .unwrap()
            .payload()
            .is_empty()
    );
}

#[test]
fn msg_4_writer_refuses_the_first_unrepresentable_delta_atomically() {
    let mut arena = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, &[]).unwrap();
    writer.set_payload(b"body").unwrap();
    assert_eq!(
        writer.option(OptionNumber(65805), &[]),
        Err(ResponseError::Capacity)
    );
    assert_eq!(
        writer
            .finish(MessageType::Acknowledgement, 1)
            .unwrap()
            .as_bytes(),
        &[0x60, Code::CONTENT.0, 0, 1, 0xff, b'b', b'o', b'd', b'y']
    );
}

#[cfg(feature = "discovery")]
#[test]
fn api_1_policy_scratch_preserves_option_values_and_discards_the_body() {
    let mut arena = [0; 32];
    let mut writer = ResponseWriter::<32>::new(&mut arena, Code::CONTENT, b"token123").unwrap();
    writer.option(OptionNumber::ETAG, b"tag").unwrap();
    writer.set_payload(b"old").unwrap();
    assert_eq!(
        writer.with_scratch::<()>(|scratch| {
            assert_eq!(scratch.len(), 29);
            scratch.fill(0xff);
            Err(Code::INTERNAL_ERROR)
        }),
        Err(Code::INTERNAL_ERROR)
    );
    let message = writer.finish(MessageType::Acknowledgement, 1).unwrap();
    assert_eq!(message.option(OptionNumber::ETAG).unwrap().value, b"tag");
    assert!(message.payload().is_empty());
}
