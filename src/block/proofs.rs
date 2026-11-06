use super::*;

/// BLK-1: the option integer and `Block` are interchangeable for valid values.
#[kani::proof]
fn decode_encode_round_trip() {
    let value: u64 = kani::any();
    if let Ok(block) = Block::decode(value) {
        assert_eq!(block.encode(), Ok(value));
        kani::cover!(
            block.number == 0xfffff && block.more,
            "largest block number"
        );
    }
    let block = Block {
        number: kani::any(),
        more: kani::any(),
        szx: kani::any(),
    };
    match block.encode() {
        Ok(value) => assert_eq!(Block::decode(value), Ok(block)),
        Err(error) => {
            assert_eq!(error, Error::Malformed);
            assert!(block.number > 0xfffff || block.szx > 6);
        }
    }
}

/// A smaller server block size keeps the requested byte offset, failing only
/// when the rescaled block number no longer fits in twenty bits.
#[kani::proof]
fn capped_retains_offset() {
    let Ok(block) = Block::new(kani::any(), kani::any(), kani::any()) else {
        return;
    };
    let maximum_szx: u8 = kani::any();
    let szx = block.szx.min(maximum_szx).min(6);
    let offset = block.offset().unwrap();
    match block.capped(maximum_szx) {
        Ok(capped) => {
            assert_eq!(capped.szx, szx);
            assert!(!capped.more);
            assert_eq!(capped.offset(), Ok(offset));
            kani::cover!(capped.szx < block.szx, "size reduced");
        }
        Err(error) => {
            assert_eq!(error, Error::Malformed);
            assert!(offset >> (szx + 4) > 0xfffff);
            kani::cover!(true, "rescaled number overflows");
        }
    }
}

/// RFC 7959 sections 2.3–2.4: the served window starts at the requested byte
/// offset, uses the smaller of the requested and server block sizes, and `more`
/// reports any remainder.
#[kani::proof]
fn slice_in_bounds() {
    static REPRESENTATION: [u8; 4096] = [0; 4096];
    let len: usize = kani::any_where(|&len| len <= REPRESENTATION.len());
    let representation = &REPRESENTATION[..len];
    let block = Block {
        number: kani::any(),
        more: kani::any(),
        szx: kani::any(),
    };
    let maximum_szx: u8 = kani::any();
    if let Ok((chosen, bytes)) = block.slice(representation, maximum_szx) {
        let start = chosen.offset().unwrap();
        let end = start + bytes.len();
        assert_eq!(start, block.offset().unwrap());
        assert_eq!(chosen.szx, block.szx.min(maximum_szx).min(6));
        assert_eq!(end, (start + chosen.size().unwrap()).min(len));
        assert!(end <= len);
        // RFC 7959 section 2.3: with M set, the payload is exactly the block size.
        if chosen.more {
            assert_eq!(bytes.len(), chosen.size().unwrap());
        } else {
            assert!(bytes.len() <= chosen.size().unwrap());
        }
        assert!(core::ptr::eq(
            bytes.as_ptr(),
            representation[start..].as_ptr()
        ));
        assert_eq!(chosen.more, end < len);
        assert!(!bytes.is_empty() || len == 0);
        kani::cover!(chosen.more && start > 0, "middle block");
        kani::cover!(!chosen.more && start > 0, "final partial block");
    }
}
