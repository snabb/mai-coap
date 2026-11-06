use super::*;

// Each dot is matched independently, so `/.%2E` exercises every dot form.
const PATH_BYTES: usize = 5;

/// RFC 7252 section 5.10.1: after dot-segment removal no segment decodes to "."
/// or "..", including segments spelled with `%2E` (RFC 3986 section 2.3). This
/// proves only that invariant; equivalence with RFC 3986 section 5.2.4 is checked
/// exhaustively over a token alphabet in `uri::tests`, beyond this byte bound.
#[kani::proof]
#[kani::unwind(7)]
fn normalized_segments_are_never_dots() {
    let bytes: [u8; PATH_BYTES] = kani::any();
    // Enough to spell every dot form; other unreserved bytes behave like `a`.
    for &b in &bytes {
        kani::assume(matches!(b, b'/' | b'.' | b'%' | b'2' | b'e' | b'E' | b'a'));
    }
    let len: usize = kani::any_where(|&len| len <= PATH_BYTES);
    let input = &bytes[..len];
    let mut output = [0; PATH_BYTES];
    // Dot-segment removal never lengthens the path.
    let n = normalize_path(input, &mut output).unwrap();
    for segment in output[..n].split(|&b| b == b'/') {
        let mut decoded = [0; PATH_BYTES];
        if let Ok(m) = percent_decode(segment, &mut decoded) {
            assert!(!matches!(&decoded[..m], b"." | b".."));
        }
    }
    kani::cover!(input == b"/.%2E", "mixed encoded dot segment");
}
