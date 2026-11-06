use super::*;
use crate::codec::{Code, MessageType, MessageView};
use proptest::prelude::*;
use std::{format, string::String, vec::Vec};

fn options(
    add: impl FnOnce(&mut MessageBuilder<'_>) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let mut bytes = [0; 512];
    let mut builder = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[])?;
    add(&mut builder)?;
    let n = builder.finish(&[])?;
    Ok(MessageView::parse(&bytes[..n])?.as_bytes().to_vec())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]
    /// The copy-free resolution emits the same options as normalizing an
    /// escaped copy, for every spelling of dot segments. Relative targets are
    /// merged with the base path "/" before dot removal (RFC 3986 section 5.2.2).
    #[test]
    fn resolved_targets_match_normalized_paths(
        absolute in any::<bool>(),
        segments in prop::collection::vec(
            prop::sample::select(&["a", "", ".", "..", "%2E", "%2e%2E", ".%2E", "a%2Eb", "%41"][..]),
            0..12,
        ),
    ) {
        let path = format!("{}{}", if absolute { "/" } else { "" }, segments.join("/"));
        let merged = format!("/{}", path.strip_prefix('/').unwrap_or(&path));
        let expected = options(|b| {
            let mut scratch = [0; 512];
            let n = normalize_path(merged.as_bytes(), &mut scratch)?;
            path_options(core::str::from_utf8(&scratch[..n]).unwrap(), b)
        });
        let actual = options(|b| resolved_path_query_options(&path, b));
        prop_assert_eq!(actual, expected, "{}", path);
    }
}

/// RFC 3986 section 5.2.4 steps A-E, transcribed literally for literal dots.
fn remove_dot_segments(mut input: &[u8]) -> Vec<u8> {
    fn pop(output: &mut Vec<u8>) {
        let last = output.iter().rposition(|&b| b == b'/').unwrap_or(0);
        output.truncate(last);
    }
    let mut output = Vec::new();
    while !input.is_empty() {
        if input.starts_with(b"../") {
            input = &input[3..];
        } else if input.starts_with(b"./") || input.starts_with(b"/./") {
            input = &input[2..];
        } else if input == b"/." {
            input = b"/";
        } else if input.starts_with(b"/../") {
            input = &input[3..];
            pop(&mut output);
        } else if input == b"/.." {
            input = b"/";
            pop(&mut output);
        } else if input == b"." || input == b".." {
            input = &[];
        } else {
            let start = usize::from(input[0] == b'/');
            let end = input[start..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(input.len(), |i| i + start);
            output.extend_from_slice(&input[..end]);
            input = &input[end..];
        }
    }
    output
}

/// `%2E` and `%2e` are equivalent to "." (RFC 3986 section 2.3).
fn canonical(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if matches!(&bytes[i..], [b'%', b'2', b'e' | b'E', ..]) {
            out.push(b'.');
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// RFC 3986 section 5.2.4: `normalize_path` equals the literal algorithm on the
/// `%2E`-canonical path, and `resolved_path_query_options` emits the options of
/// that result after merging with the base path "/" (section 5.2.2), for every
/// path of up to seven tokens. This reaches "%2E%2E" segments, consecutive pops
/// and pops of encoded segments.
#[test]
fn dot_segment_removal_matches_rfc3986_exhaustively() {
    const TOKENS: [&[u8]; 5] = [b"/", b".", b"%2E", b"%2e", b"a"];
    let mut cases = 0;
    let mut path = Vec::new();
    fn visit(path: &mut Vec<u8>, depth: usize, cases: &mut usize) {
        let text = core::str::from_utf8(path).unwrap();
        let mut output = [0; 64];
        let n = normalize_path(path, &mut output).unwrap();
        let expected = remove_dot_segments(&canonical(path));
        assert_eq!(canonical(&output[..n]), expected, "{text}");
        let merged = format!("/{}", text.strip_prefix('/').unwrap_or(text));
        let resolved = String::from_utf8(remove_dot_segments(&canonical(merged.as_bytes())));
        assert_eq!(
            options(|b| resolved_path_query_options(text, b)),
            options(|b| path_options(&resolved.unwrap(), b)),
            "{text}"
        );
        *cases += 1;
        if depth < 7 {
            for token in TOKENS {
                path.extend_from_slice(token);
                visit(path, depth + 1, cases);
                path.truncate(path.len() - token.len());
            }
        }
    }
    visit(&mut path, 0, &mut cases);
    assert_eq!(cases, (0..=7).map(|d| 5usize.pow(d)).sum::<usize>());
}

#[test]
fn resolved_targets_need_a_builder_byte_per_segment() {
    let mut bytes = [0; 68];
    let mut builder =
        MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, &[]).unwrap();
    let fits = std::vec![".."; 64].join("/");
    assert_eq!(resolved_path_query_options(&fits, &mut builder), Ok(()));
    assert_eq!(
        resolved_path_query_options(&format!("{fits}/a"), &mut builder),
        Err(Error::Capacity)
    );
}

fn request_authority(uri: &str, destination: Option<&str>) -> (Option<Vec<u8>>, Option<u64>) {
    let destination = destination.map(|d| d.parse().unwrap());
    let bytes =
        options(|b| Uri::parse(uri)?.request_options(b, &mut [0; 512], destination)).unwrap();
    let message = MessageView::parse(&bytes).unwrap();
    (
        message
            .option(OptionNumber::URI_HOST)
            .map(|o| o.value.to_vec()),
        message
            .option(OptionNumber::URI_PORT)
            .map(|o| o.uint().unwrap()),
    )
}

/// RFC 7252 section 6.4 steps 5 and 7: authority options name what the destination doesn't.
#[test]
fn request_options_omit_authority_that_repeats_the_destination() {
    let local = Some("192.0.2.1:5683");
    assert_eq!(request_authority("coap://192.0.2.1/x", local), (None, None));
    assert_eq!(
        request_authority("coap://[2001:db8::1]:5700/x", Some("[2001:db8::1]:5700")),
        (None, None)
    );
    assert_eq!(
        request_authority("coap://192.0.2.1/x", Some("[::ffff:192.0.2.1]:5683")),
        (None, None)
    );
    assert_eq!(
        request_authority("coap://192.0.2.1:5700/x", Some("192.0.2.1:5700")),
        (None, None)
    );
    // A URI without a port means 5683, which is not the destination's default here.
    assert_eq!(
        request_authority("coap://192.0.2.1/x", Some("192.0.2.1:5700")),
        (None, Some(5683))
    );
    assert_eq!(
        request_authority("coap://192.0.2.1:5700/x", local),
        (None, Some(5700))
    );
    assert_eq!(
        request_authority("coap://192.0.2.9/x", local),
        (Some(b"192.0.2.9".to_vec()), None)
    );
    assert_eq!(
        request_authority("coap://Node.Example/x", local),
        (Some(b"node.example".to_vec()), None)
    );
}

#[test]
fn request_options_name_the_origin_through_a_proxy() {
    assert_eq!(
        request_authority("coap://192.0.2.1/x", None),
        (Some(b"192.0.2.1".to_vec()), Some(5683))
    );
}
