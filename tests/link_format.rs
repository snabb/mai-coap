//! Compact RFC 6690 attribute serialization.
#![cfg(feature = "link-format")]

use mai_coap::link_format::{Links, Writer};

#[test]
fn bare_tokens_are_compact_but_quoted_grammars_remain_quoted() {
    let mut bytes = [0; 256];
    let mut writer = Writer::new(&mut bytes);
    writer
        .link(
            "/x",
            &[
                ("ct", Some("60")),
                ("rt", Some("temperature")),
                ("if", Some("core.s")),
                ("sz", Some("1024")),
                ("obs", None),
                ("title", Some("safe")),
                ("anchor", Some("/context")),
                ("rel", Some("alternate describedby")),
            ],
        )
        .unwrap();

    let used = writer.len();
    let serialized = core::str::from_utf8(&bytes[..used]).unwrap();
    assert_eq!(
        serialized,
        r#"</x>;ct=60;rt=temperature;if=core.s;sz=1024;obs;title="safe";anchor="/context";rel="alternate describedby""#
    );
    let link = Links::new(serialized.as_bytes())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert!(link.matches("ct=60").unwrap());
    assert!(link.matches("rt=temperature").unwrap());
    assert!(link.matches("rel=describedby").unwrap());
}

#[test]
fn extension_values_quote_and_escape_when_they_are_not_ptokens() {
    let mut bytes = [0; 128];
    let mut writer = Writer::new(&mut bytes);
    writer
        .link(
            "/x",
            &[
                ("ct", Some("application/cbor")),
                ("title", Some("a, \"b\"")),
            ],
        )
        .unwrap();

    let used = writer.len();
    assert_eq!(
        core::str::from_utf8(&bytes[..used]).unwrap(),
        r#"</x>;ct=application/cbor;title="a, \"b\"""#
    );
    let link = Links::new(&bytes[..used]).unwrap().next().unwrap().unwrap();
    assert!(link.matches("title=a, \"b\"").unwrap());
}

#[test]
fn dsc_1_bare_values_follow_the_ptoken_grammar() {
    fn attribute(payload: &str) -> Result<Option<&str>, mai_coap::Error> {
        Links::new(payload.as_bytes())
            .unwrap()
            .next()
            .unwrap()
            .and_then(|link| link.attributes().next().unwrap())
            .map(|attr| attr.value)
    }
    // RFC 6690 section 2: ptokenchar includes "<" and ">", but not "\".
    assert_eq!(attribute("</x>;rt=<a>"), Ok(Some("<a>")));
    for invalid in [
        r"</x>;rt=\",
        r"</x>;rt=a\b",
        "</x>;rt=\u{e9}",
        "</x>;rt=a\u{1}",
    ] {
        assert!(attribute(invalid).is_err(), "{invalid:?}");
    }

    let mut bytes = [0; 64];
    let mut writer = Writer::new(&mut bytes);
    writer.link("/x", &[("rt", Some("<a>"))]).unwrap();
    let used = writer.len();
    assert_eq!(&bytes[..used], b"</x>;rt=<a>");
    let link = Links::new(&bytes[..used]).unwrap().next().unwrap().unwrap();
    assert!(link.matches("rt=<a>").unwrap());
}
