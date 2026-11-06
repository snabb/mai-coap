//! Content-Format names: numbers, MIME types and libcoap's documented shortcuts.

/// IANA CoAP Content-Formats this tool can name, with their shortcuts.
const FORMATS: &[(u16, &str, &[&str])] = &[
    (0, "text/plain", &["plain", "text/plain;charset=utf-8"]),
    (40, "application/link-format", &["link", "link-format"]),
    (41, "application/xml", &["xml"]),
    (42, "application/octet-stream", &["binary", "octet-stream"]),
    (47, "application/exi", &["exi"]),
    (50, "application/json", &["json"]),
    (51, "application/json-patch+json", &[]),
    (52, "application/merge-patch+json", &[]),
    (60, "application/cbor", &["cbor"]),
    (61, "application/cwt", &[]),
    (64, "application/edhoc+cbor-seq", &[]),
    (65, "application/cid-edhoc+cbor-seq", &[]),
    (110, "application/senml+json", &[]),
    (111, "application/sensml+json", &[]),
    (112, "application/senml+cbor", &[]),
    (113, "application/sensml+cbor", &[]),
];

/// Parses a Content-Format number, MIME type or shortcut.
pub fn parse(value: &str) -> Result<u16, String> {
    if let Ok(number) = value.parse() {
        return Ok(number);
    }
    FORMATS
        .iter()
        .find(|(_, name, shortcuts)| {
            name.eq_ignore_ascii_case(value)
                || shortcuts.iter().any(|s| s.eq_ignore_ascii_case(value))
        })
        .map(|(number, ..)| *number)
        .ok_or_else(|| format!("unknown content format {value:?}"))
}

pub fn name(number: u16) -> Option<&'static str> {
    FORMATS
        .iter()
        .find(|(n, ..)| *n == number)
        .map(|(_, name, _)| *name)
}

/// aiocoap reads a non-file payload of these formats as CBOR diagnostic notation.
pub fn is_cbor(number: u16) -> bool {
    matches!(number, 60 | 61 | 64 | 65 | 112 | 113)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_numbers_mime_types_and_shortcuts() {
        assert_eq!(parse("60"), Ok(60));
        assert_eq!(parse("65000"), Ok(65000));
        assert_eq!(parse("application/cbor"), Ok(60));
        assert_eq!(parse("Application/JSON"), Ok(50));
        assert_eq!(parse("binary"), Ok(42));
        assert_eq!(parse("octet-stream"), Ok(42));
        assert_eq!(parse("plain"), Ok(0));
        assert_eq!(parse("link"), Ok(40));
        assert!(parse("70000").is_err());
        assert!(parse("nonsense").is_err());
    }

    #[test]
    fn names_round_trip() {
        for (number, name_, _) in FORMATS {
            assert_eq!(parse(name_), Ok(*number));
            assert_eq!(name(*number), Some(*name_));
        }
        assert_eq!(name(9999), None);
    }
}
