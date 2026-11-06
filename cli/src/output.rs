//! Response bodies and diagnostics. Everything a server sends is untrusted here.
use crate::{exit::Failure, formats};
use mai_coap::{
    Error,
    codec::{Code, MessageView, OptionNumber},
    endpoint::client::DownloadSink,
};
use std::{
    fs::File,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
};

/// Bounded body buffer. Writing only completed bodies keeps a representation change from
/// emitting a mix of versions, since stdout can't be rewound.
pub struct BodySink {
    pub bytes: Vec<u8>,
    base: usize,
    maximum: usize,
}
impl BodySink {
    pub fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            base: 0,
            maximum,
        }
    }
}
impl DownloadSink for BodySink {
    async fn begin(&mut self, offset: usize, total: Option<u64>) -> Result<(), Error> {
        if total.is_some_and(|total| total > self.maximum as u64) {
            return Err(Error::Capacity);
        }
        self.base = offset;
        self.bytes.clear();
        Ok(())
    }
    async fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let start = offset.checked_sub(self.base).ok_or(Error::Malformed)?;
        let end = start.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        if end > self.maximum {
            return Err(Error::Capacity);
        }
        self.bytes.truncate(start);
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    async fn restart(&mut self) -> Result<(), Error> {
        self.bytes.clear();
        self.base = 0;
        Ok(())
    }
    async fn finish(&mut self, _: usize) -> Result<(), Error> {
        Ok(())
    }
}

enum Destination {
    Stdout,
    /// Created by the first write, so a failed request leaves an existing file alone.
    Unopened(PathBuf),
    File(File),
}

/// Where response bodies go.
pub struct Output {
    destination: Destination,
    /// Output reaches a terminal that hasn't been explicitly requested with `-o -`.
    guarded: bool,
    pub newline: bool,
}
impl Output {
    pub fn new(path: Option<&Path>, newline: bool) -> Self {
        let (destination, guarded) = match path {
            None => (Destination::Stdout, std::io::stdout().is_terminal()),
            Some(path) if path.as_os_str() == "-" => (Destination::Stdout, false),
            Some(path) => (Destination::Unopened(path.to_owned()), false),
        };
        Self {
            destination,
            guarded,
            newline,
        }
    }
    pub fn to_terminal(&self) -> bool {
        matches!(self.destination, Destination::Stdout) && std::io::stdout().is_terminal()
    }
    /// Writes one body, refusing bytes that could drive the terminal unless requested.
    pub fn write(&mut self, body: &[u8]) -> Result<(), Failure> {
        if self.guarded && !terminal_safe(body) {
            return Err(Failure::local(
                "refusing to write binary data to a terminal; use -o - or -o FILE",
            ));
        }
        if let Destination::Unopened(path) = &self.destination {
            let file = File::create(path)
                .map_err(|e| Failure::local(format!("{}: {e}", path.display())))?;
            self.destination = Destination::File(file);
        }
        let result = match &mut self.destination {
            Destination::Unopened(_) => unreachable!("opened above"),
            Destination::Stdout => {
                let mut stdout = std::io::stdout().lock();
                write_body(&mut stdout, body, self.newline)
            }
            Destination::File(file) => write_body(file, body, self.newline),
        };
        result.map_err(|e| Failure::local(format!("writing response: {e}")))
    }
}

fn write_body(writer: &mut impl Write, body: &[u8], newline: bool) -> std::io::Result<()> {
    writer.write_all(body)?;
    if newline {
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

/// Whether bytes are plain text, without escape sequences or other control characters.
pub fn terminal_safe(body: &[u8]) -> bool {
    std::str::from_utf8(body).is_ok_and(|text| {
        !text
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    })
}

/// Renders untrusted bytes for a diagnostic line.
pub fn escaped(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c.is_control() {
                text.extend(c.escape_default());
            } else {
                text.push(c);
            }
        }
        for byte in chunk.invalid() {
            text.push_str(&format!("\\x{byte:02x}"));
        }
    }
    text
}

fn code_name(code: Code) -> &'static str {
    match code {
        Code::CREATED => "Created",
        Code::DELETED => "Deleted",
        Code::VALID => "Valid",
        Code::CHANGED => "Changed",
        Code::CONTENT => "Content",
        Code::CONTINUE => "Continue",
        Code::BAD_REQUEST => "Bad Request",
        Code::UNAUTHORIZED => "Unauthorized",
        Code::BAD_OPTION => "Bad Option",
        Code::FORBIDDEN => "Forbidden",
        Code::NOT_FOUND => "Not Found",
        Code::METHOD_NOT_ALLOWED => "Method Not Allowed",
        Code::NOT_ACCEPTABLE => "Not Acceptable",
        Code::INCOMPLETE => "Request Entity Incomplete",
        Code::PRECONDITION_FAILED => "Precondition Failed",
        Code::TOO_LARGE => "Request Entity Too Large",
        Code::UNSUPPORTED_FORMAT => "Unsupported Content-Format",
        Code::TOO_MANY_REQUESTS => "Too Many Requests",
        Code::INTERNAL_ERROR => "Internal Server Error",
        Code::NOT_IMPLEMENTED => "Not Implemented",
        Code::BAD_GATEWAY => "Bad Gateway",
        Code::UNAVAILABLE => "Service Unavailable",
        Code::GATEWAY_TIMEOUT => "Gateway Timeout",
        Code::PROXY_UNSUPPORTED => "Proxying Not Supported",
        _ => "",
    }
}

/// `4.04 Not Found`; a code name comes from this table, never from the server.
pub fn status_line(code: Code) -> String {
    let name = code_name(code);
    let separator = if name.is_empty() { "" } else { " " };
    format!("{}.{:02}{separator}{name}", code.0 >> 5, code.0 & 31)
}

fn option_line(number: OptionNumber, value: &[u8], uint: Option<u64>) -> String {
    let name = match number {
        OptionNumber::ETAG => "ETag",
        OptionNumber::OBSERVE => "Observe",
        OptionNumber::LOCATION_PATH => "Location-Path",
        OptionNumber::CONTENT_FORMAT => "Content-Format",
        OptionNumber::MAX_AGE => "Max-Age",
        OptionNumber::LOCATION_QUERY => "Location-Query",
        OptionNumber::BLOCK2 => "Block2",
        OptionNumber::BLOCK1 => "Block1",
        OptionNumber::SIZE2 => "Size2",
        OptionNumber::SIZE1 => "Size1",
        OptionNumber::ECHO => "Echo",
        _ => "Option",
    };
    let rendered = match (number, uint) {
        (OptionNumber::CONTENT_FORMAT, Some(format)) => {
            match u16::try_from(format).ok().and_then(formats::name) {
                Some(text) => format!("{format} ({text})"),
                None => format.to_string(),
            }
        }
        (
            OptionNumber::OBSERVE
            | OptionNumber::MAX_AGE
            | OptionNumber::SIZE1
            | OptionNumber::SIZE2,
            Some(value),
        ) => value.to_string(),
        (OptionNumber::BLOCK1 | OptionNumber::BLOCK2, Some(value)) => format!(
            "{}/{}/{}",
            value >> 4,
            u8::from(value & 8 != 0),
            16u32 << (value & 7).min(6)
        ),
        (OptionNumber::LOCATION_PATH | OptionNumber::LOCATION_QUERY, _) => escaped(value),
        _ => hex(value),
    };
    if name == "Option" {
        format!("  Option {}: {rendered}", number.0)
    } else {
        format!("  {name}: {rendered}")
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Response details for `-v`. Tokens are shortened to keep complete ones out of logs.
pub fn details(remote: std::net::SocketAddr, message: MessageView<'_>) -> Vec<String> {
    let token = message.token();
    let shown = &token[..token.len().min(2)];
    let mut lines = vec![format!(
        "response from {remote}: {}, token {}.. ({} bytes)",
        status_line(message.code()),
        hex(shown),
        token.len()
    )];
    for option in message.options() {
        lines.push(option_line(option.number, option.value, option.uint().ok()));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_lite::future::block_on;
    use mai_coap::codec::{MessageBuilder, MessageType};

    #[test]
    fn terminal_guard_allows_text_only() {
        assert!(terminal_safe(b"plain text\twith\r\nlines\n"));
        assert!(terminal_safe("ääkköset €".as_bytes()));
        assert!(terminal_safe(b""));
        assert!(!terminal_safe(b"\x1b[2Jcleared"));
        assert!(!terminal_safe(b"bell\x07"));
        assert!(!terminal_safe(b"\xff\xfe"));
        assert!(!terminal_safe("c1\u{9b}31m".as_bytes()));
    }

    #[test]
    fn diagnostics_escape_control_characters_and_invalid_utf8() {
        assert_eq!(escaped(b"ok"), "ok");
        assert_eq!(escaped("äö".as_bytes()), "äö");
        assert_eq!(escaped(b"\x1b[2J"), "\\u{1b}[2J");
        assert_eq!(escaped(b"a\nb"), "a\\nb");
        assert_eq!(escaped(b"\xffa"), "\\xffa");
    }

    #[test]
    fn status_lines_use_dotted_codes() {
        assert_eq!(status_line(Code::NOT_FOUND), "4.04 Not Found");
        assert_eq!(status_line(Code::CONTENT), "2.05 Content");
        assert_eq!(status_line(Code(0xa9)), "5.09");
    }

    #[test]
    fn details_shorten_tokens_and_escape_values() {
        let mut bytes = [0; 128];
        let mut builder = MessageBuilder::new(
            &mut bytes,
            MessageType::Acknowledgement,
            Code::CONTENT,
            1,
            &[0xaa, 0xbb, 0xcc, 0xdd],
        )
        .unwrap();
        builder.uint_option(OptionNumber::OBSERVE, 5).unwrap();
        builder
            .option(OptionNumber::LOCATION_PATH, b"\x1b[2J")
            .unwrap();
        builder
            .uint_option(OptionNumber::CONTENT_FORMAT, 60)
            .unwrap();
        builder.uint_option(OptionNumber::BLOCK2, 0x1e).unwrap();
        let n = builder.finish(b"").unwrap();
        let lines = details(
            "192.0.2.1:5683".parse().unwrap(),
            MessageView::parse(&bytes[..n]).unwrap(),
        );
        assert_eq!(
            lines[0],
            "response from 192.0.2.1:5683: 2.05 Content, token aabb.. (4 bytes)"
        );
        assert!(!lines.join("\n").contains("aabbccdd"));
        assert!(!lines.join("\n").contains('\x1b'));
        assert!(lines.contains(&"  Observe: 5".to_owned()));
        assert!(lines.contains(&"  Content-Format: 60 (application/cbor)".to_owned()));
        assert!(lines.contains(&"  Block2: 1/1/1024".to_owned()));
    }

    #[test]
    fn body_sink_is_bounded_and_restartable() {
        block_on(async {
            let mut sink = BodySink::new(8);
            assert_eq!(sink.begin(0, Some(9)).await, Err(Error::Capacity));
            sink.begin(0, Some(8)).await.unwrap();
            sink.write(0, b"abcd").await.unwrap();
            sink.write(4, b"efgh").await.unwrap();
            assert_eq!(sink.bytes, b"abcdefgh");
            assert_eq!(sink.write(8, b"i").await, Err(Error::Capacity));
            sink.restart().await.unwrap();
            assert!(sink.bytes.is_empty());
            sink.begin(16, None).await.unwrap();
            sink.write(16, b"xy").await.unwrap();
            assert_eq!(sink.bytes, b"xy");
            assert_eq!(sink.write(4, b"z").await, Err(Error::Malformed));
        });
    }
}
