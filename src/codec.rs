//! Borrowed CoAP messages and ordered serialization (RFC 7252 §§3, 5.4).
use crate::Error;

/// CoAP message type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageType {
    /// Confirmable message.
    Confirmable = 0,
    /// Non-confirmable message.
    NonConfirmable = 1,
    /// Acknowledgement.
    Acknowledgement = 2,
    /// Reset.
    Reset = 3,
}

macro_rules! numbers {
    ($name:ident, $ty:ty, $doc:literal; $($constant:ident = $value:expr => $comment:literal),* $(,)?) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[cfg_attr(feature = "defmt", derive(defmt::Format))]
        pub struct $name(pub $ty);
        impl $name {
            $(#[doc = $comment] pub const $constant: Self = Self($value);)*
        }
    };
}

numbers!(Code, u8, "Open CoAP code; unknown methods and response codes are preserved.";
    EMPTY = 0 => "Empty message.", GET = 1 => "GET.", POST = 2 => "POST.",
    PUT = 3 => "PUT.", DELETE = 4 => "DELETE.", FETCH = 5 => "FETCH (RFC 8132).",
    PATCH = 6 => "PATCH (RFC 8132).", IPATCH = 7 => "iPATCH (RFC 8132).",
    CREATED = 65 => "2.01 Created.", DELETED = 66 => "2.02 Deleted.",
    VALID = 67 => "2.03 Valid.", CHANGED = 68 => "2.04 Changed.", CONTENT = 69 => "2.05 Content.",
    CONTINUE = 95 => "2.31 Continue.", BAD_REQUEST = 128 => "4.00 Bad Request.",
    UNAUTHORIZED = 129 => "4.01 Unauthorized.", BAD_OPTION = 130 => "4.02 Bad Option.",
    FORBIDDEN = 131 => "4.03 Forbidden.", NOT_FOUND = 132 => "4.04 Not Found.",
    METHOD_NOT_ALLOWED = 133 => "4.05 Method Not Allowed.", NOT_ACCEPTABLE = 134 => "4.06 Not Acceptable.",
    INCOMPLETE = 136 => "4.08 Request Entity Incomplete.", PRECONDITION_FAILED = 140 => "4.12 Precondition Failed.",
    TOO_LARGE = 141 => "4.13 Request Entity Too Large.", UNSUPPORTED_FORMAT = 143 => "4.15 Unsupported Content-Format.",
    UNPROCESSABLE = 150 => "4.22 Unprocessable Entity (RFC 8132).", TOO_MANY_REQUESTS = 157 => "4.29 Too Many Requests.",
    INTERNAL_ERROR = 160 => "5.00 Internal Server Error.", NOT_IMPLEMENTED = 161 => "5.01 Not Implemented.",
    BAD_GATEWAY = 162 => "5.02 Bad Gateway.", UNAVAILABLE = 163 => "5.03 Service Unavailable.",
    GATEWAY_TIMEOUT = 164 => "5.04 Gateway Timeout.", PROXY_UNSUPPORTED = 165 => "5.05 Proxying Not Supported.",
    HOP_LIMIT_REACHED = 168 => "5.08 Hop Limit Reached."
);
impl Code {
    /// True for a nonempty class-zero code.
    pub const fn is_request(self) -> bool {
        self.0 > 0 && self.0 < 32
    }
    /// True for a response code in classes two through five.
    pub const fn is_response(self) -> bool {
        self.0 >= 64 && self.0 < 192
    }
    /// True for a class-two response.
    pub const fn is_success(self) -> bool {
        self.0 >> 5 == 2
    }
}

numbers!(OptionNumber, u32, "Open option number with RFC 7252 forwarding properties.";
    IF_MATCH = 1 => "If-Match.", URI_HOST = 3 => "Uri-Host.", ETAG = 4 => "ETag.",
    IF_NONE_MATCH = 5 => "If-None-Match.", OBSERVE = 6 => "Observe.", URI_PORT = 7 => "Uri-Port.",
    LOCATION_PATH = 8 => "Location-Path.", OSCORE = 9 => "OSCORE.", URI_PATH = 11 => "Uri-Path.",
    CONTENT_FORMAT = 12 => "Content-Format.", MAX_AGE = 14 => "Max-Age.", URI_QUERY = 15 => "Uri-Query.",
    HOP_LIMIT = 16 => "Hop-Limit.", ACCEPT = 17 => "Accept.", LOCATION_QUERY = 20 => "Location-Query.",
    EDHOC = 21 => "EDHOC combined request (RFC 9668).", BLOCK2 = 23 => "Block2.", BLOCK1 = 27 => "Block1.", SIZE2 = 28 => "Size2.",
    PROXY_URI = 35 => "Proxy-Uri.", PROXY_SCHEME = 39 => "Proxy-Scheme.", SIZE1 = 60 => "Size1.",
    ECHO = 252 => "Echo.", REQUEST_TAG = 292 => "Request-Tag."
);
impl OptionNumber {
    /// Critical at a terminating endpoint.
    pub const fn critical(self) -> bool {
        self.0 & 1 != 0
    }
    /// Unsafe for a proxy to forward without understanding it.
    pub const fn unsafe_to_forward(self) -> bool {
        self.0 & 2 != 0
    }
    /// Excluded from a cache key when safe to forward.
    pub const fn no_cache_key(self) -> bool {
        self.0 & 0x1e == 0x1c
    }
    /// Registry length and repeatability, or `None` for an unknown option.
    pub const fn definition(self) -> Option<OptionDefinition> {
        let (min, max, repeatable) = match self.0 {
            1 => (0, 8, true),
            3 => (1, 255, false),
            4 => (1, 8, true),
            5 => (0, 0, false),
            6 => (0, 3, false),
            7 => (0, 2, false),
            8 | 11 | 15 | 20 => (0, 255, true),
            9 => (0, 255, false),
            12 | 17 => (0, 2, false),
            14 | 28 | 60 => (0, 4, false),
            16 => (1, 1, false),
            21 => (0, usize::MAX, false),
            23 | 27 => (0, 3, false),
            35 => (1, 1034, false),
            39 => (1, 255, false),
            252 => (1, 40, false),
            292 => (0, 8, true),
            _ => return None,
        };
        Some(OptionDefinition {
            min,
            max,
            repeatable,
        })
    }
}
/// Registry constraints for an option value.
#[derive(Clone, Copy, Debug)]
pub struct OptionDefinition {
    /// Minimum encoded value length.
    pub min: usize,
    /// Maximum encoded value length.
    pub max: usize,
    /// Whether the option may repeat (ETag repeats in requests only).
    pub repeatable: bool,
}
numbers!(ContentFormat, u16, "Open IANA Content-Format value.";
    TEXT = 0 => "text/plain; charset=utf-8.", LINK_FORMAT = 40 => "application/link-format.",
    OCTET_STREAM = 42 => "application/octet-stream.", CBOR = 60 => "application/cbor.",
    EDHOC = 64 => "application/edhoc+cbor-seq.", CID_EDHOC = 65 => "application/cid-edhoc+cbor-seq."
);

/// Borrowed option value, retaining its exact encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MessageOption<'a> {
    /// Option number.
    pub number: OptionNumber,
    /// Encoded option value.
    pub value: &'a [u8],
}
/// Uri-Path and Location-Path values MUST NOT be "." or ".." (RFC 7252 §§5.10.1, 5.10.7).
/// Enforced by `check_options` for recognized options and by the high-level
/// builders; `MessageOption::valid` covers only registry length and repetition,
/// which proxies also use to decide recognition and forwarding.
pub(crate) fn dot_segment(number: OptionNumber, value: &[u8]) -> bool {
    matches!(number, OptionNumber::URI_PATH | OptionNumber::LOCATION_PATH)
        && matches!(value, b"." | b"..")
}
impl MessageOption<'_> {
    pub(crate) fn valid(self, previous: Option<OptionNumber>, code: Code) -> bool {
        self.number.definition().is_none_or(|d| {
            (d.min..=d.max).contains(&self.value.len())
                && (d.repeatable && (self.number != OptionNumber::ETAG || code.is_request())
                    || previous != Some(self.number))
        })
    }
    /// Decodes an unsigned integer including leading zeroes (MSG-4).
    pub fn uint(self) -> Result<u64, Error> {
        self.value.iter().try_fold(0u64, |n, &b| {
            n.checked_mul(256)
                .and_then(|n| n.checked_add(b.into()))
                .ok_or(Error::Malformed)
        })
    }
}

fn retain_option(
    option: MessageOption<'_>,
    previous: &mut Option<OptionNumber>,
    code: Code,
    recognized: &impl Fn(OptionNumber) -> bool,
) -> bool {
    let keep = option.valid(*previous, code) && recognized(option.number);
    *previous = Some(option.number);
    keep
}

/// Fully validated borrowed datagram. Parsing does not copy payload or options.
#[derive(Clone, Copy, Debug)]
pub struct MessageView<'a> {
    bytes: &'a [u8],
    option_start: usize,
    option_end: usize,
    payload_start: usize,
}
impl<'a> MessageView<'a> {
    /// Validates the complete message, including all option boundaries (MSG-1–3).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = bytes.get(..4).ok_or(Error::Malformed)?;
        let tkl = usize::from(header[0] & 15);
        if header[0] >> 6 != 1 || tkl > 8 {
            return Err(Error::Malformed);
        }
        let start = 4 + tkl;
        if start > bytes.len() || (header[1] == 0 && bytes.len() != 4) {
            return Err(Error::Malformed);
        }
        let mut offset = start;
        let mut number = 0u32;
        while offset < bytes.len() {
            if bytes[offset] == 255 {
                if offset + 1 == bytes.len() {
                    return Err(Error::Malformed);
                }
                return Ok(Self {
                    bytes,
                    option_start: start,
                    option_end: offset,
                    payload_start: offset + 1,
                });
            }
            decode_option(bytes, &mut offset, &mut number)?;
        }
        Ok(Self {
            bytes,
            option_start: start,
            option_end: offset,
            payload_start: offset,
        })
    }
    /// Exact wire bytes.
    pub fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// Wire version (always one for validated messages).
    pub fn version(self) -> u8 {
        1
    }
    /// Message type.
    pub fn message_type(self) -> MessageType {
        match (self.bytes[0] >> 4) & 3 {
            0 => MessageType::Confirmable,
            1 => MessageType::NonConfirmable,
            2 => MessageType::Acknowledgement,
            _ => MessageType::Reset,
        }
    }
    /// Request or response code.
    pub fn code(self) -> Code {
        Code(self.bytes[1])
    }
    /// Message identifier.
    pub fn message_id(self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }
    /// Opaque token, zero through eight bytes.
    pub fn token(self) -> &'a [u8] {
        &self.bytes[4..self.option_start]
    }
    /// Ordered options; the message has already been fully validated.
    pub fn options(self) -> Options<'a> {
        Options {
            bytes: &self.bytes[..self.option_end],
            offset: self.option_start,
            number: 0,
        }
    }
    /// Raw payload, without a marker.
    pub fn payload(self) -> &'a [u8] {
        &self.bytes[self.payload_start..]
    }
    /// First occurrence of an option.
    pub fn option(self, number: OptionNumber) -> Option<MessageOption<'a>> {
        self.options().find(|o| o.number == number)
    }
    /// Values of all occurrences of an option, in wire order.
    pub fn values(self, number: OptionNumber) -> impl Iterator<Item = &'a [u8]> {
        self.options()
            .filter(move |o| o.number == number)
            .map(|o| o.value)
    }
    /// Checks endpoint recognition, lengths and repeated singleton options (MSG-4–6).
    /// Rebuilds an endpoint message after discarding unrecognized elective options.
    /// The raw borrowed view remains available for transparent forwarding.
    /// Recognition must be deterministic during this call. `output` need only
    /// fit the filtered result; a capacity error may leave it partially written.
    pub fn processed(
        self,
        recognized: impl Fn(OptionNumber) -> bool,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        self.check_options(&recognized)?;
        let mut builder = MessageBuilder::new(
            output,
            self.message_type(),
            self.code(),
            self.message_id(),
            self.token(),
        )?;
        let mut previous = None;
        for option in self.options() {
            if retain_option(option, &mut previous, self.code(), &recognized) {
                builder.option(option.number, option.value)?;
            }
        }
        builder.finish(self.payload())
    }
    /// Discards invalid or unrecognized elective options in the supplied datagram.
    /// Critical-option errors are checked before changing bytes. Returns the new
    /// length; callers must stop using the old length after compaction.
    /// Recognition must be deterministic during this call. A retained datagram
    /// is unchanged; filtering needs no additional datagram-sized buffer.
    /// A serialization-capacity error can leave bytes partly compacted, including
    /// when removing an option makes a retained delta exceed the wire range.
    pub fn process_in_place(
        bytes: &mut [u8],
        recognized: impl Fn(OptionNumber) -> bool,
    ) -> Result<usize, Error> {
        let view = MessageView::parse(bytes)?;
        view.check_options(&recognized)?;
        let (start, end, payload, code) = (
            view.option_start,
            view.option_end,
            view.payload_start,
            view.code(),
        );
        let mut previous = None;
        if view
            .options()
            .all(|option| retain_option(option, &mut previous, code, &recognized))
        {
            return Ok(bytes.len());
        }
        let (mut read, mut write, mut number, mut kept) = (start, start, 0, 0);
        let mut previous = None;
        while read < end {
            let option = decode_option(bytes, &mut read, &mut number)?;
            if !retain_option(option, &mut previous, code, &recognized) {
                continue;
            }
            let length = option.value.len();
            let value_start = read - length;
            let (dn, db, dl) = encode_extension((number - kept) as usize)?;
            let (ln, lb, ll) = encode_extension(length)?;
            let header = 1 + dl + ll;
            let next = write.checked_add(header + length).ok_or(Error::Capacity)?;
            // Removing options never grows the prefix, even when the delta widens.
            if next > read {
                return Err(Error::Capacity);
            }
            bytes.copy_within(value_start..read, write + header);
            bytes[write] = (dn << 4) | ln;
            bytes[write + 1..write + 1 + dl].copy_from_slice(&db[..dl]);
            bytes[write + 1 + dl..write + header].copy_from_slice(&lb[..ll]);
            write = next;
            kept = number;
        }
        if payload < bytes.len() {
            bytes[write] = 255;
            write += 1;
            let length = bytes.len() - payload;
            bytes.copy_within(payload.., write);
            write += length;
        }
        Ok(write)
    }
    /// Checks endpoint recognition, lengths and repeated singleton options (MSG-4–6).
    /// A Uri-Path or Location-Path value of `.` or `..` is a `BadOption`.
    /// Recognition must be deterministic during validation and filtering.
    pub fn check_options(self, recognized: impl Fn(OptionNumber) -> bool) -> Result<(), Error> {
        // A recognized Location-Path is elective, but ignoring one dot segment would
        // silently change the location; reject the message instead. Unrecognized
        // elective options stay ignored (RFC 7252 section 5.4.1).
        if let Some(option) = self
            .options()
            .find(|o| dot_segment(o.number, o.value) && recognized(o.number))
        {
            return Err(Error::BadOption(option.number));
        }
        // RFC 7252 erratum 4949: these elective extensions still affect Location-*.
        if self.code().is_response()
            && self.options().any(|o| {
                matches!(
                    o.number,
                    OptionNumber::LOCATION_PATH | OptionNumber::LOCATION_QUERY
                )
            })
        {
            for option in self.options() {
                if matches!(option.number.0, 128 | 132 | 136 | 140) && !recognized(option.number) {
                    return Err(Error::BadOption(option.number));
                }
            }
        }
        let mut previous = None;
        for option in self.options() {
            if !retain_option(option, &mut previous, self.code(), &recognized)
                && option.number.critical()
            {
                return Err(Error::BadOption(option.number));
            }
        }
        Ok(())
    }
}

/// Option iterator over a validated message.
#[derive(Clone, Debug)]
pub struct Options<'a> {
    bytes: &'a [u8],
    offset: usize,
    number: u32,
}
impl<'a> Iterator for Options<'a> {
    type Item = MessageOption<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.bytes.len() {
            return None;
        }
        decode_option(self.bytes, &mut self.offset, &mut self.number).ok()
    }
}
fn extension(bytes: &[u8], offset: &mut usize, nibble: u8) -> Result<usize, Error> {
    match nibble {
        0..=12 => Ok(nibble.into()),
        13 => {
            let b = *bytes.get(*offset).ok_or(Error::Malformed)?;
            *offset += 1;
            Ok(13 + usize::from(b))
        }
        14 => {
            let b = bytes
                .get(*offset..offset.checked_add(2).ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?;
            *offset += 2;
            Ok(269 + usize::from(u16::from_be_bytes([b[0], b[1]])))
        }
        _ => Err(Error::Malformed),
    }
}
fn decode_option<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    number: &mut u32,
) -> Result<MessageOption<'a>, Error> {
    let h = *bytes.get(*offset).ok_or(Error::Malformed)?;
    *offset += 1;
    let delta = extension(bytes, offset, h >> 4)?;
    let length = extension(bytes, offset, h & 15)?;
    *number = number.checked_add(delta as u32).ok_or(Error::Malformed)?;
    let end = offset.checked_add(length).ok_or(Error::Malformed)?;
    let value = bytes.get(*offset..end).ok_or(Error::Malformed)?;
    *offset = end;
    Ok(MessageOption {
        number: OptionNumber(*number),
        value,
    })
}

/// CoAP encoder. Options must be inserted in ascending order (MSG-7).
///
/// Failed insertions leave the previous valid prefix intact. `finish` returns the
/// used length; no empty payload marker is emitted.
#[derive(Debug)]
pub struct MessageBuilder<'a> {
    bytes: &'a mut [u8],
    used: usize,
    previous: u32,
    code: Code,
}
impl<'a> MessageBuilder<'a> {
    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.used)
    }
    /// Starts a message, rejecting a long token or a token in an empty message.
    pub fn new(
        bytes: &'a mut [u8],
        ty: MessageType,
        code: Code,
        mid: u16,
        token: &[u8],
    ) -> Result<Self, Error> {
        if token.len() > 8 || code == Code::EMPTY && !token.is_empty() {
            return Err(Error::Malformed);
        }
        let used = 4 + token.len();
        let target = bytes.get_mut(..used).ok_or(Error::Capacity)?;
        target[0] = 0x40 | ((ty as u8) << 4) | token.len() as u8;
        target[1] = code.0;
        target[2..4].copy_from_slice(&mid.to_be_bytes());
        target[4..].copy_from_slice(token);
        Ok(Self {
            bytes,
            used,
            previous: 0,
            code,
        })
    }
    /// Adds an exact option value; use `uint_option` for canonical integers.
    ///
    /// Values are not validated, so raw construction can emit options that
    /// [`MessageView::check_options`] rejects, such as a `..` Uri-Path.
    pub fn option(&mut self, number: OptionNumber, value: &[u8]) -> Result<&mut Self, Error> {
        if self.code == Code::EMPTY {
            return Err(Error::Malformed);
        }
        let delta = number
            .0
            .checked_sub(self.previous)
            .ok_or(Error::OptionOrder)?;
        let (dn, db, dl) = encode_extension(delta as usize)?;
        let (ln, lb, ll) = encode_extension(value.len())?;
        let end = self
            .used
            .checked_add(1 + dl + ll)
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(Error::Capacity)?;
        let target = self.bytes.get_mut(self.used..end).ok_or(Error::Capacity)?;
        target[0] = (dn << 4) | ln;
        target[1..1 + dl].copy_from_slice(&db[..dl]);
        target[1 + dl..1 + dl + ll].copy_from_slice(&lb[..ll]);
        target[1 + dl + ll..].copy_from_slice(value);
        self.used = end;
        self.previous = number.0;
        Ok(self)
    }
    /// Adds a minimally encoded unsigned integer (MSG-4).
    pub fn uint_option(&mut self, number: OptionNumber, value: u64) -> Result<&mut Self, Error> {
        self.option(number, minimal_uint(&value.to_be_bytes()))
    }
    /// Completes the message with a payload and returns its used length.
    pub fn finish(self, payload: &[u8]) -> Result<usize, Error> {
        self.finish_parts(&[payload])
    }
    /// Completes a message by concatenating payload slices behind one marker.
    /// Returns `Capacity` if their combined length does not fit the output.
    pub fn finish_parts(mut self, parts: &[&[u8]]) -> Result<usize, Error> {
        let length = parts.iter().try_fold(0usize, |n, part| {
            n.checked_add(part.len()).ok_or(Error::Capacity)
        })?;
        if length != 0 {
            if self.code == Code::EMPTY {
                return Err(Error::Malformed);
            }
            let end = self
                .used
                .checked_add(1)
                .and_then(|n| n.checked_add(length))
                .ok_or(Error::Capacity)?;
            let target = self.bytes.get_mut(self.used..end).ok_or(Error::Capacity)?;
            target[0] = 255;
            let mut offset = 1;
            for part in parts {
                target[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
            }
            self.used = end;
        }
        Ok(self.used)
    }
}
/// Rewrites a validated message's type, MID and token in place. Option encoding
/// is canonical, so the options and payload are moved rather than re-encoded.
#[cfg(any(feature = "server", feature = "client", kani))]
pub(crate) fn reheader(
    bytes: &mut [u8],
    length: usize,
    ty: MessageType,
    mid: u16,
    token: &[u8],
) -> Result<usize, Error> {
    let message = MessageView::parse(bytes.get(..length).ok_or(Error::Malformed)?)?;
    let (code, old) = (message.code(), message.option_start);
    let new = 4 + token.len();
    let total = length - old + new;
    if total > bytes.len() {
        return Err(Error::Capacity);
    }
    bytes.copy_within(old..length, new);
    MessageBuilder::new(&mut bytes[..new], ty, code, mid, token)?;
    Ok(total)
}
pub(crate) fn minimal_uint(bytes: &[u8; 8]) -> &[u8] {
    &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..]
}
pub(crate) fn encode_extension(n: usize) -> Result<(u8, [u8; 2], usize), Error> {
    match n {
        0..=12 => Ok((n as u8, [0, 0], 0)),
        13..=268 => Ok((13, [(n - 13) as u8, 0], 1)),
        269..=65804 => Ok((14, ((n - 269) as u16).to_be_bytes(), 2)),
        _ => Err(Error::Capacity),
    }
}

#[cfg(kani)]
mod proofs;

#[cfg(all(test, any(feature = "server", feature = "client")))]
mod tests {
    use super::*;

    #[test]
    fn reheader_grows_and_shrinks_the_token_without_touching_content() {
        let mut bytes = [0; 32];
        let mut b = MessageBuilder::new(&mut bytes, MessageType::Confirmable, Code::GET, 1, b"old")
            .unwrap();
        b.option(OptionNumber::URI_PATH, b"a").unwrap();
        let n = b.finish(b"body").unwrap();
        for token in [&b""[..], b"old", b"12345678"] {
            let mut rewritten = bytes;
            let length =
                reheader(&mut rewritten, n, MessageType::NonConfirmable, 9, token).unwrap();
            let view = MessageView::parse(&rewritten[..length]).unwrap();
            assert_eq!(view.message_type(), MessageType::NonConfirmable);
            assert_eq!(view.message_id(), 9);
            assert_eq!(view.code(), Code::GET);
            assert_eq!(view.token(), token);
            assert_eq!(view.values(OptionNumber::URI_PATH).next(), Some(&b"a"[..]));
            assert_eq!(view.payload(), b"body");
        }
    }

    #[test]
    fn reheader_rejects_overflow_and_invalid_tokens() {
        let mut bytes = [0x40, 1, 0, 0, 0xff, 1];
        assert_eq!(
            reheader(&mut bytes, 6, MessageType::Confirmable, 0, b"t"),
            Err(Error::Capacity)
        );
        let mut bytes = [0x40, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            reheader(&mut bytes, 4, MessageType::Confirmable, 0, &[0; 9]),
            Err(Error::Malformed)
        );
        let mut bytes = [0x40, 0, 0, 0, 0];
        assert_eq!(
            reheader(&mut bytes, 4, MessageType::Confirmable, 0, b"t"),
            Err(Error::Malformed)
        );
    }
}
