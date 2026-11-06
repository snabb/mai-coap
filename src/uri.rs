//! Allocation-free `coap://` URI decomposition and composition (RFC 7252 §6).
use crate::{
    Error,
    codec::{MessageBuilder, MessageView, OptionNumber},
};

/// Borrowed normalized URI components; percent escapes are decoded into options.
#[derive(Clone, Copy, Debug)]
pub struct Uri<'a> {
    /// Host without IPv6 brackets; an IP literal or application-resolved hostname.
    pub host: &'a str,
    /// UDP port, defaulting to 5683.
    pub port: u16,
    /// Escaped path, starting with `/` when present.
    pub path: &'a str,
    /// Escaped query without `?`.
    pub query: Option<&'a str>,
}
impl<'a> Uri<'a> {
    /// Parses a CoAP URI; fragments, userinfo and non-CoAP schemes are rejected.
    pub fn parse(uri: &'a str) -> Result<Self, Error> {
        let scheme_end = uri.find("://").ok_or(Error::Malformed)?;
        if !uri[..scheme_end].eq_ignore_ascii_case("coap") {
            return Err(Error::UnsupportedScheme);
        }
        let rest = &uri[scheme_end + 3..];
        if rest.contains('#') || rest.bytes().any(|b| b <= 32 || b >= 127) {
            return Err(Error::Malformed);
        }
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.contains('@') {
            return Err(Error::Malformed);
        }
        let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
            let close = ipv6.find(']').ok_or(Error::Malformed)?;
            let host = &ipv6[..close];
            host.parse::<core::net::Ipv6Addr>()
                .map_err(|_| Error::Malformed)?;
            (host, parse_port(&ipv6[close + 1..])?)
        } else {
            let (host, suffix) = authority
                .find(':')
                .map_or((authority, ""), |i| (&authority[..i], &authority[i..]));
            if host.is_empty() || host.contains(['[', ']']) {
                return Err(Error::Malformed);
            }
            (host, parse_port(suffix)?)
        };
        let tail = &rest[authority_end..];
        let (path, query) = tail
            .split_once('?')
            .map_or((tail, None), |(p, q)| (p, Some(q)));
        if !host.contains(':') {
            validate_component(host.as_bytes(), false, false)?;
        }
        validate_component(path.as_bytes(), true, false)?;
        if let Some(q) = query {
            validate_component(q.as_bytes(), true, true)?;
        }
        Ok(Self {
            host,
            port,
            path,
            query,
        })
    }
    /// Decomposes a URI using caller-provided path-normalization scratch.
    ///
    /// `scratch` must hold the escaped path before dot-segment removal (see
    /// [`normalize_path`]), not only the result; `Capacity` otherwise.
    pub fn options_with_scratch(
        self,
        builder: &mut MessageBuilder<'_>,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.authority_options(builder)?;
        let n = normalize_path(self.path.as_bytes(), scratch)?;
        path_options(
            core::str::from_utf8(&scratch[..n]).map_err(|_| Error::Malformed)?,
            builder,
        )?;
        query_options(self.query, builder)
    }
    /// Adds authority options before Observe or Uri-Path options.
    pub fn authority_options(self, builder: &mut MessageBuilder<'_>) -> Result<(), Error> {
        let mut host = [0; 255];
        let n = percent_decode(self.host.as_bytes(), &mut host)?;
        host[..n].make_ascii_lowercase();
        builder.option(OptionNumber::URI_HOST, &host[..n])?;
        if self.port != 5683 {
            builder.uint_option(OptionNumber::URI_PORT, self.port.into())?;
        }
        Ok(())
    }
}

/// Leading `.` or `..` and its encoded length, where `%2E` counts as `.` because
/// percent-encoded unreserved characters are equivalent (RFC 3986 section 2.3).
fn dots(input: &[u8]) -> Option<(usize, usize)> {
    let dot = |bytes: &[u8]| match bytes {
        [b'.', ..] => Some(1),
        [b'%', b'2', b'e' | b'E', ..] => Some(3),
        _ => None,
    };
    let first = dot(input)?;
    Some(match dot(&input[first..]) {
        Some(second) => (2, first + second),
        None => (1, first),
    })
}

/// Removes dot segments according to RFC 3986 section 5.2.4 from an escaped path.
/// Encoded dots (`%2E`) are recognized, so no decoded segment is `.` or `..`
/// (RFC 7252 section 5.10.1).
///
/// Returns the output length, or `Capacity` if `output` cannot hold an
/// intermediate result; `input.len()` bytes always suffice, even when later `..`
/// segments shorten the result.
pub fn normalize_path(mut input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let mut used = 0;
    while !input.is_empty() {
        let ends = |at: usize| input.get(at).is_none_or(|&b| b == b'/');
        if let Some((_, n)) = dots(input).filter(|&(_, n)| input.get(n) == Some(&b'/')) {
            // "../" or "./"
            input = &input[n + 1..];
        } else if let Some((count, n)) = (input[0] == b'/')
            .then(|| dots(&input[1..]))
            .flatten()
            .filter(|&(_, n)| ends(1 + n))
        {
            // "/./", "/.", "/../" or "/..": keep the following "/" or use "/".
            let rest = &input[1 + n..];
            input = if rest.is_empty() { b"/" } else { rest };
            if count == 2 {
                used = output[..used].iter().rposition(|&b| b == b'/').unwrap_or(0);
            }
        } else if dots(input).is_some_and(|(_, n)| n == input.len()) {
            input = &[];
        } else {
            let start = usize::from(input[0] == b'/');
            let end = input[start..]
                .iter()
                .position(|&b| b == b'/')
                .map_or(input.len(), |i| i + start);
            let total = used.checked_add(end).ok_or(Error::Capacity)?;
            output
                .get_mut(used..total)
                .ok_or(Error::Capacity)?
                .copy_from_slice(&input[..end]);
            used = total;
            input = &input[end..];
        }
    }
    Ok(used)
}
/// Adds ordered query components after Content-Format, preserving empty values.
pub fn query_options(query: Option<&str>, builder: &mut MessageBuilder<'_>) -> Result<(), Error> {
    if let Some(query) = query {
        for segment in query.split('&') {
            let mut decoded = [0; 255];
            let n = percent_decode(segment.as_bytes(), &mut decoded)?;
            builder.option(OptionNumber::URI_QUERY, &decoded[..n])?;
        }
    }
    Ok(())
}

/// Composes an absolute URI from request options and the transport destination.
/// Returns UTF-8 bytes in `output`, or `Capacity` without allocating.
pub fn compose<'a>(
    message: MessageView<'_>,
    destination: core::net::SocketAddr,
    output: &'a mut [u8],
) -> Result<&'a str, Error> {
    use core::fmt::Write;
    struct Writer<'a> {
        bytes: &'a mut [u8],
        used: usize,
    }
    impl Write for Writer<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.used.checked_add(s.len()).ok_or(core::fmt::Error)?;
            self.bytes
                .get_mut(self.used..end)
                .ok_or(core::fmt::Error)?
                .copy_from_slice(s.as_bytes());
            self.used = end;
            Ok(())
        }
    }
    fn escaped(writer: &mut Writer<'_>, bytes: &[u8]) -> core::fmt::Result {
        for &byte in bytes {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                writer.write_char(char::from(byte))?;
            } else {
                write!(writer, "%{byte:02X}")?;
            }
        }
        Ok(())
    }
    let mut writer = Writer {
        bytes: output,
        used: 0,
    };
    writer.write_str("coap://").map_err(|_| Error::Capacity)?;
    if let Some(host) = message.option(OptionNumber::URI_HOST) {
        let host = core::str::from_utf8(host.value).map_err(|_| Error::Malformed)?;
        if host.parse::<core::net::Ipv6Addr>().is_ok() {
            write!(writer, "[{host}]").map_err(|_| Error::Capacity)?;
        } else {
            escaped(&mut writer, host.as_bytes()).map_err(|_| Error::Capacity)?;
        }
    } else {
        match destination.ip() {
            core::net::IpAddr::V4(ip) => write!(writer, "{ip}"),
            core::net::IpAddr::V6(ip) => write!(writer, "[{ip}]"),
        }
        .map_err(|_| Error::Capacity)?;
    }
    let port = message
        .option(OptionNumber::URI_PORT)
        .map(|o| o.uint())
        .transpose()?
        .unwrap_or(destination.port().into());
    if port > u16::MAX.into() {
        return Err(Error::Malformed);
    }
    if port != 5683 {
        write!(writer, ":{port}").map_err(|_| Error::Capacity)?;
    }
    let mut paths = message.values(OptionNumber::URI_PATH).peekable();
    if paths.peek().is_none() {
        writer.write_char('/').map_err(|_| Error::Capacity)?;
    }
    for path in paths {
        writer.write_char('/').map_err(|_| Error::Capacity)?;
        escaped(&mut writer, path).map_err(|_| Error::Capacity)?;
    }
    for (i, query) in message.values(OptionNumber::URI_QUERY).enumerate() {
        writer
            .write_char(if i == 0 { '?' } else { '&' })
            .map_err(|_| Error::Capacity)?;
        escaped(&mut writer, query).map_err(|_| Error::Capacity)?;
    }
    core::str::from_utf8(&writer.bytes[..writer.used]).map_err(|_| Error::Malformed)
}
/// Adds Uri-Path segments from an escaped path to an ordered builder.
///
/// Returns `Malformed` for a segment that decodes to `.` or `..` (RFC 7252
/// section 5.10.1); remove dot segments first with [`normalize_path`].
pub fn path_options(path: &str, builder: &mut MessageBuilder<'_>) -> Result<(), Error> {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    if !stripped.is_empty() {
        for segment in stripped.split('/') {
            segment_option(segment, builder)?;
        }
    }
    Ok(())
}
fn segment_option(segment: &str, builder: &mut MessageBuilder<'_>) -> Result<(), Error> {
    let mut decoded = [0u8; 255];
    let n = percent_decode(segment.as_bytes(), &mut decoded)?;
    if crate::codec::dot_segment(OptionNumber::URI_PATH, &decoded[..n]) {
        return Err(Error::Malformed);
    }
    builder.option(OptionNumber::URI_PATH, &decoded[..n])?;
    Ok(())
}
/// Number of dots when the whole escaped segment is `.` or `..`.
fn dot_count(segment: &str) -> Option<usize> {
    dots(segment.as_bytes())
        .filter(|&(_, n)| n == segment.len())
        .map(|(count, _)| count)
}
/// Whether `..` segments after segment `index` remove it. Scanning right to left,
/// each `..` cancels the nearest earlier segment that is not itself removed, as
/// RFC 3986 section 5.2.4 does; excess `..` are discarded.
fn removed_by_later(path: &str, count: usize, index: usize) -> bool {
    let mut pending = 0usize;
    for segment in path.split('/').rev().take(count - index - 1) {
        match dot_count(segment) {
            Some(2) => pending += 1,
            Some(_) => {}
            None => pending = pending.saturating_sub(1),
        }
    }
    pending > 0
}
fn split_target(target: &str) -> Result<(&str, Option<&str>), Error> {
    if target.contains('#') {
        return Err(Error::Malformed);
    }
    Ok(target
        .split_once('?')
        .map_or((target, None), |(p, q)| (p, Some(q))))
}
/// Adds an escaped relative path and optional query to a request without Content-Format.
/// Call `path_options` and `query_options` separately when inserting Content-Format.
///
/// Returns `Malformed` for dot segments, as [`path_options`] does; use
/// [`resolved_path_query_options`] to remove them instead.
pub fn path_query_options(target: &str, builder: &mut MessageBuilder<'_>) -> Result<(), Error> {
    let (path, query) = split_target(target)?;
    path_options(path, builder)?;
    query_options(query, builder)
}
/// Like [`path_query_options`], but resolves the target against the base path
/// `/` and removes dot segments (RFC 3986 sections 5.2.2 and 5.2.4) instead of
/// rejecting them.
///
/// Surviving segments are a subset of the input's, so they are emitted directly
/// without scratch storage; only the encoded options must fit the builder.
///
/// Returns `Capacity` when the path has more segments than the builder has bytes
/// left. Each surviving segment needs at least one byte, so only targets that
/// cancel most of their segments are refused; the limit bounds the survival scan,
/// which is quadratic in the segment count.
pub fn resolved_path_query_options(
    target: &str,
    builder: &mut MessageBuilder<'_>,
) -> Result<(), Error> {
    let (path, query) = split_target(target)?;
    let stripped = path.strip_prefix('/').unwrap_or(path);
    if !stripped.is_empty() {
        let count = stripped.split('/').count();
        if count > builder.remaining() {
            return Err(Error::Capacity);
        }
        let kept = stripped
            .split('/')
            .enumerate()
            .filter(|&(index, segment)| {
                dot_count(segment).is_none() && !removed_by_later(stripped, count, index)
            })
            .map(|(_, segment)| segment);
        // A final dot segment leaves a trailing "/": an empty segment after any
        // kept ones.
        let trailing = stripped.rsplit('/').next().and_then(dot_count).is_some();
        let mut first_two = kept.clone();
        let lone_empty = first_two.next() == Some("") && first_two.next().is_none();
        // A path resolving to "/" alone has no Uri-Path (RFC 7252 section 6.4, step 8).
        if !(lone_empty && !trailing) {
            let mut emitted = false;
            for segment in kept {
                segment_option(segment, builder)?;
                emitted = true;
            }
            if emitted && trailing {
                builder.option(OptionNumber::URI_PATH, &[])?;
            }
        }
    }
    query_options(query, builder)
}
fn parse_port(suffix: &str) -> Result<u16, Error> {
    if suffix.is_empty() {
        return Ok(5683);
    }
    let port = suffix.strip_prefix(':').ok_or(Error::Malformed)?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Malformed);
    }
    port.parse().map_err(|_| Error::Malformed)
}
fn hex(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Malformed),
    }
}
fn validate_component(bytes: &[u8], path: bool, query: bool) -> Result<(), Error> {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            hex(*bytes.get(i + 1).ok_or(Error::Malformed)?)?;
            hex(*bytes.get(i + 2).ok_or(Error::Malformed)?)?;
            i += 3;
        } else {
            let b = bytes[i];
            if !b.is_ascii_alphanumeric()
                && !b"-._~!$&'()*+,;=".contains(&b)
                && !(path && b":@/".contains(&b))
                && !(query && b == b'?')
            {
                return Err(Error::Malformed);
            }
            i += 1;
        }
    }
    Ok(())
}
/// Decodes percent escapes without interpreting `+` as space.
pub fn percent_decode(input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    let (mut i, mut used) = (0, 0);
    while i < input.len() {
        let byte = if input[i] == b'%' {
            let a = hex(*input.get(i + 1).ok_or(Error::Malformed)?)?;
            let b = hex(*input.get(i + 2).ok_or(Error::Malformed)?)?;
            i += 3;
            (a << 4) | b
        } else {
            let b = input[i];
            i += 1;
            b
        };
        *output.get_mut(used).ok_or(Error::Capacity)? = byte;
        used += 1;
    }
    Ok(used)
}

#[cfg(kani)]
mod proofs;

#[cfg(test)]
mod tests;
