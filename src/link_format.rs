//! Borrowed CoRE link-format parsing, filtering and encoding (RFC 6690).
use crate::{
    Error,
    link_format_validation::{singleton_bit, valid_name, validate_attributes},
};

/// Borrowed link target and its encoded attributes.
#[derive(Clone, Copy, Debug)]
pub struct Link<'a> {
    href: &'a str,
    attributes: &'a str,
}
impl<'a> Link<'a> {
    /// Link URI-reference.
    pub const fn href(self) -> &'a str {
        self.href
    }
    /// Attribute iterator, preserving encoded quoted values.
    pub fn attributes(self) -> Attributes<'a> {
        Attributes {
            remaining: self.attributes,
        }
    }
    /// Matches one RFC 6690 query, including space-separated attribute values.
    pub fn matches(self, query: &str) -> Result<bool, Error> {
        let query = Query::new(query)?;
        if query.name == "href" {
            return Ok(query.value(self.href));
        }
        for attr in self.attributes() {
            let attr = attr?;
            if attr.name == query.name {
                if attr.value.is_some() {
                    let mut escaped = false;
                    let decoded = attr.value.unwrap_or("").bytes().filter(move |&b| {
                        if !escaped && b == b'\\' {
                            escaped = true;
                            false
                        } else {
                            escaped = false;
                            true
                        }
                    });
                    if query.attribute_bytes(decoded) {
                        return Ok(true);
                    }
                } else if query.attribute(None) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}
/// Link attribute, with quotes removed but escape sequences retained.
#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    /// Attribute name.
    pub name: &'a str,
    /// Optional encoded value, without surrounding quotes.
    pub value: Option<&'a str>,
}
impl Attribute<'_> {
    /// Decodes quoted backslash escapes into caller storage.
    pub fn decode_value(self, out: &mut [u8]) -> Result<usize, Error> {
        let Some(value) = self.value else {
            return Ok(0);
        };
        let mut bytes = value.bytes();
        let mut n = 0;
        while let Some(b) = bytes.next() {
            let b = if b == b'\\' {
                bytes.next().ok_or(Error::Malformed)?
            } else {
                b
            };
            *out.get_mut(n).ok_or(Error::Capacity)? = b;
            n += 1;
        }
        Ok(n)
    }
}
/// Iterator over a link-format payload; malformed input terminates iteration.
#[derive(Debug)]
pub struct Links<'a> {
    remaining: &'a str,
}
impl<'a> Links<'a> {
    /// Starts parsing a UTF-8 link-format payload without allocation.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            remaining: core::str::from_utf8(bytes).map_err(|_| Error::Malformed)?,
        })
    }
    fn one(&mut self) -> Result<Link<'a>, Error> {
        let text = self.remaining.trim_start();
        let text = text.strip_prefix('<').ok_or(Error::Malformed)?;
        let close = text.find('>').ok_or(Error::Malformed)?;
        let href = &text[..close];
        if href.bytes().any(|b| b <= 32 || b == b'<' || b == b'"') {
            return Err(Error::Malformed);
        }
        let rest = &text[close + 1..];
        let mut quoted = false;
        let mut escaped = false;
        let mut split = rest.len();
        for (i, b) in rest.bytes().enumerate() {
            if escaped {
                escaped = false;
                continue;
            }
            match b {
                b'\\' if quoted => escaped = true,
                b'"' => quoted = !quoted,
                b',' if !quoted => {
                    split = i;
                    break;
                }
                _ => {}
            }
        }
        if quoted || escaped {
            return Err(Error::Malformed);
        }
        let attributes = &rest[..split];
        let mut seen = 0;
        for attr in (Attributes {
            remaining: attributes,
        }) {
            let attr = attr?;
            let bit = singleton_bit(attr.name);
            if seen & bit != 0 {
                return Err(Error::Malformed);
            }
            seen |= bit;
        }
        self.remaining = if split == rest.len() {
            ""
        } else {
            let tail = &rest[split + 1..];
            if tail.trim().is_empty() {
                return Err(Error::Malformed);
            }
            tail
        };
        Ok(Link { href, attributes })
    }
}
impl<'a> Iterator for Links<'a> {
    type Item = Result<Link<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.trim().is_empty() {
            return None;
        }
        let result = self.one();
        if result.is_err() {
            self.remaining = "";
        }
        Some(result)
    }
}
/// Iterator over borrowed link attributes.
#[derive(Debug)]
pub struct Attributes<'a> {
    remaining: &'a str,
}
impl<'a> Attributes<'a> {
    fn one(&mut self) -> Result<Attribute<'a>, Error> {
        let rest = self
            .remaining
            .trim_start()
            .strip_prefix(';')
            .ok_or(Error::Malformed)?
            .trim_start();
        let end = rest
            .find(['=', ';', ' ', '\t', '\r', '\n'])
            .unwrap_or(rest.len());
        let name = &rest[..end];
        if !valid_name(name) {
            return Err(Error::Malformed);
        }
        let suffix = rest[end..].trim_start();
        let (value, remaining) = if let Some(value) = suffix.strip_prefix('=') {
            if let Some(quoted) = value.strip_prefix('"') {
                let mut escaped = false;
                let mut close = None;
                for (i, b) in quoted.bytes().enumerate() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if b == b'\\' {
                        escaped = true;
                    } else if b == b'"' {
                        close = Some(i);
                        break;
                    } else if b < 32 {
                        return Err(Error::Malformed);
                    }
                }
                let close = close.ok_or(Error::Malformed)?;
                (Some(&quoted[..close]), &quoted[close + 1..])
            } else {
                let end = value
                    .find([';', ' ', '\t', '\r', '\n'])
                    .unwrap_or(value.len());
                if !is_ptoken(&value[..end]) {
                    return Err(Error::Malformed);
                }
                (Some(&value[..end]), &value[end..])
            }
        } else {
            (None, suffix)
        };
        if !remaining.trim_start().is_empty() && !remaining.trim_start().starts_with(';') {
            return Err(Error::Malformed);
        }
        self.remaining = remaining;
        Ok(Attribute { name, value })
    }
}
impl<'a> Iterator for Attributes<'a> {
    type Item = Result<Attribute<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.trim().is_empty() {
            return None;
        }
        let result = self.one();
        if result.is_err() {
            self.remaining = "";
        }
        Some(result)
    }
}
/// Caller-buffer link-format serializer.
#[derive(Debug)]
pub struct Writer<'a> {
    output: &'a mut [u8],
    used: usize,
    links: usize,
}
impl<'a> Writer<'a> {
    /// Starts an empty link set.
    pub fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            used: 0,
            links: 0,
        }
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.used.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        self.output
            .get_mut(self.used..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
    /// Adds a link with application-supplied attributes using the shortest form
    /// allowed by each attribute's link-format grammar.
    pub fn link(&mut self, href: &str, attributes: &[(&str, Option<&str>)]) -> Result<(), Error> {
        let previous = self.used;
        let separator = self.links != 0;
        let result = write_link(href, attributes, separator, |bytes| self.append(bytes));
        if result.is_err() {
            self.used = previous;
        } else {
            self.links += 1;
        }
        result
    }
    /// Used output length.
    pub const fn len(&self) -> usize {
        self.used
    }
    /// Whether no link was serialized.
    pub const fn is_empty(&self) -> bool {
        self.links == 0
    }
}

pub(crate) struct Query<'a> {
    name: &'a str,
    wanted: &'a str,
}
impl<'a> Query<'a> {
    pub(crate) fn new(query: &'a str) -> Result<Self, Error> {
        let (name, wanted) = query.split_once('=').ok_or(Error::Malformed)?;
        if name.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self { name, wanted })
    }
    fn value(&self, actual: &str) -> bool {
        self.value_bytes(actual.bytes())
    }
    fn value_bytes(&self, mut actual: impl Iterator<Item = u8>) -> bool {
        let prefix = self.wanted.strip_suffix('*');
        for b in prefix.unwrap_or(self.wanted).bytes() {
            if actual.next() != Some(b) {
                return false;
            }
        }
        prefix.is_some() || actual.next().is_none()
    }
    fn attribute_bytes(&self, value: impl Iterator<Item = u8> + Clone) -> bool {
        if self.value_bytes(value.clone()) {
            return true;
        }
        if matches!(self.name, "rt" | "if" | "ct" | "rel") {
            let mut bytes = value.peekable();
            while bytes.peek().is_some() {
                while bytes.peek().is_some_and(u8::is_ascii_whitespace) {
                    bytes.next();
                }
                if bytes.peek().is_none() {
                    break;
                }
                let mut word = bytes.by_ref().take_while(|b| !b.is_ascii_whitespace());
                let matched = self.value_bytes(&mut word);
                // A failed prefix comparison must consume the rest of this word.
                for _ in word {}
                if matched {
                    return true;
                }
            }
        }
        false
    }
    fn attribute(&self, value: Option<&str>) -> bool {
        value.map_or(self.wanted.is_empty(), |value| {
            self.attribute_bytes(value.bytes())
        })
    }
    #[cfg(feature = "discovery")]
    pub(crate) fn matches_link(&self, href: &str, attributes: &[(&str, Option<&str>)]) -> bool {
        if self.name == "href" {
            self.value_bytes(encoded_path(href))
        } else {
            attributes
                .iter()
                .any(|(name, value)| *name == self.name && self.attribute(*value))
        }
    }
}

pub(crate) fn write_link(
    href: &str,
    attributes: &[(&str, Option<&str>)],
    separator: bool,
    append: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    write_link_inner(href, attributes, separator, false, append)
}

#[cfg(feature = "discovery")]
pub(crate) fn write_path_link(
    path: &str,
    attributes: &[(&str, Option<&str>)],
    separator: bool,
    append: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    write_link_inner(path, attributes, separator, true, append)
}

fn write_link_inner(
    href: &str,
    attributes: &[(&str, Option<&str>)],
    separator: bool,
    encode_path: bool,
    mut append: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    if !encode_path && href.bytes().any(|b| b <= 32 || b"<>\"".contains(&b)) {
        return Err(Error::Malformed);
    }
    validate_attributes(attributes)?;
    if separator {
        append(b",")?;
    }
    append(b"<")?;
    if encode_path {
        for b in encoded_path(href) {
            append(&[b])?;
        }
    } else {
        append(href.as_bytes())?;
    }
    append(b">")?;
    for (name, value) in attributes {
        append(b";")?;
        append(name.as_bytes())?;
        if let Some(value) = value {
            let quoted = matches!(*name, "title" | "anchor") || !is_ptoken(value);
            append(if quoted { b"=\"" } else { b"=" })?;
            for b in value.bytes() {
                if quoted && (b == b'"' || b == b'\\') {
                    append(b"\\")?;
                }
                append(&[b])?;
            }
            if quoted {
                append(b"\"")?;
            }
        }
    }
    Ok(())
}

fn is_ptoken(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'()*+-./:<=>?@[]^_`{|}~".contains(&b))
}

fn encoded_path(path: &str) -> impl Iterator<Item = u8> + Clone + '_ {
    path.bytes().flat_map(|b| {
        let (bytes, len) = if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b) {
            ([b, 0, 0], 1)
        } else {
            let hex = b"0123456789ABCDEF";
            ([b'%', hex[(b >> 4) as usize], hex[(b & 15) as usize]], 3)
        };
        bytes.into_iter().take(len)
    })
}
