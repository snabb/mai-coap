//! Bounds checks before Lakers' fixed-buffer decoders (PLT-5).
use crate::{Error, edhoc::CcsEncoding};

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(n).ok_or(Error::Malformed)?;
        let bytes = self.bytes.get(self.position..end).ok_or(Error::Malformed)?;
        self.position = end;
        Ok(bytes)
    }
    fn head(&mut self) -> Result<(u8, u64), Error> {
        let first = self.take(1)?[0];
        let value = match first & 31 {
            n @ 0..=23 => u64::from(n),
            24 => u64::from(self.take(1)?[0]),
            25 => u64::from(u16::from_be_bytes(
                self.take(2)?.try_into().map_err(|_| Error::Malformed)?,
            )),
            26 => u64::from(u32::from_be_bytes(
                self.take(4)?.try_into().map_err(|_| Error::Malformed)?,
            )),
            27 => u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| Error::Malformed)?),
            _ => return Err(Error::Malformed),
        };
        Ok((first >> 5, value))
    }
    fn bytes(&mut self) -> Result<&'a [u8], Error> {
        let (major, n) = self.head()?;
        if major != 2 {
            return Err(Error::Malformed);
        }
        self.take(usize::try_from(n).map_err(|_| Error::Malformed)?)
    }
    fn map(&mut self) -> Result<u64, Error> {
        let (major, count) = self.head()?;
        if major != 5 {
            return Err(Error::Malformed);
        }
        Ok(count)
    }
    fn key(&mut self) -> Result<(u8, u64), Error> {
        let start = self.position;
        self.item(8)?;
        Reader::new(&self.bytes[start..self.position]).head()
    }
    fn connection(&mut self) -> Result<lakers::ConnId, Error> {
        let first = *self.bytes.get(self.position).ok_or(Error::Malformed)?;
        let raw = if first <= 0x17 || (0x20..=0x37).contains(&first) {
            self.take(1)?
        } else {
            // A seven-byte OSCORE ID also fits Lakers' eight-byte encoded-ID buffer.
            let bytes = self.bytes()?;
            if bytes.len() > 7 {
                return Err(Error::Malformed);
            }
            bytes
        };
        lakers::ConnId::from_slice(raw).ok_or(Error::Malformed)
    }
    fn item(&mut self, depth: u8) -> Result<(), Error> {
        if depth == 0 {
            return Err(Error::Malformed);
        }
        let (major, n) = self.head()?;
        match major {
            0 | 1 | 7 => Ok(()),
            2 | 3 => {
                self.take(usize::try_from(n).map_err(|_| Error::Malformed)?)?;
                Ok(())
            }
            4 | 5 => {
                let count = if major == 5 {
                    n.checked_mul(2).ok_or(Error::Malformed)?
                } else {
                    n
                };
                if count > self.bytes.len().saturating_sub(self.position) as u64 {
                    return Err(Error::Malformed);
                }
                for _ in 0..count {
                    self.item(depth - 1)?;
                }
                Ok(())
            }
            _ => Err(Error::Malformed),
        }
    }
    fn ead(&mut self) -> Result<(), Error> {
        let mut count = 0;
        while self.position < self.bytes.len() {
            count += 1;
            if count > lakers::MAX_EAD_ITEMS {
                return Err(Error::Malformed);
            }
            let (major, label) = self.head()?;
            if major > 1 || label > u64::from(u16::MAX) {
                return Err(Error::Malformed);
            }
            if self.bytes.get(self.position).is_some_and(|b| b >> 5 == 2) {
                self.bytes()?;
            }
        }
        Ok(())
    }
}

pub(super) fn credential(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(bytes);
    for _ in 0..reader.map()? {
        let (major, claim) = reader.key()?;
        if (major, claim) == (0, 8) {
            for _ in 0..reader.map()? {
                let (major, confirmation) = reader.key()?;
                if (major, confirmation) == (0, 1) {
                    for _ in 0..reader.map()? {
                        // Supported COSE labels all fit the immediate integer form.
                        // Avoid Lakers' extended i8 decoder (issues 443, 444, 451).
                        let first = *reader.bytes.get(reader.position).ok_or(Error::Malformed)?;
                        if first > 0x17 && !(0x20..=0x37).contains(&first) {
                            return Err(Error::Malformed);
                        }
                        reader.head()?;
                        reader.item(8)?;
                    }
                } else {
                    reader.item(8)?;
                }
            }
        } else {
            reader.item(8)?;
        }
    }
    if reader.position != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Extracts the optional byte-string y-coordinate from a supported CCS.
pub(super) fn credential_y(bytes: &[u8]) -> Result<Option<[u8; 32]>, Error> {
    let mut reader = Reader::new(bytes);
    let mut y = None;
    for _ in 0..reader.map()? {
        if reader.key()? != (0, 8) {
            reader.item(8)?;
            continue;
        }
        for _ in 0..reader.map()? {
            if reader.key()? != (0, 1) {
                reader.item(8)?;
                continue;
            }
            for _ in 0..reader.map()? {
                if reader.key()? != (1, 2) {
                    reader.item(8)?;
                    continue;
                }
                if y.is_some() {
                    return Err(Error::Malformed);
                }
                y = Some(reader.bytes()?.try_into().map_err(|_| Error::Malformed)?);
            }
        }
    }
    if reader.position != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(y)
}

pub(super) fn encode_ccs(
    kid: &[u8],
    public: &[u8; 65],
    encoding: CcsEncoding,
) -> Result<heapless::Vec<u8, 192>, Error> {
    if kid.len() > 16 {
        return Err(Error::Capacity);
    }
    if public[0] != 4 {
        return Err(Error::Malformed);
    }
    let mut ccs = heapless::Vec::new();
    ccs.extend_from_slice(&[0xa1, 0x08, 0xa1, 0x01])
        .map_err(|_| Error::Capacity)?;
    ccs.push(match encoding {
        CcsEncoding::CompactX => 0xa4,
        CcsEncoding::FullXY => 0xa5,
    })
    .map_err(|_| Error::Capacity)?;
    ccs.extend_from_slice(&[0x01, 0x02, 0x02])
        .map_err(|_| Error::Capacity)?;
    append_bytes(&mut ccs, kid)?;
    ccs.extend_from_slice(&[0x20, 0x01, 0x21])
        .map_err(|_| Error::Capacity)?;
    append_bytes(&mut ccs, &public[1..33])?;
    if encoding == CcsEncoding::FullXY {
        ccs.push(0x22).map_err(|_| Error::Capacity)?;
        append_bytes(&mut ccs, &public[33..])?;
    }
    Ok(ccs)
}

fn append_bytes(ccs: &mut heapless::Vec<u8, 192>, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() <= 23 {
        ccs.push(0x40 + bytes.len() as u8)
            .map_err(|_| Error::Capacity)?;
    } else {
        ccs.extend_from_slice(&[0x58, bytes.len() as u8])
            .map_err(|_| Error::Capacity)?;
    }
    ccs.extend_from_slice(bytes).map_err(|_| Error::Capacity)
}

pub(super) fn message_1(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(bytes);
    let (major, method) = reader.head()?;
    if major != 0 || method > 3 {
        return Err(Error::Malformed);
    }
    let (major, suite) = reader.head()?;
    match major {
        0 if suite <= 255 => {}
        4 if suite > 0 && suite <= lakers::MAX_SUITES_LEN as u64 => {
            for _ in 0..suite {
                let (major, suite) = reader.head()?;
                if major != 0 || suite > 255 {
                    return Err(Error::Malformed);
                }
            }
        }
        _ => return Err(Error::Malformed),
    }
    if reader.bytes()?.len() != 32 {
        return Err(Error::Malformed);
    }
    reader.connection()?;
    reader.ead()
}
#[cfg(any(
    feature = "server",
    feature = "client",
    all(test, feature = "software-crypto")
))]
pub(super) fn prefix(bytes: &[u8]) -> Result<(lakers::ConnId, usize), Error> {
    let mut reader = Reader::new(bytes);
    let connection = reader.connection()?;
    Ok((connection, reader.position))
}
pub(super) fn bstr_end(bytes: &[u8]) -> Result<usize, Error> {
    // Enforce deterministic framing and locate the combined request's ciphertext boundary.
    let (header, length) = match bytes.first().copied() {
        Some(first @ 0x40..=0x57) => (1, usize::from(first - 0x40)),
        Some(0x58) => match bytes.get(1).copied() {
            Some(length @ 24..=255) => (2, usize::from(length)),
            _ => return Err(Error::Malformed),
        },
        _ => return Err(Error::Malformed),
    };
    let end = header + length;
    if end > lakers::MAX_MESSAGE_SIZE_LEN || bytes.get(..end).is_none() {
        return Err(Error::Malformed);
    }
    Ok(end)
}
pub(super) fn message_3(bytes: &[u8]) -> Result<(), Error> {
    if bstr_end(bytes)? != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}
pub(super) fn plaintext_3(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(bytes);
    reader.item(8)?;
    if reader.bytes()?.len() != 8 {
        return Err(Error::Malformed);
    }
    reader.ead()
}
pub(super) fn plaintext_2(bytes: &[u8]) -> Result<(), Error> {
    let mut reader = Reader::new(bytes);
    reader.connection()?;
    plaintext_3(&bytes[reader.position..])
}
