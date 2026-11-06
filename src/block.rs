//! End-to-end block transfer primitives (RFC 7959, RFC 9175).
//!
//! [`Block`], [`Download`] and [`etag`] are supported standalone APIs.
//! With `block1`, the module also exposes transactional upload primitives.
//! Callers own transfer storage, expiry scheduling and sink cleanup; endpoint
//! integration is optional.
use crate::Error;
#[cfg(feature = "block1")]
use crate::time::Instant;

/// Computes an eight-byte validator from complete representation bytes (BLK-2).
pub fn etag(bytes: &[u8]) -> [u8; 8] {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(bytes);
    let mut result = [0; 8];
    result.copy_from_slice(&hash[..8]);
    result
}

/// Block option: a twenty-bit number, continuation flag, and UDP size exponent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block {
    /// Block number, at most 0xfffff.
    pub number: u32,
    /// Whether more body bytes follow this block.
    pub more: bool,
    /// Size exponent, zero through six (16 through 1024 bytes).
    pub szx: u8,
}
impl Block {
    /// Validates a UDP block option; BERT is unsupported.
    pub fn new(number: u32, more: bool, szx: u8) -> Result<Self, Error> {
        if number > 0xfffff || szx > 6 {
            return Err(Error::Malformed);
        }
        Ok(Self { number, more, szx })
    }
    /// Decodes the option's unsigned integer.
    pub fn decode(value: u64) -> Result<Self, Error> {
        if value > 0xffffff {
            return Err(Error::Malformed);
        }
        Self::new((value >> 4) as u32, value & 8 != 0, (value & 7) as u8)
    }
    /// Encodes the option's unsigned integer.
    pub fn encode(self) -> Result<u64, Error> {
        Self::new(self.number, self.more, self.szx)?;
        Ok((u64::from(self.number) << 4) | (u64::from(self.more) << 3) | u64::from(self.szx))
    }
    /// Block length in bytes, rejecting an invalid exponent.
    pub fn size(self) -> Result<usize, Error> {
        if self.szx > 6 {
            Err(Error::Malformed)
        } else {
            Ok(1usize << (self.szx + 4))
        }
    }
    /// Byte offset, checked even on small-address-space targets.
    pub fn offset(self) -> Result<usize, Error> {
        Self::new(self.number, self.more, self.szx)?;
        (self.number as usize)
            .checked_mul(self.size()?)
            .ok_or(Error::Malformed)
    }
    /// Selects a server size while retaining the client's requested byte offset.
    pub fn capped(self, maximum_szx: u8) -> Result<Self, Error> {
        let offset = self.offset()?;
        let szx = self.szx.min(maximum_szx.min(6));
        Self::new((offset / (1usize << (szx + 4))) as u32, false, szx)
    }
    /// Slices a complete representation, with a smaller configured block size.
    pub fn slice(self, representation: &[u8], maximum_szx: u8) -> Result<(Self, &[u8]), Error> {
        let mut chosen = self.capped(maximum_szx)?;
        let start = chosen.offset()?;
        if start > representation.len() || (start == representation.len() && start != 0) {
            return Err(Error::BadOption(crate::codec::OptionNumber::BLOCK2));
        }
        let end = start
            .saturating_add(chosen.size()?)
            .min(representation.len());
        chosen.more = end < representation.len();
        Ok((chosen, &representation[start..end]))
    }
}

/// Request body identity; tags are bound to endpoint, resource and context (BLK-5).
#[cfg(feature = "block1")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BodyKey {
    /// Source identity, with irrelevant IPv6 flow/scope fields normalized.
    pub remote: core::net::SocketAddr,
    /// Stable application resource identifier.
    pub resource: u32,
    /// Context generation; `None` denotes unprotected traffic.
    pub context: Option<u64>,
    /// Digest of the method and matchable options (RFC 9175 section 3.3.1).
    pub match_options: [u8; 32],
    /// Length-prefixed Request-Tag occurrences in their original order.
    pub tags: heapless::Vec<u8, 64>,
}
#[cfg(feature = "block1")]
impl BodyKey {
    /// Binds a body to its method and options, excluding block coordinates and tags.
    pub fn from_request(
        remote: core::net::SocketAddr,
        resource: u32,
        context: Option<u64>,
        message: crate::codec::MessageView<'_>,
    ) -> Result<Self, Error> {
        use crate::codec::OptionNumber;
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update([message.code().0]);
        let mut key = Self {
            remote: crate::transport::peer_address(remote),
            resource,
            context,
            match_options: [0; 32],
            tags: heapless::Vec::new(),
        };
        for option in message.options() {
            if option.number == OptionNumber::REQUEST_TAG {
                key.add_tag(option.value)?;
            } else if !matches!(option.number, OptionNumber::BLOCK1 | OptionNumber::BLOCK2)
                && option.number.0 & 0x1e != 0x1c
            {
                hash.update(option.number.0.to_be_bytes());
                hash.update((option.value.len() as u32).to_be_bytes());
                hash.update(option.value);
            }
        }
        key.match_options.copy_from_slice(&hash.finalize());
        Ok(key)
    }
    /// Adds a Request-Tag occurrence, preserving boundaries and order.
    pub fn add_tag(&mut self, tag: &[u8]) -> Result<(), Error> {
        if tag.len() > 8 {
            return Err(Error::Malformed);
        }
        if self.tags.capacity() - self.tags.len() < tag.len() + 1 {
            return Err(Error::Capacity);
        }
        self.tags
            .push(tag.len() as u8)
            .map_err(|_| Error::Capacity)?;
        self.tags
            .extend_from_slice(tag)
            .map_err(|_| Error::Capacity)
    }
}

/// Result of accepting a Block1 message.
#[cfg(feature = "block1")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Accepted non-final data; respond with 2.31 Continue.
    Continue,
    /// Final data is available and may be committed once.
    Complete,
    /// Byte-identical retransmission, requiring no write or commit.
    Duplicate,
}
/// A transactional streaming body destination.
#[cfg(feature = "block1")]
pub trait UploadSink {
    /// Starts a new transaction; no partially received body becomes active.
    fn begin(&mut self, key: &BodyKey, size: Option<u64>) -> Result<(), Error>;
    /// Writes ordered bytes at the given offset into an inactive transaction.
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error>;
    /// Atomically makes a complete body active.
    fn commit(&mut self) -> Result<(), Error>;
    /// Discards an incomplete transaction, including after a write failure.
    fn abort(&mut self);
}

/// Ordered streaming upload state with exact duplicate detection (BLK-4).
#[cfg(feature = "block1")]
#[derive(Debug)]
pub struct StreamingUpload<const BLOCK_BYTES: usize = 1024> {
    next: usize,
    last_offset: usize,
    last: crate::Packet<BLOCK_BYTES>,
    final_seen: bool,
    aborted: bool,
    deadline: Instant,
    limit: usize,
    size: Option<u64>,
}
#[cfg(feature = "block1")]
impl<const BLOCK_BYTES: usize> StreamingUpload<BLOCK_BYTES> {
    /// Starts an inactive upload transaction.
    pub fn begin(
        key: &BodyKey,
        size: Option<u64>,
        limit: usize,
        deadline: Instant,
        sink: &mut (impl UploadSink + ?Sized),
    ) -> Result<Self, Error> {
        if size.is_some_and(|n| n > limit as u64) {
            return Err(Error::Response(crate::codec::Code::TOO_LARGE));
        }
        sink.begin(key, size)?;
        Ok(Self {
            next: 0,
            last_offset: usize::MAX,
            last: crate::Packet::new(),
            final_seen: false,
            aborted: false,
            deadline,
            limit,
            size,
        })
    }
    /// Writes an ordered block and commits exactly once on final data.
    /// Expiry and sink errors abort the transaction.
    pub fn push(
        &mut self,
        block: Block,
        bytes: &[u8],
        now: Instant,
        deadline: Instant,
        sink: &mut (impl UploadSink + ?Sized),
    ) -> Result<Progress, Error> {
        if self.aborted {
            return Err(Error::Response(crate::codec::Code::INCOMPLETE));
        }
        if now >= self.deadline {
            if !self.final_seen {
                sink.abort();
                self.final_seen = true;
                self.aborted = true;
            }
            return Err(Error::Timeout);
        }
        let offset = block.offset()?;
        let end = offset.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        if bytes.len() > block.size()? || (block.more && bytes.len() != block.size()?) {
            return Err(Error::Response(crate::codec::Code::INCOMPLETE));
        }
        if self.is_duplicate(block, bytes) {
            return Ok(Progress::Duplicate);
        }
        if self.final_seen || offset != self.next {
            return Err(Error::Response(crate::codec::Code::INCOMPLETE));
        }
        if end > self.limit
            || self
                .size
                .is_some_and(|n| end as u64 > n || (!block.more && end as u64 != n))
        {
            return Err(Error::Response(crate::codec::Code::TOO_LARGE));
        }
        let saved = crate::Packet::copy_from(bytes)?;
        if let Err(e) = sink.write(offset, bytes) {
            sink.abort();
            self.final_seen = true;
            self.aborted = true;
            return Err(e);
        }
        if !block.more {
            if let Err(e) = sink.commit() {
                sink.abort();
                self.final_seen = true;
                self.aborted = true;
                return Err(e);
            }
            self.final_seen = true;
        }
        self.next = end;
        self.last_offset = offset;
        self.last = saved;
        self.deadline = deadline;
        Ok(if block.more {
            Progress::Continue
        } else {
            Progress::Complete
        })
    }
    /// Aborts an unfinished body once its deadline passes.
    pub fn expire(&mut self, now: Instant, sink: &mut (impl UploadSink + ?Sized)) -> bool {
        if now >= self.deadline && !self.final_seen {
            sink.abort();
            self.final_seen = true;
            self.aborted = true;
            return true;
        }
        false
    }
    /// Total successfully written bytes.
    pub const fn received(&self) -> usize {
        self.next
    }
    /// Whether the transaction committed or was aborted.
    pub const fn closed(&self) -> bool {
        self.final_seen
    }
    pub(crate) fn is_duplicate(&self, block: Block, bytes: &[u8]) -> bool {
        block.offset() == Ok(self.last_offset)
            && bytes == self.last.as_slice()
            && self.final_seen == !block.more
    }
}

/// Buffered transactional upload state (BLK-4a).
#[cfg(feature = "block1")]
#[derive(Debug)]
pub struct BufferedUpload<const BODY_BYTES: usize = 4096> {
    body: heapless::Vec<u8, BODY_BYTES>,
    next: usize,
    last_offset: usize,
    last_len: usize,
    final_seen: bool,
    deadline: Instant,
}
#[cfg(feature = "block1")]
impl<const BODY_BYTES: usize> BufferedUpload<BODY_BYTES> {
    /// Creates an empty body with a configured inactivity deadline.
    pub const fn new(deadline: Instant) -> Self {
        Self {
            body: heapless::Vec::new(),
            next: 0,
            last_offset: usize::MAX,
            last_len: 0,
            final_seen: false,
            deadline,
        }
    }
    /// Accepts one ordered block; callers deliver the body only on `Complete`.
    /// Completed bodies remain available for duplicate checks until dropped.
    /// An incomplete body's expiry resets it to the supplied new deadline and
    /// returns `Timeout`; a subsequent call can start again with block zero.
    pub fn push(
        &mut self,
        block: Block,
        bytes: &[u8],
        size: Option<u64>,
        now: Instant,
        deadline: Instant,
    ) -> Result<Progress, Error> {
        if !self.final_seen && now >= self.deadline {
            *self = Self::new(deadline);
            return Err(Error::Timeout);
        }
        let offset = block.offset()?;
        if bytes.len() > block.size()? || (block.more && bytes.len() != block.size()?) {
            return Err(Error::Response(crate::codec::Code::INCOMPLETE));
        }
        if self.is_duplicate(block, bytes) {
            return Ok(Progress::Duplicate);
        }
        if self.final_seen || offset != self.next {
            return Err(Error::Response(crate::codec::Code::INCOMPLETE));
        }
        let end = offset.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        if end > BODY_BYTES
            || size.is_some_and(|n| {
                n > BODY_BYTES as u64 || end as u64 > n || (!block.more && end as u64 != n)
            })
        {
            return Err(Error::Response(crate::codec::Code::TOO_LARGE));
        }
        self.body
            .extend_from_slice(bytes)
            .map_err(|_| Error::Capacity)?;
        self.last_offset = offset;
        self.last_len = bytes.len();
        self.next = end;
        self.final_seen = !block.more;
        self.deadline = deadline;
        Ok(if block.more {
            Progress::Continue
        } else {
            Progress::Complete
        })
    }
    /// Complete buffered body, never exposing an incomplete body as committed.
    pub fn complete_body(&self) -> Option<&[u8]> {
        self.final_seen.then_some(&self.body)
    }
    /// Tests expiry for reclamation by a bounded table.
    pub const fn expired(&self, now: Instant) -> bool {
        now.0 >= self.deadline.0
    }
    pub(crate) fn is_duplicate(&self, block: Block, bytes: &[u8]) -> bool {
        block.offset() == Ok(self.last_offset)
            && bytes.len() == self.last_len
            && self
                .body
                .get(self.last_offset..self.last_offset.saturating_add(bytes.len()))
                == Some(bytes)
            && self.final_seen == !block.more
    }
}

/// Client-side consistency and ordered reassembly state (BLK-3).
#[derive(Debug)]
pub struct Download {
    next: usize,
    etag: Option<heapless::Vec<u8, 8>>,
    restarts: u8,
    maximum_restarts: u8,
    started: bool,
}
impl Download {
    /// Starts at a byte offset; three restarts are allowed by default.
    pub const fn new(offset: usize) -> Self {
        Self {
            next: offset,
            etag: None,
            restarts: 0,
            maximum_restarts: 3,
            started: false,
        }
    }
    /// Sets the restart bound.
    pub fn with_restart_limit(mut self, maximum: u8) -> Self {
        self.maximum_restarts = maximum;
        self
    }
    /// Checks an incoming block before writing it. `false` requests a restart at zero.
    pub fn accept(
        &mut self,
        block: Block,
        bytes: &[u8],
        etag: Option<&[u8]>,
    ) -> Result<bool, Error> {
        if bytes.len() > block.size()? || (block.more && bytes.len() != block.size()?) {
            return Err(Error::Malformed);
        }
        let incoming = etag
            .map(|e| heapless::Vec::from_slice(e).map_err(|_| Error::Malformed))
            .transpose()?;
        if self.started && self.etag != incoming && self.next != 0 {
            if self.restarts == self.maximum_restarts {
                return Err(Error::RepresentationChanged);
            }
            self.restarts += 1;
            self.next = 0;
            self.etag = None;
            self.started = false;
            return Ok(false);
        }
        if block.offset()? != self.next {
            return Err(Error::Malformed);
        }
        self.etag = incoming;
        self.started = true;
        self.next = self.next.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        Ok(true)
    }
    /// Byte offset required next, including zero after a restart.
    pub const fn next_offset(&self) -> usize {
        self.next
    }
}

#[cfg(kani)]
mod proofs;
