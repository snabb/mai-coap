//! Bounded response construction in a borrowed datagram arena.
use super::{Response, ResponseError};
use crate::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber, encode_extension},
};
use core::num::NonZeroU64;
use zeroize::Zeroize;

#[derive(Clone, Copy)]
// Reset and replacement abandon bytes outside logical lengths; retain both watermarks.
struct Written {
    prefix: usize,
    suffix: usize,
}

pub(super) struct ResponseArena<'a, const D: usize> {
    bytes: &'a mut [u8; D],
    written: Written,
}
impl<'a, const D: usize> ResponseArena<'a, D> {
    pub(super) fn new(bytes: &'a mut [u8; D]) -> Self {
        Self {
            bytes,
            written: Written {
                prefix: 0,
                suffix: D,
            },
        }
    }
    pub(super) fn writer(
        &mut self,
        code: Code,
        token: &[u8],
        protected: bool,
    ) -> Result<ResponseWriter<'_, D>, Error> {
        let mut writer = ResponseWriter::new(&mut *self.bytes, code, token)?;
        writer.written = protected.then_some(&mut self.written);
        Ok(writer)
    }
}
impl<const D: usize> Drop for ResponseArena<'_, D> {
    fn drop(&mut self) {
        let Written { prefix, suffix } = self.written;
        if prefix != 0 {
            self.bytes[..prefix].zeroize();
        }
        if suffix < D {
            self.bytes[prefix.max(suffix)..].zeroize();
        }
        #[cfg(all(test, feature = "server", feature = "software-crypto"))]
        if prefix != 0 || suffix < D {
            WIPE_EVENTS.with(|events| events.set(events.get() + 1));
        }
    }
}

#[cfg(all(test, feature = "server", feature = "software-crypto"))]
std::thread_local! {
    static WIPE_EVENTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

#[cfg(all(test, feature = "server", feature = "software-crypto"))]
pub(super) fn wipe_events() -> usize {
    WIPE_EVENTS.with(core::cell::Cell::get)
}

type Options = heapless::Vec<(OptionNumber, usize), 16, u8>;

fn wire_size(options: &[(OptionNumber, usize)], payload: usize, token: usize) -> Option<usize> {
    let mut size = 4usize.checked_add(token)?;
    let mut previous = 0;
    for &(number, length) in options {
        let delta = number.0.checked_sub(previous)?;
        let (_, _, delta_bytes) = encode_extension(delta as usize).ok()?;
        let (_, _, length_bytes) = encode_extension(length).ok()?;
        size = size
            .checked_add(1 + delta_bytes + length_bytes)?
            .checked_add(length)?;
        previous = number.0;
    }
    if payload != 0 {
        size = size.checked_add(1)?.checked_add(payload)?;
    }
    Some(size)
}

/// Synchronous response construction in one caller-owned datagram arena.
///
/// Options, payload, header and token share `DATAGRAM_BYTES`. Setters preserve
/// existing content on capacity or validation errors. Unlike [`Response`], this
/// view cannot retain independently full option-value and payload buffers.
/// Synchronous callbacks receive this view; use [`Self::copy_from`] when building
/// larger intermediate content with an owned response, and [`Self::to_owned`]
/// when an explicit snapshot must outlive a callback.
///
/// ```
/// use mai_coap::{codec::Code, endpoint::{Disposition, Request, ResponseWriter}};
/// fn handle(_: Request<'_>, response: &mut ResponseWriter<'_, 64>)
///     -> Result<Disposition, Code>
/// {
///     response.set_payload(b"ready")?;
///     Ok(Disposition::Complete)
/// }
/// let mut arena = [0; 64];
/// let mut writer = ResponseWriter::<64>::new(&mut arena, Code::CONTENT, b"t")?;
/// writer.set_payload(b"ready")?;
/// # Ok::<(), mai_coap::Error>(())
/// ```
///
/// A callback cannot retain a borrow of the temporary arena:
///
/// ```compile_fail
/// use mai_coap::endpoint::ResponseWriter;
/// fn retain<'a>(response: &mut ResponseWriter<'_, 64>, saved: &mut Option<&'a [u8]>) {
///     *saved = Some(response.payload());
/// }
/// ```
///
/// Out-of-order options are sorted stably; singleton replacement removes all
/// previous instances. The endpoint erases written regions of its protected
/// response arenas after processing, including errors and unwinding; it does not
/// erase unprotected responses. Users of [`Self::new`] own their arena's cleanup.
pub struct ResponseWriter<'buf, const DATAGRAM_BYTES: usize = { crate::DEFAULT_DATAGRAM }> {
    bytes: &'buf mut [u8],
    written: Option<&'buf mut Written>,
    options: Options,
    token: heapless::Vec<u8, 8, u8>,
    values: usize,
    payload: usize,
    code: Code,
    pub(super) deferred_timeout_ms: Option<NonZeroU64>,
}

impl<const D: usize> core::fmt::Debug for ResponseWriter<'_, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponseWriter")
            .field("code", &self.code)
            .field("options", &self.options.len())
            .field("payload_bytes", &self.payload)
            .finish_non_exhaustive()
    }
}

impl<'buf, const D: usize> ResponseWriter<'buf, D> {
    /// Starts an empty response in the first D bytes of `arena`.
    /// Returns `Capacity` for a short arena/header and `Malformed` for a token
    /// longer than eight bytes. The MID and message type are supplied at finish.
    pub fn new(arena: &'buf mut [u8], code: Code, token: &[u8]) -> Result<Self, Error> {
        let token = heapless::Vec::from_slice(token).map_err(|_| Error::Malformed)?;
        let bytes = arena.get_mut(..D).ok_or(Error::Capacity)?;
        if 4 + token.len() > bytes.len() {
            return Err(Error::Capacity);
        }
        Ok(Self {
            bytes,
            written: None,
            options: Options::new(),
            token,
            values: 0,
            payload: 0,
            code,
            deferred_timeout_ms: None,
        })
    }
    /// Response status.
    pub const fn code(&self) -> Code {
        self.code
    }
    /// Replaces the status code; finalization rejects a non-response code.
    pub fn set_code(&mut self, code: Code) {
        self.code = code;
    }
    /// Temporary refusal with an explicit one-second Max-Age.
    #[cfg(feature = "server")]
    pub(crate) fn set_unavailable(&mut self) -> Result<(), ResponseError> {
        self.set_code(Code::UNAVAILABLE);
        self.uint_option(OptionNumber::MAX_AGE, 1)
    }
    pub(super) fn reset(&mut self, code: Code) {
        self.options.clear();
        self.values = 0;
        self.payload = 0;
        self.code = code;
        self.deferred_timeout_ms = None;
    }
    /// Sets a nonzero processing budget before returning [`super::Disposition::Deferred`].
    /// The endpoint retains the ticket for this many milliseconds plus one local
    /// exchange lifetime for delivery; without a budget, only that lifetime applies.
    /// Applications enforce processing expiry. This is not response content and
    /// is not included in [`Self::to_owned`]; [`Self::copy_from`] preserves it.
    pub fn set_deferred_timeout(&mut self, timeout_ms: u64) -> Result<(), ResponseError> {
        self.deferred_timeout_ms =
            Some(NonZeroU64::new(timeout_ms).ok_or(ResponseError::InvalidTimeout)?);
        Ok(())
    }
    /// Application body currently stored in the arena.
    pub fn payload(&self) -> &[u8] {
        &self.bytes[D - self.payload..]
    }
    /// Maximum replacement payload length with the current header and options.
    pub fn remaining_payload(&self) -> usize {
        let base = wire_size(&self.options, 0, self.token.len()).unwrap_or(D);
        D.saturating_sub(base).saturating_sub(1)
    }
    /// Replaces the body. An oversized body leaves all existing content unchanged.
    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), ResponseError> {
        self.check_size(&self.options, payload.len())?;
        self.touch_suffix(D - payload.len());
        self.bytes[D - payload.len()..].copy_from_slice(payload);
        self.payload = payload.len();
        Ok(())
    }
    #[cfg(feature = "server")]
    /// Clears the existing body before admission or rendering, including on failure.
    pub(crate) fn fill_payload<R>(
        &mut self,
        wanted: usize,
        fill: impl FnOnce(&mut [u8]) -> Result<(usize, R), Code>,
    ) -> Result<R, Code> {
        self.payload = 0;
        if wanted > self.remaining_payload() {
            return Err(Code::INTERNAL_ERROR);
        }
        let start = D - wanted;
        // A callback may write beyond its returned length, including before error/unwind.
        self.touch_suffix(start);
        match fill(&mut self.bytes[start..]) {
            Ok((length, result)) if length <= wanted => {
                if length != wanted {
                    self.bytes.copy_within(start..start + length, D - length);
                }
                self.payload = length;
                Ok(result)
            }
            result => Err(result.err().unwrap_or(Code::INTERNAL_ERROR)),
        }
    }
    #[cfg(feature = "discovery")]
    /// Clears the existing body and offers its storage as scratch, including on failure.
    pub(crate) fn with_scratch<R>(
        &mut self,
        process: impl FnOnce(&mut [u8]) -> Result<R, Code>,
    ) -> Result<R, Code> {
        self.payload = 0;
        // Policy probes are temporary messages, so response header overhead does
        // not reduce their scratch space. Retain existing raw option values.
        self.touch_suffix(self.values);
        process(&mut self.bytes[self.values..])
    }
    fn touch_prefix(&mut self, end: usize) {
        if let Some(written) = self.written.as_deref_mut() {
            written.prefix = written.prefix.max(end);
        }
    }
    fn touch_suffix(&mut self, start: usize) {
        if let Some(written) = self.written.as_deref_mut() {
            written.suffix = written.suffix.min(start);
        }
    }
    fn check_size(
        &self,
        options: &[(OptionNumber, usize)],
        payload: usize,
    ) -> Result<(), ResponseError> {
        match wire_size(options, payload, self.token.len()) {
            Some(size) if size <= D => Ok(()),
            _ => Err(ResponseError::Capacity),
        }
    }
    /// Adds an option, preserving insertion order among repeated option numbers.
    pub fn option(&mut self, number: OptionNumber, value: &[u8]) -> Result<(), ResponseError> {
        self.update_option(number, value, false)
    }
    /// Replaces all instances of an option without changing other option order.
    pub fn set_option(&mut self, number: OptionNumber, value: &[u8]) -> Result<(), ResponseError> {
        self.update_option(number, value, true)
    }
    fn update_option(
        &mut self,
        number: OptionNumber,
        value: &[u8],
        replace: bool,
    ) -> Result<(), ResponseError> {
        if crate::codec::dot_segment(number, value) {
            return Err(ResponseError::InvalidOption);
        }
        // Preflight descriptors and exact wire space before moving either region.
        let mut planned = self.options.clone();
        if replace {
            planned.retain(|(n, _)| *n != number);
        }
        let index = planned.partition_point(|(n, _)| *n <= number);
        planned
            .insert(index, (number, value.len()))
            .map_err(|_| ResponseError::Capacity)?;
        self.check_size(&planned, self.payload)?;
        if self.written.is_some() {
            self.touch_prefix(self.values.max(planned.iter().map(|(_, n)| *n).sum()));
        }
        if replace {
            let mut index = 0;
            let mut start = 0;
            while index < self.options.len() {
                let (n, length) = self.options[index];
                if n == number {
                    self.bytes.copy_within(start + length..self.values, start);
                    self.values -= length;
                    self.options.remove(index);
                } else {
                    start += length;
                    index += 1;
                }
            }
        }
        let index = self.options.partition_point(|(n, _)| *n <= number);
        let start: usize = self.options[..index].iter().map(|(_, n)| *n).sum();
        self.bytes
            .copy_within(start..self.values, start + value.len());
        self.bytes[start..start + value.len()].copy_from_slice(value);
        self.values += value.len();
        self.options = planned;
        Ok(())
    }
    /// Adds a minimally encoded unsigned option.
    pub fn uint_option(&mut self, number: OptionNumber, value: u64) -> Result<(), ResponseError> {
        self.option(number, crate::codec::minimal_uint(&value.to_be_bytes()))
    }
    /// Replaces an option with a minimally encoded unsigned value.
    pub fn set_uint_option(
        &mut self,
        number: OptionNumber,
        value: u64,
    ) -> Result<(), ResponseError> {
        self.set_option(number, crate::codec::minimal_uint(&value.to_be_bytes()))
    }
    /// Copies owned content after checking the complete resulting wire size.
    /// The writer's token and deferred processing budget are retained.
    /// Failure leaves its content and budget unchanged.
    pub fn copy_from(&mut self, response: &Response<D>) -> Result<(), ResponseError> {
        self.copy_content(
            response.code,
            response.options.iter().map(|&(number, start, length)| {
                (number, &response.values.as_slice()[start..start + length])
            }),
            response.payload.as_slice(),
        )
    }
    /// As [`Self::copy_from`], for content retained by [`Self::serialized_content`].
    #[cfg(all(feature = "server", feature = "block1"))]
    pub(crate) fn copy_message(&mut self, message: MessageView<'_>) -> Result<(), ResponseError> {
        self.copy_content(
            message.code(),
            message
                .options()
                .map(|option| (option.number, option.value)),
            message.payload(),
        )
    }
    fn copy_content<'a>(
        &mut self,
        code: Code,
        options: impl Iterator<Item = (OptionNumber, &'a [u8])> + Clone,
        payload: &[u8],
    ) -> Result<(), ResponseError> {
        let mut planned = Options::new();
        for (number, value) in options.clone() {
            planned
                .push((number, value.len()))
                .map_err(|_| ResponseError::Capacity)?;
        }
        self.check_size(&planned, payload.len())?;
        let budget = self.deferred_timeout_ms;
        self.reset(code);
        self.deferred_timeout_ms = budget;
        for (number, value) in options {
            self.option(number, value)?;
        }
        self.set_payload(payload)?;
        Ok(())
    }
    /// Serializes content without a token so a later duplicate can rebind its own.
    #[cfg(all(feature = "server", feature = "block1"))]
    pub(crate) fn serialized_content(&self) -> Result<crate::Packet<D>, ResponseError> {
        crate::Packet::encoded(|wire| self.serialize(wire, MessageType::NonConfirmable, 0, &[]))
            .map_err(|_| ResponseError::Capacity)
    }
    /// Copies content into an independently owned response for retention.
    /// The token and deferred processing budget are not response content.
    pub fn to_owned(&self) -> Result<Response<D>, ResponseError> {
        let mut response = Response::new(self.code);
        let mut start = 0;
        for &(number, length) in &self.options {
            response.option(number, &self.bytes[start..start + length])?;
            start += length;
        }
        response.set_payload(self.payload())?;
        Ok(response)
    }
    /// Copies the message using the writer's token into another output buffer,
    /// still bounded by D.
    /// Use [`Self::finish`] to finalize the borrowed arena without this copy.
    pub fn encode(&self, output: &mut [u8], ty: MessageType, mid: u16) -> Result<usize, Error> {
        if !self.code.is_response() {
            return Err(Error::Malformed);
        }
        self.serialize(output, ty, mid, &self.token)
    }
    fn serialize(
        &self,
        output: &mut [u8],
        ty: MessageType,
        mid: u16,
        token: &[u8],
    ) -> Result<usize, Error> {
        let limit = output.len().min(D);
        let mut builder = MessageBuilder::new(&mut output[..limit], ty, self.code, mid, token)?;
        let mut start = 0;
        for &(number, length) in &self.options {
            builder.option(number, &self.bytes[start..start + length])?;
            start += length;
        }
        builder.finish(self.payload())
    }
    /// Consumes the view, expands option headers in place and returns the message.
    /// The caller retains ownership of the arena. No payload marker is emitted
    /// for an empty body. A non-response code returns `Malformed`.
    pub fn finish(self, ty: MessageType, mid: u16) -> Result<MessageView<'buf>, Error> {
        MessageView::parse(self.finish_bytes(ty, mid)?)
    }
    pub(super) fn finish_bytes(mut self, ty: MessageType, mid: u16) -> Result<&'buf [u8], Error> {
        if !self.code.is_response() {
            return Err(Error::Malformed);
        }
        let length =
            wire_size(&self.options, self.payload, self.token.len()).ok_or(Error::Capacity)?;
        self.touch_prefix(length);
        let mut end = length
            - if self.payload == 0 {
                0
            } else {
                self.payload + 1
            };
        let mut source_end = self.values;
        // Expanding backwards cannot overwrite an earlier option's raw values.
        for index in (0..self.options.len()).rev() {
            let (number, size) = self.options[index];
            let previous = index.checked_sub(1).map_or(0, |i| self.options[i].0.0);
            let (dn, db, dl) = encode_extension((number.0 - previous) as usize)?;
            let (ln, lb, ll) = encode_extension(size)?;
            self.bytes
                .copy_within(source_end - size..source_end, end - size);
            source_end -= size;
            end -= size + 1 + dl + ll;
            self.bytes[end] = (dn << 4) | ln;
            self.bytes[end + 1..end + 1 + dl].copy_from_slice(&db[..dl]);
            self.bytes[end + 1 + dl..end + 1 + dl + ll].copy_from_slice(&lb[..ll]);
        }
        let _ = MessageBuilder::new(self.bytes, ty, self.code, mid, &self.token)?;
        if self.payload != 0 {
            let marker = length - self.payload - 1;
            self.bytes.copy_within(D - self.payload..D, marker + 1);
            self.bytes[marker] = 0xff;
        }
        Ok(&self.bytes[..length])
    }
}

#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod tests;
