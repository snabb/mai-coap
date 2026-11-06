//! OSCORE context derivation and message processing (RFC 8613).
use crate::{
    Error,
    codec::{Code, MessageBuilder, MessageType, MessageView, OptionNumber},
    security::{CryptoProvider, PeerId},
};
use zeroize::Zeroize;

const MAX_SEQUENCE: u64 = (1u64 << 40) - 1;
/// Maximum retained ID Context length supported by the one-byte wire length.
pub const MAX_ID_CONTEXT_BYTES: usize = u8::MAX as usize;

pub(crate) const fn assert_context_capacity<const N: usize>() {
    assert!(
        N <= MAX_ID_CONTEXT_BYTES,
        "ID_CONTEXT_BYTES exceeds MAX_ID_CONTEXT_BYTES"
    );
}

#[cfg(any(feature = "server", feature = "client"))]
pub(crate) mod endpoint;
#[cfg(any(feature = "server", feature = "client"))]
pub use endpoint::{Binding, Oscore};

/// OSCORE option protection class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionClass {
    /// Encrypted and authenticated.
    Encrypted,
    /// Unprotected routing metadata.
    Unprotected,
    /// Observe is present both inside and outside protection.
    Observe,
}
/// Default classes, including extensions published after RFC 8613 (OSC-3).
pub(crate) const fn option_class(number: OptionNumber) -> OptionClass {
    match number.0 {
        3 | 7 | 16 | 21 | 35 | 39 => OptionClass::Unprotected,
        6 => OptionClass::Observe,
        _ => OptionClass::Encrypted,
    }
}

/// Parsed compressed COSE header, borrowing the OSCORE option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OscoreOption<'a> {
    /// Partial IV; absent for a response using its request nonce.
    pub partial_iv: Option<&'a [u8]>,
    /// Sender ID; absence differs from an empty sender ID.
    pub kid: Option<&'a [u8]>,
    /// Optional context identifier.
    pub kid_context: Option<&'a [u8]>,
}
impl<'a> OscoreOption<'a> {
    /// Decodes flags, lengths and reserved values (OSC-6).
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Ok(Self {
                partial_iv: None,
                kid: None,
                kid_context: None,
            });
        }
        let flags = bytes[0];
        let n = usize::from(flags & 7);
        // All-zero flags SHALL be sent as an empty value (RFC 8613 §2).
        if flags == 0 || flags & 0xe0 != 0 || n > 5 {
            return Err(Error::Malformed);
        }
        let mut offset = 1;
        let partial_iv = if n != 0 {
            let piv = bytes.get(offset..offset + n).ok_or(Error::Malformed)?;
            if n > 1 && piv[0] == 0 {
                return Err(Error::Malformed);
            }
            offset += n;
            Some(piv)
        } else {
            None
        };
        let kid_context = if flags & 16 != 0 {
            let len = usize::from(*bytes.get(offset).ok_or(Error::Malformed)?);
            offset += 1;
            let context = bytes.get(offset..offset + len).ok_or(Error::Malformed)?;
            offset += len;
            Some(context)
        } else {
            None
        };
        let kid = if flags & 8 != 0 {
            Some(&bytes[offset..])
        } else {
            if offset != bytes.len() {
                return Err(Error::Malformed);
            }
            None
        };
        if kid.is_some_and(|id| id.len() > 7) {
            return Err(Error::Malformed);
        }
        Ok(Self {
            partial_iv,
            kid,
            kid_context,
        })
    }
    /// Writes the compressed option into caller storage.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.partial_iv.map_or(0, <[u8]>::len);
        if n > 5
            || self
                .partial_iv
                .is_some_and(|p| p.is_empty() || p.len() > 1 && p[0] == 0)
            || self.kid.is_some_and(|id| id.len() > 7)
            || self
                .kid_context
                .is_some_and(|c| c.len() > MAX_ID_CONTEXT_BYTES)
        {
            return Err(Error::Malformed);
        }
        if n == 0 && self.kid.is_none() && self.kid_context.is_none() {
            return Ok(0);
        }
        let mut writer = Cbor::new(out);
        writer.raw(&[(n as u8)
            | if self.kid.is_some() { 8 } else { 0 }
            | if self.kid_context.is_some() { 16 } else { 0 }])?;
        if let Some(p) = self.partial_iv {
            writer.raw(p)?;
        }
        if let Some(c) = self.kid_context {
            writer.raw(&[c.len() as u8])?;
            writer.raw(c)?;
        }
        if let Some(k) = self.kid {
            writer.raw(k)?;
        }
        Ok(writer.used)
    }
    /// Numeric Partial IV, rejecting its absence.
    pub fn sequence(self) -> Result<u64, Error> {
        let p = self.partial_iv.ok_or(Error::Malformed)?;
        Ok(p.iter().fold(0, |n, &b| (n << 8) | u64::from(b)))
    }
}

/// Thirty-two-entry recipient replay window (OSC-8).
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u32,
}
impl ReplayWindow {
    /// Checks without changing state; call `accept` only after AEAD verification.
    pub fn check(self, sequence: u64) -> Result<(), Error> {
        if sequence > MAX_SEQUENCE {
            return Err(Error::Malformed);
        }
        if let Some(highest) = self.highest
            && sequence <= highest
        {
            let gap = highest - sequence;
            if gap >= 32 || self.bitmap & (1 << gap) != 0 {
                return Err(Error::Replay);
            }
        }
        Ok(())
    }
    /// Atomically checks and records an authenticated sequence number.
    pub fn accept(&mut self, sequence: u64) -> Result<(), Error> {
        self.check(sequence)?;
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bitmap = 1;
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.bitmap = if shift >= 32 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(sequence);
            }
            Some(highest) => self.bitmap |= 1 << (highest - sequence),
        }
        Ok(())
    }
}

/// Request binding retained until its response or observation ends (OSC-11).
/// Not cloneable: request-nonce response generation is a one-shot operation.
#[derive(Debug)]
pub struct RequestBinding {
    // Wire bounds fit in byte-sized lengths; bindings are repeated in exchanges.
    kid: heapless::Vec<u8, 7, u8>,
    partial_iv: heapless::Vec<u8, 5, u8>,
    response_used: bool,
    notification_number: Option<u64>,
}
impl RequestBinding {
    fn new(kid: &[u8], partial_iv: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            kid: heapless::Vec::from_slice(kid).map_err(|_| Error::Malformed)?,
            partial_iv: heapless::Vec::from_slice(partial_iv).map_err(|_| Error::Malformed)?,
            response_used: false,
            notification_number: None,
        })
    }
}
/// Response nonce selection for independently used contexts. Endpoints always
/// select fresh Partial IVs, including after reply-cache eviction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseNonce {
    /// Reserve a new server sender sequence number.
    Fresh,
    /// Use the request nonce once, guarded by its non-cloneable binding. Once
    /// selected, even failed protection consumes this permission; later responses
    /// and notifications must select `Fresh`.
    FirstRequestNonce,
}

/// Transient OSCORE context with the full 255-byte ID Context storage bound.
///
/// Derivation is independently usable. A context is fresh only when its master
/// secret/IDs identify a new key epoch. Reconstructing a used context from static
/// secrets is unsupported; production endpoints install EDHOC-derived contexts.
pub type Context = BoundedContext<MAX_ID_CONTEXT_BYTES>;

/// Transient OSCORE context with explicitly bounded ID Context storage.
///
/// `ID_CONTEXT_BYTES` bounds retained ID Context bytes. Zero supports absent and
/// present-empty IDs, which remain distinct key-derivation inputs. The capacity
/// must be at most [`MAX_ID_CONTEXT_BYTES`], checked at compile time when
/// deriving. Oversized IDs return [`Error::Capacity`] without truncation. Keys
/// are zeroized on drop (OSC-18).
/// Fresh-epoch requirements are the same as for [`Context`].
pub struct BoundedContext<const ID_CONTEXT_BYTES: usize> {
    sender: heapless::Vec<u8, 7, u8>,
    recipient: heapless::Vec<u8, 7, u8>,
    id_context: Option<heapless::Vec<u8, ID_CONTEXT_BYTES>>,
    sender_key: [u8; 16],
    recipient_key: [u8; 16],
    common_iv: [u8; 13],
    next_sequence: u64,
    replay: ReplayWindow,
    peer: PeerId,
}
impl<const ID_CONTEXT_BYTES: usize> core::fmt::Debug for BoundedContext<ID_CONTEXT_BYTES> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Context")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}
impl<const ID_CONTEXT_BYTES: usize> Drop for BoundedContext<ID_CONTEXT_BYTES> {
    fn drop(&mut self) {
        self.sender_key.zeroize();
        self.recipient_key.zeroize();
        self.common_iv.zeroize();
    }
}
fn store_context_id<const CAPACITY: usize>(
    id: Option<&[u8]>,
) -> Result<Option<heapless::Vec<u8, CAPACITY>>, Error> {
    id.map(|bytes| heapless::Vec::from_slice(bytes).map_err(|_| Error::Capacity))
        .transpose()
}

impl<const ID_CONTEXT_BYTES: usize> BoundedContext<ID_CONTEXT_BYTES> {
    /// Derives a new, transient AES-CCM/HKDF-SHA-256 context (OSC-1–2).
    #[cfg_attr(
        feature = "software-crypto",
        doc = r#"
```
use mai_coap::{
    crypto::SoftwareCrypto,
    oscore::{BoundedContext, MAX_ID_CONTEXT_BYTES},
    security::PeerId,
};
use rand::{SeedableRng, rngs::StdRng};

let mut provider = SoftwareCrypto::new(StdRng::from_seed([1; 32]));
let context = BoundedContext::<MAX_ID_CONTEXT_BYTES>::derive(
    &mut provider, &[1; 16], None, &[1], &[2], None, PeerId(1),
).unwrap();
```

Capacities above [`MAX_ID_CONTEXT_BYTES`] fail at compile time, including when
deriving without an endpoint table:

```compile_fail,E0080
use mai_coap::{
    crypto::SoftwareCrypto,
    oscore::{BoundedContext, MAX_ID_CONTEXT_BYTES},
    security::PeerId,
};
use rand::{SeedableRng, rngs::StdRng};

let mut provider = SoftwareCrypto::new(StdRng::from_seed([1; 32]));
let _ = BoundedContext::<{ MAX_ID_CONTEXT_BYTES + 1 }>::derive(
    &mut provider, &[1; 16], None, &[1], &[2], None, PeerId(1),
);
```
"#
    )]
    pub fn derive(
        provider: &mut impl CryptoProvider,
        master_secret: &[u8],
        salt: Option<&[u8]>,
        sender: &[u8],
        recipient: &[u8],
        id_context: Option<&[u8]>,
        peer: PeerId,
    ) -> Result<Self, Error> {
        const { assert_context_capacity::<ID_CONTEXT_BYTES>() };
        if sender == recipient || sender.len() > 7 || recipient.len() > 7 {
            return Err(Error::Malformed);
        }
        let sender = heapless::Vec::from_slice(sender).map_err(|_| Error::Capacity)?;
        let recipient = heapless::Vec::from_slice(recipient).map_err(|_| Error::Capacity)?;
        let id_context = store_context_id(id_context)?;
        let prk = zeroize::Zeroizing::new(provider.hkdf_extract(salt, master_secret)?);
        let mut context = Self {
            sender,
            recipient,
            id_context,
            sender_key: [0; 16],
            recipient_key: [0; 16],
            common_iv: [0; 13],
            next_sequence: 0,
            replay: ReplayWindow::default(),
            peer,
        };
        let mut info = [0; 288];
        let idc = context.id_context.as_deref();
        let n = derive_info(&mut info, &context.sender, idc, b"Key", 16)?;
        provider.hkdf_expand(&prk, &info[..n], &mut context.sender_key)?;
        let n = derive_info(&mut info, &context.recipient, idc, b"Key", 16)?;
        provider.hkdf_expand(&prk, &info[..n], &mut context.recipient_key)?;
        let n = derive_info(&mut info, &[], idc, b"IV", 13)?;
        provider.hkdf_expand(&prk, &info[..n], &mut context.common_iv)?;
        Ok(context)
    }
    /// Application-selected credential identity.
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Sender ID used to locate this context at its peer.
    pub fn sender_id(&self) -> &[u8] {
        &self.sender
    }
    /// Recipient ID used to locate incoming requests.
    pub fn recipient_id(&self) -> &[u8] {
        &self.recipient
    }
    /// Optional context identifier, independent of EDHOC context re-derivation.
    pub fn id_context(&self) -> Option<&[u8]> {
        self.id_context.as_deref()
    }
    /// Next sender sequence; increments are never rolled back after failure.
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
    fn reserve(&mut self) -> Result<heapless::Vec<u8, 5, u8>, Error> {
        if self.next_sequence > MAX_SEQUENCE {
            return Err(Error::SequenceExhausted);
        }
        let current = self.next_sequence;
        self.next_sequence += 1;
        let bytes = current.to_be_bytes();
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        heapless::Vec::from_slice(&bytes[first..]).map_err(|_| Error::SequenceExhausted)
    }
    /// Protects a request and returns its opaque response binding.
    pub fn protect_request<const DATAGRAM_BYTES: usize>(
        &mut self,
        provider: &mut impl CryptoProvider,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<(usize, RequestBinding), Error> {
        if !request.code().is_request()
            || request.option(OptionNumber::OSCORE).is_some()
            || request.option(OptionNumber::PROXY_URI).is_some()
        {
            return Err(Error::Malformed);
        }
        let piv = self.reserve()?;
        let binding = RequestBinding::new(&self.sender, &piv)?;
        let option = OscoreOption {
            partial_iv: Some(&piv),
            kid: Some(&self.sender),
            kid_context: self.id_context.as_deref(),
        };
        let nonce = nonce(&self.common_iv, &self.sender, &piv)?;
        let n = protect::<DATAGRAM_BYTES>(
            provider,
            request,
            output,
            &self.sender_key,
            &nonce,
            option,
            &binding,
            false,
        )?;
        Ok((n, binding))
    }
    /// Verifies, restores and replay-checks an incoming request (OSC-8–9).
    pub fn unprotect_request<const DATAGRAM_BYTES: usize>(
        &mut self,
        provider: &mut impl CryptoProvider,
        outer: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<(usize, RequestBinding), Error> {
        let option = incoming_option(outer)?;
        if option.kid != Some(&self.recipient[..])
            || option.kid_context != self.id_context.as_deref()
        {
            return Err(Error::ContextNotFound);
        }
        let sequence = option.sequence()?;
        // RFC 8613 section 8.2 step 3: refuse a known replay before decrypting; the
        // window records the number only after verification (section 7.4).
        self.replay.check(sequence)?;
        let binding =
            RequestBinding::new(&self.recipient, option.partial_iv.ok_or(Error::Malformed)?)?;
        let nonce = nonce(&self.common_iv, &self.recipient, &binding.partial_iv)?;
        let n = unprotect::<DATAGRAM_BYTES>(
            provider,
            outer,
            output,
            &self.recipient_key,
            &nonce,
            &binding,
            false,
        )?;
        let restored = MessageView::parse(&output[..n])?;
        if !restored.code().is_request() {
            return Err(Error::Malformed);
        }
        self.replay.accept(sequence)?;
        Ok((n, binding))
    }
    /// Protects a response with a fresh Partial IV or its guarded first request nonce.
    pub fn protect_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        provider: &mut impl CryptoProvider,
        response: MessageView<'_>,
        binding: &mut RequestBinding,
        mode: ResponseNonce,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        if !response.code().is_response() {
            return Err(Error::Malformed);
        }
        let (piv, iv) = match mode {
            ResponseNonce::Fresh => {
                let piv = self.reserve()?;
                let iv = nonce(&self.common_iv, &self.sender, &piv)?;
                (Some(piv), iv)
            }
            ResponseNonce::FirstRequestNonce => {
                if binding.response_used {
                    return Err(Error::Protection);
                }
                (
                    None,
                    nonce(&self.common_iv, &binding.kid, &binding.partial_iv)?,
                )
            }
        };
        // OSC-14: a failed serialization/encryption attempt still consumes permission.
        binding.response_used = true;
        let option = OscoreOption {
            partial_iv: piv.as_deref(),
            kid: None,
            kid_context: None,
        };
        protect::<DATAGRAM_BYTES>(
            provider,
            response,
            output,
            &self.sender_key,
            &iv,
            option,
            binding,
            true,
        )
    }
    /// Verifies a response against its request, including notification ordering.
    pub fn unprotect_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        provider: &mut impl CryptoProvider,
        outer: MessageView<'_>,
        binding: &mut RequestBinding,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let option = incoming_option(outer)?;
        if option.kid.is_some_and(|k| k != &self.recipient[..])
            || option
                .kid_context
                .is_some_and(|c| Some(c) != self.id_context.as_deref())
        {
            return Err(Error::ContextNotFound);
        }
        let iv = if let Some(piv) = option.partial_iv {
            nonce(&self.common_iv, &self.recipient, piv)?
        } else {
            nonce(&self.common_iv, &binding.kid, &binding.partial_iv)?
        };
        let n = unprotect::<DATAGRAM_BYTES>(
            provider,
            outer,
            output,
            &self.recipient_key,
            &iv,
            binding,
            true,
        )?;
        let inner = MessageView::parse(&output[..n])?;
        if !inner.code().is_response() {
            return Err(Error::Malformed);
        }
        let observation = inner.option(OptionNumber::OBSERVE).is_some();
        if observation {
            if option.partial_iv.is_some() {
                let sequence = option.sequence()?;
                if binding
                    .notification_number
                    .is_some_and(|last| sequence <= last)
                {
                    return Err(Error::Replay);
                }
                binding.notification_number = Some(sequence);
            } else if binding.response_used {
                return Err(Error::Replay);
            }
        } else if binding.response_used {
            let sequence = option.sequence()?;
            if binding
                .notification_number
                .is_none_or(|last| sequence <= last)
            {
                return Err(Error::Replay);
            }
            binding.notification_number = Some(sequence);
        }
        binding.response_used = true;
        Ok(n)
    }
}

/// OSCORE nonce construction for an ID of at most seven bytes (OSC-5).
pub(crate) fn nonce(common_iv: &[u8; 13], id: &[u8], piv: &[u8]) -> Result<[u8; 13], Error> {
    if id.len() > 7 || piv.is_empty() || piv.len() > 5 {
        return Err(Error::Malformed);
    }
    let mut nonce = *common_iv;
    nonce[0] ^= id.len() as u8;
    for (out, &b) in nonce[8 - id.len()..8].iter_mut().zip(id) {
        *out ^= b;
    }
    for (out, &b) in nonce[13 - piv.len()..].iter_mut().zip(piv) {
        *out ^= b;
    }
    Ok(nonce)
}
fn incoming_option(outer: MessageView<'_>) -> Result<OscoreOption<'_>, Error> {
    if outer
        .options()
        .filter(|o| o.number == OptionNumber::OSCORE)
        .count()
        != 1
    {
        return Err(Error::Malformed);
    }
    for option in outer.options() {
        if option.number == OptionNumber::BLOCK1 || option.number == OptionNumber::BLOCK2 {
            return Err(Error::BadOption(option.number));
        }
    }
    OscoreOption::parse(
        outer
            .option(OptionNumber::OSCORE)
            .ok_or(Error::Malformed)?
            .value,
    )
}
fn derive_info(
    output: &mut [u8],
    id: &[u8],
    context: Option<&[u8]>,
    kind: &[u8],
    length: usize,
) -> Result<usize, Error> {
    let mut w = Cbor::new(output);
    w.raw(&[0x85])?;
    w.bytes(id)?;
    if let Some(context) = context {
        w.bytes(context)?;
    } else {
        w.raw(&[0xf6])?;
    }
    w.uint(10)?;
    w.text(kind)?;
    w.uint(length as u64)?;
    Ok(w.used)
}
fn aad(output: &mut [u8], binding: &RequestBinding) -> Result<usize, Error> {
    let mut external = [0; 32];
    let mut e = Cbor::new(&mut external);
    e.raw(&[0x85, 1, 0x81, 10])?;
    e.bytes(&binding.kid)?;
    e.bytes(&binding.partial_iv)?;
    e.bytes(&[])?;
    let n = e.used;
    let mut w = Cbor::new(output);
    w.raw(&[0x83])?;
    w.text(b"Encrypt0")?;
    w.bytes(&[])?;
    w.bytes(&external[..n])?;
    Ok(w.used)
}
#[allow(
    clippy::too_many_arguments,
    reason = "explicit inputs mirror the fixed COSE protection operation"
)]
fn protect<const DATAGRAM_BYTES: usize>(
    provider: &mut impl CryptoProvider,
    plain: MessageView<'_>,
    output: &mut [u8],
    key: &[u8; 16],
    nonce: &[u8; 13],
    oscore: OscoreOption<'_>,
    binding: &RequestBinding,
    response: bool,
) -> Result<usize, Error> {
    let mut scratch = zeroize::Zeroizing::new([0u8; DATAGRAM_BYTES]);
    let mut inner = MessageBuilder::new(
        &mut scratch[..],
        MessageType::NonConfirmable,
        plain.code(),
        0,
        &[],
    )?;
    let observing = plain.option(OptionNumber::OBSERVE).is_some();
    for option in plain.options() {
        match option_class(option.number) {
            OptionClass::Encrypted => {
                inner.option(option.number, option.value)?;
            }
            OptionClass::Observe => {
                inner.option(option.number, if response { &[] } else { option.value })?;
            }
            _ => {}
        }
    }
    let n = inner.finish(plain.payload())?;
    // OSC-5: the inner encoding contains Code, options and payload, not a CoAP header.
    scratch[3] = plain.code().0;
    let mut aad_bytes = [0; 48];
    let aad_len = aad(&mut aad_bytes, binding)?;
    let tag = provider.encrypt(key, nonce, &aad_bytes[..aad_len], &mut scratch[3..n])?;
    scratch
        .get_mut(n..n + 8)
        .ok_or(Error::Capacity)?
        .copy_from_slice(&tag);
    let code = match (response, observing) {
        (false, false) => Code::POST,
        (false, true) => Code::FETCH,
        (true, false) => Code::CHANGED,
        (true, true) => Code::CONTENT,
    };
    let mut outer = MessageBuilder::new(
        output,
        plain.message_type(),
        code,
        plain.message_id(),
        plain.token(),
    )?;
    let mut option_buffer = [0; 270];
    let len = oscore.encode(&mut option_buffer)?;
    let mut inserted = false;
    for option in plain.options() {
        if option.number == OptionNumber::OSCORE {
            return Err(Error::Malformed);
        }
        if option.number > OptionNumber::OSCORE && !inserted {
            outer.option(OptionNumber::OSCORE, &option_buffer[..len])?;
            inserted = true;
        }
        match option_class(option.number) {
            OptionClass::Unprotected => {
                outer.option(option.number, option.value)?;
            }
            OptionClass::Observe => {
                outer.option(option.number, option.value)?;
            }
            _ => {}
        }
    }
    if !inserted {
        outer.option(OptionNumber::OSCORE, &option_buffer[..len])?;
    }
    outer.finish(&scratch[3..n + 8])
}
fn unprotect<const DATAGRAM_BYTES: usize>(
    provider: &mut impl CryptoProvider,
    outer: MessageView<'_>,
    output: &mut [u8],
    key: &[u8; 16],
    nonce: &[u8; 13],
    binding: &RequestBinding,
    response: bool,
) -> Result<usize, Error> {
    let ciphertext = outer.payload();
    if ciphertext.len() < 9 {
        return Err(Error::Malformed);
    }
    let length = ciphertext.len() - 8;
    let mut inner_bytes = zeroize::Zeroizing::new([0u8; DATAGRAM_BYTES]);
    inner_bytes
        .get_mut(3..3 + length)
        .ok_or(Error::Capacity)?
        .copy_from_slice(&ciphertext[..length]);
    let tag: &[u8; 8] = ciphertext[length..]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let mut aad_bytes = [0; 48];
    let aad_len = aad(&mut aad_bytes, binding)?;
    provider.decrypt(
        key,
        nonce,
        &aad_bytes[..aad_len],
        &mut inner_bytes[3..3 + length],
        tag,
    )?;
    let code = Code(inner_bytes[3]);
    inner_bytes[0] = 0x50;
    inner_bytes[1] = code.0;
    inner_bytes[2] = 0;
    inner_bytes[3] = 0;
    let inner = MessageView::parse(&inner_bytes[..3 + length])?;
    let mut b = MessageBuilder::new(
        output,
        outer.message_type(),
        code,
        outer.message_id(),
        outer.token(),
    )?;
    let mut outside = outer
        .options()
        .filter(|o| {
            option_class(o.number) == OptionClass::Unprotected && o.number != OptionNumber::EDHOC
        })
        .peekable();
    for option in inner.options() {
        if option_class(option.number) == OptionClass::Unprotected
            || option.number == OptionNumber::OSCORE
        {
            return Err(Error::Malformed);
        }
        while outside.peek().is_some_and(|o| o.number < option.number) {
            let o = outside.next().ok_or(Error::Malformed)?;
            b.option(o.number, o.value)?;
        }
        if option.number == OptionNumber::OBSERVE && response {
            if !option.value.is_empty() {
                return Err(Error::Malformed);
            }
            let sequence = incoming_option(outer)?
                .partial_iv
                .map_or(0, |p| p.iter().fold(0u64, |n, &v| (n << 8) | u64::from(v)));
            b.uint_option(option.number, sequence & 0xffffff)?;
        } else {
            b.option(option.number, option.value)?;
        }
    }
    for o in outside {
        b.option(o.number, o.value)?;
    }
    b.finish(inner.payload())
}

pub(crate) struct Cbor<'a> {
    bytes: &'a mut [u8],
    pub(crate) used: usize,
}
impl<'a> Cbor<'a> {
    pub(crate) fn new(bytes: &'a mut [u8]) -> Self {
        Self { bytes, used: 0 }
    }
    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.used.checked_add(bytes.len()).ok_or(Error::Capacity)?;
        self.bytes
            .get_mut(self.used..end)
            .ok_or(Error::Capacity)?
            .copy_from_slice(bytes);
        self.used = end;
        Ok(())
    }
    fn head(&mut self, major: u8, n: u64) -> Result<(), Error> {
        if n < 24 {
            self.raw(&[(major << 5) | n as u8])
        } else if n <= 255 {
            self.raw(&[(major << 5) | 24, n as u8])
        } else if n <= 65535 {
            self.raw(&[(major << 5) | 25])?;
            self.raw(&(n as u16).to_be_bytes())
        } else if n <= u32::MAX.into() {
            self.raw(&[(major << 5) | 26])?;
            self.raw(&(n as u32).to_be_bytes())
        } else {
            self.raw(&[(major << 5) | 27])?;
            self.raw(&n.to_be_bytes())
        }
    }
    pub(crate) fn uint(&mut self, n: u64) -> Result<(), Error> {
        self.head(0, n)
    }
    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.head(2, bytes.len() as u64)?;
        self.raw(bytes)
    }
    fn text(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.head(3, bytes.len() as u64)?;
        self.raw(bytes)
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::SoftwareCrypto;
    use std::vec::Vec;

    #[test]
    fn osc_5_7_11_full_identifiers_and_last_sequence_round_trip() {
        fn exercise<const N: usize>(id_context: Option<&[u8]>) {
            let client_id = [1, 2, 3, 4, 5, 6, 7];
            let server_id = [8, 9, 10, 11, 12, 13, 14];
            for mode in [ResponseNonce::Fresh, ResponseNonce::FirstRequestNonce] {
                let mut crypto = SoftwareCrypto::new(rand::rng());
                let mut client = BoundedContext::<N>::derive(
                    &mut crypto,
                    &[1; 16],
                    None,
                    &client_id,
                    &server_id,
                    id_context,
                    PeerId(1),
                )
                .unwrap();
                let mut server = BoundedContext::<N>::derive(
                    &mut crypto,
                    &[1; 16],
                    None,
                    &server_id,
                    &client_id,
                    id_context,
                    PeerId(1),
                )
                .unwrap();
                client.next_sequence = MAX_SEQUENCE;
                server.next_sequence = MAX_SEQUENCE;
                let mut plain = [0; 64];
                let n =
                    MessageBuilder::new(&mut plain, MessageType::Confirmable, Code::GET, 7, b"t")
                        .unwrap()
                        .finish(b"request")
                        .unwrap();
                let request = MessageView::parse(&plain[..n]).unwrap();
                let mut wire = [0; 512];
                let (n, mut client_binding) = client
                    .protect_request::<512>(&mut crypto, request, &mut wire)
                    .unwrap();
                let outer = MessageView::parse(&wire[..n]).unwrap();
                let option = incoming_option(outer).unwrap();
                assert_eq!(option.kid, Some(client_id.as_slice()));
                assert_eq!(option.partial_iv, Some([0xff; 5].as_slice()));
                assert_eq!(option.kid_context, id_context);
                let mut restored = [0; 512];
                let (n, mut server_binding) = server
                    .unprotect_request::<512>(&mut crypto, outer, &mut restored)
                    .unwrap();
                assert_eq!(&restored[..n], request.as_bytes());
                assert_eq!(client.next_sequence(), MAX_SEQUENCE + 1);
                assert!(matches!(
                    client.protect_request::<512>(&mut crypto, request, &mut wire),
                    Err(Error::SequenceExhausted)
                ));
                let n = MessageBuilder::new(
                    &mut plain,
                    MessageType::Acknowledgement,
                    Code::CONTENT,
                    7,
                    b"t",
                )
                .unwrap()
                .finish(b"response")
                .unwrap();
                let response = MessageView::parse(&plain[..n]).unwrap();
                let n = server
                    .protect_response::<512>(
                        &mut crypto,
                        response,
                        &mut server_binding,
                        mode,
                        &mut wire,
                    )
                    .unwrap();
                let outer = MessageView::parse(&wire[..n]).unwrap();
                assert_eq!(
                    incoming_option(outer).unwrap().partial_iv,
                    (mode == ResponseNonce::Fresh).then_some([0xff; 5].as_slice())
                );
                let n = client
                    .unprotect_response::<512>(
                        &mut crypto,
                        outer,
                        &mut client_binding,
                        &mut restored,
                    )
                    .unwrap();
                assert_eq!(&restored[..n], response.as_bytes());
            }
        }
        exercise::<0>(None);
        exercise::<0>(Some(&[]));
        exercise::<MAX_ID_CONTEXT_BYTES>(Some(&[0x5a; MAX_ID_CONTEXT_BYTES]));
    }

    #[test]
    fn osc_2_15_context_id_capacity_preserves_bytes_and_presence() {
        assert_eq!(store_context_id::<0>(None).unwrap(), None);
        assert_eq!(
            store_context_id::<0>(Some(&[])).unwrap().as_deref(),
            Some(&[][..])
        );
        assert_eq!(store_context_id::<0>(Some(&[1])), Err(Error::Capacity));
        assert_eq!(
            store_context_id::<1>(Some(&[1])).unwrap().as_deref(),
            Some(&[1][..])
        );
        assert_eq!(store_context_id::<1>(Some(&[1, 2])), Err(Error::Capacity));
        let bytes = [0x5a; 255];
        assert_eq!(
            store_context_id::<255>(Some(&bytes)).unwrap().as_deref(),
            Some(&bytes[..])
        );
        assert_eq!(
            store_context_id::<255>(Some(&[0; 256])),
            Err(Error::Capacity)
        );
    }

    #[test]
    fn osc_2_15_compact_context_matches_default_and_distinguishes_empty_id() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let full =
            Context::derive(&mut crypto, &[1; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let compact =
            BoundedContext::<0>::derive(&mut crypto, &[1; 16], None, &[1], &[0], None, PeerId(1))
                .unwrap();
        let mut empty = BoundedContext::<0>::derive(
            &mut crypto,
            &[1; 16],
            None,
            &[1],
            &[0],
            Some(&[]),
            PeerId(1),
        )
        .unwrap();
        assert_eq!(full.sender_key, compact.sender_key);
        assert_eq!(full.recipient_key, compact.recipient_key);
        assert_eq!(full.common_iv, compact.common_iv);
        assert_eq!(compact.id_context(), None);
        assert_eq!(empty.id_context(), Some(&[][..]));
        assert_ne!(compact.sender_key, empty.sender_key);
        assert_ne!(compact.common_iv, empty.common_iv);
        let mut request = [0; 64];
        let plain = MessageBuilder::new(&mut request, MessageType::Confirmable, Code::GET, 7, b"t")
            .unwrap()
            .finish(&[])
            .unwrap();
        let plain = &request[..plain];
        let mut protected = [0; 128];
        let (len, _) = empty
            .protect_request::<128>(
                &mut crypto,
                MessageView::parse(plain).unwrap(),
                &mut protected,
            )
            .unwrap();
        let outer = MessageView::parse(&protected[..len]).unwrap();
        assert_eq!(incoming_option(outer).unwrap().kid_context, Some(&[][..]));
        let mut server = BoundedContext::<0>::derive(
            &mut crypto,
            &[1; 16],
            None,
            &[0],
            &[1],
            Some(&[]),
            PeerId(1),
        )
        .unwrap();
        let mut restored = [0; 128];
        let (len, _) = server
            .unprotect_request::<128>(&mut crypto, outer, &mut restored)
            .unwrap();
        assert_eq!(&restored[..len], plain);
        assert_eq!(
            BoundedContext::<0>::derive(
                &mut crypto,
                &[1; 16],
                None,
                &[1],
                &[0],
                Some(&[1]),
                PeerId(1)
            )
            .unwrap_err(),
            Error::Capacity
        );
    }
    fn hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| {
                let digit = |b: u8| match b {
                    b'0'..=b'9' => b - b'0',
                    b'a'..=b'f' => b - b'a' + 10,
                    _ => panic!("test hex"),
                };
                (digit(p[0]) << 4) | digit(p[1])
            })
            .collect()
    }
    #[test]
    fn osc_2_19_appendix_c1_c2_c3_both_roles() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        for (sender, salt, id_context, sk, rk, iv) in [
            (
                "",
                "9e7ca92223786340",
                None,
                "f0910ed7295e6ad4b54fc793154302ff",
                "ffb14e093c94c9cac9471648b4f98710",
                "4622d4dd6d944168eefb54987c",
            ),
            (
                "00",
                "",
                None,
                "321b26943253c7ffb6003b0b64d74041",
                "e57b5635815177cd679ab4bcec9d7dda",
                "be35ae297d2dace910c52e99f9",
            ),
            (
                "",
                "9e7ca92223786340",
                Some("37cbf3210017a2d3"),
                "af2a1300a5e95788b356336eeecd2b92",
                "e39a0c7c77b43f03b4b39ab9a268699f",
                "2ca58fb85ff1b81c0b7181b85e",
            ),
        ] {
            let context_bytes = id_context.map(hex);
            let client = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex(salt)),
                &hex(sender),
                &[1],
                context_bytes.as_deref(),
                PeerId(1),
            )
            .unwrap();
            let server = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex(salt)),
                &[1],
                &hex(sender),
                context_bytes.as_deref(),
                PeerId(2),
            )
            .unwrap();
            assert_eq!(&client.sender_key[..], hex(sk));
            assert_eq!(&client.recipient_key[..], hex(rk));
            assert_eq!(&client.common_iv[..], hex(iv));
            assert_eq!(client.sender_key, server.recipient_key);
            assert_eq!(client.recipient_key, server.sender_key);
            assert_eq!(client.common_iv, server.common_iv);
        }
    }
    #[test]
    fn osc_5_19_appendix_c4_c5_c6_round_trip_byte_exact() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        for (sender, salt, id_context, raw, wire) in [
            (
                "",
                "9e7ca92223786340",
                None,
                "44015d1f00003974396c6f63616c686f737483747631",
                "44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e",
            ),
            (
                "00",
                "",
                None,
                "440171c30000b932396c6f63616c686f737483747631",
                "440271c30000b932396c6f63616c686f737463091400ff4ed339a5a379b0b8bc731fffb0",
            ),
            (
                "",
                "9e7ca92223786340",
                Some("37cbf3210017a2d3"),
                "44012f8eef9bbf7a396c6f63616c686f737483747631",
                "44022f8eef9bbf7a396c6f63616c686f73746b19140837cbf3210017a2d3ff72cd7273fd331ac45cffbe55c3",
            ),
        ] {
            let context_bytes = id_context.map(hex);
            let mut client = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex(salt)),
                &hex(sender),
                &[1],
                context_bytes.as_deref(),
                PeerId(1),
            )
            .unwrap();
            let mut server = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex(salt)),
                &[1],
                &hex(sender),
                context_bytes.as_deref(),
                PeerId(2),
            )
            .unwrap();
            client.next_sequence = 20;
            let raw = hex(raw);
            let mut output = [0; 256];
            let (n, _) = client
                .protect_request::<256>(&mut crypto, MessageView::parse(&raw).unwrap(), &mut output)
                .unwrap();
            assert_eq!(&output[..n], hex(wire));
            let mut restored = [0; 256];
            let (used, _) = server
                .unprotect_request::<256>(
                    &mut crypto,
                    MessageView::parse(&output[..n]).unwrap(),
                    &mut restored,
                )
                .unwrap();
            assert_eq!(&restored[..used], raw);
            assert!(matches!(
                server.unprotect_request::<256>(
                    &mut crypto,
                    MessageView::parse(&output[..n]).unwrap(),
                    &mut restored
                ),
                Err(Error::Replay)
            ));
        }
    }
    #[test]
    fn osc_10_14_19_appendix_c7_c8_response_binding_and_nonce_guard() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        for (mode, expected) in [
            (
                ResponseNonce::FirstRequestNonce,
                "64445d1f0000397490ffdbaad1e9a7e7b2a813d3c31524378303cdafae119106",
            ),
            (
                ResponseNonce::Fresh,
                "64445d1f00003974920100ff4d4c13669384b67354b2b6175ff4b8658c666a6cf88e",
            ),
        ] {
            let mut server = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex("9e7ca92223786340")),
                &[1],
                &[],
                None,
                PeerId(1),
            )
            .unwrap();
            let mut client = Context::derive(
                &mut crypto,
                &hex("0102030405060708090a0b0c0d0e0f10"),
                Some(&hex("9e7ca92223786340")),
                &[],
                &[1],
                None,
                PeerId(2),
            )
            .unwrap();
            let mut binding = RequestBinding::new(&[], &[20]).unwrap();
            let raw = hex("64455d1f00003974ff48656c6c6f20576f726c6421");
            let mut out = [0; 256];
            let n = server
                .protect_response::<256>(
                    &mut crypto,
                    MessageView::parse(&raw).unwrap(),
                    &mut binding,
                    mode,
                    &mut out,
                )
                .unwrap();
            assert_eq!(&out[..n], hex(expected));
            let mut received = RequestBinding::new(&[], &[20]).unwrap();
            let mut plain = [0; 256];
            let used = client
                .unprotect_response::<256>(
                    &mut crypto,
                    MessageView::parse(&out[..n]).unwrap(),
                    &mut received,
                    &mut plain,
                )
                .unwrap();
            assert_eq!(&plain[..used], raw);
            assert!(matches!(
                server.protect_response::<256>(
                    &mut crypto,
                    MessageView::parse(&raw).unwrap(),
                    &mut binding,
                    ResponseNonce::FirstRequestNonce,
                    &mut plain
                ),
                Err(Error::Protection)
            ));
        }
    }
    #[test]
    fn osc_10_14_failed_first_response_consumes_permission_and_fresh_failures_consume_sequences() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let mut server =
            Context::derive(&mut crypto, &[7; 16], None, &[1], &[0], None, PeerId(1)).unwrap();
        let mut binding = RequestBinding::new(&[0], &[0]).unwrap();
        let raw = [0x60, 0x45, 0, 1];
        let response = MessageView::parse(&raw).unwrap();
        let mut output = [0; 128];
        assert_eq!(
            server.protect_response::<128>(
                &mut crypto,
                response,
                &mut binding,
                ResponseNonce::FirstRequestNonce,
                &mut []
            ),
            Err(Error::Capacity)
        );
        assert_eq!(
            server.protect_response::<128>(
                &mut crypto,
                response,
                &mut binding,
                ResponseNonce::FirstRequestNonce,
                &mut output
            ),
            Err(Error::Protection)
        );
        assert_eq!(
            server.protect_response::<128>(
                &mut crypto,
                response,
                &mut binding,
                ResponseNonce::Fresh,
                &mut []
            ),
            Err(Error::Capacity)
        );
        let n = server
            .protect_response::<128>(
                &mut crypto,
                response,
                &mut binding,
                ResponseNonce::Fresh,
                &mut output,
            )
            .unwrap();
        let message = MessageView::parse(&output[..n]).unwrap();
        assert_eq!(
            OscoreOption::parse(message.option(OptionNumber::OSCORE).unwrap().value)
                .unwrap()
                .partial_iv,
            Some(&[1][..])
        );
    }
    #[test]
    fn osc_6_all_zero_flags_require_empty_value() {
        assert_eq!(OscoreOption::parse(&[0]), Err(Error::Malformed));
        assert_eq!(OscoreOption::parse(&[0, 0]), Err(Error::Malformed));
        let empty = OscoreOption::parse(&[]).unwrap();
        assert_eq!(empty.encode(&mut [0; 1]), Ok(0));
    }
    #[test]
    fn osc_8_bad_authentication_does_not_advance_replay_window() {
        let mut window = ReplayWindow::default();
        window.accept(32).unwrap();
        window.accept(1).unwrap();
        assert_eq!(window.check(0), Err(Error::Replay));
        assert_eq!(window.check(1), Err(Error::Replay));
        assert_eq!(window.check(2), Ok(()));
        window.accept(64).unwrap();
        assert_eq!(window.check(32), Err(Error::Replay));
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let mut server = Context::derive(
            &mut crypto,
            &hex("0102030405060708090a0b0c0d0e0f10"),
            Some(&hex("9e7ca92223786340")),
            &[1],
            &[],
            None,
            PeerId(1),
        )
        .unwrap();
        let mut wire =
            hex("44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e");
        let last = wire.len() - 1;
        wire[last] ^= 1;
        let mut plain = [0; 256];
        assert!(matches!(
            server.unprotect_request::<256>(
                &mut crypto,
                MessageView::parse(&wire).unwrap(),
                &mut plain
            ),
            Err(Error::Protection)
        ));
        wire[last] ^= 1;
        server
            .unprotect_request::<256>(&mut crypto, MessageView::parse(&wire).unwrap(), &mut plain)
            .unwrap();
    }
    /// Counts AEAD decryptions and forwards everything to the software provider.
    struct Counting {
        inner: SoftwareCrypto<rand::rngs::ThreadRng>,
        decrypts: usize,
    }
    impl CryptoProvider for Counting {
        type Sha256<'a> = <SoftwareCrypto<rand::rngs::ThreadRng> as CryptoProvider>::Sha256<'a>;
        fn sha256_start(&mut self) -> Result<Self::Sha256<'_>, Error> {
            self.inner.sha256_start()
        }
        fn hkdf_extract(&mut self, salt: Option<&[u8]>, input: &[u8]) -> Result<[u8; 32], Error> {
            self.inner.hkdf_extract(salt, input)
        }
        fn hkdf_expand(
            &mut self,
            prk: &[u8; 32],
            info: &[u8],
            output: &mut [u8],
        ) -> Result<(), Error> {
            self.inner.hkdf_expand(prk, info, output)
        }
        fn encrypt(
            &mut self,
            key: &[u8; 16],
            nonce: &[u8; 13],
            aad: &[u8],
            plaintext: &mut [u8],
        ) -> Result<[u8; 8], Error> {
            self.inner.encrypt(key, nonce, aad, plaintext)
        }
        fn decrypt(
            &mut self,
            key: &[u8; 16],
            nonce: &[u8; 13],
            aad: &[u8],
            ciphertext: &mut [u8],
            tag: &[u8; 8],
        ) -> Result<(), Error> {
            self.decrypts += 1;
            self.inner.decrypt(key, nonce, aad, ciphertext, tag)
        }
        fn p256_key_pair(&mut self) -> Result<([u8; 32], [u8; 32]), Error> {
            self.inner.p256_key_pair()
        }
        fn p256_public_key(&mut self, private: &[u8; 32]) -> Result<[u8; 65], Error> {
            self.inner.p256_public_key(private)
        }
        fn p256_decompress(&mut self, x: &[u8; 32]) -> Result<[u8; 65], Error> {
            self.inner.p256_decompress(x)
        }
        fn p256_validate(&mut self, point: &[u8]) -> Result<(), Error> {
            self.inner.p256_validate(point)
        }
        fn p256_ecdh(
            &mut self,
            private: &[u8; 32],
            public_x: &[u8; 32],
        ) -> Result<[u8; 32], Error> {
            self.inner.p256_ecdh(private, public_x)
        }
        fn random(&mut self, output: &mut [u8]) {
            self.inner.random(output)
        }
    }
    #[test]
    fn osc_9_known_replays_are_refused_before_decryption() {
        let mut crypto = Counting {
            inner: SoftwareCrypto::new(rand::rng()),
            decrypts: 0,
        };
        let mut server = Context::derive(
            &mut crypto,
            &hex("0102030405060708090a0b0c0d0e0f10"),
            Some(&hex("9e7ca92223786340")),
            &[1],
            &[],
            None,
            PeerId(1),
        )
        .unwrap();
        let mut wire =
            hex("44025d1f00003974396c6f63616c686f7374620914ff612f1092f1776f1c1668b3825e");
        let mut plain = [0; 256];
        server
            .unprotect_request::<256>(&mut crypto, MessageView::parse(&wire).unwrap(), &mut plain)
            .unwrap();
        assert_eq!(crypto.decrypts, 1);
        let last = wire.len() - 1;
        for flip in [0, 1] {
            wire[last] ^= flip;
            assert!(matches!(
                server.unprotect_request::<256>(
                    &mut crypto,
                    MessageView::parse(&wire).unwrap(),
                    &mut plain
                ),
                Err(Error::Replay)
            ));
        }
        assert_eq!(crypto.decrypts, 1);
    }
    #[test]
    fn osc_7_sequence_exhaustion_and_failed_send_consume_sequence() {
        let mut crypto = SoftwareCrypto::new(rand::rng());
        let mut context =
            Context::derive(&mut crypto, &[1; 16], None, &[1], &[2], None, PeerId(1)).unwrap();
        let raw = [0x40, 1, 0, 0];
        let mut output = [0; 2];
        assert!(
            context
                .protect_request::<64>(&mut crypto, MessageView::parse(&raw).unwrap(), &mut output)
                .is_err()
        );
        assert_eq!(context.next_sequence(), 1);
        context.next_sequence = MAX_SEQUENCE;
        assert!(context.reserve().is_ok());
        assert_eq!(context.reserve(), Err(Error::SequenceExhausted));
    }
}

#[cfg(kani)]
mod proofs;
