//! Application identities and authorization policy (AUT-1–6).
use crate::{
    Error,
    codec::{Code, MessageView, OptionNumber},
};

/// Application-selected peer credential identifier; unrelated to OSCORE IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct PeerId(pub u32);
/// Authenticated request state, established before resource dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SecurityState {
    /// No end-to-end authentication was performed.
    Unprotected,
    /// Authentication succeeded against a registered peer credential.
    Protected {
        /// Application-selected credential identifier.
        peer: PeerId,
    },
}
/// Application authorization hook for endpoint resources.
pub trait Policy {
    /// Decides access using the authenticated inner message.
    fn allow(&self, state: SecurityState, request: MessageView<'_>) -> bool;
}
/// Allows every request, including requests without end-to-end protection.
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AllowAll;
impl Policy for AllowAll {
    fn allow(&self, _: SecurityState, _: MessageView<'_>) -> bool {
        true
    }
}
/// Denies unprotected requests and accepts authenticated registered peers (AUT-2).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtectedOnly;
impl Policy for ProtectedOnly {
    fn allow(&self, state: SecurityState, _: MessageView<'_>) -> bool {
        matches!(state, SecurityState::Protected { .. })
    }
}
/// Public method/path exceptions, with protected access to all other resources.
#[derive(Clone, Copy, Debug)]
pub struct PublicPaths<'a>(pub &'a [(Code, &'a str)]);
impl Policy for PublicPaths<'_> {
    fn allow(&self, state: SecurityState, request: MessageView<'_>) -> bool {
        matches!(state, SecurityState::Protected { .. })
            || self
                .0
                .iter()
                .any(|(method, path)| *method == request.code() && path_matches(request, path))
    }
}
/// Compares Uri-Path segments against an unescaped application path.
pub(crate) fn path_matches(request: MessageView<'_>, path: &str) -> bool {
    let path = path.strip_prefix('/').unwrap_or(path);
    if path.is_empty() {
        return request.values(OptionNumber::URI_PATH).next().is_none();
    }
    let mut options = request.values(OptionNumber::URI_PATH);
    for segment in path.split('/') {
        if options.next() != Some(segment.as_bytes()) {
            return false;
        }
    }
    options.next().is_none()
}

/// Incremental SHA-256 state owned by a [`CryptoProvider`].
/// Implementations must erase buffered input on drop and release any borrowed
/// peripheral, including after errors or cancellation. Errors must not disclose input.
pub trait Sha256State {
    /// Appends bytes in order. After an error the caller must drop the state.
    fn update(&mut self, input: &[u8]) -> Result<(), Error>;
    /// Consumes the state and returns the digest, releasing its resources on error too.
    fn finalize(self) -> Result<[u8; 32], Error>;
}

/// Synchronous cryptographic primitives required by OSCORE and suite-2 EDHOC.
/// Implementations must reject invalid public points and use constant-time AEAD
/// verification. Errors must not expose keys or protected plaintext.
pub trait CryptoProvider {
    /// Incremental state, optionally borrowing a hardware peripheral.
    type Sha256<'a>: Sha256State
    where
        Self: 'a;
    /// Starts an empty hash. Failure must release any acquired resources.
    fn sha256_start(&mut self) -> Result<Self::Sha256<'_>, Error>;
    /// SHA-256 through the same provider used for incremental hashing.
    fn sha256(&mut self, input: &[u8]) -> Result<[u8; 32], Error> {
        let mut state = self.sha256_start()?;
        state.update(input)?;
        state.finalize()
    }
    /// HKDF-SHA-256 extract; absent salt is an all-zero hash-length salt.
    fn hkdf_extract(&mut self, salt: Option<&[u8]>, input: &[u8]) -> Result<[u8; 32], Error>;
    /// HKDF-SHA-256 expand into caller storage.
    fn hkdf_expand(&mut self, prk: &[u8; 32], info: &[u8], output: &mut [u8]) -> Result<(), Error>;
    /// AES-CCM with a 128-bit key, 13-byte nonce and detached 8-byte tag.
    fn encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        plaintext: &mut [u8],
    ) -> Result<[u8; 8], Error>;
    /// Authenticates before exposing any decrypted message to its caller.
    fn decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 13],
        aad: &[u8],
        ciphertext: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), Error>;
    /// Generates a P-256 private scalar and public x-coordinate using the provider RNG.
    fn p256_key_pair(&mut self) -> Result<([u8; 32], [u8; 32]), Error>;
    /// Derives an uncompressed SEC1 public point from a P-256 private scalar.
    fn p256_public_key(&mut self, private: &[u8; 32]) -> Result<[u8; 65], Error>;
    /// Validates/decompresses an x-only P-256 point, returning an uncompressed SEC1 point.
    fn p256_decompress(&mut self, x: &[u8; 32]) -> Result<[u8; 65], Error>;
    /// Validates a compressed or uncompressed SEC1 public point.
    fn p256_validate(&mut self, point: &[u8]) -> Result<(), Error>;
    /// Computes the ECDH shared x-coordinate; rejects invalid points and scalars.
    fn p256_ecdh(&mut self, private: &[u8; 32], public_x: &[u8; 32]) -> Result<[u8; 32], Error>;
    /// Cryptographically secure random bytes, shared with MID and token generation.
    fn random(&mut self, output: &mut [u8]);
}
