//! Lakers integration for method-3/suite-2 EDHOC (RFC 9528, RFC 9668).
//! State is stored separately from the shared provider, allowing bounded sessions
//! without self-references or duplicated hardware/RNG instances.
use crate::{
    Error, Packet,
    oscore::{BoundedContext, Context},
    security::{CryptoProvider, PeerId},
};
use core::cell::Cell;
use zeroize::{Zeroize, Zeroizing};
#[cfg(any(feature = "server", feature = "client"))]
pub mod endpoint;
mod validation;

/// COSE_Key encoding used when constructing an EDHOC CCS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CcsEncoding {
    /// Encode the public key with only its x-coordinate.
    CompactX,
    /// Encode both P-256 public coordinates as byte strings.
    FullXY,
}

// Retain validated, immutable CCS bytes; reconstruct Lakers' parsed fields only
// while checking an identifier or processing a handshake. Share the parser frame
// across registration and handshake paths.
#[inline(never)]
fn parse_credential(ccs: &[u8]) -> Result<lakers::Credential, Error> {
    validation::credential(ccs)?;
    let credential = lakers::Credential::parse_ccs(ccs).map_err(|_| Error::Edhoc)?;
    if credential.bytes.as_slice() != ccs
        || !matches!(credential.key, lakers::CredentialKey::EC2Compact(_))
    {
        return Err(Error::Edhoc);
    }
    Ok(credential)
}

/// Application-provided byte-exact CCS credential and static private key (EDH-4).
pub struct Identity {
    credential: lakers::BufferCred,
    private: Zeroizing<[u8; 32]>,
}
impl Identity {
    /// Parses the byte-exact CCS and rejects a private key that does not match it.
    pub fn new(
        ccs: &[u8],
        private: [u8; 32],
        provider: &mut impl CryptoProvider,
    ) -> Result<Self, Error> {
        let private = Zeroizing::new(private);
        let public = provider.p256_public_key(&private)?;
        Self::from_derived_public(ccs, private, &public)
    }

    fn from_derived_public(
        ccs: &[u8],
        private: Zeroizing<[u8; 32]>,
        public: &[u8; 65],
    ) -> Result<Self, Error> {
        let credential = parse_credential(ccs)?;
        let lakers::CredentialKey::EC2Compact(public_x) = &credential.key else {
            return Err(Error::Edhoc);
        };
        if public[0] != 4
            || public.get(1..33) != Some(public_x.as_slice())
            || validation::credential_y(ccs)?.is_some_and(|y| public[33..] != y)
        {
            return Err(Error::Edhoc);
        }
        Ok(Self {
            credential: credential.bytes,
            private,
        })
    }

    /// Builds a CCS from a private key and its derived public point.
    pub fn from_private_key(
        private: [u8; 32],
        kid: &[u8],
        encoding: CcsEncoding,
        provider: &mut impl CryptoProvider,
    ) -> Result<Self, Error> {
        let private = Zeroizing::new(private);
        let public = provider.p256_public_key(&private)?;
        let ccs = validation::encode_ccs(kid, &public, encoding)?;
        Self::from_derived_public(&ccs, private, &public)
    }

    /// Returns the byte-exact CCS used by this identity.
    pub fn credential_bytes(&self) -> &[u8] {
        self.credential.as_slice()
    }
}
impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity").finish_non_exhaustive()
    }
}
/// Registered trust anchor carrying the application's identity and policy data key.
#[derive(Clone)]
pub struct TrustedPeer {
    /// Application-selected credential identity.
    pub id: PeerId,
    credential: lakers::BufferCred,
}
impl TrustedPeer {
    /// Registers a byte-exact CCS credential; arbitrary presented credentials are not trusted.
    pub fn new(id: PeerId, ccs: &[u8]) -> Result<Self, Error> {
        let credential = parse_credential(ccs)?;
        Ok(Self {
            id,
            credential: credential.bytes,
        })
    }

    /// Builds a trusted CCS from an uncompressed P-256 public point.
    pub fn from_public_key(
        id: PeerId,
        kid: &[u8],
        public: &[u8; 65],
        encoding: CcsEncoding,
        provider: &mut impl CryptoProvider,
    ) -> Result<Self, Error> {
        if public[0] != 4 {
            return Err(Error::Edhoc);
        }
        provider.p256_validate(public)?;
        let ccs = validation::encode_ccs(kid, public, encoding)?;
        Self::new(id, &ccs)
    }

    /// Returns the byte-exact CCS registered for this peer.
    pub fn credential_bytes(&self) -> &[u8] {
        self.credential.as_slice()
    }
    fn resolve(&self, id: &lakers::IdCred) -> Result<lakers::Credential, Error> {
        let credential = parse_credential(self.credential_bytes())?;
        let checked = lakers::credential_check_or_fetch(Some(credential), id.clone())
            .map_err(|_| Error::Edhoc)?;
        if checked.bytes != self.credential {
            return Err(Error::Edhoc);
        }
        Ok(checked)
    }
}
impl core::fmt::Debug for TrustedPeer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustedPeer")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Borrowed EDHOC credential identifier, preserving its complete CBOR value.
#[derive(Clone, Copy)]
pub struct CredentialId<'a>(&'a lakers::IdCred);
impl CredentialId<'_> {
    /// Full ID_CRED map, suitable for application-specific indexed lookup.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_full_value()
    }
    /// Whether a registered credential matches this identifier.
    pub fn matches(&self, peer: &TrustedPeer) -> bool {
        peer.resolve(self.0).is_ok()
    }
}
/// Nonblocking credential lookup. Returned credentials are handshake snapshots.
/// A `kid` is scoped by the store's application namespace, not globally unique.
/// Ambiguous incoming identifiers must be rejected. Store updates affect future
/// authentication; established contexts retain their identity until retired.
pub trait CredentialStore {
    /// Finds the expected outgoing peer by its stable application identity.
    fn get(&self, peer: PeerId) -> Option<TrustedPeer>;
    /// Resolves an incoming ID_CRED within the store's trust namespace.
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer>;
}
impl<S: CredentialStore + ?Sized> CredentialStore for &S {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        (**self).get(peer)
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        (**self).find(id)
    }
}
impl<S: CredentialStore + ?Sized> CredentialStore for &mut S {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        (**self).get(peer)
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        (**self).find(id)
    }
}
impl CredentialStore for [TrustedPeer] {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        self.iter().find(|p| p.id == peer).cloned()
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        let mut matches = self.iter().filter(|peer| id.matches(peer));
        let peer = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(peer.clone())
    }
}
impl<const CREDENTIALS: usize> CredentialStore for [TrustedPeer; CREDENTIALS] {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        CredentialStore::get(self.as_slice(), peer)
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        self.as_slice().find(id)
    }
}
impl<const CREDENTIALS: usize> CredentialStore for heapless::Vec<TrustedPeer, CREDENTIALS> {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        CredentialStore::get(self.as_slice(), peer)
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        CredentialStore::find(self.as_slice(), id)
    }
}
/// Bounded in-memory store; applications may instead implement `CredentialStore`.
pub struct TrustedPeers<const CREDENTIALS: usize = 16>(heapless::Vec<TrustedPeer, CREDENTIALS>);
impl<const CREDENTIALS: usize> Default for TrustedPeers<CREDENTIALS> {
    fn default() -> Self {
        Self::new()
    }
}
impl<const CREDENTIALS: usize> TrustedPeers<CREDENTIALS> {
    /// Creates an empty credential store.
    pub const fn new() -> Self {
        Self(heapless::Vec::new())
    }
    /// Inserts or replaces a peer's credential for subsequent authentication.
    pub fn insert(&mut self, peer: TrustedPeer) -> Result<(), Error> {
        if let Some(previous) = self.0.iter_mut().find(|p| p.id == peer.id) {
            *previous = peer;
            Ok(())
        } else {
            self.0.push(peer).map_err(|_| Error::Capacity)
        }
    }
    /// Removes trust for subsequent authentication; established contexts are unchanged.
    pub fn remove(&mut self, peer: PeerId) {
        self.0.retain(|p| p.id != peer);
    }
}
impl<const CREDENTIALS: usize> CredentialStore for TrustedPeers<CREDENTIALS> {
    fn get(&self, peer: PeerId) -> Option<TrustedPeer> {
        CredentialStore::get(&self.0, peer)
    }
    fn find(&self, id: CredentialId<'_>) -> Option<TrustedPeer> {
        CredentialStore::find(&self.0, id)
    }
}

struct ParsedPeer {
    id: PeerId,
    credential: lakers::Credential,
}
// Release lookup and reconstruction scratch before entering verification.
#[inline(never)]
fn find_credential(
    store: &(impl CredentialStore + ?Sized),
    id: &lakers::IdCred,
) -> Result<ParsedPeer, Error> {
    let peer = store.find(CredentialId(id)).ok_or(Error::Edhoc)?;
    let credential = parse_credential(peer.credential_bytes())?;
    Ok(ParsedPeer {
        id: peer.id,
        credential,
    })
}

/// Exported material for a fresh volatile OSCORE epoch; secrets zeroize on drop.
pub struct KeyMaterial {
    secret: Zeroizing<[u8; 16]>,
    salt: Zeroizing<[u8; 8]>,
    sender: heapless::Vec<u8, 7>,
    recipient: heapless::Vec<u8, 7>,
    peer: PeerId,
}
impl KeyMaterial {
    /// Derives the context, then discards the EDHOC exporter secrets.
    pub fn into_context(self, provider: &mut impl CryptoProvider) -> Result<Context, Error> {
        self.into_bounded_context(provider)
    }

    /// Derives an EDHOC context with explicit ID Context storage capacity.
    /// EDHOC supplies no OSCORE ID Context, so zero capacity is sufficient.
    pub fn into_bounded_context<const ID_CONTEXT_BYTES: usize>(
        self,
        provider: &mut impl CryptoProvider,
    ) -> Result<BoundedContext<ID_CONTEXT_BYTES>, Error> {
        BoundedContext::derive(
            provider,
            &self.secret[..],
            Some(&self.salt[..]),
            &self.sender,
            &self.recipient,
            None,
            self.peer,
        )
    }
}
impl core::fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KeyMaterial")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

/// Initiator waiting for message_2, without owning its crypto provider.
pub struct Initiator {
    state: Sensitive<lakers::WaitM2>,
    connection: lakers::ConnId,
}
impl Initiator {
    /// Local connection identifier reserved during this handshake.
    pub fn connection_id(&self) -> &[u8] {
        self.connection.as_slice()
    }
    /// Starts method 3, suite 2. Preferred suite numbers may precede 2, preserving
    /// the RFC 9529 negotiation trace without claiming support for those suites.
    pub fn start<const MESSAGE_BYTES: usize>(
        provider: &mut impl CryptoProvider,
        connection_id: &[u8],
        preferences: &[u8],
    ) -> Result<(Self, Packet<MESSAGE_BYTES>), Error> {
        let connection = lakers::ConnId::from_slice(connection_id).ok_or(Error::Malformed)?;
        if connection_id.len() > 7 || preferences.last() != Some(&2) {
            return Err(Error::Malformed);
        }
        let fault = Cell::new(false);
        let mut crypto = Bridge::with_preferences(provider, &fault, preferences);
        let suites =
            lakers::EdhocBuffer::new_from_slice(preferences).map_err(|_| Error::Capacity)?;
        let (mut x, g_x) = crypto.p256_key_pair_checked()?;
        let start = Sensitive(lakers::InitiatorStart {
            suites_i: suites,
            method: lakers::EDHOCMethod::StatStat,
            x,
            g_x,
        });
        x.zeroize();
        let result =
            lakers::i_prepare_message_1(&start, &mut crypto, connection, &lakers::EadItems::new());
        let (state, message) = result.map_err(|_| Error::Edhoc)?;
        let state = Sensitive(state);
        drop(start);
        check(&fault)?;
        Ok((
            Self { state, connection },
            Packet::copy_from(message.as_slice())?,
        ))
    }
    /// Verifies message_2 and returns message_3 and a fresh OSCORE key epoch.
    /// No message_4 is used; a protected application response confirms the keys.
    // The single endpoint call site reuses message scratch across this transition.
    // Multiple application call sites may trade more flash for the smaller frame.
    #[inline(always)]
    pub fn finish<const MESSAGE_BYTES: usize>(
        self,
        provider: &mut impl CryptoProvider,
        identity: &Identity,
        expected: &TrustedPeer,
        message_2: &[u8],
        by_value: bool,
    ) -> Result<(Packet<MESSAGE_BYTES>, KeyMaterial), Error> {
        let message =
            lakers::BufferMessage2::new_from_slice(message_2).map_err(|_| Error::Malformed)?;
        let fault = Cell::new(false);
        let mut crypto = Bridge::new(provider, &fault);
        let (processing, remote, details, ead) =
            lakers::i_parse_message_2(&self.state, &mut crypto, &message)
                .map_err(|_| Error::Edhoc)?;
        let processing = Sensitive(processing);
        check(&fault)?;
        ead.processed_critical_items().map_err(|_| Error::Edhoc)?;
        validation::plaintext_2(processing.plaintext_2.as_slice())?;
        let lakers::ParsedMessage2Details::StatStat { id_cred_r } = details else {
            return Err(Error::Edhoc);
        };
        let credential = expected.resolve(&id_cred_r)?;
        if remote.as_slice() == self.connection.as_slice() {
            return Err(Error::Edhoc);
        }
        let state = lakers::i_verify_message_2(
            &processing,
            &mut crypto,
            credential,
            lakers::InitiatorIdentity::StatStat {
                i: *identity.private,
            },
        )
        .map_err(|_| Error::Edhoc)?;
        let state = Sensitive(state);
        drop(processing);
        check(&fault)?;
        let (wait, message_3, prk) = lakers::i_prepare_message_3(
            &state,
            &mut crypto,
            parse_credential(identity.credential_bytes())?,
            transfer(by_value),
            &lakers::EadItems::new(),
        )
        .map_err(|_| Error::Edhoc)?;
        let wait = Sensitive(wait);
        let _prk = Zeroizing::new(prk);
        drop(state);
        check(&fault)?;
        let mut completed =
            Sensitive(lakers::i_complete_without_message_4(&wait).map_err(|_| Error::Edhoc)?);
        drop(wait);
        let material = export(
            &mut completed,
            &mut crypto,
            &fault,
            remote.as_slice(),
            self.connection.as_slice(),
            expected.id,
        )?;
        Ok((Packet::copy_from(message_3.as_slice())?, material))
    }
}

/// Responder waiting for message_3, with secrets zeroized when the session expires.
pub struct Responder {
    state: Sensitive<ResponderState>,
    local: lakers::ConnId,
    remote: lakers::ConnId,
}
// Reconstruct before the completion call so its crypto frame does not reserve
// both retained and method-generic representations.
struct ExpandedResponder {
    state: Sensitive<lakers::WaitM3>,
    local: lakers::ConnId,
    remote: lakers::ConnId,
}
// Lakers' method-generic state also reserves a PSK credential. Method 3 needs
// only these fields; expand through its public API while processing message_3.
struct ResponderState {
    y: [u8; 32],
    prk_3e2m: [u8; 32],
    th_3: [u8; 32],
}
impl ResponderState {
    fn retain(state: &lakers::WaitM3) -> Result<Sensitive<Self>, Error> {
        if !matches!(
            state.method_specifics,
            lakers::WaitM3MethodSpecifics::StatStat {}
        ) {
            return Err(Error::Edhoc);
        }
        Ok(Sensitive(Self {
            y: state.y,
            prk_3e2m: state.prk_3e2m,
            th_3: state.th_3,
        }))
    }
    fn expand(&self) -> Sensitive<lakers::WaitM3> {
        Sensitive(lakers::WaitM3 {
            method_specifics: lakers::WaitM3MethodSpecifics::StatStat {},
            y: self.y,
            prk_3e2m: self.prk_3e2m,
            th_3: self.th_3,
        })
    }
}
impl Responder {
    /// Processes message_1 using Lakers, returning message_2 and bounded session state.
    pub fn start<const MESSAGE_BYTES: usize>(
        provider: &mut impl CryptoProvider,
        identity: &Identity,
        connection_id: &[u8],
        message_1: &[u8],
        by_value: bool,
    ) -> Result<(Self, Packet<MESSAGE_BYTES>), Error> {
        validation::message_1(message_1)?;
        let local = lakers::ConnId::from_slice(connection_id).ok_or(Error::Malformed)?;
        if connection_id.len() > 7 {
            return Err(Error::Malformed);
        }
        let message =
            lakers::BufferMessage1::new_from_slice(message_1).map_err(|_| Error::Malformed)?;
        let fault = Cell::new(false);
        let mut crypto = Bridge::new(provider, &fault);
        let (mut y, g_y) = crypto.p256_key_pair_checked()?;
        let start = Sensitive(lakers::ResponderStart { y, g_y });
        y.zeroize();
        let result = lakers::r_process_message_1(&start, &mut crypto, &message);
        let (processed, remote, ead) = result.map_err(|_| Error::Edhoc)?;
        let processed = Sensitive(processed);
        drop(start);
        check(&fault)?;
        ead.processed_critical_items().map_err(|_| Error::Edhoc)?;
        if local.as_slice() == remote.as_slice() {
            return Err(Error::Edhoc);
        }
        let details = lakers::PrepareMessage2Details::StatStat {
            r: &identity.private,
            cred_transfer: transfer(by_value),
        };
        let (state, message) = lakers::r_prepare_message_2(
            &processed,
            &mut crypto,
            parse_credential(identity.credential_bytes())?,
            details,
            local,
            &lakers::EadItems::new(),
        )
        .map_err(|_| Error::Edhoc)?;
        let state = Sensitive(state);
        drop(processed);
        check(&fault)?;
        let retained = ResponderState::retain(&state)?;
        drop(state);
        Ok((
            Self {
                state: retained,
                local,
                remote,
            },
            Packet::copy_from(message.as_slice())?,
        ))
    }
    /// Local connection identifier, used to match sequential/combined message_3.
    pub fn connection_id(&self) -> &[u8] {
        self.local.as_slice()
    }
    /// Authenticates message_3 against registered credentials, then exports keys.
    pub fn finish(
        self,
        provider: &mut impl CryptoProvider,
        trusted: &(impl CredentialStore + ?Sized),
        message_3: &[u8],
    ) -> Result<KeyMaterial, Error> {
        self.expand()
            .finish_inner(provider, trusted, message_3, false)
            .map(|(material, _)| material)
    }
    /// Authenticates message_3 and produces optional explicit key confirmation.
    /// Sequential CoAP peers may require message_4 before sending application data.
    pub fn finish_with_message_4(
        self,
        provider: &mut impl CryptoProvider,
        trusted: &(impl CredentialStore + ?Sized),
        message_3: &[u8],
    ) -> Result<(KeyMaterial, Packet<64>), Error> {
        self.expand()
            .finish_inner(provider, trusted, message_3, true)
    }
    fn expand(self) -> ExpandedResponder {
        ExpandedResponder {
            state: self.state.expand(),
            local: self.local,
            remote: self.remote,
        }
    }
}
impl ExpandedResponder {
    fn finish_inner(
        self,
        provider: &mut impl CryptoProvider,
        trusted: &(impl CredentialStore + ?Sized),
        message_3: &[u8],
        confirm: bool,
    ) -> Result<(KeyMaterial, Packet<64>), Error> {
        validation::message_3(message_3)?;
        let message =
            lakers::BufferMessage3::new_from_slice(message_3).map_err(|_| Error::Malformed)?;
        let fault = Cell::new(false);
        let mut crypto = Bridge::new(provider, &fault);
        crypto.validate_plaintext_3 = true;
        let (processing, id, ead) = lakers::r_parse_message_3(&self.state, &mut crypto, &message)
            .map_err(|_| Error::Edhoc)?;
        let processing = Sensitive(processing);
        check(&fault)?;
        ead.processed_critical_items().map_err(|_| Error::Edhoc)?;
        let trusted = find_credential(trusted, &id)?;
        // Cloning instead of moving keeps the M4/M33 verification frame smaller.
        let (processed, prk) =
            lakers::r_verify_message_3(&processing, &mut crypto, trusted.credential.clone())
                .map_err(|_| Error::Edhoc)?;
        let processed = Sensitive(processed);
        let _prk = Zeroizing::new(prk);
        drop(processing);
        check(&fault)?;
        let (mut completed, message_4) = if confirm {
            let (completed, message) =
                lakers::r_prepare_message_4(&processed, &mut crypto, &lakers::EadItems::new())
                    .map_err(|_| Error::Edhoc)?;
            let completed = Sensitive(completed);
            check(&fault)?;
            (completed, Packet::copy_from(message.as_slice())?)
        } else {
            (
                Sensitive(
                    lakers::r_complete_without_message_4(&processed).map_err(|_| Error::Edhoc)?,
                ),
                Packet::new(),
            )
        };
        drop(processed);
        let material = export(
            &mut completed,
            &mut crypto,
            &fault,
            self.remote.as_slice(),
            self.local.as_slice(),
            trusted.id,
        )?;
        Ok((material, message_4))
    }
}
fn transfer(by_value: bool) -> lakers::CredentialTransfer {
    if by_value {
        lakers::CredentialTransfer::ByValue
    } else {
        lakers::CredentialTransfer::ByReference
    }
}
fn check(fault: &Cell<bool>) -> Result<(), Error> {
    if fault.get() {
        Err(Error::Edhoc)
    } else {
        Ok(())
    }
}
fn export<P: CryptoProvider>(
    completed: &mut lakers::Completed,
    crypto: &mut Bridge<'_, P>,
    fault: &Cell<bool>,
    sender: &[u8],
    recipient: &[u8],
    peer: PeerId,
) -> Result<KeyMaterial, Error> {
    let mut secret = Zeroizing::new([0; 16]);
    let mut salt = Zeroizing::new([0; 8]);
    lakers::edhoc_exporter(completed, crypto, 0, &[], &mut secret[..]);
    lakers::edhoc_exporter(completed, crypto, 1, &[], &mut salt[..]);
    completed.prk_out.zeroize();
    completed.prk_exporter.zeroize();
    check(fault)?;
    Ok(KeyMaterial {
        secret,
        salt,
        sender: heapless::Vec::from_slice(sender).map_err(|_| Error::Malformed)?,
        recipient: heapless::Vec::from_slice(recipient).map_err(|_| Error::Malformed)?,
        peer,
    })
}

/// Returns the encoded length of the CBOR byte-string message_3 prefix in a combined payload.
#[cfg(any(
    feature = "server",
    feature = "client",
    all(test, feature = "software-crypto")
))]
pub(crate) fn combined_message_3_length(payload: &[u8]) -> Result<usize, Error> {
    validation::bstr_end(payload)
}
/// Splits a sequential message_3's connection-ID prefix, preserving message bytes.
#[cfg(any(
    feature = "server",
    feature = "client",
    all(test, feature = "software-crypto")
))]
pub(crate) fn sequential_message_3(payload: &[u8]) -> Result<(lakers::ConnId, &[u8]), Error> {
    let (id, position) = validation::prefix(payload)?;
    let rest = payload.get(position..).ok_or(Error::Malformed)?;
    if rest.is_empty() {
        return Err(Error::Malformed);
    }
    Ok((id, rest))
}

/// Adapter from the public provider to Lakers' infallible primitive contract.
/// EDH-12: any provider error latches failure; callers check it after every
/// transition before accepting output or installing a context.
pub(crate) struct Bridge<'a, P> {
    provider: &'a mut P,
    fault: &'a Cell<bool>,
    preferences: &'a [u8],
    validate_plaintext_3: bool,
}
impl<P> core::fmt::Debug for Bridge<'_, P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bridge").finish_non_exhaustive()
    }
}
impl<'a, P: CryptoProvider> Bridge<'a, P> {
    /// Borrows a provider and a fault latch; the caller must reject a latched session.
    pub fn new(provider: &'a mut P, fault: &'a Cell<bool>) -> Self {
        Self {
            provider,
            fault,
            preferences: &[2],
            validate_plaintext_3: false,
        }
    }
    fn with_preferences(provider: &'a mut P, fault: &'a Cell<bool>, preferences: &'a [u8]) -> Self {
        Self {
            provider,
            fault,
            preferences,
            validate_plaintext_3: false,
        }
    }
    fn value<T: Default>(&self, result: Result<T, Error>) -> T {
        match result {
            Ok(value) => value,
            Err(_) => {
                self.fault.set(true);
                T::default()
            }
        }
    }
    fn p256_key_pair_checked(&mut self) -> Result<([u8; 32], [u8; 32]), Error> {
        self.provider.p256_key_pair()
    }
}
impl<P: CryptoProvider> lakers::Crypto for Bridge<'_, P> {
    type HashInProcess<'a>
        = ProviderHash<'a, P>
    where
        Self: 'a;
    fn supported_suites(&self) -> lakers::EdhocBuffer<{ lakers::MAX_SUITES_LEN }> {
        lakers::EdhocBuffer::new_from_slice(self.preferences).unwrap_or_default()
    }
    fn sha256_digest(&mut self, message: &[u8]) -> [u8; 32] {
        let result = self.provider.sha256(message);
        self.value(result)
    }
    fn sha256_start<'a>(&'a mut self) -> ProviderHash<'a, P> {
        let state = self
            .provider
            .sha256_start()
            .map_err(|_| self.fault.set(true))
            .ok();
        ProviderHash {
            state,
            fault: self.fault,
        }
    }
    fn hkdf_expand(&mut self, prk: &[u8; 32], info: &[u8], result: &mut [u8]) {
        if self.provider.hkdf_expand(prk, info, result).is_err() {
            self.fault.set(true);
            result.zeroize();
        }
    }
    fn hkdf_extract(&mut self, salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32] {
        let result = self.provider.hkdf_extract(Some(salt), ikm);
        self.value(result)
    }
    fn hkdf_extract_psk(&mut self, salt: &[u8; 32], ikm: &lakers::BufferPsk) -> [u8; 32] {
        let result = self.provider.hkdf_extract(Some(salt), ikm.as_slice());
        self.value(result)
    }
    fn aes_ccm_encrypt<const MESSAGE_BYTES: usize, T: lakers::CcmTagLen>(
        &mut self,
        key: &[u8; 16],
        iv: &[u8; 13],
        ad: &[u8],
        plaintext: &[u8],
    ) -> lakers::EdhocBuffer<MESSAGE_BYTES> {
        let mut output = lakers::EdhocBuffer::<MESSAGE_BYTES>::new();
        let result = (|| {
            if T::LEN != 8 {
                return Err(Error::Protection);
            }
            // Plaintext must fit the output as well as leave room for its tag.
            if !plaintext
                .len()
                .checked_add(8)
                .is_some_and(|n| n <= MESSAGE_BYTES)
            {
                return Err(Error::Capacity);
            }
            let mut bytes = Zeroizing::new([0u8; MESSAGE_BYTES]);
            let body = bytes.get_mut(..plaintext.len()).ok_or(Error::Capacity)?;
            body.copy_from_slice(plaintext);
            let tag = self.provider.encrypt(key, iv, ad, body)?;
            output
                .extend_from_slice(body)
                .map_err(|_| Error::Capacity)?;
            output
                .extend_from_slice(&tag)
                .map_err(|_| Error::Capacity)?;
            Ok(())
        })();
        if result.is_err() {
            self.fault.set(true);
            return lakers::EdhocBuffer::new();
        }
        output
    }
    fn aes_ccm_decrypt<const MESSAGE_BYTES: usize, T: lakers::CcmTagLen>(
        &mut self,
        key: &[u8; 16],
        iv: &[u8; 13],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<lakers::EdhocBuffer<MESSAGE_BYTES>, lakers::EDHOCError> {
        if T::LEN != 8 || ciphertext.len() < 8 {
            self.fault.set(true);
            return Err(lakers::EDHOCError::ParsingError);
        }
        let length = ciphertext.len() - 8;
        let mut bytes = Zeroizing::new([0u8; MESSAGE_BYTES]);
        let Some(body) = bytes.get_mut(..length) else {
            self.fault.set(true);
            return Err(lakers::EDHOCError::EncodingError);
        };
        body.copy_from_slice(&ciphertext[..length]);
        let tag = ciphertext[length..]
            .try_into()
            .map_err(|_| lakers::EDHOCError::ParsingError)?;
        if self.provider.decrypt(key, iv, ad, body, tag).is_err() {
            self.fault.set(true);
            return Err(lakers::EDHOCError::MacVerificationFailed);
        }
        if self.validate_plaintext_3 && validation::plaintext_3(body).is_err() {
            self.fault.set(true);
            return Err(lakers::EDHOCError::ParsingError);
        }
        lakers::EdhocBuffer::new_from_slice(body).map_err(|_| lakers::EDHOCError::EncodingError)
    }
    fn p256_ecdh(&mut self, private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
        let result = self.provider.p256_ecdh(private, public);
        self.value(result)
    }
    fn get_random_byte(&mut self) -> u8 {
        let mut byte = [0];
        self.provider.random(&mut byte);
        byte[0]
    }
    fn p256_generate_key_pair(&mut self) -> ([u8; 32], [u8; 32]) {
        let result = self.provider.p256_key_pair();
        self.value(result)
    }
}

/// Bounded streaming-hash bridge to Lakers' digest-0.10 contract.
/// Every byte is hashed by the application's provider, including hardware backends.
///
/// # Panics
/// `Digest::new`, `new_with_prefix` and `digest` have no provider and are API misuse.
/// Lakers obtains this type only through `Crypto::sha256_start`.
pub(crate) struct ProviderHash<'a, P: CryptoProvider + 'a> {
    state: Option<P::Sha256<'a>>,
    fault: &'a Cell<bool>,
}
impl<P: CryptoProvider> digest_legacy::OutputSizeUser for ProviderHash<'_, P> {
    type OutputSize = digest_legacy::consts::U32;
}
impl<P: CryptoProvider> digest_legacy::Digest for ProviderHash<'_, P> {
    fn new() -> Self {
        panic!("construct through the crypto provider")
    }
    fn new_with_prefix(_: impl AsRef<[u8]>) -> Self {
        Self::new()
    }
    fn update(&mut self, data: impl AsRef<[u8]>) {
        use crate::crypto::Sha256State;
        if let Some(state) = self.state.as_mut()
            && state.update(data.as_ref()).is_err()
        {
            self.fault.set(true);
            self.state = None;
        }
    }
    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update(data);
        self
    }
    fn finalize(self) -> digest_legacy::Output<Self> {
        use crate::crypto::Sha256State;
        let result = self
            .state
            .ok_or(Error::Protection)
            .and_then(Sha256State::finalize);
        match result {
            Ok(hash) => hash.into(),
            Err(_) => {
                self.fault.set(true);
                [0; 32].into()
            }
        }
    }
    fn finalize_into(self, out: &mut digest_legacy::Output<Self>) {
        *out = self.finalize();
    }
    fn finalize_reset(&mut self) -> digest_legacy::Output<Self>
    where
        Self: digest_legacy::FixedOutputReset,
    {
        digest_legacy::FixedOutputReset::finalize_fixed_reset(self)
    }
    fn finalize_into_reset(&mut self, out: &mut digest_legacy::Output<Self>)
    where
        Self: digest_legacy::FixedOutputReset,
    {
        digest_legacy::FixedOutputReset::finalize_into_reset(self, out);
    }
    fn reset(&mut self)
    where
        Self: digest_legacy::Reset,
    {
        digest_legacy::Reset::reset(self);
    }
    fn output_size() -> usize {
        32
    }
    fn digest(_: impl AsRef<[u8]>) -> digest_legacy::Output<Self> {
        panic!("hash through the crypto provider")
    }
}

// Guards cover states returned to this wrapper; Lakers owns its transition temporaries.
trait Wipe {
    fn wipe(&mut self);
}
impl<const N: usize> Wipe for [u8; N] {
    fn wipe(&mut self) {
        self.zeroize();
    }
}
impl<const N: usize> Wipe for lakers::EdhocBuffer<N> {
    #[allow(
        deprecated,
        reason = "Lakers has no mutable slice API for wiping the full buffer"
    )]
    fn wipe(&mut self) {
        self.content.zeroize();
    }
}
struct Sensitive<T: Wipe>(T);
impl<T: Wipe> core::ops::Deref for Sensitive<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Wipe> core::ops::DerefMut for Sensitive<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}
impl<T: Wipe> Drop for Sensitive<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}
macro_rules! wipe_fields {
    ($ty:ty, $($field:ident),+ $(,)?) => {
        impl Wipe for $ty {
            fn wipe(&mut self) { $(self.$field.wipe();)+ }
        }
    };
}
wipe_fields!(lakers::InitiatorStart, x);
wipe_fields!(lakers::ResponderStart, y);
wipe_fields!(lakers::WaitM2, x, h_message_1);
wipe_fields!(lakers::WaitM3, y, prk_3e2m, th_3);
wipe_fields!(ResponderState, y, prk_3e2m, th_3);
wipe_fields!(lakers::ProcessingM1, y, h_message_1);
wipe_fields!(lakers::ProcessingM2, prk_2e, x, th_2, plaintext_2);
wipe_fields!(lakers::ProcessedM2, prk_3e2m, prk_4e3m, th_3);
wipe_fields!(lakers::ProcessingM3, prk_3e2m, y, th_3, plaintext_3);
wipe_fields!(lakers::ProcessedM3, prk_4e3m, prk_out, prk_exporter, th_4);
wipe_fields!(lakers::WaitM4, prk_4e3m, prk_out, prk_exporter, th_4);
wipe_fields!(lakers::Completed, prk_out, prk_exporter);

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::crypto::SoftwareCrypto;
    use rand::SeedableRng;
    use std::vec::Vec;
    pub(super) fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    pub(super) const CRED_I: &str = "a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8";
    pub(super) const CRED_R: &str = "a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072";
    pub(super) const SK_I: &str =
        "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
    pub(super) const SK_R: &str =
        "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac";
    fn identity(ccs: &[u8], private: [u8; 32]) -> Result<Identity, Error> {
        let mut provider = SoftwareCrypto::new(rand::rngs::StdRng::from_seed([0; 32]));
        Identity::new(ccs, private, &mut provider)
    }
    pub(super) const M1: &str =
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637";
    const M2: &str = "582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d59862a1eef9e0e7e1886fcd";
    const M3: &str = "52e562097bc417dd5919485ac7891ffd90a9fc";
    impl<T: Wipe> Wipe for &mut T {
        fn wipe(&mut self) {
            (**self).wipe();
        }
    }
    struct Fixed {
        inner: SoftwareCrypto<rand::rngs::StdRng>,
        private: [u8; 32],
        public: [u8; 32],
        calls: usize,
        fail_at: Option<usize>,
        hash_drops: usize,
    }
    impl Fixed {
        fn gate(&mut self) -> Result<(), Error> {
            self.calls += 1;
            if self.fail_at == Some(self.calls) {
                Err(Error::Protection)
            } else {
                Ok(())
            }
        }
        fn initiator() -> Self {
            Self {
                calls: 0,
                fail_at: None,
                hash_drops: 0,
                inner: SoftwareCrypto::new(rand::rngs::StdRng::from_seed([1; 32])),
                private: hex("368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525")
                    .try_into()
                    .unwrap(),
                public: hex("8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6")
                    .try_into()
                    .unwrap(),
            }
        }
        fn responder() -> Self {
            Self {
                calls: 0,
                fail_at: None,
                hash_drops: 0,
                inner: SoftwareCrypto::new(rand::rngs::StdRng::from_seed([2; 32])),
                private: hex("e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418")
                    .try_into()
                    .unwrap(),
                public: hex("419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5")
                    .try_into()
                    .unwrap(),
            }
        }
    }
    struct FixedHash<'a> {
        state: Option<crate::crypto::SoftwareSha256>,
        calls: &'a mut usize,
        fail_at: Option<usize>,
        drops: &'a mut usize,
    }
    impl Drop for FixedHash<'_> {
        fn drop(&mut self) {
            *self.drops += 1;
        }
    }
    impl FixedHash<'_> {
        fn gate(&mut self) -> Result<(), Error> {
            *self.calls += 1;
            if self.fail_at == Some(*self.calls) {
                Err(Error::Protection)
            } else {
                Ok(())
            }
        }
    }
    impl crate::crypto::Sha256State for FixedHash<'_> {
        fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
            self.gate()?;
            self.state.as_mut().unwrap().update(bytes)
        }
        fn finalize(mut self) -> Result<[u8; 32], Error> {
            self.gate()?;
            self.state.take().unwrap().finalize()
        }
    }
    impl CryptoProvider for Fixed {
        type Sha256<'a> = FixedHash<'a>;
        fn sha256_start(&mut self) -> Result<Self::Sha256<'_>, Error> {
            self.gate()?;
            Ok(FixedHash {
                state: Some(self.inner.sha256_start()?),
                calls: &mut self.calls,
                fail_at: self.fail_at,
                drops: &mut self.hash_drops,
            })
        }
        fn hkdf_extract(&mut self, s: Option<&[u8]>, b: &[u8]) -> Result<[u8; 32], Error> {
            self.gate()?;
            self.inner.hkdf_extract(s, b)
        }
        fn hkdf_expand(&mut self, p: &[u8; 32], i: &[u8], o: &mut [u8]) -> Result<(), Error> {
            self.gate()?;
            self.inner.hkdf_expand(p, i, o)
        }
        fn encrypt(
            &mut self,
            k: &[u8; 16],
            n: &[u8; 13],
            a: &[u8],
            b: &mut [u8],
        ) -> Result<[u8; 8], Error> {
            if let Err(error) = self.gate() {
                b.fill(0xa5);
                return Err(error);
            }
            self.inner.encrypt(k, n, a, b)
        }
        fn decrypt(
            &mut self,
            k: &[u8; 16],
            n: &[u8; 13],
            a: &[u8],
            b: &mut [u8],
            t: &[u8; 8],
        ) -> Result<(), Error> {
            if let Err(error) = self.gate() {
                b.fill(0xa5);
                return Err(error);
            }
            self.inner.decrypt(k, n, a, b, t)
        }
        fn p256_key_pair(&mut self) -> Result<([u8; 32], [u8; 32]), Error> {
            self.gate()?;
            Ok((self.private, self.public))
        }
        fn p256_public_key(&mut self, private: &[u8; 32]) -> Result<[u8; 65], Error> {
            self.gate()?;
            self.inner.p256_public_key(private)
        }
        fn p256_decompress(&mut self, x: &[u8; 32]) -> Result<[u8; 65], Error> {
            self.gate()?;
            self.inner.p256_decompress(x)
        }
        fn p256_validate(&mut self, p: &[u8]) -> Result<(), Error> {
            self.gate()?;
            self.inner.p256_validate(p)
        }
        fn p256_ecdh(&mut self, s: &[u8; 32], p: &[u8; 32]) -> Result<[u8; 32], Error> {
            self.gate()?;
            self.inner.p256_ecdh(s, p)
        }
        fn random(&mut self, o: &mut [u8]) {
            self.inner.random(o);
        }
    }
    const AEAD_KEY: [u8; 16] = [0x11; 16];
    const AEAD_NONCE: [u8; 13] = [0x22; 13];
    const AEAD_AAD: &[u8] = b"adapter boundary test";

    fn aead_wire(plaintext: &[u8]) -> Vec<u8> {
        let mut provider = Fixed::initiator();
        let mut wire = plaintext.to_vec();
        let tag = provider
            .encrypt(&AEAD_KEY, &AEAD_NONCE, AEAD_AAD, &mut wire)
            .unwrap();
        wire.extend_from_slice(&tag);
        wire
    }

    fn aead_capacity<const N: usize>() {
        for length in [0, N.saturating_sub(8), N.saturating_sub(8) + 1, N, N + 1] {
            let plaintext: Vec<_> = (0..length).map(|n| (n as u8).wrapping_mul(17)).collect();
            let original = plaintext.clone();
            let expected = aead_wire(&plaintext);
            let mut provider = Fixed::initiator();
            let fault = Cell::new(false);
            let output = lakers::Crypto::aes_ccm_encrypt::<N, lakers::CcmTagLen8>(
                &mut Bridge::new(&mut provider, &fault),
                &AEAD_KEY,
                &AEAD_NONCE,
                AEAD_AAD,
                &plaintext,
            );
            if length.checked_add(8).is_some_and(|n| n <= N) {
                assert_eq!(output.as_slice(), expected);
                assert!(!fault.get());
                assert_eq!(provider.calls, 1);
            } else {
                assert!(output.as_slice().is_empty());
                assert!(fault.get());
                assert_eq!(provider.calls, 0);
            }
            assert_eq!(plaintext, original);
        }
        for length in [0, N.saturating_sub(1), N, N + 1] {
            let plaintext: Vec<_> = (0..length).map(|n| (n as u8).wrapping_mul(17)).collect();
            let wire = aead_wire(&plaintext);
            let original = wire.clone();
            let mut provider = Fixed::initiator();
            let fault = Cell::new(false);
            let output = lakers::Crypto::aes_ccm_decrypt::<N, lakers::CcmTagLen8>(
                &mut Bridge::new(&mut provider, &fault),
                &AEAD_KEY,
                &AEAD_NONCE,
                AEAD_AAD,
                &wire,
            );
            if length <= N {
                assert_eq!(output.unwrap().as_slice(), plaintext);
                assert!(!fault.get());
                assert_eq!(provider.calls, 1);
            } else {
                assert!(output.is_err());
                assert!(fault.get());
                assert_eq!(provider.calls, 0);
            }
            assert_eq!(wire, original);
        }
    }

    #[test]
    fn edh_12_aead_output_capacity_includes_tag_only_for_encryption() {
        aead_capacity::<0>();
        aead_capacity::<7>();
        aead_capacity::<8>();
        aead_capacity::<9>();
        aead_capacity::<16>();
        aead_capacity::<192>();
        aead_capacity::<256>();
        aead_capacity::<1024>();
    }

    #[test]
    fn edh_12_aead_rejects_truncated_and_unsupported_tags_before_provider_use() {
        for length in 0..8 {
            let mut provider = Fixed::initiator();
            let fault = Cell::new(false);
            assert!(
                lakers::Crypto::aes_ccm_decrypt::<32, lakers::CcmTagLen8>(
                    &mut Bridge::new(&mut provider, &fault),
                    &AEAD_KEY,
                    &AEAD_NONCE,
                    AEAD_AAD,
                    &[0xa5; 8][..length],
                )
                .is_err()
            );
            assert!(fault.get());
            assert_eq!(provider.calls, 0);
        }
        let mut provider = Fixed::initiator();
        let fault = Cell::new(false);
        let output = lakers::Crypto::aes_ccm_encrypt::<32, lakers::CcmTagLen16>(
            &mut Bridge::new(&mut provider, &fault),
            &AEAD_KEY,
            &AEAD_NONCE,
            AEAD_AAD,
            b"plaintext",
        );
        assert!(output.as_slice().is_empty());
        assert!(fault.get());
        fault.set(false);
        assert!(
            lakers::Crypto::aes_ccm_decrypt::<32, lakers::CcmTagLen16>(
                &mut Bridge::new(&mut provider, &fault),
                &AEAD_KEY,
                &AEAD_NONCE,
                AEAD_AAD,
                &[0; 16],
            )
            .is_err()
        );
        assert!(fault.get());
        assert_eq!(provider.calls, 0);
    }

    #[test]
    fn edh_12_aead_errors_never_return_partial_output_or_accept_bad_plaintext() {
        let plaintext = b"plaintext";
        let wire = aead_wire(plaintext);
        let mut provider = Fixed::initiator();
        provider.fail_at = Some(1);
        let fault = Cell::new(false);
        let output = lakers::Crypto::aes_ccm_encrypt::<32, lakers::CcmTagLen8>(
            &mut Bridge::new(&mut provider, &fault),
            &AEAD_KEY,
            &AEAD_NONCE,
            AEAD_AAD,
            plaintext,
        );
        assert!(output.as_slice().is_empty());
        assert!(fault.get());
        provider.fail_at = None;
        fault.set(false);
        let output = lakers::Crypto::aes_ccm_encrypt::<32, lakers::CcmTagLen8>(
            &mut Bridge::new(&mut provider, &fault),
            &AEAD_KEY,
            &AEAD_NONCE,
            AEAD_AAD,
            plaintext,
        );
        assert_eq!(output.as_slice(), wire);
        assert!(!fault.get());

        for kind in 0..3 {
            let mut provider = Fixed::initiator();
            let fault = Cell::new(false);
            let mut input = wire.clone();
            match kind {
                0 => provider.fail_at = Some(1),
                1 => input[0] ^= 1,
                _ => *input.last_mut().unwrap() ^= 1,
            }
            let original = input.clone();
            assert!(
                lakers::Crypto::aes_ccm_decrypt::<32, lakers::CcmTagLen8>(
                    &mut Bridge::new(&mut provider, &fault),
                    &AEAD_KEY,
                    &AEAD_NONCE,
                    AEAD_AAD,
                    &input,
                )
                .is_err()
            );
            assert!(fault.get());
            assert_eq!(input, original);
            provider.fail_at = None;
            fault.set(false);
            let output = lakers::Crypto::aes_ccm_decrypt::<32, lakers::CcmTagLen8>(
                &mut Bridge::new(&mut provider, &fault),
                &AEAD_KEY,
                &AEAD_NONCE,
                AEAD_AAD,
                &wire,
            )
            .unwrap();
            assert_eq!(output.as_slice(), plaintext);
            assert!(!fault.get());
        }
        // Authenticated bytes still need the EDHOC MAC_3 field's eight-byte shape.
        for mac_length in [7, 8] {
            let mut plaintext = std::vec![0x01, 0x40 + mac_length];
            plaintext.resize(2 + usize::from(mac_length), 0);
            let wire = aead_wire(&plaintext);
            let mut provider = Fixed::initiator();
            let fault = Cell::new(false);
            let mut bridge = Bridge::new(&mut provider, &fault);
            bridge.validate_plaintext_3 = true;
            let output = lakers::Crypto::aes_ccm_decrypt::<32, lakers::CcmTagLen8>(
                &mut bridge,
                &AEAD_KEY,
                &AEAD_NONCE,
                AEAD_AAD,
                &wire,
            );
            if mac_length == 8 {
                assert_eq!(output.unwrap().as_slice(), plaintext);
                assert!(!fault.get());
            } else {
                assert!(output.is_err());
                assert!(fault.get());
            }
        }
    }

    #[test]
    fn edh_12_streaming_hash_errors_and_cancellation_release_state() {
        use digest_legacy::Digest;
        for fail_at in 1..=3 {
            let mut provider = Fixed::initiator();
            provider.fail_at = Some(fail_at);
            let fault = Cell::new(false);
            let mut bridge = Bridge::new(&mut provider, &fault);
            let mut hash = lakers::Crypto::sha256_start(&mut bridge);
            hash.update(b"abc");
            if fail_at == 2 {
                hash.update(b"ignored after failure");
            }
            assert_eq!(hash.finalize().as_slice(), &[0; 32]);
            assert!(fault.get());
            assert_eq!(provider.hash_drops, usize::from(fail_at != 1));
            assert_eq!(provider.calls, fail_at);
        }
        let mut provider = Fixed::initiator();
        let fault = Cell::new(false);
        {
            let mut bridge = Bridge::new(&mut provider, &fault);
            let mut hash = lakers::Crypto::sha256_start(&mut bridge);
            hash.update(b"cancelled");
        }
        assert!(!fault.get());
        assert_eq!(provider.hash_drops, 1);
        provider.sha256(b"reusable").unwrap();
        assert_eq!(provider.hash_drops, 2);
    }

    #[test]
    fn edh_2_streaming_adapter_preserves_every_byte_without_transcript_bound() {
        use digest_legacy::Digest;
        let input = [0xa5; 8193];
        let mut provider = Fixed::initiator();
        let expected = provider.sha256(&input).unwrap();
        let fault = Cell::new(false);
        let mut bridge = Bridge::new(&mut provider, &fault);
        let mut hash = lakers::Crypto::sha256_start(&mut bridge);
        for chunk in input.chunks(63) {
            hash.update(chunk);
        }
        assert_eq!(hash.finalize().as_slice(), expected);
        assert!(!fault.get());
    }

    #[test]
    fn edh_4_credential_validation_consumes_complete_map_keys() {
        let cred = hex(CRED_R);
        let cnf = cred.iter().position(|&b| b == 8).unwrap();
        for key in [b"\x42\x08\x01".as_slice(), b"\x62\x08\x01"] {
            let mut outer = std::vec![0xa2];
            outer.extend_from_slice(key);
            outer.push(0);
            outer.extend_from_slice(&cred[cnf..]);
            assert_eq!(validation::credential(&outer), Ok(()));
            assert!(identity(&outer, [1; 32]).is_err());
            assert!(TrustedPeer::new(PeerId(1), &outer).is_err());

            let mut confirmation = std::vec![0xa1, 8, 0xa2];
            confirmation.extend_from_slice(key);
            confirmation.push(0);
            confirmation.extend_from_slice(&cred[cnf + 2..]);
            assert_eq!(validation::credential(&confirmation), Ok(()));
            assert!(identity(&confirmation, [1; 32]).is_err());
            assert!(TrustedPeer::new(PeerId(1), &confirmation).is_err());
        }
        for bytes in [&[0xa1, 0x42, 8][..], &[0xa1, 8, 0xa1, 0x62, 1]] {
            assert_eq!(validation::credential(bytes), Err(Error::Malformed));
        }
    }
    #[test]
    fn edh_4_ccs_constructors_reject_extended_cose_labels() {
        let valid = hex(CRED_R);
        // The cnf COSE_Key starts with kty=2; retain a complete map/value tail.
        let offset = valid
            .windows(4)
            .position(|v| v == [0xa1, 1, 0xa5, 1])
            .unwrap()
            + 3;
        for label in [&[0x38, 0x18][..], &[0x38, 0], &[0x18, 0xff], &[0x18, 1]] {
            let mut ccs = valid[..offset].to_vec();
            ccs.extend_from_slice(label);
            ccs.extend_from_slice(&valid[offset + 1..]);
            assert!(matches!(identity(&ccs, [1; 32]), Err(Error::Malformed)));
            assert!(matches!(
                TrustedPeer::new(PeerId(1), &ccs),
                Err(Error::Malformed)
            ));
        }
        for len in 0..valid.len() {
            assert!(identity(&valid[..len], [1; 32]).is_err());
            assert!(TrustedPeer::new(PeerId(1), &valid[..len]).is_err());
        }
        assert!(identity(&valid, hex(SK_R).try_into().unwrap()).is_ok());
        assert!(TrustedPeer::new(PeerId(1), &valid).is_ok());
    }

    #[test]
    fn edh_4_generated_ccs_preserves_encoding_and_matches_key_material() {
        let private: [u8; 32] = hex(SK_R).try_into().unwrap();
        let mut provider = SoftwareCrypto::new(rand::rngs::StdRng::from_seed([3; 32]));
        let identity =
            Identity::from_private_key(private, b"example.edu", CcsEncoding::FullXY, &mut provider)
                .unwrap();
        let public = provider.p256_public_key(&private).unwrap();
        let peer = TrustedPeer::from_public_key(
            PeerId(23),
            b"example.edu",
            &public,
            CcsEncoding::FullXY,
            &mut provider,
        )
        .unwrap();
        assert_eq!(identity.credential_bytes(), peer.credential_bytes());
        assert_eq!(
            validation::credential_y(identity.credential_bytes()).unwrap(),
            Some(public[33..].try_into().unwrap())
        );
        let mut wrong_y = identity.credential_bytes().to_vec();
        *wrong_y.last_mut().unwrap() ^= 1;
        assert!(Identity::new(&wrong_y, private, &mut provider).is_err());

        let compact = Identity::from_private_key(
            private,
            b"example.edu",
            CcsEncoding::CompactX,
            &mut provider,
        )
        .unwrap();
        assert_eq!(
            validation::credential_y(compact.credential_bytes()).unwrap(),
            None
        );
        assert!(Identity::new(compact.credential_bytes(), [1; 32], &mut provider).is_err());

        let one = core::array::from_fn(|index| u8::from(index == 31));
        let negative_one: [u8; 32] =
            hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")
                .try_into()
                .unwrap();
        let compact_one =
            Identity::from_private_key(one, b"sign", CcsEncoding::CompactX, &mut provider).unwrap();
        assert!(Identity::new(compact_one.credential_bytes(), negative_one, &mut provider).is_ok());
        let full_one =
            Identity::from_private_key(one, b"sign", CcsEncoding::FullXY, &mut provider).unwrap();
        assert!(Identity::new(full_one.credential_bytes(), negative_one, &mut provider).is_err());
    }

    #[test]
    fn edh_10_ead_limit_is_checked_in_every_supported_plaintext() {
        let mut m1 = hex(M1);
        let mut p3 = std::vec![0x01, 0x48];
        p3.extend_from_slice(&[0; 8]);
        let mut p2 = std::vec![0x27];
        p2.extend_from_slice(&p3);
        for (bytes, validate) in [
            (
                &mut m1,
                validation::message_1 as fn(&[u8]) -> Result<(), Error>,
            ),
            (&mut p2, validation::plaintext_2),
            (&mut p3, validation::plaintext_3),
        ] {
            for _ in 0..lakers::MAX_EAD_ITEMS {
                // A label with an optional byte-string value is one EAD item.
                bytes.extend_from_slice(&[0x01, 0x41, 0]);
                assert_eq!(validate(bytes), Ok(()));
            }
            bytes.push(0x20);
            assert_eq!(validate(bytes), Err(Error::Malformed));
        }
    }
    #[test]
    fn edh_3_osc_18_retained_responder_state_preserves_method_3_and_wiping() {
        let state = lakers::WaitM3 {
            method_specifics: lakers::WaitM3MethodSpecifics::StatStat {},
            y: [1; 32],
            prk_3e2m: [2; 32],
            th_3: [3; 32],
        };
        let mut retained = ResponderState::retain(&state).unwrap();
        let expanded = retained.expand();
        assert!(matches!(
            expanded.method_specifics,
            lakers::WaitM3MethodSpecifics::StatStat {}
        ));
        assert_eq!(expanded.y, state.y);
        assert_eq!(expanded.prk_3e2m, state.prk_3e2m);
        assert_eq!(expanded.th_3, state.th_3);
        drop(Sensitive(&mut *retained));
        assert_eq!(retained.y, [0; 32]);
        assert_eq!(retained.prk_3e2m, [0; 32]);
        assert_eq!(retained.th_3, [0; 32]);

        let unsupported = lakers::WaitM3 {
            method_specifics: lakers::WaitM3MethodSpecifics::Psk {
                cred_r: lakers::Credential::parse_ccs(&hex(CRED_R)).unwrap(),
            },
            ..state
        };
        assert!(matches!(
            ResponderState::retain(&unsupported),
            Err(Error::Edhoc)
        ));
    }

    #[test]
    fn osc_18_sensitive_guards_wipe_returned_state_on_early_return() {
        fn early(state: &mut lakers::WaitM4) -> Result<(), Error> {
            let _state = Sensitive(state);
            Err(Error::Edhoc)
        }
        let mut state = lakers::WaitM4 {
            prk_4e3m: [1; 32],
            th_4: [2; 32],
            prk_out: [3; 32],
            prk_exporter: [4; 32],
        };
        assert_eq!(early(&mut state), Err(Error::Edhoc));
        assert_eq!(state.prk_4e3m, [0; 32]);
        assert_eq!(state.th_4, [0; 32]);
        assert_eq!(state.prk_out, [0; 32]);
        assert_eq!(state.prk_exporter, [0; 32]);
        let mut bytes = lakers::EdhocBuffer::<32>::new_from_slice(&[7; 32]).unwrap();
        drop(Sensitive(&mut bytes));
        assert_eq!(bytes.as_slice(), &[0; 32]);
    }
    #[test]
    fn edh_12_provider_errors_never_export_keys() {
        let identity_i = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap()).unwrap();
        let identity_r = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let trusted_i = [TrustedPeer::new(PeerId(17), &hex(CRED_I)).unwrap()];
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        // Exercise every provider call, including exporter failures after authentication.
        let mut reference = Fixed::responder();
        let (responder, _) =
            Responder::start::<256>(&mut reference, &identity_r, &[0x27], &hex(M1), false).unwrap();
        let start = reference.calls;
        responder
            .finish_with_message_4(&mut reference, &trusted_i, &hex(M3))
            .unwrap();
        for fail_at in 1..=reference.calls {
            let mut crypto = Fixed::responder();
            crypto.fail_at = Some(fail_at);
            let result =
                Responder::start::<256>(&mut crypto, &identity_r, &[0x27], &hex(M1), false)
                    .and_then(|(session, _)| {
                        session.finish_with_message_4(&mut crypto, &trusted_i, &hex(M3))
                    });
            assert!(
                result.is_err(),
                "responder provider call {fail_at} (start uses {start})"
            );
        }
        let mut reference = Fixed::initiator();
        let (initiator, _) = Initiator::start::<256>(&mut reference, &[0x37], &[6, 2]).unwrap();
        initiator
            .finish::<256>(&mut reference, &identity_i, &trusted_r, &hex(M2), false)
            .unwrap();
        for fail_at in 1..=reference.calls {
            let mut crypto = Fixed::initiator();
            crypto.fail_at = Some(fail_at);
            let result =
                Initiator::start::<256>(&mut crypto, &[0x37], &[6, 2]).and_then(|(session, _)| {
                    session.finish::<256>(&mut crypto, &identity_i, &trusted_r, &hex(M2), false)
                });
            assert!(result.is_err(), "initiator provider call {fail_at}");
        }
    }
    #[test]
    fn edh_12_lakers_rejects_malformed_message_3_without_outer_guard() {
        let identity = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let malformed: &[&[u8]] = &[
            &[],
            &[0x41],
            &[0x58],
            &[0x58, 0x20],
            &[0x59, 0x00],
            &[0x00],
            &[0x40],
            &[0x41, 0x00],
            &[0x48, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        ];
        for bytes in malformed {
            let mut provider = Fixed::responder();
            let (state, _) =
                Responder::start::<256>(&mut provider, &identity, &[0x27], &hex(M1), false)
                    .unwrap();
            let message = lakers::BufferMessage3::new_from_slice(bytes).unwrap();
            let fault = Cell::new(false);
            let mut crypto = Bridge::new(&mut provider, &fault);
            let state = state.state.expand();
            // Exercise the dependency fix without our framing check masking a regression.
            assert!(matches!(
                lakers::r_parse_message_3(&state, &mut crypto, &message),
                Err(lakers::EDHOCError::ParsingError)
            ));
        }
    }
    #[test]
    fn edh_12_message_3_envelope_is_checked_before_processing() {
        let identity = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let trusted = [TrustedPeer::new(PeerId(17), &hex(CRED_I)).unwrap()];
        let malformed: &[&[u8]] = &[
            &[],
            &[0x41],
            &[0x58],
            &[0x58, 24],
            &[0x59],
            &[0x00],
            &[0x58, 0],
            &[0x40, 0],
            &[0x59, 0, 0],
            &[0x5f, 0xff],
        ];
        for bytes in malformed {
            for confirm in [false, true] {
                let mut crypto = Fixed::responder();
                let (state, _) =
                    Responder::start::<256>(&mut crypto, &identity, &[0x27], &hex(M1), false)
                        .unwrap();
                let result = if confirm {
                    state
                        .finish_with_message_4(&mut crypto, &trusted, bytes)
                        .map(|(keys, _)| keys)
                } else {
                    state.finish(&mut crypto, &trusted, bytes)
                };
                assert!(matches!(result, Err(Error::Malformed)), "{bytes:02x?}");
            }
        }
        for length in [0, 8, 23, 24, 100] {
            let mut bytes = Vec::new();
            if length < 24 {
                bytes.push(0x40 + length);
            } else {
                bytes.extend_from_slice(&[0x58, length]);
            }
            bytes.resize(bytes.len() + usize::from(length), 0);
            assert_eq!(validation::message_3(&bytes), Ok(()));
            let end = bytes.len();
            bytes.push(0);
            assert_eq!(validation::bstr_end(&bytes), Ok(end));
            assert_eq!(validation::message_3(&bytes), Err(Error::Malformed));
        }
    }
    #[test]
    fn edh_4_retained_credentials_preserve_exact_bytes_and_identifier_forms() {
        let original = hex(CRED_I);
        let identity = identity(&original, hex(SK_I).try_into().unwrap()).unwrap();
        let trusted = TrustedPeer::new(PeerId(17), &original).unwrap();
        assert_eq!(identity.credential_bytes(), original);
        assert_eq!(trusted.clone().credential_bytes(), original);
        let parsed = parse_credential(&original).unwrap();
        for id in [parsed.by_kid().unwrap(), parsed.by_value().unwrap()] {
            assert!(CredentialId(&id).matches(&trusted));
            assert_eq!(trusted.resolve(&id).unwrap().bytes.as_slice(), original);
        }

        // Same key and kid, but a distinct subject must not match by value.
        let mut changed = original.clone();
        changed[3] ^= 1;
        let changed = TrustedPeer::new(PeerId(23), &changed).unwrap();
        let presented = parse_credential(changed.credential_bytes()).unwrap();
        assert!(CredentialId(&presented.by_kid().unwrap()).matches(&trusted));
        assert!(!CredentialId(&presented.by_value().unwrap()).matches(&trusted));
        let peers = [trusted.clone(), changed];
        assert!(
            peers
                .find(CredentialId(&parsed.by_kid().unwrap()))
                .is_none()
        );
        assert_eq!(
            peers
                .find(CredentialId(&parsed.by_value().unwrap()))
                .unwrap()
                .id,
            PeerId(17)
        );
        assert_eq!(
            peers
                .find(CredentialId(&presented.by_value().unwrap()))
                .unwrap()
                .id,
            PeerId(23)
        );
        assert_eq!(trusted.credential_bytes(), original);
    }

    #[test]
    fn edh_4_retained_credentials_keep_the_full_registration_bound() {
        let original = hex(CRED_R);
        assert_eq!(original[2], 0x6b);
        // Replace the 11-byte subject with a longer, still valid text claim.
        for length in [192, 193] {
            let subject_length = length - original.len() + 10;
            let mut credential = std::vec![0xa2, 0x02, 0x78, subject_length as u8];
            credential.resize(credential.len() + subject_length, b'x');
            credential.extend_from_slice(&original[14..]);
            assert_eq!(credential.len(), length);
            let peer = TrustedPeer::new(PeerId(23), &credential);
            let identity = identity(&credential, hex(SK_R).try_into().unwrap());
            if length == 192 {
                let peer = peer.unwrap();
                let identity = identity.unwrap();
                assert_eq!(peer.credential_bytes(), credential);
                assert_eq!(identity.credential_bytes(), credential);
                let id = parse_credential(&credential).unwrap().by_kid().unwrap();
                assert_eq!(peer.resolve(&id).unwrap().bytes.as_slice(), credential);
            } else {
                assert!(peer.is_err());
                assert!(identity.is_err());
            }
        }
    }

    #[test]
    fn edh_4_credential_store_rejects_ambiguous_ids_and_replaces_by_peer() {
        let first = TrustedPeer::new(PeerId(1), &hex(CRED_I)).unwrap();
        let id = parse_credential(first.credential_bytes())
            .unwrap()
            .by_kid()
            .unwrap();
        let mut peers = TrustedPeers::<2>::new();
        peers.insert(first).unwrap();
        assert_eq!(peers.find(CredentialId(&id)).unwrap().id, PeerId(1));
        peers
            .insert(TrustedPeer::new(PeerId(2), &hex(CRED_I)).unwrap())
            .unwrap();
        assert!(peers.find(CredentialId(&id)).is_none());
        peers
            .insert(TrustedPeer::new(PeerId(1), &hex(CRED_R)).unwrap())
            .unwrap();
        assert_eq!(peers.find(CredentialId(&id)).unwrap().id, PeerId(2));
        assert!(
            peers
                .insert(TrustedPeer::new(PeerId(3), &hex(CRED_R)).unwrap())
                .is_err()
        );
        peers.remove(PeerId(2));
        assert!(peers.find(CredentialId(&id)).is_none());
        assert!(peers.get(PeerId(1)).is_some());
    }
    #[test]
    fn edh_4_6_13_rfc_9529_method_3_suite_2_trace() {
        let identity_i = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap()).unwrap();
        let identity_r = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let trusted_i = TrustedPeer::new(PeerId(17), &hex(CRED_I)).unwrap();
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        let mut ci = Fixed::initiator();
        let mut cr = Fixed::responder();
        let (i, m1) = Initiator::start::<256>(&mut ci, &[0x37], &[6, 2]).unwrap();
        assert_eq!(m1.as_slice(), hex(M1));
        let (r, m2) =
            Responder::start::<256>(&mut cr, &identity_r, &[0x27], m1.as_slice(), false).unwrap();
        assert_eq!(m2.as_slice(), hex(M2));
        let (m3, material_i) = i
            .finish::<256>(&mut ci, &identity_i, &trusted_r, m2.as_slice(), false)
            .unwrap();
        assert_eq!(m3.as_slice(), hex(M3));
        let material_r = r.finish(&mut cr, &[trusted_i], m3.as_slice()).unwrap();
        assert_eq!(
            material_i.secret.as_slice(),
            hex("f9868f6a3aca78a05d1485b35030b162")
        );
        assert_eq!(material_i.salt.as_slice(), hex("ada24c7dbfc85eeb"));
        assert_eq!(material_i.secret.as_slice(), material_r.secret.as_slice());
        assert_eq!(material_i.salt.as_slice(), material_r.salt.as_slice());
        assert_eq!(&material_i.sender[..], &[0x27]);
        assert_eq!(&material_r.sender[..], &[0x37]);
        assert_eq!(&material_i.recipient[..], &[0x37]);
        assert_eq!(&material_r.recipient[..], &[0x27]);
    }
    #[test]
    fn edh_12_invalid_points_fail_without_panicking_or_installing_keys() {
        let identity_r = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let mut cr = Fixed::responder();
        let mut m1 = hex(M1);
        m1[6..38].fill(0xff);
        assert!(Responder::start::<256>(&mut cr, &identity_r, &[0x27], &m1, false).is_err());
        let identity_i = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap()).unwrap();
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        let mut ci = Fixed::initiator();
        let (i, _) = Initiator::start::<256>(&mut ci, &[0x37], &[6, 2]).unwrap();
        let mut m2 = hex(M2);
        m2[2..34].fill(0xff);
        assert!(
            i.finish::<256>(&mut ci, &identity_i, &trusted_r, &m2, false)
                .is_err()
        );
    }
    #[test]
    fn edh_7_8_prefixes_do_not_reencode_credential_or_message_bytes() {
        let mut payload = hex(M3);
        payload.extend_from_slice(b"ciphertext");
        assert_eq!(combined_message_3_length(&payload), Ok(19));
        payload.insert(0, 0x27);
        let (id, m3) = sequential_message_3(&payload).unwrap();
        assert_eq!(id.as_slice(), &[0x27]);
        assert_eq!(&m3[..19], hex(M3));
    }
    #[test]
    fn edh_4_5_credentials_by_value_preserve_transcript_bytes() {
        let credential_i = hex(CRED_I);
        let credential_r = hex(CRED_R);
        let identity_i = identity(&credential_i, hex(SK_I).try_into().unwrap()).unwrap();
        let identity_r = identity(&credential_r, hex(SK_R).try_into().unwrap()).unwrap();
        assert_eq!(identity_i.credential_bytes(), credential_i);
        assert_eq!(identity_r.credential_bytes(), credential_r);
        let trusted_i = TrustedPeer::new(PeerId(17), &hex(CRED_I)).unwrap();
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        assert_eq!(trusted_i.credential_bytes(), credential_i);
        assert_eq!(trusted_r.credential_bytes(), credential_r);
        let mut ci = Fixed::initiator();
        let mut cr = Fixed::responder();
        let (initiator, m1) = Initiator::start::<512>(&mut ci, &[0x37], &[2]).unwrap();
        let (responder, m2) =
            Responder::start::<512>(&mut cr, &identity_r, &[0x27], m1.as_slice(), true).unwrap();
        let (m3, i) = initiator
            .finish::<512>(&mut ci, &identity_i, &trusted_r, m2.as_slice(), true)
            .unwrap();
        let r = responder
            .finish(&mut cr, &[trusted_i], m3.as_slice())
            .unwrap();
        assert_eq!(i.secret.as_slice(), r.secret.as_slice());
        assert_eq!(i.salt.as_slice(), r.salt.as_slice());
    }
    #[test]
    fn plt_5_edh_6_connection_encoding_bounds_at_each_entry() {
        assert!(sequential_message_3(&[0x48]).is_err());
        let identity_r = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let mut m1 = hex(M1);
        *m1.last_mut().unwrap() = 0x48;
        m1.extend_from_slice(&[0; 8]);
        assert!(
            Responder::start::<256>(&mut Fixed::responder(), &identity_r, &[0x27], &m1, false)
                .is_err()
        );
        let identity_i = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap()).unwrap();
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        for length in 8..24 {
            let mut provider = Fixed::initiator();
            let (initiator, _) = Initiator::start::<256>(&mut provider, &[0x37], &[6, 2]).unwrap();
            let mut m2 = hex(M2);
            m2[34] ^= 0x27 ^ (0x40 | length);
            assert!(
                initiator
                    .finish::<256>(&mut provider, &identity_i, &trusted_r, &m2, false)
                    .is_err()
            );
        }
    }
    #[test]
    fn edh_6_connection_byte_strings_through_seven_bytes_establish_matching_keys() {
        let identity_i = identity(&hex(CRED_I), hex(SK_I).try_into().unwrap()).unwrap();
        let identity_r = identity(&hex(CRED_R), hex(SK_R).try_into().unwrap()).unwrap();
        let trusted_i = TrustedPeer::new(PeerId(17), &hex(CRED_I)).unwrap();
        let trusted_r = TrustedPeer::new(PeerId(23), &hex(CRED_R)).unwrap();
        for length in 0..=7 {
            let id = &[0xa5; 7][..length];
            let mut ci = Fixed::initiator();
            let mut cr = Fixed::responder();
            let (initiator, m1) = Initiator::start::<256>(&mut ci, &[0x37], &[2]).unwrap();
            let (responder, m2) =
                Responder::start::<256>(&mut cr, &identity_r, id, m1.as_slice(), false).unwrap();
            let (m3, i) = initiator
                .finish::<256>(&mut ci, &identity_i, &trusted_r, m2.as_slice(), false)
                .unwrap();
            let r = responder
                .finish(&mut cr, core::slice::from_ref(&trusted_i), m3.as_slice())
                .unwrap();
            assert_eq!(i.sender.as_slice(), id);
            assert_eq!(i.secret.as_slice(), r.secret.as_slice());
            assert_eq!(i.salt.as_slice(), r.salt.as_slice());
        }
    }
}
