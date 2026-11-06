//! Transient context table and endpoint protection (OSC-15–16).
use super::{
    BoundedContext, MAX_ID_CONTEXT_BYTES, OscoreOption, RequestBinding, ResponseNonce,
    assert_context_capacity,
};
use crate::codec::{MessageView, OptionNumber};
use crate::{
    Error,
    endpoint::{Prepared, Protection, Target},
    security::{CryptoProvider, SecurityState},
};

struct Entry<const ID_CONTEXT_BYTES: usize> {
    context: BoundedContext<ID_CONTEXT_BYTES>,
    generation: u64,
    pins: usize,
    last_used: u64,
}
/// Opaque context lease paired with the request's authenticated response binding.
#[derive(Debug)]
pub struct Binding {
    generation: u64,
    request: RequestBinding,
}
/// Endpoint OSCORE layer with a bounded LRU table; contexts exist only in RAM.
/// Installation and successful cryptographic operations update recency
/// internally. Failed operations do not refresh it; pinned contexts cannot be
/// evicted.
/// `ID_CONTEXT_BYTES` bounds each installed context's retained ID Context, with
/// [`MAX_ID_CONTEXT_BYTES`] by default. Construction rejects larger capacities at
/// compile time. Installed contexts must use the same bound.
pub struct Oscore<
    P,
    const CONTEXTS: usize = 4,
    const ID_CONTEXT_BYTES: usize = MAX_ID_CONTEXT_BYTES,
> {
    /// Shared provider for OSCORE, EDHOC, MID and token entropy.
    pub(crate) provider: P,
    entries: heapless::Vec<Entry<ID_CONTEXT_BYTES>, CONTEXTS>,
    next_generation: u64,
    activity: u64,
    evictions: u64,
}
impl<P, const CONTEXTS: usize, const ID_CONTEXT_BYTES: usize>
    Oscore<P, CONTEXTS, ID_CONTEXT_BYTES>
{
    /// Creates an empty transient context table.
    ///
    /// ```
    /// use mai_coap::oscore::{MAX_ID_CONTEXT_BYTES, Oscore};
    /// let _ = Oscore::<(), 4, MAX_ID_CONTEXT_BYTES>::new(());
    /// ```
    ///
    /// Capacities above [`MAX_ID_CONTEXT_BYTES`] fail at compile time:
    ///
    /// ```compile_fail,E0080
    /// use mai_coap::oscore::{MAX_ID_CONTEXT_BYTES, Oscore};
    /// let _ = Oscore::<(), 4, { MAX_ID_CONTEXT_BYTES + 1 }>::new(());
    /// ```
    pub const fn new(provider: P) -> Self {
        const { assert_context_capacity::<ID_CONTEXT_BYTES>() };
        Self {
            provider,
            entries: heapless::Vec::new(),
            next_generation: 1,
            activity: 0,
            evictions: 0,
        }
    }
    /// Installs a fresh key epoch selected by its authenticated peer identity.
    /// Never reconstruct a used context from static secrets: persistent sender
    /// sequences and replay recovery are intentionally unsupported.
    pub fn install_fresh(
        &mut self,
        context: BoundedContext<ID_CONTEXT_BYTES>,
    ) -> Result<(), Error> {
        self.install_epoch(context).map(|_| ())
    }
    pub(crate) fn install_epoch(
        &mut self,
        context: BoundedContext<ID_CONTEXT_BYTES>,
    ) -> Result<u64, Error> {
        if CONTEXTS == 0 || self.next_generation == u64::MAX {
            return Err(Error::Capacity);
        }
        if self.entries.iter().any(|e| {
            e.context.recipient_id() == context.recipient_id()
                && e.context.id_context() == context.id_context()
        }) {
            return Err(Error::Capacity);
        }
        if self.entries.is_full() {
            let index = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.pins == 0)
                .min_by_key(|(_, e)| e.last_used)
                .map(|(i, _)| i)
                .ok_or(Error::Capacity)?;
            self.entries.swap_remove(index);
            self.evictions += 1;
        }
        let generation = self.next_generation;
        self.next_generation += 1;
        self.activity = self.activity.saturating_add(1);
        self.entries
            .push(Entry {
                context,
                generation,
                pins: 0,
                last_used: self.activity,
            })
            .map_err(|_| Error::Capacity)?;
        Ok(generation)
    }
    /// Whether a context can be installed without evicting an in-use epoch.
    #[cfg(any(feature = "edhoc", all(test, feature = "software-crypto")))]
    pub(crate) fn has_capacity(&self) -> bool {
        self.next_generation != u64::MAX
            && (!self.entries.is_full() || self.entries.iter().any(|e| e.pins == 0))
    }
    /// Tests connection-ID uniqueness before an EDHOC handshake allocates one.
    #[cfg(feature = "edhoc")]
    pub(crate) fn id_available(&self, recipient: &[u8]) -> bool {
        self.entries
            .iter()
            .all(|e| e.context.recipient_id() != recipient)
    }
    /// Whether an incoming OSCORE identifier locates an established epoch.
    #[cfg(any(feature = "edhoc", all(test, feature = "software-crypto")))]
    pub(crate) fn has_recipient(&self, kid: &[u8], id_context: Option<&[u8]>) -> bool {
        self.entries
            .iter()
            .any(|e| e.context.recipient_id() == kid && e.context.id_context() == id_context)
    }
    /// Number of contexts held in RAM.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether no contexts have been established.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Number of unpinned contexts evicted due to table pressure.
    pub const fn evictions(&self) -> u64 {
        self.evictions
    }
    /// Removes all epochs for an idle peer, independently of its transport addresses.
    /// Returns `Capacity` without changes while any epoch is pinned. Cancel that
    /// peer's exchanges, observations and uploads before retiring its credentials.
    pub fn forget_peer(&mut self, peer: crate::security::PeerId) -> Result<(), Error> {
        if self
            .entries
            .iter()
            .any(|entry| entry.context.peer == peer && entry.pins != 0)
        {
            return Err(Error::Capacity);
        }
        self.entries.retain(|entry| entry.context.peer != peer);
        Ok(())
    }
    #[cfg(feature = "edhoc")]
    pub(crate) fn retire_unpinned(&mut self, peer: crate::security::PeerId) {
        // Rekeying may coexist with an observation or body using the old epoch.
        self.entries
            .retain(|entry| entry.context.peer != peer || entry.pins != 0);
    }
    fn touch(&mut self, index: usize) {
        self.activity = self.activity.saturating_add(1);
        self.entries[index].last_used = self.activity;
    }
    fn bound_index(&self, binding: &Binding) -> Result<usize, Error> {
        self.entries
            .iter()
            .position(|e| e.generation == binding.generation)
            .ok_or(Error::ContextNotFound)
    }
    /// Pins a live Block1 or observation reference independently of its exchange.
    pub(crate) fn pin(&mut self, generation: u64) -> Result<(), Error> {
        let e = self
            .entries
            .iter_mut()
            .find(|e| e.generation == generation)
            .ok_or(Error::ContextNotFound)?;
        e.pins = e.pins.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }
    /// Releases a live Block1 or observation reference.
    pub(crate) fn unpin(&mut self, generation: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.generation == generation) {
            e.pins = e.pins.saturating_sub(1);
        }
    }
}
impl<P: CryptoProvider, const CONTEXTS: usize, const ID_CONTEXT_BYTES: usize> Protection
    for Oscore<P, CONTEXTS, ID_CONTEXT_BYTES>
{
    fn context_evictions(&self) -> u64 {
        self.evictions
    }
    fn pin_epoch(&mut self, generation: u64) -> Result<(), Error> {
        self.pin(generation)
    }
    fn unpin_epoch(&mut self, generation: u64) {
        self.unpin(generation);
    }
    type Binding = Binding;
    fn random(&mut self, bytes: &mut [u8]) {
        self.provider.random(bytes);
    }
    fn requires_request_retention(&self, _: Target) -> bool {
        false
    }
    fn outgoing<const DATAGRAM_BYTES: usize>(
        &mut self,
        target: Target,
        request: MessageView<'_>,
        output: &mut [u8],
    ) -> Result<Prepared<Binding>, Error> {
        let Some(peer) = target.peer else {
            output
                .get_mut(..request.as_bytes().len())
                .ok_or(Error::Capacity)?
                .copy_from_slice(request.as_bytes());
            return Ok(Prepared::Request {
                length: request.as_bytes().len(),
                binding: None,
            });
        };
        let index = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.context.peer == peer)
            .max_by_key(|(_, entry)| entry.generation)
            .map(|(index, _)| index)
            .ok_or(Error::ContextNotFound)?;
        let (n, request) = self.entries[index]
            .context
            .protect_request::<DATAGRAM_BYTES>(&mut self.provider, request, output)?;
        self.entries[index].pins = self.entries[index]
            .pins
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        self.touch(index);
        Ok(Prepared::Request {
            length: n,
            binding: Some(Binding {
                generation: self.entries[index].generation,
                request,
            }),
        })
    }
    fn incoming<const DATAGRAM_BYTES: usize>(
        &mut self,
        request: MessageView<'_>,
        _: crate::transport::Metadata,
        output: &mut [u8],
    ) -> Result<(usize, SecurityState, Option<Binding>), Error> {
        let Some(option) = request.option(OptionNumber::OSCORE) else {
            output
                .get_mut(..request.as_bytes().len())
                .ok_or(Error::Capacity)?
                .copy_from_slice(request.as_bytes());
            return Ok((request.as_bytes().len(), SecurityState::Unprotected, None));
        };
        let option = OscoreOption::parse(option.value)?;
        let index = self
            .entries
            .iter()
            .position(|e| {
                Some(e.context.recipient_id()) == option.kid
                    && e.context.id_context() == option.kid_context
            })
            .ok_or(Error::ContextNotFound)?;
        let (n, request) = self.entries[index]
            .context
            .unprotect_request::<DATAGRAM_BYTES>(&mut self.provider, request, output)?;
        self.entries[index].pins = self.entries[index]
            .pins
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        self.touch(index);
        Ok((
            n,
            SecurityState::Protected {
                peer: self.entries[index].context.peer(),
            },
            Some(Binding {
                generation: self.entries[index].generation,
                request,
            }),
        ))
    }
    fn response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Binding,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let i = self.bound_index(binding)?;
        let n = self.entries[i].context.protect_response::<DATAGRAM_BYTES>(
            &mut self.provider,
            response,
            &mut binding.request,
            ResponseNonce::Fresh,
            output,
        )?;
        self.touch(i);
        Ok(n)
    }
    fn received_response<const DATAGRAM_BYTES: usize>(
        &mut self,
        response: MessageView<'_>,
        binding: &mut Binding,
        output: &mut [u8],
    ) -> Result<usize, Error> {
        let i = self.bound_index(binding)?;
        let n = self.entries[i]
            .context
            .unprotect_response::<DATAGRAM_BYTES>(
                &mut self.provider,
                response,
                &mut binding.request,
                output,
            )?;
        self.touch(i);
        Ok(n)
    }
    fn release(&mut self, binding: Binding) {
        self.unpin(binding.generation);
    }
    fn generation(&self, binding: &Binding) -> Option<u64> {
        Some(binding.generation)
    }
}

#[cfg(all(test, feature = "software-crypto"))]
mod tests {
    use super::*;
    use crate::oscore::Context;
    use core::net::SocketAddr;
    fn target(remote: SocketAddr, peer: u32) -> Target {
        Target {
            peer: Some(PeerId(peer)),
            ..Target::new(remote)
        }
    }
    use crate::{crypto::SoftwareCrypto, security::PeerId};

    #[test]
    fn osc_15_admission_checks_generation_and_space_before_installation() {
        let mut table = Oscore::<_, 1>::new(SoftwareCrypto::new(rand::rng()));
        assert!(table.has_capacity());
        table.next_generation = u64::MAX;
        assert!(!table.has_capacity());
        let empty = Oscore::<_, 0>::new(SoftwareCrypto::new(rand::rng()));
        assert!(!empty.has_capacity());
    }
    #[test]
    fn osc_15_failed_operations_do_not_refresh_recency() {
        let remote = "192.0.2.1:5683".parse().unwrap();
        let mut tables = [0u8, 1].map(|id| {
            let mut table = Oscore::<_, 1>::new(SoftwareCrypto::new(rand::rng()));
            let context = Context::derive(
                &mut table.provider,
                &[7; 16],
                None,
                &[id],
                &[1 - id],
                None,
                PeerId(1),
            )
            .unwrap();
            table.install_epoch(context).unwrap();
            table
        });
        let [client, server] = &mut tables;
        let request = MessageView::parse(&[0x40, 1, 0, 0]).unwrap();
        assert!(matches!(
            client.outgoing::<128>(target(remote, 1), request, &mut []),
            Err(Error::Capacity)
        ));
        assert_eq!(client.activity, 1);
        let mut request_bytes = [0; 128];
        let Prepared::Request {
            length,
            binding: Some(mut client_binding),
        } = client
            .outgoing::<128>(target(remote, 1), request, &mut request_bytes)
            .unwrap()
        else {
            panic!("installed context must protect the request")
        };
        assert_eq!(client.activity, 2);
        let request = MessageView::parse(&request_bytes[..length]).unwrap();
        let metadata = crate::transport::Metadata {
            remote,
            local: "192.0.2.2".parse().unwrap(),
            interface: None,
            original_len: length,
        };
        let (_, _, binding) = server
            .incoming::<128>(request, metadata, &mut [0; 128])
            .unwrap();
        let mut server_binding = binding.unwrap();
        assert_eq!(server.activity, 2);
        assert!(matches!(
            server.incoming::<128>(request, metadata, &mut [0; 128]),
            Err(Error::Replay)
        ));
        assert_eq!(server.activity, 2);
        let response = MessageView::parse(&[0x60, 69, 0, 0]).unwrap();
        assert_eq!(
            server.response::<128>(response, &mut server_binding, &mut []),
            Err(Error::Capacity)
        );
        assert_eq!(server.activity, 2);
        let mut response_bytes = [0; 128];
        let length = server
            .response::<128>(response, &mut server_binding, &mut response_bytes)
            .unwrap();
        assert_eq!(server.activity, 3);
        let mut tampered = response_bytes;
        tampered[length - 1] ^= 1;
        assert!(
            client
                .received_response::<128>(
                    MessageView::parse(&tampered[..length]).unwrap(),
                    &mut client_binding,
                    &mut [0; 128]
                )
                .is_err()
        );
        assert_eq!(client.activity, 2);
        client
            .received_response::<128>(
                MessageView::parse(&response_bytes[..length]).unwrap(),
                &mut client_binding,
                &mut [0; 128],
            )
            .unwrap();
        assert_eq!(client.activity, 3);
        client.release(client_binding);
        server.release(server_binding);
    }

    #[test]
    fn osc_15_installation_and_authenticated_use_update_lru_without_a_clock() {
        let mut table = Oscore::<_, 3>::new(SoftwareCrypto::new(rand::rng()));
        let mut generations = [0; 6];
        let remote = |id: u8| SocketAddr::from(([192, 0, 2, id + 1], 5683));
        for id in 0..5u8 {
            let context = Context::derive(
                &mut table.provider,
                &[7; 16],
                None,
                &[0x80],
                &[id],
                None,
                PeerId(id.into()),
            )
            .unwrap();
            generations[usize::from(id)] = table.install_epoch(context).unwrap();
        }
        assert!(!table.has_recipient(&[0], None));
        assert!(!table.has_recipient(&[1], None));
        assert!(table.has_recipient(&[2], None));
        assert!(table.has_recipient(&[3], None));
        assert!(table.has_recipient(&[4], None));
        table.pin(generations[2]).unwrap();
        let request = MessageView::parse(&[0x40, 1, 0, 0]).unwrap();
        let prepared = table
            .outgoing::<128>(target(remote(3), 3), request, &mut [0; 128])
            .unwrap();
        if let Prepared::Request {
            binding: Some(binding),
            ..
        } = prepared
        {
            table.release(binding);
        } else {
            panic!("installed context must protect the request");
        }
        let context = Context::derive(
            &mut table.provider,
            &[7; 16],
            None,
            &[0x80],
            &[5],
            None,
            PeerId(5),
        )
        .unwrap();
        generations[5] = table.install_epoch(context).unwrap();
        assert!(table.has_recipient(&[2], None), "pinned oldest context");
        assert!(
            table.has_recipient(&[3], None),
            "most recently used context"
        );
        assert!(!table.has_recipient(&[4], None));
        table.unpin(generations[2]);
        assert_eq!(table.evictions(), 3);
    }
}
