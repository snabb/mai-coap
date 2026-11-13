# Roadmap

Copyright (c) 2026 mai-coap contributors.

Proposed future work, in suggested priority order. Nothing here is implemented or part
of the current [requirements](requirements.md), and [conformance](conformance.md)
describes current coverage. Agree on each item's scope before implementing it, then record
the resulting decisions in those documents.

## Near-term priorities

### 1. Support xarxa as the IP stack

Finish validating the native xarxa and xarxa-backed Embassy integrations required by
TR-6–7. Released Embassy stays supported.

- [ ] Validate board drivers and compare complete firmware RAM on real hardware. The
  host bridge and simulated raw-IP drivers don't validate NIC, radio, Thread or
  board-specific memory use.

### 2. Reduce RAM overhead

Continue at the 1,152-byte
datagram bound with unchanged packet, reply-cache, context and handshake capacities, and
preserve default rate-limit admission, exact cached replies and credential snapshot
semantics. Smaller buffers and network pools are separate deployment trade-offs.

- [ ] Select a production xarxa pool size. Compare receive-burst and concurrent-send headroom
  against the copying adapter on real hardware.
- [ ] Attribute retained storage to packet buffers, queues, tables and security contexts, then
  reduce the largest overheads while preserving behavior and cleanup guarantees.
- [ ] Continue compacting endpoint metadata and tables.
- [ ] Choose an explicit worker representation before sharing `Job` buffers. Buffered Block1
  jobs can carry a body larger than the last datagram, and `Job::request` exposes both.
  Observer request copies stay, because notification callbacks read them.
- [ ] Measure credential-count scaling, out-of-order writer cases and production-layout timing.
- [ ] Consider repeatable per-role stack gates alongside global fixture peaks.
- [ ] Assess further admission diagnostics when a concrete need justifies their storage cost.
- [ ] Exercise initiator sessions on hardware once a client-capable integration exists.
- [ ] Validate reductions on real MCUs, including security, Observe and streaming
  paths, and cover loss, cancellation, reconnects and context exhaustion against an independent
  host peer.

### 3. Forward Observe through the proxy

Enable monitoring through gateways using the same proxy paths as ordinary
requests. Direct client/server Observe already works; PRX-8 remains deferred.
Forwarding between separately driven endpoints is available; subscription
forwarding needs its own protocol state and interoperability work.

- [ ] Define bounded forwarding state, subscription sharing or isolation, and
  overload behavior.
- [ ] Forward registration, notifications, refresh and cancellation while
  preserving opaque OSCORE traffic.
- [ ] Cover lost and reordered notifications, block-wise retrieval, downstream
  cancellation, upstream expiry and cleanup with independent interoperability
  checks.

### 4. Implement Echo

Add the deferred return-path check (DOS-4) and prepare the replay-recovery
mechanism needed by optional long-lived OSCORE contexts.

- [ ] Implement client challenge handling and an explicit server challenge policy
  according to [RFC 9175](https://www.rfc-editor.org/rfc/rfc9175.html).
- [ ] Bound challenge processing, retries and state; define freshness and expiry
  with deterministic clocks and an application-supplied secure RNG where needed.
- [ ] Test challenge expiry, repeated challenges, protected requests and retry
  cleanup. Verify interoperability independently.

### 5. Add optional DTLS-backed CoAP (`coaps://`)

Support existing DTLS-only peers. This expands the current scope, which excludes
DTLS; OSCORE remains available for protection through proxies.

- [ ] Evaluate external DTLS backends before selecting one. Check maintenance,
  licensing, client/server roles, authentication profiles, DTLS versions,
  embedded targets and allocation requirements. Preserve empty default features
  and an allocator-independent protocol core.
- [ ] Start with PSK authentication in both roles, selecting the DTLS version and
  cipher profile for concrete interoperability peers. Consider raw public keys
  and certificates separately when an integration requires them.
- [ ] Extend transport/security integration to expose authenticated peer identity
  and session lifetime to authorization and exchange matching. Distinguish
  transport authentication from OSCORE message protection.
- [ ] Integrate bounded session storage, handshake timers, cancellation,
  backpressure and record-size overhead without blocking unrelated endpoint work.
- [ ] Preserve the URI scheme through routing, support the default port 5684,
  and define proxy behavior. Never downgrade a secure destination to plaintext.
  Follow [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.html#section-6.2).
- [ ] Check both roles against independent peers, including handshake loss,
  expiry, session replacement, authorization and capacity recovery. Measure
  embedded memory cost with the chosen backend.

Prioritize this when a concrete integration requires DTLS.

### 6. Improve credential lifecycle APIs

Allow applications to maintain a provisioned fleet without rebuilding the
endpoint to change its trust configuration.

Nonblocking `CredentialStore` lookup and bounded `TrustedPeers<N>` updates are
available. Initiator handshakes snapshot expected credentials; changes do not
automatically invalidate established contexts.

- [ ] Define APIs for replacing and revoking trusted peer credentials and rotating
  the local identity, alongside the existing registration APIs.
- [ ] Specify what happens to handshakes, OSCORE contexts, requests, observations
  and uploads when credentials change. Revocation must have an explicit effect
  on already authenticated work.
- [ ] Cover bounded storage, application-selected peer identities, key cleanup,
  failed updates and continued operation during rotation.

### Release

- [ ] Use linked symbol reports to assess driver outlining and panic/Debug formatting before
  making flash-only changes.
- [ ] Validate integrating applications against the host server with their provisioned
  credentials, exact CCS bytes and addressing. The [credential fixtures](../tests/fixtures/README.md)
  don't establish deployed-node interoperability.
- [ ] Replace the Lakers Git pin with a suitable published release, after regression tests and
  independent interoperability pass.
- [ ] Replace the xarxa and xarxa-backed Embassy Git pins with coherent published releases, after
  regression validation. These pins and the Lakers pin block crates.io publication.

## Protocol follow-ups

### Observe notification versioning

Review notification freshness when a resource changes while a confirmable
notification is awaiting acknowledgement. Retries currently use the stored packet,
and subsequent changes coalesce for a later notification.

- [ ] Settle sequence-number semantics against
  [RFC 7641 section 4.4](https://www.rfc-editor.org/rfc/rfc7641.html#section-4.4),
  including pending retries and clients observing the same resource.
- [ ] Evaluate superseding an outstanding notification with the latest state as
  described in [section 4.5.2](https://www.rfc-editor.org/rfc/rfc7641.html#section-4.5.2).
  Use a new MID and fresh OSCORE Partial IV for a newly protected notification;
  preserve the retry counter, backoff and NSTART limits required by that procedure.
  Updating an Observe value alone does not deliver a newer representation.
- [ ] Cover lost notifications and ACKs, reordered and duplicate packets, late
  ACKs for superseded notifications, coalesced changes and retry exhaustion.
  Verify both unprotected and OSCORE observations with independent peers.
- [ ] Update the conformance decision after agreeing on and validating the design.
  Preserve current retransmission behavior until then.

### Proof and fuzz-oracle gaps

From an independent review of the Kani harnesses and fuzz oracles against the RFCs.

- [ ] Fuzz the writers from arbitrary inputs, not only from parsed values:
  link-format href/attribute injection, `compose` from arbitrary options, and
  `OscoreOption::encode` from arbitrary fields.
- [ ] Prove critical/elective option handling (RFC 7252 section 5.4.1) and
  acceptance of integers with leading zero bytes (section 3.2).
- [ ] Prove the builder with several options and extended lengths; the current
  harness emits one option of at most four bytes.
- [ ] Prove `check_options`, `processed` and `process_in_place` over datagrams with
  a 269+ byte option value. The parse harness is limited to 12 bytes by memory
  (24 bytes exceeded 13 GB), so this needs a larger runner; the codec fuzz target
  covers these paths meanwhile.
- [ ] Prove the OSCORE request composition of RFC 8613 section 8.2 steps 3-6
  (replay check before decryption, window update only after verification). The
  window is proven in isolation; unit tests and the plaintext fuzz oracle check
  the composition.
- [ ] Fuzz OSCORE responses: request binding, request-nonce reuse versus own
  Partial IV, and strictly increasing Partial IVs across failed protect calls.
- [ ] Check Block1 reassembly against a reference model, and that the served
  Block2 SZX does not exceed the requested one.
- [ ] The codec fuzz target skips inputs the parser accepts but the builder
  refuses; assert the reason instead.

## Optional resource integration

- [ ] **Shared/proxy packet ownership:** prototype bounded caller-owned packet
  leases across command, completion and forwarding states. Preserve datagram and
  concurrency limits, exact retries, context pins and progress when either
  endpoint's command slots or packet pool are full. Compare static storage,
  future storage and construction/poll peaks before selecting a pool budget.
- [ ] **Capacity-independent driver helpers:** evaluate temporary runtime table
  views if significant duplicate code remains after fixed endpoint roles. Keep
  the const-generic storage facade and avoid references into the owning object.
- [ ] **Proxy scratch storage:** evaluate merging URI normalization directly into
  caller output while preserving option order and opaque values. Measure linked
  frames and runtime stack before claiming savings; current source-level buffers
  are accounted for in [sizes](sizes.md#design-trade-offs).
- [ ] **Dependency cleanup:** reassess Lakers-private transition and EAD storage
  zeroization when its public API permits explicit cleanup. Keep the documented
  wrapper cleanup boundary accurate.
- [ ] **CBOR resources (API-5 SHOULD):** design an optional no_std minicbor helper
  for bounded encoding/decoding, caller-owned buffers and application-selected
  error handling. Keep the core independent of CBOR crates. Validate encoded
  resources, insufficient buffers and large random-access representations.
- [ ] **Portable host transport:** the supplied `std` UDP transport and host clock
  currently require Linux. Define a separate portable unicast adapter's metadata
  contract before adding macOS/Windows runtime support; do not invent destination
  addresses or silently claim multicast/source-selection support.

## Command-line client

- [ ] **Multicast discovery:** accept multicast destinations for `/.well-known/core` through
  `Handle::discover_multicast`, with `-B` as the collection time. Other multicast requests
  stay unsupported (section 13).
- [ ] **EDHOC context cache (`--session-cache`):** optional reuse of derived contexts between
  runs, to avoid one handshake per process. Store them in `$XDG_RUNTIME_DIR`, not `~/.cache`,
  since a restored counter means nonce reuse, and don't cache if it's unset. Reserve a
  sequence range under a file lock, fsynced before first use and never rolled back. Key
  entries by the own and peer credential hashes, with mode `0600`, an ownership check and
  a lifetime of about an hour. This needs library context export and import and a sequence
  limit behind a feature, Kani coverage, and an RFC 8613 Appendix B.1 interpretation:
  `requirements.md` exempts EDHOC contexts because they live only in RAM.

## Conditional work

- [ ] **Static and persistent OSCORE contexts (OSC-20):** add only for deployments
  that need provisioned contexts or continuity across reboot. Require sender
  sequence persistence and replay recovery using Echo before exposing the
  feature; test reboot and interrupted persistence. Keep fresh EDHOC-derived
  RAM contexts usable without persistence.
- [ ] **Thread commissioning or management tooling:** define the exact Thread
  role and version first. DTLS is only one dependency; credential profiles,
  MeshCoP endpoints, TLVs and commissioning state machines need their own scope
  and interoperability work. Application CoAP over a Thread IP network does not
  require implementing those roles. This would not make the crate a Matter stack.

Additional cipher suites, EDHOC authentication methods, certificate support and
broader protocol extensions should follow a concrete integration need rather
than precede the interoperability and embedded validation above.
