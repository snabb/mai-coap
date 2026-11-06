# Implementation and conformance

Copyright (c) 2026 mai-coap contributors.

How mai-coap implements its [requirements](requirements.md): decisions, interpretations,
evidence and validation limits. A module existing does not establish conformance;
acceptance requires its tests and independent interop. For usage, see the [user
guide](guide.md) and [integration guide](integration.md).

## Status

The [requirement matrix](#requirement-matrix) maps requirements to implementation and
evidence. Explicitly deferred optional items: static OSCORE contexts (OSC-20), proxy
Observe forwarding (PRX-8) and the Echo return-path check (DOS-4). Optional CBOR
resource integration (API-5 SHOULD) is also deferred, so applications supply their
encodings. Pre-shared contexts are test fixtures. Follow-up work is in the
[roadmap](todo.md).

## Decisions

- **Package:** one public crate, `mai-coap`, MIT OR Apache-2.0. Lakers' BSD-3-Clause
  notice ships with binaries through
  [THIRD_PARTY_NOTICES.txt](../THIRD_PARTY_NOTICES.txt).
- **Rust:** 1.97 is the declared minimum, and CI also checks current stable. The
  `memory-layout` protocol fixture has compiled on the ESP 1.97 Xtensa toolchain. That was a
  manual compile check, not part of CI, and not an ESP HAL integration, linked firmware
  or hardware result.
- **Transport:** the supplied std transport and host clock require Linux; a portable
  adapter is future work. An embedded-nal-async adapter is out of scope: its async-only
  send API does not expose the nonblocking acceptance contract the independently driven
  receive and send handles require.
- **Lakers:** pinned to `de1bf6bdb562eda7e29db47ec8540e759e68375d` until a published
  release provides the required public API. Validate dependency changes with regression
  tests, independent interoperability and the embedded target matrix.
- **Crypto versions:** software-provider lockfiles include `crypto-bigint` 0.7.10,
  `ctutils` 0.4.8 and `inout` 0.2.5, which carry upstream arithmetic and constant-time
  fixes, including 32-bit, Thumb-1 and RISC-V code generation. Applications must update
  their own lockfiles to receive them. Validation covers the host matrix, Rust 1.97, four
  no_std targets with QEMU fixtures, fuzz smoke tests and aiocoap interoperability. The
  M0 EDHOC fixture exercises initiator startup; larger targets run both roles.
  Functional checks don't establish constant-time execution on every target.
- **AES version:** lockfiles hold `aes` 0.9.3. Version 0.9.4 stores a smaller key schedule
  but rebuilds the native-width one on the stack per call. The software provider keeps
  no cipher between operations, so that gains nothing and costs about 3 KiB of flash on
  Cortex-M4 and 504 bytes of OSCORE stack on M4 and M33. The manifest doesn't exclude
  newer releases, so a fresh application lockfile selects 0.9.4 unless it runs
  `cargo update -p aes --precise 0.9.3`.
- **Logging:** features are mutually exclusive, and dependency logging stays disabled.

## Public API boundary

Supported standalone APIs:

- codec and URI operations, owned `Response` and borrowed `ResponseWriter`
- OSCORE `Context`, `BoundedContext`, `RequestBinding`, `ResponseNonce`, `OscoreOption`
- EDHOC role and credential types
- with `block`: Block2, `Download`, `etag`, server-side `BodyWindow`
- with `block1`: `BodyKey`, `StreamingUpload`, `BufferedUpload`, `Progress`,
  `UploadSink`, client uploads. Callers own transfer storage, expiry scheduling and sink
  cleanup.
- for custom drivers: `with_send_window` and its restricted `SendWindow` view,
  `receive`, `poll`, `front_outgoing`, `complete_outgoing`, `discard_outgoing`,
  `poll_resources`, `deadline` and optional `poll_observations`. Resource polling
  includes notifications. Drivers preserve metadata and pending sends, arrange command
  wakeups, pass the task context to resource polling and honor endpoint and application
  deadlines.
- `Oscore`: fresh installation by peer identity, peer retirement and counts

Internal: Oscore provider, generation, capacity and pin bookkeeping; reliability, rate
and Observe scheduling state; Lakers and wire-format adapters. Narrow hidden
`_test-support` hooks serve repository fuzz and target harnesses only. Ordinary
integration tests use supported APIs, and primitive and model tests live inside the
crate.

Configuration and output types identified in API-5 are non-exhaustive, with constructors
or defaults for external construction. Response content setters return `ResponseError`,
which maps to 5.00 only for locally constructed responses. Protocol `Error` mappings
stay contextual, and `RunError` preserves its source where supported. Owned
`Response<D>` keeps independent D-byte option-value and payload bounds, and `encode` can
use a larger caller-supplied output.

### OSCORE ID Context bound

`Context` keeps the default 255-byte ID Context capacity. `BoundedContext<N>`,
`Oscore<P, CONTEXTS, N>` and the final `Edhoc` type parameter select a bound.
`MAX_ID_CONTEXT_BYTES` (255) is the shared limit, and larger capacities are rejected at
compile time.

- Oversized ID Contexts fail with `Capacity` before key derivation, without truncation.
- Zero capacity accepts absent and present-empty IDs as distinct values: RFC 8613
  section 3.2.1 derives with CBOR `nil` versus an empty byte string.
- RFC 9528 Appendix A.1 supplies no OSCORE ID Context, so EDHOC-derived contexts fit
  zero capacity.
- The 255-byte bound matches the one-byte `kid context` wire length. RFC 8613 section
  3.3 permits longer abstract ID Contexts, which this wire profile does not support.

Evidence: unit tests at capacities 0, 1 and 255; a storage Kani harness over all inputs
up to eight bytes at capacities zero and seven; the plaintext fuzz oracle at zero
capacity; a host compact-endpoint regression through both handshake modes with one
context and handshake per peer. Slice runtime gates and `memory-layout` fixtures keep the
default, and native xarxa gates use zero.

## Bounded state and scheduling

Capacities are const arguments sized per table and buffer.
[Integration](integration.md#storage) lists the defaults and overload results.

### Exchanges and independent capacities

`OUTBOUND` bounds the shared exchange table for client requests, deferred CON responses
and CON notifications; command and observer slots add no exchange capacity. `OUTBOUND`,
`COMMANDS`, `DEFERRED` and `BODY_CONTEXTS` are independent and permit zero.

- Zero outbound capacity refuses deferred CON work (NON responses can still be deferred
  with command and ticket capacity), and declines Observe registration by returning the
  current response without Observe, because later CON notifications need an exchange
  slot.
- Immediate handlers work while deferred admission is unavailable, and workers and
  proxies check `deferred_ticket` before accepting jobs. Disabled capabilities fail
  promptly; transient pressure waits.
- Packet reservation precedes application handling and protection side effects.
  Reservations are scoped and passed explicitly, and queueing returns the retained
  reference used for retries or duplicate replies.
- Handshake and recovery continuation failures complete the operation promptly,
  including packet pool exhaustion after an ACK, rather than leaving an exchange with no
  retry until timeout.
- Protection bindings have a scoped owner until transferred into an exchange, deferred
  ticket or observation. Failed encoding and table insertion release it. Failed
  body-lease insertion also unpins the epoch and aborts its application body. Rejected
  NON exchanges release both the queued reference and their local packet owner.
- Request admission and execution share readiness and retention checks. Admission
  snapshots contain owned metadata, and parsed views never escape `Shared`'s critical
  section. Malformed queued requests are claimed and completed with an error outside the
  lock, freeing their command slot.
- Plaintext request retention is conditional on Observe or the protection layer's
  `requires_request_retention` query (conservative for external implementations).

`tests/server_send_acceptance.rs` covers zero-exchange refusal, server CON
retransmissions after acceptance, local-expiry cleanup and notification timing without
the client role.

### Response construction

`Application::handle`, proxy forwarding and `Protection::control` use
`ResponseWriter<'_, D>` over a temporary datagram arena, with exact RFC 7252 section 3
wire accounting for the actual token and all option extensions. Setters preflight before
mutation. Option values stay sorted stably, the payload occupies the arena tail, and
finalization expands headers backwards in place. Protected replies pass that view
directly to `Protection::response`, keeping the reserved output packet and fresh-nonce
5.00 fallback. Unprotected replies copy it into the selected packet storage. Internal
render and scratch helpers deliberately clear an existing body, including on failure;
public content setters stay transactional.

**Cleanup.** Protected response construction tracks prefix and tail write high-water
marks and erases their union on normal, error and unwinding exits. Render and scratch
callbacks mark their whole offered window before entry. This is a temporary-buffer
guarantee only. Public plaintext, opaque forwarding, multicast and unprotected error
arenas are not erased, and explicit owned copies, caller-managed writers, decoded input
and dependency-private storage are outside it. Panic-abort, reset and power loss don't
run it.

**Discovery probes** reuse raw arena space independently of final-payload overhead, and
a minimum-datagram test preserves the bare 5.00 fallback when EDHOC diagnostics don't
fit beside an eight-byte token.

Evidence: writer unit tests at literal wire thresholds; one table run through owned and
borrowed responses; the `response_writer` fuzz target against a literal RFC wire
encoder; Kani size-arithmetic proofs for two symbolic ordered options and for render
cleanup on a 16-byte arena; a sentinel proptest of cleanup over generated sequences;
endpoint tests with real OSCORE replies and a host-only wipe witness. The proofs do not
cover in-place byte movement, arbitrary setter sequences, or endpoint stack memory after
a protection error.

### Incoming protection

`Protection::incoming` receives the request, metadata and caller-provided output buffer
in one call, and returns the decoded length, security state and optional binding. There
is no borrowed-input fast path. EDHOC and OSCORE use the same copying contract. Opaque
forwarding precedes local protection, and control precedes resource policy. Deferred,
Observe and body retention keep their explicit owned bytes and leases.

### Deferred responses

`respond()` returns `ResponseOperation` with output `Result<(), Error>` at queue
handoff. Later failures are not returned to the caller, and there is no dedicated
ACK-timeout counter. The built-in proxy and upload worker use it. Opt-in
`respond_confirmed()` waits for ACK, RST or retransmission timeout on CON and local
acceptance on NON, including initial local failures, and only it keeps a command slot
while waiting. Dropping before handoff cancels submission; afterward it detaches the
waiter while transport and CoAP retries continue. The handoff and cancellation decision
share a critical section.

**Budgets.** `ResponseWriter::set_deferred_timeout` sets explicit processing budgets,
and owned `Response` stores only content, so a submitted reply can't change an admitted
ticket's budget. Tickets stay valid for the budget plus one incoming exchange lifetime,
or one lifetime without a budget. `WorkQueue` supplies its timeout. The proxy supplies
its destination profile's exchange lifetime and enforces that budget from admission,
including NSTART queueing, returning 5.04 on expiry. Relayed responses stay retained
across `Capacity` completions until delivery succeeds or the ticket is cancelled or
expires.

Tests: `tests/deferred_delivery.rs` (milestones, detachment, stale replies, slot reuse),
unit tests for cancellation during preparation, and an endpoint fuzz oracle for
completion milestones.

### Duplicate detection

`DEDUP_ENTRIES` metadata records and `CACHED_REPLIES` references to full replies are
separate bounds. Silence, reclaimed replies and replies up to four bytes share one small
enum alternative. Records store canonical peer address, port, zone, local destination
and MID, while transport metadata keeps original scope and flow values.

- **Eviction.** Record pressure evicts the oldest record, and releases its reply slot
  before pool reclamation. Pool pressure prefers the oldest full reply from the same
  remote socket and local address, then the oldest globally, keeping duplicate metadata
  and expiry. This is a heuristic: a new request doesn't prove an earlier reply arrived.
  Pool pressure reclaims only cache-exclusive replies, so it can't overwrite bytes
  pinned by a send or exchange.
- **Reclaimed reply.** A duplicate CON receives an unprotected piggybacked 5.03 with
  Max-Age 0, the request's MID and token, subject to send-queue space, a free packet
  slot and the unprotected-response rate limit. Refusals release expired records first,
  including for drivers calling `receive()` without `poll()`, and never reclaim a live
  cached reply. With no free slot, the duplicate is suppressed without queueing a
  refusal or incrementing `dropped_messages`. This bounded-storage exception to the
  same-ACK recommendation of [RFC 7252 section
  4.5](https://www.rfc-editor.org/rfc/rfc7252.html#section-4.5) ends the exchange
  without dispatching again or attempting OSCORE replay verification. It doesn't reveal
  whether the original operation succeeded. Silent records and duplicate NON requests
  stay silent.
- **Replay.** Retained replies replay exact bytes. After record eviction, ordinary
  policy and OSCORE replay checks apply, and any newly protected response uses a fresh
  sender sequence number.
- **Capacity.** `Capacity` admissions leave the table unchanged, including expired
  records. The internal table permits a zero full-reply budget for silence and inline
  replies, but endpoints reject zero record or full-reply capacities.

**Counters.** `duplicates` counts recognized duplicates before attempting to resend or
refuse. `dedup_record_evictions` counts live metadata loss, and `dedup_reply_drops`
counts reply-only reclamation. Both can increment on one admission; expiry, replacement
and replies released with record eviction don't increment the reply-drop counter.
`dedup_reply_misses` counts rate-admitted duplicate CONs with a reclaimed reply,
including failed refusal attempts; a full send queue rejects requests before lookup.
`rate_limited` counts each endpoint unprotected-response budget rejection once,
including work suppressed before duplicate lookup, multicast work, resets and
protected-request error and refusal responses. It doesn't increment `dropped_messages`
or count silent decisions without a limiter check. Proxy admission returning 4.29 uses a
separate limiter.

Tests: `tests/rate_limited.rs`, `tests/endpoint.rs`, `tests/counters.rs`, cache unit
tests and a bounded model property test in `src/messaging/tests.rs`.

### Send queue and message IDs

- `SEND_QUEUE` defaults to 16; zero is rejected. Retries wait for queue space without
  advancing their timers. Commands stay queued and observations registered while send
  space or reusable MIDs are unavailable. The driver polls deferred work after draining
  sends and wakes at MID reuse deadlines.
- Per-message failures increment `dropped_messages` and don't stop the driver, including
  handshake or recovery failures that complete the client operation with an error.
  `Protection`, `SequenceExhausted`, `ContextNotFound` and `Edhoc` also increment
  `protection_failures`. Replies that can't be queued are dropped and counted, leaving
  peers to retry.
- Every due observer is visited once per poll. Client refresh and cancellation preserve
  the registered method, options and payload. Due work wakes immediately with NSTART
  credit; queue, packet and MID pressure wait on their progress sources without
  spinning.
- Message IDs use sixteen quarantine blocks of 4096 IDs, relative to the initial random
  seed. Each block waits for its own latest expiry before reuse.
- A 4.29 delays only its source destination, honoring Max-Age. A full backoff table
  replaces the earliest-expiring destination, which may permit an earlier retry. No
  aggregate backoff applies to unrelated destinations. Local requests still pass
  protection and policy checks when the proxy's deferred table is full.
- Source-table pressure replaces the rate bucket with the most remaining credit.
  Aggregate admission stays enforced, and source credit stays per IP address.

### Peer identity and addressing

Outgoing protection is selected only by explicit `Target::peer`, looking up the newest
epoch for that identity and surviving next-hop changes. URI authority is distinct from
peer identity and the UDP route. No address-keyed security policy or implicit context
selection exists, and installing a context doesn't select a peer. Installation and
successful protection or unprotection update context recency; failures don't. Pinned
contexts can't be evicted. Standalone contexts expose both `ResponseNonce` modes,
including the request-nonce mode of RFC 8613 Appendix C.8; its binding consumes the
one-use permission even on failure, and endpoints always select `Fresh`.

IPv6 peer matching ignores flow information and irrelevant global-unicast scope IDs,
keeping link-local and multicast zones. ACK and response matching, NSTART, backoff,
probing, duplicate records, EDHOC sessions, observations and upload keys share this
rule. Transport routes and received metadata keep original values
(`tests/ipv6_peers.rs`).

`Handle::client` creates a caller-owned profile, and GET, block transfers, Observe,
refreshes, cancellation, recovery and handshakes keep its route, expected peer and
transmission parameters. Absolute URIs name the origin, and `through_proxy` explicitly
adds Proxy-Scheme. `Client::get` returns complete non-2.xx replies, and block-transfer
helpers check codes. `Router::observable` returns a typed resource ID scoped to its
endpoint's application tree and rejects another route's ID without mutation; composed
applications maintain uniqueness themselves.

### Shared counters

With `shared-counters`, `Shared` holds one owned `Counters` snapshot independent of
`COMMANDS`. `run()` publishes it at the start of each pass before application polling,
before waiting, and before returning, including fatal errors. It starts at zero, may lag
and stays readable after the driver stops. Reads copy it under the existing mutex
without changing command revisions or waking the driver. Publication includes provider
statistics, queried before borrowing `Shared` so provider hooks can reenter it safely.
Disabled, the storage, accessors and publication are absent; `Endpoint::counters` stays
available. Tests: `tests/counters.rs`, `tests/counters_disabled.rs`.

### Uploads

**Table.** Pressure reclaims completed and aborted bodies first. Unfinished bodies are
reclaimable only by their own remote or after half the inactivity timeout recorded at
last progress (123.5 s by default), least recent first. A recent body owned by another
remote keeps its slot or sink, and competing starts receive 5.03 with Max-Age.

**Blocks.** Block zero restarts an existing body unless it repeats the last accepted
block, and MID duplicates still reuse cached responses. Duplicate blocks don't extend
the timeout. Completing a buffered body clears the preceding Continue reply before
calling its handler. A final-block duplicate without a cached final reply receives 4.08
and doesn't invoke the handler. Standalone `BufferedUpload` keeps completed bytes until
dropped and resets incomplete ordering state on expiry.

**`UploadWorker`** owns one asynchronous sink and reuses `StreamingUpload` validation
through a synchronous I/O plan. It awaits storage in the worker, responds after writes
and commit, rejects competing active remotes and preserves exact-block retries. Waiting
enforces inactivity, and processing has its own job deadline. Dropping a processing
future aborts staging synchronously. An idle worker arms no timer. Worker 4.13 replies
include Size1, and temporary 5.03 refusals include Max-Age 1.

**Worker delivery.** Submission and `Capacity` failures retry after 100 ms, 250 ms, then
every 500 ms, keeping the computed response without repeating storage I/O. Admission,
retries and pending commands are bounded by `Job::delivery_deadline()`. Queued commands
keep their operation while NSTART waits for an earlier response's ACK. Cancellation,
other errors and delivery expiry discard only that reply. `run` returns `Infallible`;
during delivery it neither serves the next job nor expires an unfinished upload. The
delivery budget can span the processing timeout plus one exchange lifetime (494 s for
two 247 s budgets), which is an upper bound.

Tests: `tests/upload_table.rs`, `tests/upload_worker.rs`, `tests/block.rs`.

### EDHOC sessions and credentials

Expiry defaults to `MAX_TRANSMIT_WAIT` (93 s), configurable, and initiator steps keep at
least the operation profile's `MAX_TRANSMIT_WAIT`. Sessions distinguish logical peers
behind one next hop.

- **Storage.** Initiator snapshots keep exact CCS bytes and application identity, and
  reparse key and kid at completion, so store updates can't change an in-flight
  snapshot. Responders keep only method-3 secret and transcript fields and reconstruct
  Lakers state through its public API. Both have drop guards.
- **Admission.** Several responder sessions can share a sender address, including equal
  initiator connection IDs behind a proxy; message_3 selects the responder ID. The
  default global bound is four, with at most two responder sessions per source IP (or
  the smaller global bound). UDP port changes don't change accounting. At the limit, a
  new message_1 receives 4.29 with Max-Age 1 and leaves live sessions unchanged. Below
  it, only a full table permits oldest-responder eviction, committed after a valid new
  response is prepared. Initiator work is preserved, and an all-initiator table returns
  4.29 with Max-Age 1. Isolation requires a total bound larger than the source
  allowance. Shared proxies share this limit, which gives no isolation against
  distributed sources.
- **Credentials.** `CredentialStore` supports nonblocking lookup, and `TrustedPeers<N>`
  is the bounded implementation. Incoming duplicate ID_CRED matches are rejected.
  Updates affect later authentication, and established epochs aren't automatically
  revoked.
- **Minimal CCS.** [Fixtures](../tests/fixtures/README.md) use RFC test keys with an
  empty responder kid and a single-byte initiator kid. `tools/interop-aiocoap.py
  --profile minimal-ccs` checks them against aiocoap in both directions, which doesn't
  establish interoperability with any deployed application.

### Proxy across endpoints

A proxy may forward through a second endpoint's handle with an independent exchange
table. Tickets complete on the receiving endpoint, and driver wakers pass through
`Application::poll`. Custom drivers use `poll_resources` for cross-endpoint operations.
Both drivers must run.

### Transport errors

`Transport::discard_send_error` counts and drops recoverable send failures without
blocking other destinations. Fatal errors keep the front packet and return from the
driver. A failed CON send keeps its normal retry budget. Linux classifies
destination-unreachable, refused and oversized sends as recoverable; Embassy does so for
NoRoute, PacketTooLarge and unsupported address families. With `log` or `defmt`, a send
using a compiled-out family emits one warning per program lifetime; the critical-section
latch is set before logging and released before invoking the logger. Source and
destination family mismatches stay per-datagram errors without that warning.

`Transport::discard_receive_error` separates per-datagram failures from fatal socket
errors. Missing Embassy destination metadata increments `dropped_messages` and permits
further receives; unspecified addresses are not fabricated. Delegation macros forward
complete contracts including lifecycle and peer-aware dispatch, and their `except` lists
reject unknown names even for disabled features.

### Block rendering and discovery

Option processing compacts the decoded buffer in place, and Block2 rendering uses the
writer's remaining payload space. Discovery computes per-route policy flags in unused
arena space, streams the requested range and hashes the complete representation without
a full-body buffer. `BodyWindow` keeps only the requested window while hashing every
emitted byte, so each pass must render one coherent snapshot, and applications must keep
bytes stable across blocks for a stable ETag.

Discovery percent-encodes decoded route paths and validates attributes at registration.
Output leaves valid `ptoken` values bare (including numeric `ct`) and quotes `title` and
`anchor`. Parsing accepts a bare value only as a `ptoken`. Parsing and writing reject
repeated `rt`, `if`, `sz` and `ct`, and matching handles relation lists and streams
decoded values with no 255-byte scratch limit.

Borrowed-output and in-place codec interfaces share option selection and validation.
Their writers stay separate: in-place compaction checks critical-option errors before
changing bytes. Recognition callbacks must be deterministic.

### Coverage

`tests/admission_pressure.rs`, `tests/upload_table.rs`, `tests/response_paths.rs`,
`tests/routing_and_worker_api.rs`, `tests/client_and_wrapper_api.rs`, the endpoint,
codec, discovery, messaging and rate tests, and the EDHOC and OSCORE unit tests cover
these behaviors. Messaging property tests compare cache admission with an independent
bounded model, and codec properties compare both writers with explicitly constructed
expected options. The codec fuzz target also checks writer equivalence, in-place
idempotence and unchanged input on preflight errors, and the endpoint target exercises
zero and bounded full-reply pools.

## Owned packets and send acceptance (TR-6–8)

Released Embassy keeps its copying receive path. Native xarxa and xarxa-backed Embassy
receive owned packets without endpoint receive scratch, and stack borrows end before
application or crypto callbacks. Applications supply the medium, a bounded packet pool
and a socket bound to one known interface. The configured interface identifier preserves
IPv6 scope. Wildcard sockets spanning interfaces are deferred, because current receive
metadata lacks the ingress interface.

**Ownership.** Optional packet storage serializes into xarxa buffers. The owned driver
transfers sole-owner queued packets and copies retained packets for transmission. Cached
replies and retransmissions keep exact bytes. This establishes copying behavior at the
endpoint/socket boundary only. Encoders write into the selected storage; retained EDHOC
continuation processing may use scratch. Storage implementations erase discarded payload
bytes regardless of features.

**Send acceptance.** Receive and send handles are borrowed independently. Nonblocking
send polls distinguish acceptance, readiness wait and timed retry without consuming
queued bytes. Native xarxa uses its device-readiness waker. Xarxa-backed Embassy returns
a timed retry for `WouldBlock` instead of its cancellation-unsafe by-value async send.
Released Embassy and Linux use readiness.

**Send window.** The endpoint applies a local send policy: 1–64 ms exponential retry and
a 1-second budget from enqueue, including FIFO wait. Each synchronous producer step
stamps only its new datagrams with a fresh completion-clock reading and extends locally
chosen CON and NON MID holds through that window. Earlier datagrams keep aging,
including across driver restart. Manual drivers use `with_send_window`, whose restricted
view supplies a fixed entry timestamp to receive, protocol and polling methods and
exposes no endpoint access, nested boundary, transmission, acceptance or deadline
methods. Rate limits, storage and client backoff and protection expiry also use entry
time. Transmission follows completion and uses current time, so older queued expiry,
accepted retry spans and fixed collection deadlines stay effective.

**Expiry.** Local expiry drops and counts the queued attempt. Never-accepted requests
and new EDHOC continuation phases fail with `LocalSendTimeout`, and datagram errors use
`LocalSendFailed`. A collection expiring before acceptance reports `LocalSendTimeout`,
and an accepted one ends normally at its deadline. Fatal socket errors keep the queue
for restart. ACK timers and retransmission counts start at acceptance. Later unaccepted
CON retries keep response processing, exact bytes and the original `MAX_TRANSMIT_SPAN` /
`MAX_TRANSMIT_WAIT` envelope. MID quarantine includes the maximum initial local wait,
and promoted leisure responses hold their MIDs for `EXCHANGE_LIFETIME` plus the send
budget, even for NON.

**Observations.** Established server observations keep a fresh-state scheduling
opportunity after local expiry or rejection, delayed by the maximum retry interval to
avoid an error spin. Client refresh binding and ordering changes commit only on
acceptance, and explicit cancellation removes the local subscription even if its
datagram expires.

**Allocation.** Packet reservation may reclaim one cache-exclusive reply when backing
allocation fails. A failed retry preserves the remaining cache until allocation succeeds
again, and undersized storage reports `InvalidStorage` without reclamation. Commands
acquire all backing buffers before being claimed. Commands, client refresh and
cancellation and server notifications share delays from 1 ms to 2 s, because backing
allocators have no portable readiness waker. Successful admission clears the wait.
Complete admissions or released protocol storage reset the delay, and partial two-buffer
admissions keep its growth. Full logical pools don't start allocation backoff. Handshake
and 4.01 recovery responses check MID availability and secure storage and queue capacity
before stopping retries, acknowledging or invoking protection. Unique retry buffers are
reused, so two-slot profiles need no third packet. Temporary capacity drops the response
without changing the exchange.

**Queued routes** keep the full remote address, including IPv6 flow and scope, the
optional local source and every interface value, not the duplicate cache's canonical
identity. Compact packet handles encode one-based nonzero slots, are linear and not
`Clone`, and each holds a counted reference. This is internal storage, not a wire
format.

Evidence: `tests/send_backpressure.rs`, `tests/owned_driver.rs`,
`tests/xarxa_transport.rs`, `tests/driver_wait.rs`; compile-fail examples for the
`SendWindow` boundaries; a host property test of handler delay and message type; an
endpoint fuzz oracle that preserves queued bytes through busy outcomes; Kani harnesses
in `src/messaging/proofs.rs` for ACK-timer activation, advancement on acceptance only,
the wait bound after a skipped retry and quarantine blocks. These are component
properties, not a proof of the complete driver or delivery.

## Specification clarifications

Where requirement wording needed an RFC-based interpretation.

- **OSC-6:** a non-empty OSCORE option value whose flag byte is zero is malformed. [RFC
  8613 section 2](https://www.rfc-editor.org/rfc/rfc8613.html#section-2) requires that
  encoding to be empty, so every accepted value is the unique encoding of its fields.
- **OSC-7:** reserve the current sequence number, starting at zero, and increment before
  encryption (RFC 8613 section 8.1). Do not restore it after failure. Internal length
  fields keep full seven-byte Sender and Recipient IDs and five-byte Partial IVs, and a
  boundary regression round-trips both nonce modes at the final sender sequence.
- **OSC-9** lists verification before the replay check. [RFC 8613 section
  8.2](https://www.rfc-editor.org/rfc/rfc8613.html#section-8.2) checks the Partial IV
  against the replay window (step 3) before decryption (step 6), and section 7.4 updates
  the window only after verification. A known replay is therefore answered 4.01 without
  decryption, whatever its ciphertext.
- **OSC-11, OSC-17:** a matched unprotected 4.xx or 5.xx response (ACK, CON or NON)
  completes with `Error::UnprotectedResponse(code)`, except an enabled first EDHOC
  recovery on 4.01. This surfaces a diagnostic rather than authenticating a response:
  options and payload aren't delivered or acted on, and contexts stay installed.
  Matching ACKs stop retransmission even when payload verification fails. Unprotected
  successes stay ignored. See [RFC 8613 section
  8.4](https://www.rfc-editor.org/rfc/rfc8613.html#section-8.4). Recovery is the
  explicit OSC-17 policy.
- **OSC-18:** drop guards wipe accessible wrapper-owned Lakers secret states and
  plaintext buffers, returned PRKs and abandoned hash input on success and error. The
  wrapper can't wipe private transition temporaries or EAD storage inside Lakers through
  its public API, so this doesn't guarantee every dependency-created copy is erased.
- **OBS-7:** protected observation requests use outer FETCH; notifications use outer
  2.05 (RFC 8613 section 4.1.3.5).
- **Request authority** (no requirement ID): `Client::request` decomposes absolute URIs per
  [RFC 7252 section 6.4](https://www.rfc-editor.org/rfc/rfc7252.html#section-6.4) steps 5
  and 7, omitting Uri-Host and Uri-Port that repeat the destination. Through a proxy both
  are always sent, because the forward proxy reads an absent Uri-Port as 5683 rather than
  its own port: receive metadata has no local port.
- **BLK-3, BLK-6:** `RequestBuilder::transfer` splits a body only when it exceeds the
  block size, so servers without Block1 work with small bodies. Requests for later response
  blocks carry the initial options without Block1 or Size1 ([RFC 7959 section
  2.7](https://www.rfc-editor.org/rfc/rfc7959.html#section-2.7)), keep the Block1 phase's
  Request-Tag ([RFC 9175 section
  3.4](https://www.rfc-editor.org/rfc/rfc9175.html#section-3.4)) and send no payload (RFC
  7959 figures 10 and 11). A FETCH sent without Block1 repeats its payload, which selects
  the response ([RFC 8132 section
  2](https://www.rfc-editor.org/rfc/rfc8132.html#section-2)). RFC 7959 doesn't address
  a POST sent without Block1 that gets a block-wise response; it follows the same figures
  and sends no payload, because repeating it could repeat the action. Requests after the
  first omit If-None-Match ([section
  2.10](https://www.rfc-editor.org/rfc/rfc7959.html#section-2.10)), because the exchange
  itself would make them fail.
- **Client reactions the RFCs leave open (BLK-3, BLK-6):** these abort with `Malformed`
  rather than risk a corrupt body: a Block1 acknowledgement for another block, 2.31 for
  the last block, a block with M set and a short payload, a block other than the one
  requested, a larger block size than requested, and a Content-Format change within a
  response. A plain request answered by 4.13 with a smaller Block1 size is retried in
  blocks ([section 2.9.3](https://www.rfc-editor.org/rfc/rfc7959.html#section-2.9.3)).
  Each retry strictly shrinks the size, and any other 4.13 is the final answer. A 2.xx
  with M unset for a non-final block continues the upload, and the last response carries
  the final code ([section 2.3](https://www.rfc-editor.org/rfc/rfc7959.html#section-2.3)).
- **OBS-8 deregistration:** `Observation::deregister` waits for the Observe=1 exchange.
  RFC 7641 doesn't cover notifications arriving meanwhile: those already delivered are
  discarded, and one that matches the outstanding exchange ends it, since the Observe=1
  request was already sent. After a failed deregistration the token is forgotten anyway,
  so later confirmable notifications get Reset ([section
  3.6](https://www.rfc-editor.org/rfc/rfc7641.html#section-3.6)).
- **Uri-Host case:** [RFC 7252 section 6.4](https://www.rfc-editor.org/rfc/rfc7252.html#section-6.4)
  step 5 lowercases before percent-decoding. This implementation decodes first, so `%41`
  also becomes `a`. Host names compare case-insensitively, so this only normalizes further.
- **CLI-2:** where the two tools' flags conflict, `-v` counts as in aiocoap (`-vv`), and
  `-q` and `-h` mean quiet and help. libcoap uses those for a verbosity number, a TLS
  configuration file and PSK hints, none of which apply here. A non-file `--payload` with a
  CBOR Content-Format is refused, because aiocoap reads it as CBOR diagnostic notation and
  this tool has no parser for that. A file or stdin is sent as given.
- **CLI-3:** credentials are explicit flags rather than aiocoap's credential files, which
  select credentials by URI pattern and would contradict "a hostname never selects a
  credential".
- **Dot segments** (no requirement ID): Uri-Path and Location-Path values are never `.`
  or `..` ([RFC 7252 sections 5.10.1 and
  5.10.7](https://www.rfc-editor.org/rfc/rfc7252.html#section-5.10.1)). URI
  decomposition, including Proxy-Uri at the forward proxy, removes dot segments after
  treating `%2E` as `.` ([RFC 3986 sections 2.3 and
  6.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2)), since section
  6.4's literal steps would otherwise decode `%2E%2E` into a `..` option.
  `resolved_path_query_options` merges relative targets with base path `/` (RFC 3986
  section 5.2.2) without scratch storage; it refuses a target with more segments than
  the remaining datagram bytes (`Capacity`), bounding its quadratic scan. `path_options`
  and `path_query_options` reject dot segments, `Response` options refuse them
  (`ResponseError::InvalidOption`), and raw `MessageBuilder` construction isn't checked.
  Section 5.10.1 constrains senders, so `check_options` rejects a dot segment only in an
  option the caller recognizes: an incoming request gets 4.02 (section 5.9.2.3),
  including OSCORE inner options, an unrecognized Location-Path stays ignored (section
  5.4.1), and a recognized one rejects the response. The proxy answers 5.02 for an
  upstream response carrying one (section 5.9.3.3). Covered by `tests/dot_segments.rs`,
  `uri::tests`, a Kani proof, the URI and codec fuzz oracles and a proxy relay test.
- **DSC-1:** bare link-format attribute values follow the RFC 6690 `ptoken` grammar, so
  `<` and `>` are accepted while backslashes, controls and non-ASCII bytes require a
  quoted string. Quoted values may escape control characters (RFC 2616 `quoted-pair`),
  and the writer refuses control characters in values.
- **EDH-4, CRY-1:** checked `Identity` constructors derive a complete public point
  through `CryptoProvider`. Compact credentials compare x only, accepting scalars whose
  public points differ only by sign; full credentials compare both coordinates. Input
  credentials stay byte-exact. Identity and trusted-peer storage keep validated CCS
  bytes and reconstruct Lakers' parsed fields on use. Registration checks the full
  supported credential size (192 bytes) and local key correspondence, and lookup and
  reconstruction run outside the responder verification frame to preserve stack. Tests
  cover distinct CCS bytes sharing a key and kid, ambiguous lookup and store updates.
  RFC 9529 traces cover reference credentials. No identifier uniqueness assumption was
  added.
- **AUT-3:** `AllowAll` explicitly permits every security state and method. Default-deny
  policies stay available.
- **PRX-4:** unrecognized unsafe request options yield 4.02, and unrecognized unsafe
  response options yield 5.02 (RFC 7252 section 5.7). Invalid lengths and supernumerary
  non-repeatable occurrences count as unrecognized. Safe occurrences are kept byte-exact
  in both directions, including supernumerary Hop-Limit occurrences.
- **PRX-5:** received one-byte or empty Hop-Limit zero is invalid (4.00), and exhaustion
  after decrement is 5.08 (RFC 8768 section 3). For first occurrences longer than one
  byte, RFC 7252 section 5.4.3 length handling takes precedence over numeric range
  checks: keep the unrecognized safe value unchanged, even above 255 or longer than a
  `u64`. A recognized first occurrence is consumed; an unrecognized safe occurrence is
  forwarded after the proxy's inserted counter.
- **BLK-1:** reserved UDP SZX 7 in Block1 or Block2 requests yields 4.00, and invalid
  option lengths yield 4.02 (RFC 7959 section 2.1). Final Block1 options are inserted in
  order alongside handler options. An ETag validation response (2.03) carries no payload
  or Block2/Size2 continuation metadata.
- **SRV-5–7:** failed representation preconditions return a bare 4.12 without ETag,
  Max-Age, payload or block metadata. Omitted Max-Age keeps the default 60-second
  freshness (RFC 7252 section 5.10.5). A 2.03 keeps the representation's ETag and
  freshness metadata. Failed handlers and protection-control callbacks discard partial
  responses. Unsupported deferred notifications also discard them and terminate with
  5.03. Explicitly completed error responses may carry application-selected options and
  diagnostic payloads.
- **TR-2:** multicast replies use a suitable unicast source on the receiving interface,
  keeping the group destination solely for classification.
- **EDH-7:** only sequential message_3 has a C_R prefix. Combined requests carry C_R as
  OSCORE kid and encoded message_3 followed by OSCORE ciphertext (RFC 9668). Outgoing
  true-prefixed message_1 and sequential message_3 use Content-Format 65; message_2,
  message_4 and errors use 64.
- **EDH-8–10, PLT-5:** responder completion validates exactly one complete deterministic
  CBOR byte string before calling Lakers, and combined requests validate the same
  prefix, which also locates the OSCORE ciphertext. The wrapper keeps the default Lakers
  message-size bound, rejects wider and nonpreferred headers, and sends no EAD items.
  Lakers independently rejects malformed message_3 and message_4 since [issue
  454](https://github.com/lake-rs/lakers/issues/454)
  (`edh_12_lakers_rejects_malformed_message_3_without_outer_guard`). Credential
  registration bounds COSE labels before Lakers parses application CCS, avoiding the
  extended integer decoder affected by issues
  [443](https://github.com/lake-rs/lakers/issues/443),
  [444](https://github.com/lake-rs/lakers/issues/444) and
  [451](https://github.com/lake-rs/lakers/issues/451). Credential bytes are never
  rewritten. EAD counts are bounded by `lakers::MAX_EAD_ITEMS` in message_1, plaintext_2
  and plaintext_3, so trailing critical items can't be silently discarded.
- **EDHOC errors:** invalid combined framing yields bare 4.00. Failed EDHOC processing
  yields an unprotected 4.00 with Content-Format 64 and EDHOC error 1, consumes the
  matching session and installs no context. OSCORE processing keeps its own mapping.
  Context admission is checked before consuming the responder session. Capacity
  shortages in sequential or combined completion return unprotected 5.03 with Max-Age 1
  and keep the original session expiry. Control-response construction capacity discards
  partial content and returns bare 5.03 ([RFC 7252 section
  5.9.3](https://www.rfc-editor.org/rfc/rfc7252.html#section-5.9.3)). Incoming request
  capacity refusals don't increment `protection_failures`; EDHOC processing errors in
  the combined path do. There is no automatic client retry: the OSCORE client ignores
  unprotected 5.03 rather than accepting it as a retry instruction.
- **EDH-12, CRY-2:** AES-CCM scratch follows the requested output capacity and stays
  guarded by `Zeroizing`. Encryption's result bound includes the eight-byte tag, and
  decryption's applies to plaintext alone. Boundary tests cover capacities from zero
  through 1,024 bytes, insufficient tag space, oversized bodies, truncated and
  unsupported tags, tampering, providers modifying buffers before failing and
  authenticated malformed plaintext.
- **RFC 9529 section 3.8** has apparent explanatory typos for the master-salt KDF input
  and C_I. Use RFC 9528 Appendix A.1 and the trace's actual bytes.

## Known conformance gaps

**Observe notification retries** keep the original serialized packet, including its
Observe value, and resource changes during a pending CON coalesce for a later
notification. RFC 7641 section 4.4 requires the Observe value to be current on
retransmission, and behavior when state changes during that exchange is undecided. OSCORE preserves the protected bytes and Partial IV on retry, but its Outer
Observe value is independently mutable (RFC 8613 section 4.1.3.5.2), so OSCORE alone
doesn't justify an exception. Follow-up is in [the
roadmap](todo.md#observe-notification-versioning).

## Validation boundaries

Host tests and cross-compilation don't establish hardware or live-network behavior.
Tests under emulation are reported separately from target builds. Interop tests use
peers as black boxes and import no peer protocol code.

**Hardware.** Repository checks don't run on physical hardware. QEMU peaks don't establish
blanket adapter conformance, worst-case stack bounds, production network-pool headroom or
behavior on hardware.

**Kani** harnesses in `src/{block,codec,endpoint/writer,messaging,oscore,uri}/proofs.rs`
prove their properties for every input within stated bounds: CoAP datagrams up to 12
bytes, a single built option of up to 4 bytes, OSCORE option values up to 20 bytes,
representations up to 4096 bytes, and escaped paths up to 5 bytes. Loop-free harnesses
(option extensions, Block option values and capping, replay window, sequence
reservation) cover all inputs. Kani models a 64-bit host `usize`, so 16- and 32-bit
overflow paths aren't covered. Async drivers, shared state and crypto providers are
outside the harnesses. `tools/kani.py` fails on an unsatisfied `kani::cover!`, which
Kani itself reports without failing. Known gaps are in the
[roadmap](todo.md#proof-and-fuzz-oracle-gaps).

## Requirement matrix

Related requirements share invariant tests. Parser property tests and fuzz targets
supplement the explicit boundary cases. Paths below are relative to the repository.

| Requirements | Implementation | Verification |
|---|---|---|
| PLT-1–4, PLT-6–10 | Feature-gated no_std modules, bounded tables, public clock/transport/provider traits | `tools/checks.py`: stable library Clippy for every profile on host and all four cross targets; representative narrow host test profiles, full-profile example lint, strict public/private rustdoc and example builds |
| PLT-5 | Checked codec, block/URI/CBOR readers, fallible provider bridge | `tests/codec.rs`, EDHOC unit tests, nine targets in `fuzz/` with URI decompose/compose and OSCORE option round-trip oracles, bounded Kani harnesses |
| TR-1–4, TR-6–8 | `transport`, Linux packet-info, released Embassy, native xarxa, xarxa-backed Embassy adapters; shared endpoint; optional owned packet storage | `tests/transport.rs`: real IPv4/IPv6 destination/source selection, oversize handling and send-error continuation; `tests/driver_wait.rs`: receive priority, cancellation and metadata across restart; host/embedded/MSRV single-family, dual-family and adapter-coexistence builds; `tests/xarxa_transport.rs` / `tests/owned_driver.rs`: owned-buffer identity, scope, cancellation, exact retries and pool pressure; native M4/M33 raw-IP QEMU exchanges/loss/reclamation; both adapters interoperate with aiocoap over the IPv4 loopback UDP/IP test link; physical driver/hardware validation remains pending |
| TR-5 | Adapter-specific transport errors; no ICMP requirement imposed on adapters | `tests/simulation.rs`: unreachable indication and operation without indications |
| MSG-1–9 | `codec`: borrowed validated view, open typed numbers, ordered builder | `tests/codec.rs`: malformed headers/options, uints, repeatability, 1024-case round-trip and arbitrary-byte properties; codec fuzz target; Kani parse, builder round-trip and option-extension proofs |
| REL-1–4 | `messaging`, endpoint deduplication and exact serialized retries | `src/messaging/tests.rs`, `tests/endpoint.rs`, `tests/resource_bounds.rs`, `tests/construction_and_send_slots.rs` cache-pressure POST regressions, lossy 3-second RTT simulation; embedded runtime fixture |
| REL-5 | Destination NSTART admission, wait/fail choice and NON byte pacing | `src/messaging/tests.rs`, endpoint admission and temporal simulation |
| REL-6–9 | Peer/token/MID matching, separate responses, ping/RST, random token generation | `tests/endpoint.rs`, proxy and interop tests |
| SRV-1–4, SRV-6–7 | `server::Router`, immediate/deferred handlers, representation source, response builder | `tests/endpoint.rs` includes response-capacity error replies and deferred-ticket retry; block/interop tests, minimal and deferred-upload examples |
| SRV-5 | Accept/Content-Format and conditional representation helpers | Representation and independent Block2 tests |
| BLK-1–3, BLK-7 | `block`: offset-preserving server slicing, render-on-demand windows/full-pass ETags, buffered/streamed client download, bounded restarts/resume | `tests/client_transfer.rs` scripted peer, `client_transfer` fuzz oracle, `tests/block.rs` covers window boundaries, snapshot mutations, ETags and failures; libcoap and aiocoap Block2 at SZX 0 and 6; Kani option-value, capping and slicing proofs |
| BLK-4–6 | `block1`: buffered/transactional streaming upload, request match keys, Request-Tag, client size negotiation | `tests/client_transfer.rs`, `tests/block.rs`, streaming upload simulation with loss/duplication, libcoap Block1 both directions; deferred worker example and feature-isolation checks |
| BLK-8 | Opaque proxy options and payload forwarding | `src/proxy/tests.rs`, independent proxy tests |
| OSC-1–6, OSC-19 | `oscore`: derivation, deterministic CBOR/AAD/nonce, option classes and outer codes | Unit tests for RFC 8613 C.1–C.8, both roles; aiocoap protected GET/POST/Observe; Kani option parse/round-trip and nonce-layout proofs |
| OSC-7–14 | Reserved sender sequence numbers, replay window, request binding, retained exact response bytes | OSCORE unit tests, protected lossy proxy simulation, parser fuzzing, plaintext protect/unprotect fuzz oracle with tamper and replay checks; Kani replay-window and sequence-reservation proofs |
| OSC-15–18 | LRU volatile epochs, exchange/observer/upload leases, application PeerId, one recovery per request, zeroizing secrets | `tests/resource_bounds.rs` unauthenticated error handling; `tests/block.rs` context-retention test; repeated reboot/re-registration simulation; EDHOC/OSCORE unit tests |
| EDH-1–8, EDH-13 | Pinned Lakers public API, one provider bridge, exact CCS, both ID_CRED forms, sequential and combined transport | RFC 9529 byte-exact unit trace, by-value credentials, connection-ID boundary tests, independent aiocoap both directions and hostname/literal addressing |
| EDH-9–12 | Error/suite responses, bounded EAD/framing, expiring sessions, fallible provider bridge and cleanup guards | EDHOC unit tests including both responder completion APIs, provider-call fault injection, responder completion fuzzing, independent sequential/combined exchanges |
| AUT-1–6 | Authenticated request state and policy before resource dispatch; filtered discovery | Endpoint policy tests, discovery tests, independent protected-only server tests |
| DSC-1–3 | `link_format`, grammar-correct quoted/bare attributes, generated Block2 discovery with policy filtering and query filters | `tests/discovery.rs`, `tests/link_format.rs`, multicast tests, link-format write/parse round-trip fuzz oracle |
| MC-1–4 | Public NON discovery, random leisure, unicast replies, bounded response collection | `tests/multicast.rs`: classification, suppression, source/interface, duplicate handling and collection deadline |
| CRY-1–5 | Public fallible `crypto::CryptoProvider`, including borrowing incremental SHA-256 state, without optional features; optional RustCrypto backend using one rand_core 0.10. The EDHOC adapter streams every transcript slice through the provider; software hash state erases buffered input on drop | SHA-256 vectors and chunk boundaries, EDHOC provider-failure/cancellation tests, RFC OSCORE and EDHOC vectors, end-to-end interop, no_std feature matrix and emulated exchanges |
| PRX-1–7, PRX-9 | Default-deny routing, optional name hook, opaque forwarding table, immediate ACK, separate response, Hop-Limit and rate limits | `src/proxy/tests.rs`, independent proxies in both arrangements, slow protected proxy and timeout simulations |
| OBS-1–5, OBS-7–8 | Bounded registration, nonblocking change mailbox, schedules, CON reliability, ordering and refresh/cancel | Observe simulation and repeated reboot/rekey test; independent protected Observe |
| OBS-6 | First-block notifications and ETag-checked `Observation::next_blocks` follow-up GETs without Observe | `obs_6_client_fetches_complete_notification_with_matching_etag`, `obs_6_negotiated_size_reaches_registration_and_followups_drop_observe` |
| DOS-1–3 | Bounded per-IP/aggregate response budgets, EDHOC admission, default unprotected Block2 cap of SZX 2 (64 bytes), explicit override up to SZX 6 where datagram capacity permits | Rate-limit and multicast tests, independent lazy-refill admission model and negative mutation check, block-size interop, bounded table admission |
| API-1–10 | Public unsealed layers, bounded handle/driver/work queue, typed errors, counters and event-only optional logs | Examples, strict rustdoc, feature isolation and integration tests; `tests/upload_worker.rs` verifies continued service after reply failures |
| CLI-1–9 | `cli/`: flags, URI routing, sink, deregistration, credential handling and exit codes over the public API | `cli/tests/cli.rs` runs the binary against library servers, including a scripted deregistration peer; `cli/tests/libcoap.rs`; `tools/interop-aiocoap.py --cli`; unit tests in `cli/src`. These don't count as independent evidence for the library's own behavior beyond the two peers |
| TST-1–4 | Unit/property/vector tests and controllable fault transport | `cargo test --features std,server,client,block,block1,observe,proxy,edhoc,software-crypto,multicast,discovery` |
| TST-5 | Nine cargo-fuzz targets, reproducible seeds, buffered and streaming Block1 sequences, block-wise client exchanges against arbitrary responses | `tools/fuzz-smoke.py`; bounded smoke duration is not exhaustive fuzz coverage |
| TST-6 | Black-box libcoap and aiocoap, no peer implementation code imported | `tests/interop.rs`, `tools/interop-aiocoap.py` |
| TST-7 | Host/target profile matrix, emulated runtime tests, linked M4 workload sizes and symbol reports | `.github/workflows/ci.yml`, `tools/target-runtime.py`, `tools/firmware-size.py` |
| TST-8 | Seven host examples and board-independent Embassy task body | Host example builds/runs; `embedded-example` Cortex-M4 build |

Combined Block1/Block2 responses are supported by `RequestBuilder::transfer` with `block1`;
applications retain the response representation while serving its later blocks. Slow upload
workers own their inactive transaction and abort it on I/O failure or timeout.

## Reproducing the acceptance gates

The host suite uses libcoap 4.3.4/4.3.5 and aiocoap 0.4.17 as independent peers. The
aiocoap script checks both endpoint directions, method 3/suite 2, combined and
sequential EDHOC, protected GET/POST, Block2, protected Observe, hostname/literal
addressing over IPv4 and IPv6, and both proxy arrangements. A downstream packet
gate holds both concurrent clients' message_2 replies until both handshakes reach
the same server through aiocoap's proxy. Deterministic tests additionally force
equal initiator IDs and reverse completion order. Libcoap covers unprotected GET/POST,
Block1, Block2 and opaque proxy operation in both endpoint directions.
The libcoap proxy Block2 case uses NON requests for compatibility with the 4.3.4
CLI's handling of separate CON responses; the proxy PUT case uses CON. Hostname
fixtures listen on both address families rather than relying on resolver order.

`tools/target-runtime.py` executes actual no_std binaries under QEMU:

| Target | Machine | Runtime fixture |
|---|---|---|
| `thumbv6m-none-eabi` | micro:bit | Codec, endpoint retries/duplicates/cancellation, Block1, Observe ordering, OSCORE, EDHOC initiation |
| `thumbv7em-none-eabihf` | Netduino Plus 2 | Above plus complete two-role EDHOC and protected use of its derived contexts |
| `thumbv8m.main-none-eabihf` | MPS2 AN505 | Complete two-role fixture |
| `riscv32imac-unknown-none-elf` | virt | Complete two-role fixture |

The smallest QEMU target runs the smaller EDHOC fixture; all targets compile the
complete feature matrix. Routine CI covers M0 and M33; weekly/manual runs cover
all four targets and include fuzz smoke tests and Kani. Emulation establishes
execution for these fixtures, not hardware/network reliability or stack headroom
on a board. Linked workload results,
layout sizes, exclusions and reproduction commands are recorded in [sizes.md](sizes.md).

A separate `--stack-check` fixture polls two real endpoint drivers with 1152-byte
datagrams through combined and sequential EDHOC and established OSCORE traffic.
Cortex-M33 CI enforces separate handshake and traffic budgets on routine runs;
weekly/manual runs also enforce Cortex-M4 budgets. Both use stack paint. The
fixture stores its endpoints and shared queues in statics and keeps futures on
the stack. Its M33 binary uses modeled SSRAM; the
ordinary 32 KiB runtime fixture is unchanged. These are exercised peaks, not
worst-case bounds or physical-board headroom measurements.

## Verified RFC errata

Checked against the RFC Editor dataset on 2026-10-15. The verified records for the
listed protocol references are:

| RFC / erratum | Effect here |
|---|---|
| 7252 / [4948](https://www.rfc-editor.org/errata/eid4948) | A cache key includes applicable request payload. No generic response cache is implemented. |
| 7252 / [4949](https://www.rfc-editor.org/errata/eid4949) | Unsupported reserved Location-* extensions reject the response; checked by codec and endpoint tests. |
| 7252 / [5078](https://www.rfc-editor.org/errata/eid5078) | One `ct` attribute per link; parser, writer and router reject duplicates. |
| 7252 / [4954](https://www.rfc-editor.org/errata/eid4954) | Content-coding terminology; no wire change. |
| 7959 / [7523](https://www.rfc-editor.org/errata/eid7523) | Example notation denotes block size, not SZX. Geometry tests use `2^(SZX+4)`. |
| 8613 / [8229](https://www.rfc-editor.org/errata/eid8229) | Editorial clarification; no algorithm change. |
| 8949 / [8589](https://www.rfc-editor.org/errata/eid8589) | NaN map-key equivalence. Protocol CBOR uses fixed integer/string/container shapes, without floating-point map keys. |
| 3986 / [2525](https://www.rfc-editor.org/errata/eid2525), [7590](https://www.rfc-editor.org/errata/eid7590) | Reference and formatting corrections. |

No verified errata were present for the other listed protocol RFCs at that check.
RFC text takes precedence over requirement wording; the clarifications above
record the resulting implementation choices.
