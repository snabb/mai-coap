# Requirements: a no_std CoAP + OSCORE stack in Rust

The normative scope of mai-coap, for maintainers and reviewers. [Conformance](conformance.md)
records implementation status, interpretations and validation. To use the library, start with
the [README](../README.md).

## 0. How to read this document

- **MUST, MUST NOT, SHOULD, SHOULD NOT, MAY** are used as in RFC 2119 and RFC 8174.
- Every requirement has an ID (`MSG-3`, `OSC-12`, …). Reference the ID in code
  comments where a non-obvious rule is implemented, and in the test that checks it.
- "§" refers to sections of the RFC named in the same row or paragraph.
- Section 2 is the conformance scope: what is in, what is out, and why. Sections 4–17
  are the detailed requirements. Section 18 gives non-normative API guidance.
  Section 19 gives test and acceptance criteria.
- Where a requirement and an RFC seem to disagree, the RFC wins, unless the
  requirement explicitly narrows the RFC's scope. Report any such conflict instead
  of resolving it silently.

### 0.1 Implementation sources

- **The RFCs and their test vectors are the source.** Implement from the
  specifications listed in section 3.
- **MUST NOT** copy code from existing CoAP, OSCORE or "EDHOC over CoAP"
  implementations, in any language. Do not read their source while implementing.
  Their public APIs MUST NOT be used as the model for this crate's API. The one
  exception is CLI-2, for command-line flags of the separate `cli/` tool.
- Running an independent implementation as a **black-box interop peer** is
  allowed and required (TST-6).
- The one external protocol implementation used is **Lakers**, for EDHOC
  (section 11). Use it as a dependency through its public API. Do not vendor or
  modify it.

## 1. Purpose and context

### 1.1 Goal

A general-purpose CoAP library for constrained devices and hosts:

- one crate, or a small crate family, usable on bare-metal MCUs (no heap) and on `std` hosts;
- both server and client roles, in the same endpoint at the same time;
- end-to-end security with OSCORE, keyed by EDHOC;
- a forward proxy;
- block-wise transfer in both directions, Observe and multicast discovery.

It is meant for public use. The API must
be pleasant for an application developer who knows CoAP but not this crate (§18).

### 1.2 Target environments (non-normative)

The design must suit these constraints without hard-coding any of them.

- **Nodes:** MCUs from Cortex-M0+ (no atomic compare-and-swap) through Cortex-M4F/M33,
  RISC-V and Xtensa. 256–512 KB RAM and 1–4 MB flash on the networked parts.
  Async runtime: Embassy. Network stack: released `embassy-net`, native xarxa,
  or xarxa-backed `embassy-net`.
- **Links:**
  - Wi-Fi.
  - Thread (6LoWPAN, about 47 kbit/s, 1280-byte IPv6 MTU through fragmentation).
  - IP tunnels over low-rate radio links, with round-trip times of several seconds, a usable
    payload of a few hundred bytes per packet, and packet loss.

### 1.3 Design direction that affects the API (non-normative)

The crate's core abstractions must make adapters possible outside the crate:
- the message view and builder;
- the request handler;
- the transport;
- the crypto provider.

A third party should be able to bridge them to other CoAP ecosystems' traits or
runtimes without modifying this crate (API-9). The crate itself MUST NOT contain such
adapters, apart from the transport and time adapters listed in TR-6 and PLT-6.

## 2. Conformance scope

Legend: ✔ required; ◐ SHOULD; ○ MAY or optional feature; ✘ out of scope.
"S" is the server or endpoint side, "C" the client side, "P" the proxy role.

### 2.1 CoAP base (RFC 7252)

| Part | S | C | P | Rationale |
|---|---|---|---|---|
| §3 message format, §5.4 option encoding | ✔ | ✔ | ✔ | This is the wire format. |
| §5.4.1 critical, elective, unsafe and no-cache-key options; 4.02 for an unrecognised critical option | ✔ | ✔ | ✔ | Misclassifying options breaks interop. Options the stack understands but ignores (Uri-Host, Uri-Port) count as recognised. |
| §4.2 CON/ACK, §4.3 NON, RST, §4.4 message IDs | ✔ | ✔ | ✔ | Basic reliability. |
| §4.5 duplicate detection, with a cached reply for a CON duplicate | ✔ | ✔ | ✔ | A retransmitted request must not be processed twice. It also prevents OSCORE nonce reuse (OSC-14). |
| §4.2 retransmission with exponential back-off | – | ✔ | ✔ | Senders of CON retransmit. |
| §4.7 congestion control (NSTART) | – | ✔ | ✔ | Required of every client. |
| §4.8 transmission parameters, adjustable per destination | ✔ | ✔ | ✔ | Long-RTT links (seconds) need longer timeouts. |
| §5.2.1 piggybacked responses | ✔ | ✔ | ✔ | Usual case. |
| §5.2.2 separate responses | ✔ | ✔ | ✔ | Proxy forwarding and slow handlers take longer than `ACK_TIMEOUT`. |
| §5.3.1 tokens of 0–8 bytes | ✔ | ✔ | ✔ | Clients commonly use 8-byte tokens. |
| §5.8 methods GET/POST/PUT/DELETE, §5.9 response codes, §5.10 option definitions | ✔ | ✔ | ✔ | Core semantics. |
| §5.7.2 forward proxy (Proxy-Uri, Proxy-Scheme) | ✔ (parse, 5.05 when proxy role is off) | ✔ | ✔ | Reaches nodes behind links that have no IP routing. |
| §6 `coap://` URIs, IPv6 literals, §6.4/§6.5 URI decomposition and composition | – | ✔ | ✔ | Client and proxy addressing. |
| §8 multicast: NON requests, leisure, no error replies to multicast | ◐ | ◐ | ✘ | Discovery only (section 13). |
| §11.3 amplification mitigation | ✔ | – | ✔ | Unauthenticated replies are larger than requests. |
| §5.6 caching beyond ETag/Max-Age semantics; a caching proxy | ✘ | ✘ | ✘ | OSCORE responses can't be cached usefully, and live data must not be served stale. |
| §5.7.3 reverse proxy; CoAP-to-HTTP proxying (§10) | ✘ | ✘ | ✘ | A forward proxy covers the need, by the standard. |
| §9 DTLS, `coaps://` | ✘ | ✘ | ✘ | OSCORE replaces it and also works through proxies. |

### 2.2 Extensions

| Spec | Part | S | C | P | Rationale |
|---|---|---|---|---|---|
| RFC 7959 | Block2, including the size the client requests, random access, ETag consistency | ✔ | ✔ | transparent | Responses larger than a datagram. |
| RFC 7959 | Block1, 2.31, 4.08, 4.13 with Size1 | ✔ | ✔ | transparent | Configuration upload, firmware push. |
| RFC 7959 | Size2 | ◐ | ◐ | – | Lets the client size its buffer and show progress. |
| RFC 7959 | Block1 and Block2 in the same exchange | ◐ | ◐ | transparent | General use. |
| RFC 7959 | BERT | ✘ | ✘ | ✘ | Only for reliable transports (TCP). |
| RFC 6690 | `/.well-known/core`, link-format serialisation, attributes `ct`, `rt`, `if`, `sz`, `obs`, `title` | ✔ | ✔ (parse) | – | Discovery. |
| RFC 6690 | §4.1 query filtering | ✔ | – | – | Small, and expected by general clients. |
| RFC 7641 | Observe, with notifications and re-registration | ✔ | ✔ | ◐ | Monitoring without polling, and with less airtime on slow links. |
| RFC 8132 | FETCH | ✔ | ✔ | ✔ | Outer method of observed OSCORE requests (RFC 8613 §4.2); also useful on its own. |
| RFC 8132 | PATCH, iPATCH | ✔ (pass to handlers) | ✔ | ✔ | Partial updates, e.g. one configuration key. The stack provides the methods; resources define the semantics. |
| RFC 8768 | Hop-Limit | – | – | ✔ | Prevents proxy loops. |
| RFC 8516 | 4.29 Too Many Requests, with Max-Age | ✔ (send) | ✔ (honour) | ✔ | Turns rate limits into a signal the client can act on. |
| RFC 9175 | Request-Tag | ✔ | ✔ | transparent | Required for secure Block1 under OSCORE. |
| RFC 9175 | Echo | ○ | ○ | – | Only needed for OSC-20 (static contexts) and the optional amplification check DOS-4. |
| RFC 7967 | No-Response | ✘ | ✘ | ✘ | No fire-and-forget traffic. It also hides failures under OSCORE. |
| RFC 8974 | Extended tokens | ✘ | ✘ | ✘ | A small proxy table is cheaper than encoding state in tokens. |
| RFC 9177 | Q-Block | ✘ | ✘ | ✘ | Built for congestion (DOTS). Plain block-wise is enough here and better tested. |
| RFC 8323 | CoAP over TCP or WebSockets | ✘ | ✘ | ✘ | UDP only. |
| RFC 9176 | Resource Directory | ✘ | ✘ | ✘ | Applications use DNS-SD or mDNS. |

### 2.3 Security

| Spec | Part | S | C | P | Rationale |
|---|---|---|---|---|---|
| RFC 8613 | §3 contexts and §3.2 derivation; §4 option classes; §5 COSE object, nonce and AAD; §6 option encoding; §7 sequence numbers and replay window; §8 processing | ✔ | ✔ | transparent | Core of OSCORE. |
| RFC 8613 | §4.1.3.3 Proxy-Uri decomposition | – | ✔ | – | The client must split the URI before protecting it. |
| RFC 8613 | §4.1.3.4 Block options inside the protection | ✔ | ✔ | – | End-to-end block-wise. |
| RFC 8613 | §4.1.3.4.2 outer block-wise | ✘ | ✘ | ✘ | Only a fragmenting proxy needs it. Clients choose smaller blocks instead. |
| RFC 8613 | §4.1.3.5 Observe, and replay protection of notifications | ✔ | ✔ | – | Observe is in scope. |
| RFC 8613 | Appendix B.1 reboot handling for long-lived contexts | ○ (OSC-20) | ○ | – | Not needed for contexts derived from EDHOC, which live only in RAM. Needed if static contexts are offered. |
| RFC 8613 | Appendix B.2 context re-derivation; ID Context | ✘ | ✘ | – | Running EDHOC again replaces it. |
| RFC 8613 | Appendix C test vectors | ✔ | ✔ | – | Mandatory tests. |
| RFC 9528 | EDHOC responder and initiator, method 3, cipher suite 2 (through Lakers) | ✔ | ✔ | – | Key establishment without stored state. |
| RFC 9528 | Other methods and suites | ○ | ○ | – | Allowed where Lakers supports them. The design must not preclude them. |
| RFC 9528 | Appendix A.1 OSCORE context from EDHOC; Appendix A.2 EDHOC over CoAP | ✔ | ✔ | transparent | Integration. |
| RFC 9528 | §6 error messages, including "wrong selected cipher suite" | ✔ | ✔ | – | Suite negotiation and diagnostics. |
| RFC 9528 | message_4 | ✘ | ✘ | – | The first OSCORE response already confirms the keys. |
| RFC 9668 | EDHOC + OSCORE combined request (EDHOC option) | ✔ | ◐ | transparent | Saves a round trip, which matters most on slow links. |
| RFC 9529 | EDHOC traces | ✔ | ✔ | – | Integration tests. |
| — | Group OSCORE, ACE (RFC 9200, RFC 9203), AIF (RFC 9237) | ✘ | ✘ | ✘ | No group keys and no token-based authorisation. Authorisation is a policy hook (section 12). |

## 3. Normative references

The latest published RFC text is authoritative. Check the RFC errata for each and
apply verified errata.

| Ref | Title |
|---|---|
| RFC 7252 | The Constrained Application Protocol (CoAP) |
| RFC 7959 | Block-Wise Transfers in CoAP |
| RFC 6690 | Constrained RESTful Environments (CoRE) Link Format |
| RFC 7641 | Observing Resources in CoAP |
| RFC 8132 | PATCH and FETCH Methods for CoAP |
| RFC 8516 | "Too Many Requests" Response Code for CoAP |
| RFC 8768 | CoAP Hop-Limit Option |
| RFC 9175 | CoAP: Echo, Request-Tag, and Token Processing |
| RFC 8613 | Object Security for Constrained RESTful Environments (OSCORE) |
| RFC 9528 | Ephemeral Diffie-Hellman Over COSE (EDHOC) |
| RFC 9529 | Traces of EDHOC |
| RFC 9668 | Using EDHOC with CoAP and OSCORE |
| RFC 9052, RFC 9053 | COSE: structures and process; initial algorithms |
| RFC 8392 | CBOR Web Token (CWT), for the CWT Claims Set (CCS) |
| RFC 8747 | Proof-of-Possession Key Semantics for CWTs (`cnf`) |
| RFC 8949 | CBOR, including §4.2 deterministic encoding |
| RFC 8742 | CBOR Sequences |
| RFC 5869 | HKDF |
| RFC 3610 / NIST SP 800-38C | AES-CCM |
| FIPS 180-4 | SHA-256 |
| FIPS 186-5, SEC 1 v2 | P-256, point encoding and validation |
| RFC 3986 | URI generic syntax (used by RFC 7252 §6) |
| RFC 2119, RFC 8174 | Requirement keywords |

Informative: RFC 8610 (CDDL), for applications describing their payloads; the CoRE
working-group drafts on group communication and on OSCORE-capable proxies (not
implemented; informative only).

## 4. Platform and general constraints

- **PLT-1** `#![no_std]`. No heap is required for any feature. An `alloc` or `std`
  feature MAY add conveniences, but no protocol feature may depend on it.
- **PLT-2** Rust edition 2024, minimum supported Rust 1.97. Check the minimum
  toolchain and current stable in CI. Protocol code uses no nightly features;
  platform toolchains may require their own target build facilities.
- **PLT-3** MUST compile and pass tests on `thumbv6m-none-eabi` (no atomic CAS),
  `thumbv7em-none-eabihf`, `thumbv8m.main-none-eabihf`, `riscv32imac-unknown-none-elf`
  and the host. It MUST NOT require compare-and-swap atomics; use `critical-section`
  where shared state is needed.
- **PLT-4** `#![forbid(unsafe_code)]` in the protocol crates. If a crypto or transport
  adapter truly needs `unsafe`, isolate it in its own module with a `// SAFETY:` note.
- **PLT-5** No panics reachable from any network input or from a misbehaving peer.
  Panics are acceptable only for API misuse detected at construction time, and must
  be documented. Fuzzing enforces this (TST-5).
- **PLT-6** Async APIs MUST be executor-agnostic: core futures only, no spawning. Time
  is reached through a small clock/timer abstraction. Provide implementations for
  `embassy-time` (`Instant`, `Duration`, `Timer`) and for `std`, each behind a feature.
- **PLT-7** All capacities are compile-time bounds, with documented defaults:
  - datagram size;
  - outbound exchanges (default: 8), shared command/result slots (default: 8),
    deferred tickets (default: 8), and body-context leases (default: 8), each
    independently configurable down to zero;
  - immutable packet buffers shared by queued sends, retransmissions, retained
    client plaintext and cached replies (default: 40; SmallEndpoint: 16;
    immediate ServerEndpoint: 2);
  - outgoing datagram descriptors (default: 16; SmallEndpoint: 4);
  - deduplication records and full cached replies, bounded independently
    (defaults: 32 records and 8 full replies);
  - OSCORE contexts;
  - concurrent EDHOC sessions (default: 4), with a per-source-IP responder admission
    limit (default: 2, or the total capacity when smaller);
  - observers;
  - proxy forwarding entries;
  - Block1 reassembly buffers.

  When a bound is reached, the stack MUST behave defined and documented: 5.03 or 4.29
  with Max-Age, eviction, or rejection. It MUST NOT behave undefined.
  Failed admission, encoding or state insertion MUST release untransferred
  packet references and protection bindings. A context pin acquired for a rejected
  state insertion MUST be undone.
- **PLT-8** Logging through optional `log` and `defmt` features (mutually exclusive),
  and silent when neither is enabled. Public protocol/driver/adapter errors support
  `defmt::Format` when enabled. Logs MUST NOT contain key material, plaintext
  of protected messages, or full tokens.
- **PLT-9** Every optional protocol area is a Cargo feature, so that unused code is not
  linked: server, client, block, block1, observe, proxy, oscore, edhoc, multicast,
  link-format. `block` provides Block2; `block1` depends on `block` and provides
  Block1 upload support. A firmware that uses only the server and OSCORE must not pay
  for the proxy or Observe.
- **PLT-10** Dependencies: latest stable versions, checked at implementation time, except
  pins recorded with their reasons in the conformance document. They
  must be no_std and carry permissive licences compatible with the crate's licence.

## 5. Transport

- **TR-1** The transport abstraction carries whole UDP datagrams. On receive it gives
  the payload, the remote `core::net::SocketAddr` **and the local `IpAddr` the datagram
  was sent to**. On send it accepts the remote address and an optional local source
  address.
- **TR-2** The stack MUST reply from the local address the request was received on.
  Nodes commonly have several addresses: link-local, mesh-local and global on Thread;
  IPv4 and IPv6 on Wi-Fi. Replying from another one breaks clients.
- **TR-3** It MUST detect that a request arrived on a multicast address, from the local
  address, and apply section 13.
- **TR-4** It MUST handle a datagram larger than the configured maximum by discarding
  it. It MUST NOT truncate it.
- **TR-5** The abstraction SHOULD let the transport report ICMP errors, such as
  destination or port unreachable, so the client can fail fast instead of timing out.
  It MUST work without them. Adapters classify per-datagram send failures through
  `discard_send_error`. The driver counts and discards recoverable failures, then
  continues. Fatal failures preserve the queued bytes for an explicit restart.
  Temporary device backpressure and network-buffer shortages MUST preserve queued
  bytes and MUST NOT block receive, command, cancellation or deadline processing.
  Split receive/send handles expose nonblocking acceptance, readiness registration
  or a timed-retry outcome. Local retries use configurable exponential backoff
  (default 1–64 ms) and a finite budget from enqueue (default 1 second), including
  queue wait. The run drivers and manual-driver send-window boundary MUST exclude
  the synchronous producer step's work from newly queued datagrams' budgets without
  refreshing older queue entries or shortening MID quarantine. A manual producer
  window MUST expose only producer operations, using one fixed entry timestamp;
  transport attempts and acceptance MUST occur afterward with current time.
  Expiry MUST distinguish an unsent initial request from a CoAP timeout, preserve
  established observations and cached replies, and count local send timeouts.
  CON ACK timers and retransmission counts advance only on acceptance; local
  retries MUST NOT extend the CoAP transmission envelope.
- **TR-6** Provide adapters behind features:
  - released `embassy-net` `UdpSocket` with `UdpMetadata`;
  - xarxa-backed `embassy-net` with owned receive and transmit packet buffers;
  - native xarxa with application-owned stack access and scheduling;
  - `std::net::UdpSocket`, for host clients, test servers and examples.

  Each adapter should be a thin mapping. The core must not depend on any of them.
  Root features `embassy-net-ipv4` / `embassy-net-ipv6`, `embassy-net-xarxa-ipv4` /
  `embassy-net-xarxa-ipv6`, and `xarxa-ipv4` / `xarxa-ipv6` select each adapter's
  supported address families explicitly; applications select the network medium.
  Enabling an adapter without either corresponding root family feature MUST fail
  compilation, even when another dependency enables that stack's address family.
  A family disabled in the adapter is a checked error. With logging enabled, its
  first send failure MUST produce a warning identifying the required feature;
  later failures remain counted without repeated warnings.
  Initial xarxa integrations use one bound interface per socket, with an explicit
  application-visible interface identifier. Preserve IPv6 scope and reject conflicting
  interface selections. Wildcard sockets spanning interfaces are deferred until
  per-packet ingress interface metadata is available. Native stack access MUST use
  short borrows; applications own network polling and runner wakeups. Handlers and
  crypto callbacks MUST run after releasing the network-stack borrow.
- **TR-7** The transport abstraction MUST NOT preclude zero-copy use of the network
  stack's packet buffers. Xarxa integrations MUST receive owned packets without
  copying into endpoint receive scratch and support serialization directly into
  bounded network packet storage. Transmit packets with no remaining cache or
  exchange owners by transferring their buffers. Retained packets MAY be copied
  for transmission, but retries and duplicate replies MUST use their original
  serialized bytes without reencryption. Retained EDHOC continuation processing
  MAY use scratch storage. Pending sends, errors and cancellation
  MUST preserve endpoint ownership until a send succeeds or is explicitly discarded.
  Released Embassy and other slice-based adapters MAY copy. These requirements
  cover the endpoint/socket handoff, not crypto scratch or lower-layer copying.
- **TR-8** One endpoint (one socket) serves requests and sends client requests at the
  same time: the server role, the client role and the proxy role on one port.
  Applications bridging independent network stacks MAY connect two endpoint
  handles through a proxy; both drivers remain independently owned and scheduled.

## 6. Message codec (RFC 7252 §3, §5.4, §5.10)

- **MSG-1** Parse without copying from a byte slice into a view with these parts:
  version, type, code, message ID, token, an option iterator and the payload. Serialise
  into a caller-provided `&mut [u8]`, reporting the length used or "too small".
- **MSG-2** Reject as a message format error:
  - version ≠ 1;
  - TKL 9–15;
  - option delta or length nibble 15 when it is not the payload marker;
  - a payload marker followed by an empty payload;
  - an empty message (code 0.00) that carries a token, options or a payload;
  - a truncated option.

  Per §4.2 and §4.3: a CON with a format error gets RST; a NON with a format error is
  silently ignored.
- **MSG-3** Decode extended option deltas and lengths (13, 14) correctly, including
  the largest values, with overflow checks.
- **MSG-4** Treat option values per §3.2. Accept uint values with leading zero bytes
  and emit minimal ones. An option whose length is outside the range §5.10 defines is
  treated as unrecognised (§5.4.3).
- **MSG-5** Critical options (odd numbers) that the receiving layer doesn't recognise:
  - in a CON request: answer 4.02 Bad Option;
  - in a CON response: reject with RST;
  - in a NON message: ignore the whole message.

  Elective options it doesn't recognise are ignored. **Recognising** an option means
  the layer has processed or deliberately accepted it. Uri-Host and Uri-Port are
  recognised by the server even when it does no virtual hosting. A layer that hands
  options to the application MUST let the application declare more option numbers as
  recognised.
- **MSG-6** Repeatable options (Uri-Path, Uri-Query, ETag in requests, Location-*,
  If-Match) keep their order. Non-repeatable options that occur twice are treated per
  §5.4.5: every occurrence after the first is treated as an unrecognised option.
  Borrowed-output and in-place filtering MUST use the same validation/selection
  policy. In-place filtering MUST check critical-option errors before modifying
  bytes and MUST NOT require another datagram-sized buffer. Recognition callbacks
  MUST be deterministic during a filtering operation. A borrowed-output buffer
  need only fit the filtered result; a capacity error may leave it partly written.
- **MSG-7** The builder MUST emit options in ascending order. It either requires
  insertion in order (and reports an error otherwise), or sorts them while keeping
  the relative order of repeated options. Document which.
- **MSG-8** Name the option numbers and response codes of every RFC in section 3. The
  numbering MUST allow numbers the crate doesn't know.
- **MSG-9** Support Content-Format and Accept values from the IANA registry, including
  `application/cbor` (60), `application/link-format` (40), `application/octet-stream`
  (42), `text/plain` (0) and the EDHOC content formats registered by RFC 9528.
  Unknown values pass through.

## 7. Messaging layer (RFC 7252 §4)

- **REL-1** Message IDs: a random starting value per endpoint, then incrementing. The
  ID MUST NOT be reused for the same peer within `EXCHANGE_LIFETIME`.
- **REL-2** Transmission parameters default to §4.8: `ACK_TIMEOUT` 2 s,
  `ACK_RANDOM_FACTOR` 1.5, `MAX_RETRANSMIT` 4, `NSTART` 1, `DEFAULT_LEISURE` 5 s,
  `PROBING_RATE` 1 byte/s, with the derived values from §4.8.2. The application can
  override them for each destination (or class of destinations), and the derived
  lifetimes follow.
  All high-level client operations MUST accept a configured profile, including
  every Block1/Block2 continuation, Observe refresh/cancellation and internal
  EDHOC step. Each operation snapshots its profile; congestion remains per UDP
  next hop. Applications may own these profiles without an endpoint lookup table.
- **REL-3** Deduplication: remember received CON and NON message IDs per peer for
  `EXCHANGE_LIFETIME` and `NON_LIFETIME` respectively, within PLT-7's bound. For a
  duplicate CON, resend the **stored response bytes** (or the stored ACK) exactly. A
  duplicate NON is dropped. Record eviction under pressure is allowed and
  documented. An evicted record may result in processing a request twice, but
  never in nonce reuse (OSC-14).
  Silence and replies of up to four bytes MUST fit in record storage without a
  full reply buffer. Record pressure evicts the oldest record; full-reply pressure
  discards the oldest stored full reply for the same remote socket and local
  address if one exists, otherwise the oldest globally. Its duplicate record and
  expiry MUST be retained. This preference is an eviction heuristic, not proof
  that an earlier response arrived. Reclaimed replies MUST be distinguished from
  intentional silence. A duplicate CON request whose reply was reclaimed MUST NOT
  be dispatched again; subject to send-queue space, a free packet slot and the
  unprotected-response rate limit, return an unprotected piggybacked 5.03 with
  Max-Age 0, preserving its MID and token. This reports loss of the result, not
  whether the operation succeeded.
  Before reserving a refusal packet, expire duplicate records to release expired
  cache references. Refusals MUST use only free packet slots and MUST NOT reclaim
  live cached replies.
  If no slot is free, suppress the duplicate without a refusal.
  Duplicate NON requests and intentionally silent records remain silent.
  Record eviction MUST release its reply slot before considering
  reply-pool pressure. One admission
  MUST evict at most one live record; expiry releases records and full reply slots.
  Replacing a record MUST release or reuse its reply slot. Admission errors MUST
  leave the table unchanged. Standalone tables MAY have zero full reply slots;
  endpoints MUST reject that configuration.
  Full replies share immutable packet storage with send descriptors and retries.
  Packet pressure MAY reclaim cache-only references, with the same sender preference,
  but MUST preserve duplicate records and buffers still held by a queued send or
  retransmission. Reserve a packet before application or crypto side effects;
  reject/drop before dispatch if none can be made available. If a handshake or
  recovery reply cannot reserve storage for its continuation after retransmission
  stops, complete the operation with `Capacity` and release its retained state.
  Command storage holds either a pending command or its completed result, not
  separate datagram copies.
- **REL-4** Client retransmission: exponential back-off with a random initial timeout
  in [`ACK_TIMEOUT`, `ACK_TIMEOUT` × `ACK_RANDOM_FACTOR`], up to `MAX_RETRANSMIT`
  times, then a timeout error. An RST cancels the exchange with a distinct error.
- **REL-5** NSTART: at most `NSTART` outstanding interactions per destination. Excess
  requests wait or fail fast, as the caller chooses. `PROBING_RATE` applies to NON
  traffic without responses.
- **REL-6** Matching responses: by token and remote endpoint. For piggybacked
  responses, the message ID must also match. Accept separate responses (§5.2.2): an
  empty ACK first, then a CON or NON response, and ACK a CON response. Responses with
  an unknown token: RST for a CON, ignore for a NON.
  IPv6 peer identity ignores flow information and scope IDs on non-link-local
  unicast addresses. Link-local and multicast scopes remain significant. Apply
  this consistently to matching, NSTART/backoff, deduplication, handshakes,
  observations and upload keys. Actual send addresses and received metadata stay
  unchanged; comparison is independent of routing hints.
- **REL-7** Server responses: piggyback when the handler answers at once. When it
  doesn't (deferred responses, proxying), send an empty ACK before `ACK_TIMEOUT` is
  likely to expire and deliver a separate CON response later. A NON request gets a NON
  response.
- **REL-8** CoAP ping: an empty CON is answered with RST (§4.3). The client API SHOULD
  expose ping.
- **REL-9** Tokens: the client generates them from the RNG, 8 bytes by default,
  configurable down to 0. RFC 9175 §4 rules on token reuse apply.

## 8. Server request handling

- **SRV-1** Route requests by Uri-Path segments to application resources. Expose the
  method, path, query, options, payload and security state to the handler.
- **SRV-2** Methods: GET, POST, PUT, DELETE, FETCH, PATCH, iPATCH, plus unknown method
  codes, are passed to the handler. Without a handler, the answer is 4.04 Not Found
  for an unknown path and 4.05 Method Not Allowed for an unsupported method.
- **SRV-3** Handlers can:
  - answer at once;
  - defer the answer, which leads to a separate response (REL-7);
  - stream a response body through Block2 (section 9).

  A handler that defers MUST NOT hold the endpoint up, and the number of deferred
  responses is bounded (PLT-7).
  `respond().await` completes at queue handoff; later delivery failures are not
  returned to that caller. The API MAY offer opt-in delivery tracking through
  `respond_confirmed().await`. This variant reports matching ACK, Reset or
  retransmission timeout for CON; local transport acceptance for NON, including
  initial local expiry or rejection.
- **SRV-4** Uri-Host and Uri-Port are accepted and exposed, never rejected (MSG-5).
  Virtual hosting is the application's choice.
- **SRV-5** Content negotiation helpers: Accept → 4.06 when the handler can't produce
  the format; Content-Format → 4.15 when it can't consume it. ETag and If-Match /
  If-None-Match helpers (2.03 Valid, 4.12 Precondition Failed) SHOULD exist.
  Representation helpers return failed preconditions as bare 4.12 responses;
  they do not inherit ETag, Max-Age or block metadata. An omitted Max-Age uses
  the protocol default, not a zero freshness lifetime.
- **SRV-6** Max-Age: the handler can set it. The default follows §5.10.5.
- **SRV-7** A handler failure maps to a well-defined response: 5.00, or a code the
  handler chose. It never maps to silence or a panic. Partially built responses
  are discarded on handler failure, including Observe notifications. Failed
  protection-control callbacks likewise discard their partial responses.

## 9. Block-wise transfer (RFC 7959)

- **BLK-1** Block2, server side:
  - The handler renders the representation, and the stack slices it. The handler can
    re-render it for each block without keeping per-transfer state ("random access").
  - A render-on-demand helper MAY retain only the requested output window while
    computing the total length and an ETag from the complete representation.
    Each invocation MUST render one coherent snapshot; the same representation
    version MUST produce the same ETag across block requests. This may repeat a
    full representation pass for every requested block.
  - Honour a smaller block size the client requests (SZX), and a later block's offset.
  - Never send blocks larger than the configured maximum for the path.
- **BLK-2** When the representation can change between blocks, the server MUST attach
  an ETag that changes when the content changes. The stack SHOULD offer a helper that
  computes the ETag from the rendered content.
- **BLK-3** Block2, client side:
  - Reassemble into a caller buffer, or stream the blocks to a caller sink, for example
    flash.
  - If the ETag changes mid-transfer, restart from block 0, a bounded number of times,
    then report the error.
  - Let the caller choose the block size per destination, for example small blocks
    through a slow proxy.
  - Resume from a given block number (firmware pull after a reboot).
- **BLK-4** Block1, server side: two modes, chosen per resource.
  - **(a) Buffered:** reassemble into a bounded buffer and deliver the complete body to
    the handler.
  - **(b) Streaming:** deliver each block, in order, to the handler as it arrives. Used
    for firmware, written to flash.

  In both modes:
  - send 2.31 Continue for the non-final blocks;
  - answer 4.08 Request Entity Incomplete for a gap or a block out of order;
  - answer 4.13 Request Entity Too Large, with Size1, when the body (Size1 if given)
    exceeds the limit;
  - drop a partial body after a timeout;
  - the handler commits only on the final block, so a partially received body is never
    applied.
- **BLK-5** Request-Tag (RFC 9175 §3):
  - Blocks of one body are bound together by the endpoint, the Request-Tag value and
    the security context.
  - A block with a different Request-Tag starts a different body, or is rejected while
    one is in progress, per the bounds.
  - Under OSCORE, Request-Tag is class E and its rules MUST be followed, so that blocks
    from different bodies can't be spliced together.
- **BLK-6** Block1 client: send the body in blocks, honour a smaller size the server
  asks for in 2.31 or 4.13, and use Request-Tag where RFC 9175 requires it.
- **BLK-7** Size1 and Size2: the server SHOULD send Size2 when it knows the length
  cheaply. The client SHOULD send Size1 with Block1.
- **BLK-8** Under a proxy, blocks pass through unchanged. The proxy doesn't reassemble.

## 10. OSCORE (RFC 8613)

- **OSC-1** Algorithms: AES-CCM-16-64-128 (COSE algorithm 10) and HKDF-SHA-256 MUST be
  supported. Other algorithms MAY be added behind the crypto provider. None are
  required.
- **OSC-2** Security context derivation (§3.2) from Master Secret, Master Salt (which
  may be absent), Sender ID, Recipient ID and the optional ID Context. Check against the
  Appendix C vectors.
- **OSC-3** Options are sorted into class E (inner) and class U (outer) per §4.1, and
  class I enters the AAD. The class table MUST also cover options defined after
  RFC 8613:
  - Echo, Request-Tag, Size1, Size2, Block1, Block2: class E;
  - Hop-Limit and the RFC 9668 EDHOC option: class U;
  - Observe: both inner and outer, per §4.1.3.5.

  **An option the table doesn't list is class E** (§4.1).
- **OSC-4** Outer codes per §4.2: requests use POST, or FETCH when Observe is present.
  Responses use 2.04, or 2.05 when Observe is present. The inner code carries the real
  method or status.
- **OSC-5** COSE_Encrypt0 with the external AAD per §5.4, and the nonce per §5.2.
  Encode the CBOR structures deterministically (RFC 8949 §4.2). These structures have a
  fixed shape: hand-written encoding, or a small CBOR helper, is fine.
- **OSC-6** OSCORE option encoding and decoding per §6: Partial IV, kid and kid context
  flags. Reject reserved bits and inconsistent lengths with 4.02 (§8.2).
- **OSC-7** Sender Sequence Number:
  - starts at 0 for a new context;
  - is incremented before each use that needs a new Partial IV;
  - MUST NOT exceed 2⁴⁰ − 1; at that limit the context is unusable, and the application
    is told so, so that it re-keys (a new EDHOC run).
- **OSC-8** Replay window (§7.4): a sliding window of at least 32 entries per Recipient
  context. Requests whose Partial IV was seen, or lies below the window, are rejected
  with an unprotected 4.01. The window is updated only after the AEAD verifies.
- **OSC-9** Request processing (§8.2):
  - look up the context by kid (and kid context);
  - verify;
  - restore the inner message;
  - check replay;
  - hand the request to the handler with its security state set to "OSCORE, peer
    credential X".

  Errors produce the unprotected responses that §8.2 assigns to each step:
  - 4.02 Bad Option when the OSCORE option or COSE object can't be decoded;
  - 4.01 Unauthorized when the security context isn't found, or on a replay;
  - 4.00 Bad Request when decryption fails.

  Set Max-Age as §8.2 specifies. A diagnostic payload is optional and MUST NOT leak more
  than the error class.
- **OSC-10** Responses (§8.3): the first response to a request MAY reuse the request's
  nonce (no Partial IV). Notifications and any later responses to the same request
  MUST carry a fresh Partial IV.
- **OSC-11** Client (§8.1, §8.4):
  - protect the request;
  - bind the response to its request through the request's kid and Partial IV in the
    AAD;
  - for observations, apply the notification ordering check (§7.4.1, RFC 7641 §3.4)
    per observation.
- **OSC-12** Proxy-Uri decomposition on the client (§4.1.3.3). Proxy-Scheme, Uri-Host
  and Uri-Port go outer; Uri-Path and Uri-Query go inner.
- **OSC-13** Block options are inner (§4.1.3.4). Outer block-wise is not implemented.
  An endpoint treats an outer Block option as an unrecognised critical option (4.02). A
  proxy forwards it unchanged.
- **OSC-14** **Never reuse a nonce.** A duplicate CON request (REL-3) MUST get the
  **stored, byte-identical** protected response. If no stored response is available,
  REL-3's unprotected cache-loss refusal MAY be sent instead. Any new protected
  response MUST carry a fresh Partial IV. Re-protecting a changed plaintext
  under the request nonce is forbidden. A test exercises this with a resource whose
  content changes between the original and the retransmission.
- **OSC-15** Context storage: a bounded table of contexts, sized at compile time.
  - Applications MAY explicitly bound retained ID Context bytes per context;
    the default supports 255 bytes. Oversized values MUST fail without truncation,
    and absent and present-empty IDs MUST remain distinct derivation inputs
    (§3.2.1). A zero-byte bound MUST support the absent ID Context derived by EDHOC.
  - Eviction is least-recently-used. Installation and successful protection or
    authenticated unprotection update recency internally, without a caller clock
    tick; failed operations do not update it.
  - A context that has a live observation, an in-flight exchange or a Block1 body in
    progress is not evicted.
  - When the table is full, a new EDHOC is refused with 5.03 or 4.29 and a Max-Age.
- **OSC-16** The security state handed to handlers and to the authorisation hook
  (section 12) names the peer's credential, as an identifier the application chose
  when it registered that credential. It doesn't name the OSCORE IDs.
  Outgoing requests MAY explicitly select that stable identity independently of
  the UDP next hop and URI authority. Context selection MUST then use that peer,
  including after address changes and when several origins share one proxy.
  A missing context MUST NOT permit plaintext fallback. Address-based destination
  configuration is not part of the public API.
- **OSC-17** When the client receives an unprotected 4.01 (security context not found)
  in reply to an OSCORE request, and the context came from EDHOC, it
  runs EDHOC again **once** and retries. Server reboots are then invisible to callers.
  Callers can disable this. Other matched unprotected 4.xx/5.xx replies to a
  protected request complete with `Error::UnprotectedResponse(code)`; this is an
  unauthenticated diagnostic, never an authenticated Reply. Matching ACK transport
  semantics stop retransmission independently of payload authentication. Such an
  error MUST NOT apply destination backoff, retire a context or trigger recovery.
  Unprotected success remains unacceptable. Count these diagnostics separately
  from protection failures.
- **OSC-18** Secrets (keys, master secret, the EDHOC PRK) SHOULD be zeroised when
  dropped, including on error paths. Tag comparison MUST be constant-time.
  Document cleanup boundaries imposed by dependency-private state.
- **OSC-19** Test vectors: all RFC 8613 Appendix C vectors pass byte-exact, for both
  client and server roles.
- **OSC-20** (optional feature) Pre-established, static contexts. If offered:
  - Appendix B.1 becomes mandatory: Sender Sequence Number persistence through an
    application hook (B.1.1), and replay-window recovery with Echo (B.1.2, RFC 9175 §2).
  - The feature MUST NOT be usable without the persistence hook.

## 11. EDHOC integration (RFC 9528, RFC 9668), through Lakers

- **EDH-1** Use **Lakers** (crate `lakers`, BSD-3-Clause) for the EDHOC state machine,
  message encoding and credential parsing. Pin a revision that provides the required
  public API, preferring a published release; the conformance document records the pin.
  Do not reimplement EDHOC.
- **EDH-2** The crate's crypto provider (section 14) implements Lakers' `Crypto` trait.
  One provider then serves EDHOC and OSCORE, so hardware acceleration applies to both,
  and only one RNG abstraction is needed. Lakers' bundled software backend is not
  required.
- **EDH-3** Roles: responder (server side) and initiator (client side). Method 3
  (static DH keys on both sides) and cipher suite 2 (AES-CCM-16-64-128, SHA-256, 8-byte
  MAC, P-256, ES256, AES-CCM-16-64-128, SHA-256) are mandatory. The design MUST NOT
  rule out other methods and suites that Lakers supports.
- **EDH-4** Credentials are CWT Claims Sets (RFC 8392) with `cnf` / COSE_Key (RFC 8747,
  RFC 9052/9053).
  - The application supplies its own credential (CCS bytes plus the private key) and the
    trusted peer credentials. Identity construction derives the public point through
    the provider and rejects a mismatched private key. Compact x-only credentials
    compare x; full coordinates compare x and y. Generated CCS helpers explicitly
    select compact-x or full-x/y encoding; caller-supplied bytes remain unchanged.
  - Each peer credential carries an application-chosen identifier (OSC-16) and its
    authorisation data (section 12).
  - **Credential bytes are used byte-exact**, because they enter the EDHOC transcript.
    The stack MUST NOT re-encode them.
  - Credential lookup is a public, nonblocking extension point with a bounded
    in-memory implementation. Outgoing lookup uses the application identity;
    incoming ID_CRED lookup uses an application trust namespace and rejects
    ambiguity. A `kid` need not be globally unique or nonempty. Initiator
    handshakes snapshot their expected credential when started. Store changes
    affect subsequent authentication, not already established contexts; complete
    live-context revocation remains separate lifecycle work.
- **EDH-5** ID_CRED: send by key ID (`kid`) by default, or by value (`kccs`) if
  configured. Accept both.
- **EDH-6** Connection identifiers and the OSCORE context (Appendix A.1):
  - Each side picks its own connection identifier, which becomes its OSCORE Recipient
    ID.
  - It must be unique among that side's live contexts and must differ from the peer's.
  - Derive the Master Secret and Master Salt with EDHOC_Exporter as specified.
- **EDH-7** Transport over CoAP (Appendix A.2):
  - EDHOC messages are POSTed to `/.well-known/edhoc` (the path is configurable).
  - message_1 is prefixed with CBOR `true`, and later messages from the initiator carry
    C_R as prefix.
  - Send true-prefixed message_1 and C_R-prefixed sequential message_3 with
    Content-Format 65; message_2, message_4 and EDHOC errors use 64 (RFC 9668 §2).
  - Responses are 2.04 with EDHOC content.
  - EDHOC errors are carried as Appendix A.2 specifies.
  - Accept requests with or without Content-Format.
- **EDH-8** Combined request (RFC 9668):
  - The server MUST accept message_3 together with the first OSCORE request: process
    EDHOC first, derive the context, then the OSCORE request.
  - The client SHOULD send combined requests by default, and fall back to separate
    message_3 + request where configured.
  - The combined message MUST fit the datagram limit. If it doesn't, the client sends
    the messages separately.
  - A combined EDHOC processing failure returns an unprotected 4.00 with EDHOC
    error code 1 and Content-Format 64, without installing a context (§3.3.1).
  - Before consuming a responder session, context-install admission MUST be
    checked. Temporary capacity shortages return unprotected 5.03 with Max-Age 1,
    retaining the session and its original expiry. Apply this to sequential
    completion too. A later attempt uses a new MID; automatic client retry is
    not required.
- **EDH-9** Errors: answer with EDHOC error messages (RFC 9528 §6), including
  "wrong selected cipher suite" with the responder's supported suites. The initiator
  retries with a supported suite if it has one.
- **EDH-10** EAD: ignore items that are not critical, and abort on unsupported critical
  items (§3.8). An application hook for EAD MAY be added later. Nothing in the design
  should preclude it. Reject EAD sequences exceeding the dependency's item bound
  rather than silently ignoring trailing items.
- **EDH-11** Bounded concurrency:
  - at most HANDSHAKES simultaneous handshakes (PLT-7; default: 4);
  - several responder handshakes MAY share one sender address, including when
    clients use the same proxy. Match message_3 by that address and the responder's
    connection ID; initiator connection IDs need not be unique across clients;
  - at most one P-256 computation at a time per endpoint;
  - count responder sessions per source IP, independent of UDP port. Reject new
    message_1 at that source's limit with 4.29 and Max-Age 1, preserving its live
    sessions. The configurable limit MUST be nonzero and no greater than HANDSHAKES;
    a limit below HANDSHAKES reserves room for other sources;
  - below the source limit, a full table admits a valid new message_1 by evicting
    the oldest responder session only after the new response is prepared.
    Initiator sessions MUST NOT be evicted. If none is eligible, answer 4.29
    with Max-Age 1;
  - a half-finished handshake expires after a timeout.
- **EDH-12** Invalid peer public keys MUST end the handshake with an error. They MUST
  NOT cause a panic or a weak shared secret.
  - Lakers' `Crypto::p256_ecdh` returns no error value.
  - So the provider MUST validate the point (on the curve, not the identity), and on
  failure make the handshake fail deterministically, for example by marking the session
  as failed so that its MAC verification can't succeed.
  - Document the method chosen, and test it with an invalid point in message_1 and in
    message_2.
- **EDH-13** RFC 9529 traces for method 3 and suite 2 pass through the integration
  (with the provider fed deterministic randomness in tests).

## 12. Authorisation policy

- **AUT-1** Every request carries a security state: either *unprotected* or
  *OSCORE-protected by peer P*, with P the application's identifier (OSC-16).
- **AUT-2** A policy hook decides per request, from the security state, method, path
  (and optionally query), whether to allow it. Its default is: deny unprotected
  requests, allow protected ones.
- **AUT-3** A built-in simple policy covers the common case: a list of
  (method, path) pairs open without protection, and every other request requires OSCORE
  from any registered peer. Per-peer rules are expressed through the hook.
- **AUT-4** An unprotected request that is denied gets an unprotected 4.01. A protected
  request that is denied gets a protected 4.03.
- **AUT-5** The EDHOC endpoint is always reachable without protection while EDHOC is
  enabled. Resources are not exposed to unprotected access unless the policy allows it.
- **AUT-6** `/.well-known/core` lists only the resources the requester is allowed to
  see. Hidden resources MAY be marked per resource.

## 13. Discovery and multicast

- **DSC-1** `/.well-known/core` is generated from the registered resources and their
  attributes (RFC 6690 §5), served with Content-Format 40, and Block2-capable.
  Link-format serialization MUST quote `title` and `anchor` values and may emit other
  nonempty values as bare tokens only when they satisfy the RFC 6690 `ptoken` grammar.
- **DSC-2** Query filtering per RFC 6690 §4.1:
  - one `name=value` pair, matched against a link attribute or `href`;
  - a trailing `*` means a prefix match;
  - when no link matches, the server answers a unicast request as §4.1 specifies, and
    sends no response at all to a multicast request (RFC 7252 §8.2).
- **DSC-3** The client parses link format into an iterator of links with attributes,
  without allocating.
- **MC-1** (◐, feature `multicast`) The server accepts NON requests sent to a multicast
  address, for resources the policy allows unprotected.
  - It answers after a random delay within `DEFAULT_LEISURE` (§8.2).
  - It sends no error responses to multicast (§8.2).
  - It never sends an empty ACK or an RST for a multicast request.
- **MC-2** OSCORE is never applied to multicast. A protected request that arrives on a
  multicast address is dropped.
- **MC-3** The client can send a NON multicast request and collect multiple responses,
  each with its source address, until a caller-given deadline.
- **MC-4** Joining multicast groups is the application's and transport's job (e.g.
  `ff02::fd`, `ff03::fd`, `ff05::fd`, `224.0.1.187`). The stack only reacts to the local
  address (TR-3).

## 14. Crypto provider

- **CRY-1** A narrow provider abstraction with exactly the operations needed:
  - SHA-256 with incremental state and a one-shot convenience method;
  - HMAC-SHA-256 or HKDF (extract and expand);
  - AES-CCM-16-64-128 encryption and decryption, in place, with detached or appended
    tag;
  - P-256 key-pair generation and ECDH (x-coordinate output);
  - P-256 public-key validation, point decompression and full SEC1 point derivation
    from a private scalar;
  - cryptographically secure random bytes.

  Designed so a hardware backend can implement it per chip: CryptoCell-310, CRACEN,
  ESP32 AES/SHA/ECC units, or an existing hardware AES-CCM driver. Streaming
  hash state MAY borrow the provider. Dropping it MUST erase buffered input and
  release acquired resources, including after errors or cancellation.
- **CRY-2** The provider is synchronous (blocking), to match Lakers' `Crypto` trait and
  to keep OSCORE processing simple. Calls execute on the endpoint driver path.
  Providers MUST complete synchronously; an async-only HAL cannot be awaited through
  this trait. Applications must account for hardware wait time in the driver budget.
- **CRY-3** A software provider, behind a feature, built on the RustCrypto crates: `aes`,
  `ccm`, `sha2`, `hkdf`, `p256`, at current releases except pins recorded in the
  conformance document, using the traits `aead`, `digest` and `elliptic-curve`.
- **CRY-4** RNG: accept an RNG implementing `rand_core`'s `CryptoRng` (latest major,
  0.10 as of 2026-10-14). Exactly one `rand_core` major version is used across the
  crate. Message IDs and tokens draw from the same RNG.
- **CRY-5** The provider abstraction is public, and implementable outside the crate.

## 15. Proxy (RFC 7252 §5.7.2)

- **PRX-1** (feature `proxy`) Forward-proxy role on the same endpoint. Requests carry
  either Proxy-Uri, or Proxy-Scheme with Uri-Host/Uri-Port/Uri-Path/Uri-Query. Only the
  `coap` scheme is forwarded. Anything else gets 5.05 Proxying Not Supported.
  An optional separate outbound endpoint permits forwarding between transports.
  Both drivers remain application-owned. Reply tickets belong to the receiving
  endpoint, and upstream completion MUST wake that endpoint's driver.
- **PRX-2** **The destination policy is an application hook. Its default is deny.** The
  hook sees the target address and port and the requester's address. Recommended
  practice: allow only specific prefixes, such as a tunnel prefix. Hosts are named by IP
  literal. A host name is resolved through an optional application hook; without one
  the proxy answers 5.02.
- **PRX-3** Forwarding:
  - a new message ID, and a new token if needed, on the outgoing side;
  - a bounded forwarding table (PLT-7) that maps the outgoing exchange back to the
    requester's endpoint, token and message ID;
  - an empty ACK to the requester right away, because the outgoing side is slow;
  - a separate response later.
- **PRX-4** Passing through: the OSCORE option, the EDHOC option, the payload and every
  option the proxy doesn't consume are forwarded unchanged. The proxy never decrypts
  and never reassembles blocks.
- **PRX-5** Hop-Limit (RFC 8768): if absent, insert 16. A received one-byte zero
  or empty zero yields 4.00. First occurrences longer than one byte are treated
  as unrecognized safe options before decoding their numeric value; forward them
  unchanged after an inserted counter. Decrement a recognized occurrence on forwarding;
  if the result is zero, answer 5.08 Hop Limit Reached. Supernumerary occurrences
  follow the unrecognized safe-option forwarding rules.
- **PRX-6** Errors:
  - 5.02 Bad Gateway when the target is unreachable or answers RST;
  - 5.04 Gateway Timeout when the outgoing exchange times out (with per-destination
    transmission parameters, REL-2);
  - 4.29 when rate-limited or the table is full.
- **PRX-7** No caching (section 2.1).
- **PRX-8** (◐, later) Forwarding Observe: keep a forwarding entry per observation and
  relay notifications. Not merging observers is fine, because OSCORE makes that
  impossible anyway.
- **PRX-9** Rate limits per requester and overall, configurable.

## 16. Observe (RFC 7641)

- **OBS-1** Server: a GET (or FETCH) with Observe 0 registers the requester for that
  resource and token, if the resource is observable and the policy allows. The
  observer table is bounded (PLT-7). When it is full, the server answers normally
  without Observe (§4.1).
- **OBS-2** The application signals that a resource changed through an API that works
  from other tasks and contexts, without blocking. The stack then sends notifications.
  It MUST NOT require the application to poll.
- **OBS-3** Each resource has a minimum and a maximum notification interval, set by the
  server.
  - Changes inside the minimum interval are coalesced into one notification.
  - When the maximum interval passes without a change, a notification is sent anyway.
  - Max-Age on notifications reflects the maximum interval.
- **OBS-4** Notifications are NON by default. At least one notification every 24 hours
  is CON (§4.5), and one more often when it is configured. The observer is removed on
  RST, on a CON timeout, on a GET with Observe 1 (§3.6), or on a GET without Observe
  that uses the same token.
- **OBS-5** Notification sequence numbers per §4.4. Ordering at the client per §3.4: a
  24-bit comparison, plus the 128-second rule.
- **OBS-6** Observe with Block2 (RFC 7959 §3.4): a notification carries the first block.
  The client fetches the rest with GETs without Observe, matched by ETag.
- **OBS-7** Under OSCORE (RFC 8613 §4.1.3.5):
  - outer code FETCH;
  - each notification has its own Partial IV;
  - the client keeps a notification replay and ordering check per observation;
  - the context stays alive while it has observations (OSC-15).
- **OBS-8** Client:
  - register;
  - deliver notifications in order, dropping stale ones;
  - re-register when Max-Age expires plus a margin without a notification (server
    reboot);
  - cancel explicitly.

## 17. Denial of service and amplification

- **DOS-1** Unprotected responses are rate-limited per source and overall:
  discovery, EDHOC message_2, errors and unprotected multicast replies.
- **DOS-2** EDHOC compute limits per EDH-11. Overload is signalled with 4.29 and
  Max-Age (RFC 8516).
- **DOS-3** The block size of unprotected responses is capped by configuration, to
  limit amplification (RFC 7252 §11.3). The default cap is SZX 2 (64 bytes); a plain
  deployment may explicitly raise it up to SZX 6 (1024 bytes), subject to the
  configured datagram capacity.
- **DOS-4** (○) Before expensive work for an unverified source, check the return path
  with Echo (RFC 9175 §2.4).

## 18. API guidance (non-normative)

These principles and acceptance examples define what "usable" means. The example programs
(TST-8) should keep reading naturally as the API changes.

- **API-1 Layers that can be used separately.** Each layer must be usable without the
  ones above it:
  - codec;
  - messaging and endpoint;
  - request/response (server routing, client requests);
  - block-wise, Observe, proxy;
  - security (OSCORE, EDHOC);
  - transport adapters and crypto providers.

  A user who only needs the codec takes the codec.
- **API-2 Security is a layer, not a fork of the API.**
  - Adding OSCORE to a working server must not require changing resource handlers.
    Handlers see the security state (AUT-1); they do not do the protection.
  - A client request looks the same with or without OSCORE; the difference is
    configuration (which credentials or context apply to which destination).
- **API-3 No heap, little ceremony.**
  - Capacities are set with const generics or a configuration type, with defaults.
  - Buffers are caller-provided where it matters.
  - A minimal server with two resources should be about 30 lines. A client GET with
    Block2 reassembly should be a few lines plus setup.
- **API-4 One endpoint, several roles.**
  - One future drives the socket. Manual drivers borrow `front_outgoing` and call
    `complete_outgoing` after transport acceptance or `discard_outgoing` on a
    recoverable error. Cancelling a send leaves its bytes and metadata intact.
  - Client requests can be made from other tasks through a cheap handle, with bounded
    in-flight requests.
  - Server, client and proxy share the endpoint by default (TR-8). Cross-stack
    forwarding MAY use a separately driven outbound endpoint (PRX-1).
- **API-5 Typed where it helps, raw where it must be.**
  - Methods, codes, option numbers and content formats are typed, but open to unknown
    values.
  - Payload access is raw bytes.
  - Provide a request builder with named controls and an optional caller-owned
    destination profile. Keep raw requests for forwarding and unusual callers.
    `Handle::client` is the client entry point, accepting a socket address or Target.
    Raw requests use a borrowing builder with named submission controls.
    Route/source/interface, URI authority and authenticated peer are independent.
    Outgoing protection MUST be selected by explicit peer identity; address-keyed
    security policies and automatic address-based context selection are not exposed.
    The public target configuration is non-exhaustive and has a constructor;
    adding settings MUST NOT require downstream exhaustive construction. Public
    output records and extensible enums are non-exhaustive; constructible settings
    provide constructors/defaults and setters without external field literals.
  - Response option addition inserts in numeric order and preserves repeated
    option order. Replacing a singleton remains a distinct operation.
    Synchronous callbacks use a borrowed `ResponseWriter<D>` with one complete
    plaintext datagram bound, including the actual header/token, option encodings
    and payload marker/body. Failed setters MUST leave previous content unchanged.
    The sixteen-option bound remains independent. Owned `Response<D>` retains
    independent D-byte option-value and payload capacities for standalone and
    deferred construction; conversion to a writer MUST preflight before mutation.
  - Observable registration returns a typed resource identifier usable with the
    endpoint handle; raw application-selected IDs remain supported.
    Router registration MUST reject an ID already assigned to another route,
    without changing either registration. Composed applications remain responsible
    for uniqueness across their complete endpoint routing tree.
  - Optional integration with a no_std CBOR crate SHOULD make CBOR resources easy, but
    the core does not depend on any CBOR crate.
- **API-6 Errors:** non-exhaustive enums with clear meanings, distinguishing at least:
  - timeout;
  - RST;
  - a 4.xx or 5.xx response (with its code);
  - an unauthenticated error response to a protected request, distinct from a Reply;
  - a protection failure;
  - an EDHOC failure;
  - capacity exhausted;
  - transport error.
  Protocol errors implement `core::fmt::Display` and `core::error::Error` without
  allocation. There is no universal error-to-response mapping: handlers choose
  codes according to request context. A separate ResponseError describes local
  response-building failures and converts to 5.00 for handlers; conversion back to
  protocol Error preserves capacity and invalid-timeout meanings. RunError retains
  the transport/protocol source through core::error::Error when its transport error
  supports that trait.
  GET convenience methods return every delivered response with its code, options
  and diagnostic payload, including non-2.xx responses. Protocol, protection and
  local failures remain errors. Block-transfer helpers may require successful codes.
- **API-7 Deferred and streaming work is explicit.** Application::handle is a
  synchronous, bounded driver callback. A handler that needs time (proxy,
  slow I/O, streaming Block1 to flash) has a clear, bounded way to answer later.
  `Request::deferred_ticket()` explicitly reports whether deferred admission is
  available. Deferred workers and forwarders require a ticket before accepting work;
  synchronous handlers continue to work when the table is full or disabled.
  A deferred CON response also needs nonzero outbound capacity; withhold its
  ticket if that capability is disabled. NON responses do not need an exchange.
  Zero outbound capacity declines Observe registration with an ordinary response,
  since eventual confirmable notifications require an exchange slot.
  Permanently disabled client/deferred capabilities fail promptly with Capacity; transient queue,
  packet, message-ID and NSTART pressure leaves accepted commands pending.
  Original plaintext is retained only for Observe or when the protection layer
  declares handshake/recovery requirements. Protection wrappers forward that query.
  Response operations return `Result<(), Error>`. Dropping before queue handoff
  cancels submission; dropping afterward releases completion capacity without
  stopping sending or retransmission. A delivery timeout leaves receipt
  unconfirmed and MUST NOT repeat completed application work.
  A worker-side async upload helper reuses Block1 validation, persists bytes before
  acknowledging progress and commits once. Storage methods are cancellation-safe;
  synchronous abort invalidates staging on cancellation, failure or worker drop.
  The worker run loop MUST continue serving jobs after a response submission or
  delivery failure. The built-in worker and proxy use `respond()` (queue handoff).
  Retry response `Capacity` after 100 ms, 250 ms, then every
  500 ms without repeating storage I/O. The queue-handoff attempt, including
  command admission and queued response commands waiting for NSTART credit,
  MUST be bounded by `Job::delivery_deadline()`.
  That deadline combines the processing deadline with the receiving endpoint's
  snapshotted response grace. Other submission errors and handoff expiry discard
  only that reply. Custom workers MAY use the single-job API to manage delivery themselves.
  `UploadWorker::run` returns `core::convert::Infallible`. While handing off one
  response, it does not serve other jobs or expire its unfinished body; expiry
  is checked again after handoff completes or reaches its deadline. Transmission
  continues independently after handoff.
  Each sink has one live body; competing remotes receive 5.03 until inactivity
  expiry or completion. The endpoint never awaits application storage I/O.
- **API-8 Observability for debugging:** counters (requests, retransmissions,
  duplicates, protection failures, unauthenticated error responses, transport send
  failures, dropped messages, rate-limit rejections, oversized datagrams, EDHOC
  runs, context evictions, duplicate-record evictions, reply-only drops and misses
  after reply reclamation)
  through a cheap read API, and the optional logging of PLT-8.
  The opt-in `shared-counters` feature MUST allow reading counters while the driver
  owns the endpoint. When enabled, shared storage and its handles MUST expose
  an owned counter snapshot, including protection-layer statistics. Publish it
  at the start of every driver-loop pass before application polling, before waiting
  for input or a wakeup and before every driver return, including errors, through
  the existing critical-section mutex without waking the driver.
  It starts at zero, MAY lag in-progress work and remains readable after the driver
  stops. Snapshot storage MUST be independent of command capacity and available
  with zero command slots. Resource handlers
  and application polling callbacks MUST be able to read it without stopping the
  driver. When disabled, snapshot storage, accessors and publication MUST be
  omitted. Direct access to the endpoint's current counters MUST remain available
  independently of this feature.
  `dedup_record_evictions` counts live metadata-record pressure; `dedup_reply_drops`
  counts full-reply pressure that leaves the record intact. Both can increment on
  one admission. Expiry and replacement do not increment either; releasing a reply
  with an evicted record increments only the record counter.
  `dedup_reply_misses` counts rate-admitted duplicate CON requests whose reply was
  reclaimed, including attempts that cannot queue a refusal because no packet slot
  is free. Full send queues reject requests before duplicate lookup and counting.
  Rate-limited requests do not increment it, with or without OSCORE.
  Recognized duplicates count even when their reply cannot be sent. Suppressing
  a cache-loss refusal because no pool slot is free is not a dropped-message error.
  Incoming request capacity refusals MUST NOT increment `protection_failures`.
  `rate_limited` MUST count each datagram rejected by the endpoint's per-source
  or aggregate unprotected-response limiter once. This includes suppressed
  unicast work, cached replies, multicast work, resets and unprotected errors
  for protected requests. It is independent of `dropped_messages`; rejected
  plaintext requests do not reach duplicate lookup or application dispatch.
  A silent protocol decision that does not consult the limiter MUST NOT increment
  it. Proxy admission returning an explicit 4.29 uses a separate limiter and is
  outside this counter.
- **API-9 Open to adapters.** Core traits are public and not sealed, and message
  views and builders are reachable through traits or plain public types. This lets
  third parties bridge to other CoAP abstractions, executors or network stacks outside
  this crate.
  Standalone codec and URI operations, OSCORE Context and explicitly bounded
  BoundedContext with their opaque request
  binding and response-nonce controls, EDHOC Initiator/Responder, and the block
  primitives (Block, BodyKey, StreamingUpload, BufferedUpload, Download, Progress,
  UploadSink and etag) remain supported public layers. Callers of standalone block
  primitives own their transfer storage, expiry and sink cleanup.
  Endpoint's with_send_window and its restricted SendWindow producer view,
  receive, poll, front_outgoing, complete_outgoing, discard_outgoing, poll_resources,
  poll_observations (with Observe), and deadline
  methods are supported for custom drivers. Such drivers preserve metadata and
  pending sends, arrange command wakeups, forward the task context to resource
  polling and honor endpoint/application deadlines.
  The endpoint OSCORE facade exposes fresh installation, peer
  retirement and counts; table admission, generation and pin machinery is internal.
  Reliability tables, notification scheduling state and provider/format adapters are not
  supported public API. Repository fuzz/target harnesses MAY use the explicitly
  unstable, hidden `_test-support` feature; normal application tests MUST NOT need it.
  `Protection` remains an advanced public extension point. Its required `incoming`
  method receives a caller-provided output buffer and returns decoded length,
  security state and optional binding in one call. Absence of an OSCORE option
  MUST NOT bypass provider checks. Option validation/filtering and binding
  cleanup apply to every accepted request. Complete application
  and protection delegation helpers cover lifecycle, counters and peer dispatch.
  Wrappers MAY explicitly exclude overridden methods; all remaining methods MUST
  still be forwarded, including feature-gated methods. Reject unknown exclusions.
  Application polling has one method with the driver's task context; Protection
  has one target-aware method for each outgoing, handshake-response and recovery
  operation. Wrappers MUST forward driver wakeup contexts and transport receive-error
  classification. A recoverable per-datagram metadata error is dropped and counted;
  a real socket failure remains a driver error. Missing local addresses MUST NOT
  be replaced with unspecified addresses.
- **API-10 Documentation:** every public item has rustdoc. The crate root explains the
  layers and links each requirement area to its module.

## 19. Command-line client

The `cli/` workspace builds `mai-coap`, a curl-like client on the library's public API. It
is a Linux host tool with `std` dependencies, and the library never depends on it.

- **CLI-1** Requests: all methods of SRV-2, block-wise transfer in both directions, Observe,
  a forward proxy, and raw options other than those the library or another flag manages.
- **CLI-2** Flags SHOULD match the public documentation of libcoap's `coap-client` for short
  forms and of `aiocoap-client` for long forms, where they don't conflict. Behavior comes
  from the RFCs, not from those tools.
- **CLI-3** Security: EDHOC method 3, cipher suite 2, with the credentials given on the
  command line and one trusted server. A hostname never selects a credential. With
  credentials given, a request MUST NOT fall back to an unprotected exchange. The responder
  role is disabled. A private key comes only from a COSE_Key file
  ([RFC 9052 section 7](https://www.rfc-editor.org/rfc/rfc9052.html#section-7)), and one
  accessible by other users is refused.
- **CLI-4** URIs MUST have a scheme. A scheme without a transport here (`coaps`, `coap+tcp`,
  `coaps+tcp`, `coap+ws`, `coaps+ws`) is an error that names the missing transport, and
  never falls back to `coap`.
- **CLI-5** Output: the payload goes to stdout or a file, and status goes to stderr. Exit
  codes distinguish success, a 4.xx or 5.xx response, a usage or local error, a network
  failure, a security failure and an interruption.
- **CLI-6** Everything received is untrusted. Diagnostics escape control characters, and
  binary data isn't written to a terminal unless requested. Complete tokens, keys and
  plaintext stay out of diagnostics other than the payload itself.
- **CLI-7** A response body has an explicit size limit, and only a complete, consistent body
  is written (BLK-3).
- **CLI-8** Ending an observation sends the deregistration and waits a bounded time for it,
  on a duration ending and on SIGINT or SIGTERM (OBS-8). Stalled output MUST NOT delay this
  or the exit after it, apart from `-vv` library logs, which the driver writes directly.
- **CLI-9** A FETCH MUST have a Content-Format ([RFC 8132 section
  2.3.1](https://www.rfc-editor.org/rfc/rfc8132.html#section-2.3.1)).

## 20. Testing and acceptance

- **TST-1** Unit tests for every MUST in sections 4–17, named or commented with the
  requirement ID.
- **TST-2** Codec property tests: random valid messages round-trip byte-exactly, and
  random byte strings never panic.
- **TST-3** Byte-exact vectors: RFC 8613 Appendix C (OSC-19), RFC 9529 (EDH-13), and
  the message examples in RFC 7252 and RFC 7959.
- **TST-4** A simulated transport for host tests: loss, duplication, reordering, delay
  and ICMP errors, driven by a controllable clock. Use it for retransmission timing,
  deduplication, OSC-14, Observe re-registration and proxy timeouts.
- **TST-5** Fuzzing (`cargo fuzz`) of every parser that sees input from the network:
  - the CoAP message and options;
  - link format;
  - the OSCORE option and COSE object;
  - the EDHOC entry points (message_1, combined request);
  - Block1 sequences;
  - Proxy-Uri.

  Fuzzing must find no panic and no timeout.
- **TST-6** Black-box interop with at least one independent, widely used
  CoAP/OSCORE/EDHOC implementation, run against host builds (std transport):
  - unprotected GET and POST;
  - Block2 at block sizes 16 and 1024;
  - Block1;
  - EDHOC (method 3, suite 2) with and without the combined request;
  - OSCORE GET/POST, Observe under OSCORE;
  - a forward proxy in both directions (our proxy with their client and server, their
    proxy with our client and server);
  - requests addressed by host name (with Uri-Host) as well as by IP literal.

  The tests must run in both directions: our client against their server, and their
  client against our server.
- **TST-7** CI builds every feature combination that matters on the PLT-3 targets, runs
  clippy with warnings as errors, and records flash and RAM per feature set for a
  Cortex-M4 reference build, so that regressions are visible.
- **TST-8** Example programs, which must build and run on the host:
  - a minimal server;
  - a minimal client;
  - a secured server and client (EDHOC + OSCORE);
  - a proxy;
  - Observe;
  - a Block1 streaming upload.

  Plus one embedded example that builds for `thumbv7em-none-eabihf` with `embassy-net`.
