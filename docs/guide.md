# User guide

How to write CoAP clients and servers with mai-coap. For features, network adapters and
storage sizing, see the [integration guide](integration.md). The rustdoc API reference
covers every public item.

## Program structure

One `Endpoint` owns one socket and handles client, server and proxy work.

| Type | Role |
|---|---|
| `Endpoint` | Protocol state. `Endpoint::run` (or `Router::run`) is the driver future |
| `Shared` | Application-owned storage for commands from other tasks |
| `Handle` (`shared.handle()`) | Cheap, copyable access for making requests, deferred responses and notifications |
| `Application` | Your resource logic. `server::Router` is the supplied implementation |
| `Protection` | Message security. `Unsecured(rng)` or `edhoc::endpoint::Edhoc` |

The library spawns nothing, so poll the driver alongside your other futures. On a
multi-task executor, spawn it. A client that shares one future with its driver looks
like this ([full example](../examples/minimal-client.rs)):

```rust,ignore
let shared = DefaultShared::new();
let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
let mut no_resources = |_: Request<'_>, _: &mut ResponseWriter<'_>| Err(Code::NOT_FOUND);
let handle = shared.handle();

futures_lite::future::race(
    async {
        let reply = handle.client(remote).get("/hello").await?;
        println!("{:?}", reply.message()?.payload());
        Ok::<_, Box<dyn std::error::Error>>(())
    },
    async {
        endpoint.run(&mut socket, &clock, &mut no_resources, &ProtectedOnly).await?;
        Ok(())
    },
).await
```

**Handlers must return promptly.** `Application::handle` and `CryptoProvider` calls run
synchronously on the driver and block all other endpoint work while they run. Move slow
I/O to a [deferred worker](#slow-handlers-deferred-responses). An async-only hardware
crypto HAL needs a separate integration, because the driver cannot await it through
`CryptoProvider`.

## Client requests

`handle.client(target)` creates a cheap, caller-owned profile. Its settings apply to
every request made through it, including block continuations, Observe and internal EDHOC
steps.

```rust,ignore
let client = handle.client(proxy_addr)
    .peer(PeerId(7))                // require protection with this authenticated peer
    .parameters(link_parameters)?   // ACK timeout etc. for this link
    .through_proxy();               // send absolute URIs with Proxy-Scheme

let reply = client.get("coap://node.example/status").await?;

let reply = client.request(Code::PUT, "coap://node.example/config")?
    .uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::CBOR.0.into())?
    .payload(config_bytes)?
    .send()?.await?;
```

- **Check the response code.** `get` and `request(...).send()` return every delivered
  response, including 4.xx and 5.xx with their diagnostic payloads. Use
  `reply.message()?.code()`. The block-transfer helpers require a successful response.
- **Addressing has three independent parts:** the UDP next hop (`Target::remote`), the
  URI authority, and the security identity (`peer`). Several origins can share one
  proxy, and a peer can move between addresses. A hostname in a URI never selects a
  credential, and the library does not resolve names.
- **Selecting a peer means protection is required.** There is no fallback to plaintext.
- **Dropping a request cancels it.**
- **Option order is free.** Builders accept options in any order and sort them. Repeated
  options keep their insertion order, and `set_option` replaces existing occurrences.
- **Raw requests:**
  `client.request_raw(bytes)?.token_length(8)?.wait_for_nstart(true).send()` borrows an
  encoded request until submission. The endpoint replaces its MID and token.
- **IPv6 link-local peers** must include the scope ID: `[fe80::1%7]:5683`.

`Target::new(remote)` or `remote.into()` also lets you set the source address and
interface. Submit requests only after the network is up; see [network
readiness](integration.md#network-readiness).

## Server resources

`server::Router` maps paths and methods to handlers. An empty method list accepts every
method, including unknown ones. Handlers can be closures or `Application`
implementations.

```rust,ignore
let mut status = |request: Request<'_>, response: &mut ResponseWriter<'_>| {
    response.set_code(Code::CONTENT);
    response.set_uint_option(OptionNumber::CONTENT_FORMAT, ContentFormat::CBOR.0.into())?;
    response.set_payload(&render_status(request.payload()))?;
    Ok(Disposition::Complete)
};
let mut router = DefaultRouter::new(&policy);
router.route("/status", &[Code::GET], &mut status)?;
router.run(&mut endpoint, &mut socket, &clock).await?;
```

`Router::run` applies the same [policy](#access-policy) to requests and discovery.

**Response limits.** `ResponseWriter` borrows one datagram-sized buffer shared by the
header, token, options and payload, with at most sixteen options. A setter that would
overflow fails and leaves earlier content unchanged. `?` turns the failure into a local
5.00, and `remaining_payload()` tells you how much room is left. Owned `Response` values
are for deferred submission: `ResponseWriter::copy_from` and `to_owned` convert between
the two.

### Slow handlers: deferred responses

For slow I/O, use `server::work::WorkQueue`. The endpoint acknowledges and queues a copy
of the request, and your worker task answers later:

```rust,ignore
let queue: WorkQueue = WorkQueue::new();
let mut deferred = queue.handler(30_000)?; // processing budget in milliseconds
router.route("/slow", &[Code::POST], &mut deferred)?;

// In a worker future, polled alongside the driver. Only one task may consume a queue.
loop {
    let job = queue.next().await;
    let request = job.request()?;
    let response: Response = do_slow_io(request).await;
    handle.respond(job.ticket(), &response)?.await?;
}
```

Rules for deferred work:

- **Choosing delivery semantics:**
  - `handle.respond(ticket, &response)?.await` completes when the response is queued.
    Later delivery failures are not reported.
  - `handle.respond_confirmed(ticket, &response)?.await` waits for the ACK, RST or
    timeout on CON, or for local acceptance on NON. It fails with `LocalSendTimeout` or
    `LocalSendFailed`. A timeout means receipt is unconfirmed, and an ACK does not prove
    the client application processed the response. It holds a command slot while
    waiting.
  - Dropping either future before queue handoff cancels the submission. Dropping it
    later only releases the waiter, and transmission continues.
- **Ticket lifetime.** Tickets last for the processing budget plus one exchange
  lifetime. Set the budget in the initial handler, with `queue.handler(ms)` or
  `ResponseWriter::set_deferred_timeout`. Without one, a ticket lasts one exchange
  lifetime. Submitting a response later does not change the deadline.
- **Worker deadlines.** Workers enforce `Job::deadline()` themselves, because expiring a
  queue entry cannot cancel I/O in progress. `Job::delivery_deadline()` adds the
  response grace.
- **Capacity.** Check `Request::deferred_ticket()` before accepting deferred work. CON
  requests also need outbound capacity.

## Block-wise transfers

Enable `block` for Block2 (downloads) and `block1` for Block1 (uploads).

**Client:**

```rust,ignore
let n = client.get_blocks("/large", 6, &mut buffer).await?;          // preferred SZX 6: 1024 bytes
let reply = client.upload(Code::PUT, "/image", ContentFormat::OCTET_STREAM, &body, 6).await?;
```

`download` streams into a sink, and `upload_blocks` also retrieves a block-wise
response. `Error::RepresentationChanged` means the ETag changed mid-transfer.

**Server, large responses.** Use `Router::representation` with a `SliceBody`, or render
on demand with `BodyWindow`:

1. Create it with `BodyWindow::new(offset, output)`.
2. Pass each emitted slice to `write`.
3. Call `finish(format, max_age)`.

`BodyWindow` hashes the whole representation for its ETag and keeps only the requested
window, so it trades CPU for bounded storage, because you render the complete body for
each block. Every pass must render one coherent snapshot, and the same version must
produce the same ETag.

Unprotected Block2 responses are capped at 64 bytes per block by default, to limit
amplification. To raise this, use `Router::set_block_caps(maximum_szx,
maximum_unprotected_szx)`, up to SZX 6 (1024 bytes) and subject to datagram capacity.

**Server, uploads.** `Router::buffered_upload` collects the body in RAM.
`Router::streaming_upload` writes through an `UploadSink`. For slow storage, use
`server::work::upload::UploadWorker` with an `AsyncUploadSink`
([example](../examples/streaming-upload.rs)):

- Sinks write to inactive storage and activate it only in `commit`.
- Storage futures must be cancellation-safe, and `abort` must synchronously invalidate
  staging without touching an active image.
- Use one queue and one worker per transactional sink.
- `Router::set_upload_timeout` sets the inactivity expiry (default 247 s).

**Upload table pressure.** Completed bodies are reclaimed first. An unfinished body can
be reclaimed by its own remote, or after half its inactivity timeout without progress
(123.5 s by default). Other clients get 5.03 with Max-Age until then, and evicted
clients must restart.

## Observe

Enable `observe`.

```rust,ignore
// Server
let id = router.observable(
    "/counter",
    Settings::new(1).with_minimum_ms(100).with_maximum_ms(500).with_confirmable_ms(1000),
)?;
handle.notify(id)?; // whenever the resource changes

// Client
let mut observation = handle.client(remote).observe("/counter")?;
while let Some(reply) = observation.next().await {
    let reply = reply?;
    // use reply.message()?.payload()
}
observation.cancel();
```

- Resource IDs are unique within one endpoint. `Router` rejects duplicates, but composed
  applications must ensure this themselves.
- `Observation::next_blocks` fetches the rest of a block-wise notification.
- Applications must tolerate dropped notifications. Resource changes coalesce while a
  confirmable notification is pending.
- An endpoint with zero outbound capacity declines registration and returns a normal
  response without Observe.

## Discovery and multicast

With `discovery`, `Router` serves `/.well-known/core`. It filters the listing by your
policy, supports query filtering and sends the response block-wise. Set attributes or
hide a resource with `Router::describe`:

```rust,ignore
router.describe("/temperature", &[("rt", Some("temperature")), ("ct", Some("60"))], false)?;
```

Discovery needs a policy entry if unprotected clients should reach it: `(Code::GET,
"/.well-known/core")`. For link format without the generated resource, `link-format`
provides `link_format::Links` (parser) and `link_format::Writer`.

Multicast is limited to public, unprotected discovery. With `multicast` and `client`,
`handle.discover_multicast(group, deadline)?` collects unicast replies until the
deadline, and excess unread replies are dropped. With `multicast` and `server`, an
endpoint answers multicast discovery after a random leisure delay. Group membership is
the application's job.

## Security

mai-coap provides OSCORE (RFC 8613) with contexts established by EDHOC (RFC 9528, method
3, cipher suite 2), authenticated with preconfigured raw public keys in CCS credentials.
Adding it does not change resource handlers or client calls.

### Try it

1. Generate a P-256 key pair and CCS credential for each side. This writes `server.ccs`,
   `server.key`, `client.ccs` and `client.key` to the current directory. Run it inside
   the repository checkout so the example commands below can read them, and don't commit
   the keys.

   ```sh
   uv run --with cbor2 --with cryptography python3 - <<'EOF'
   import os, cbor2
   from cryptography.hazmat.primitives.asymmetric import ec
   os.umask(0o077)
   for name, kid in [("server", b"\x01"), ("client", b"\x02")]:
       key = ec.generate_private_key(ec.SECP256R1())
       public = key.public_key().public_numbers()
       cose_key = {1: 2, 2: kid, -1: 1,
                   -2: public.x.to_bytes(32, "big"), -3: public.y.to_bytes(32, "big")}
       open(f"{name}.ccs", "wb").write(cbor2.dumps({8: {1: cose_key}}))
       open(f"{name}.key", "wb").write(key.private_numbers().private_value.to_bytes(32, "big"))
   EOF
   ```

2. Start the server. Its arguments are the bind address, own credential, own raw private
   key and trusted peer credential.

   ```sh
   cargo run --example secured-server --features std,server,client,block,observe,edhoc,software-crypto -- \
       127.0.0.1:5683 server.ccs server.key client.ccs
   ```

3. Send requests from another terminal. The client's arguments are the server address,
   own credential, own key, peer credential, `true` for combined or `false` for
   sequential EDHOC, the path, and optionally a POST payload or `observe`.

   ```sh
   cargo run --example secured-client --features std,server,client,block,observe,edhoc,software-crypto -- \
       127.0.0.1:5683 client.ccs client.key server.ccs true /hello
   # prints: hello secured
   ```

Unprotected requests to this server receive 4.01. The published RFC 9529 keys in
`tests/fixtures` are test vectors, so never deploy them.

### In your application

```rust,ignore
use mai_coap::{crypto::SoftwareCrypto, edhoc::{Identity, TrustedPeer, endpoint::Edhoc}, security::PeerId};

let mut crypto = SoftwareCrypto::new(rng_a);
let identity = Identity::new(own_ccs_bytes, private_key, &mut crypto)?; // checks the key matches the CCS
let mut protection = Edhoc::<_>::new(SoftwareCrypto::new(rng_b), identity)?;
protection.trust(TrustedPeer::new(PeerId(1), peer_ccs_bytes)?)?;
let mut endpoint = DefaultEndpoint::new(&shared, protection)?;

// A client selects the peer explicitly; the EDHOC handshake is automatic.
let reply = handle.client(remote).peer(PeerId(1)).get("/hello").await?;
```

- **Credentials.** `Identity::new` and `TrustedPeer::new` take byte-exact CCS, which is
  never re-encoded. `Identity::from_private_key` and `TrustedPeer::from_public_key`
  build CCS from raw keys, using `CcsEncoding::CompactX` or `CcsEncoding::FullXY`. Empty
  or reused credential IDs require an explicit trust namespace, and ambiguous incoming
  matches are rejected.
- **Credential store.** `Edhoc::with_store` accepts a nonblocking `CredentialStore`.
  `TrustedPeers<N>` is the bounded in-memory store. Store changes affect later
  authentication only and do not revoke established contexts. Complete revocation and
  identity rotation are [planned](todo.md#6-improve-credential-lifecycle-apis).
- **Client options.** `combined_edhoc(false)` uses the sequential exchange.
  `recovery(false)` disables the automatic retry with a fresh handshake after an
  unprotected 4.01.
- **Contexts live in RAM.** A reboot needs a fresh EDHOC exchange. Contexts stay pinned
  while exchanges, observations or uploads use them.
- **RNG.** Pass a cryptographically secure RNG to `SoftwareCrypto`. For hardware crypto,
  implement `crypto::CryptoProvider`; see [crypto
  providers](integration.md#crypto-providers).

### Access policy

The policy decides access after decryption, using the authenticated message.

| Policy | Allows |
|---|---|
| `security::ProtectedOnly` | Authenticated peers only (the default-deny choice) |
| `security::PublicPaths(&[(Code::GET, "/hello")])` | Authenticated peers, plus the listed method/path pairs for anyone |
| `security::AllowAll` | Everything, including unprotected DELETE. Use it only deliberately |
| Your `security::Policy` implementation | Whatever `allow(state, request)` returns, for example per-peer scopes |

The server answers an unprotected request that the policy denies with 4.01. It does this
before routing, so a client sees 4.01 rather than 4.04 even for paths that don't exist.

The EDHOC resource (`/.well-known/edhoc`) is handled by the protection layer before the
policy runs, so it does not need a policy entry.

### Handshake limits

By default, `Edhoc` has four OSCORE contexts, four handshake slots and sixteen trusted
peers. These are its generic parameters, for example `Edhoc<P, 2, 2, TrustedPeers<1>, 0>`.

- **Handshake expiry** defaults to 93 s (`MAX_TRANSMIT_WAIT`). Increase it for slow
  links with `Edhoc::configure(path, timeout_ms)`, which also sets the resource path.
- **Per-source limit.** Each source IP can hold two responder sessions, whatever its UDP
  port, and clients behind one proxy share that allowance. At the limit, new handshakes
  receive 4.29 with Max-Age 1 and existing sessions continue. Change it with
  `set_responder_limit`, and keep the global bound larger so other sources have room. Zero
  disables the responder role, so an endpoint that only initiates answers EDHOC requests
  with 4.04.
- **Table full.** The oldest responder session is replaced. Initiator sessions are
  retained.
- **No free context slot at completion:** the responder answers 5.03 with Max-Age 1 and
  keeps the handshake until its original expiry.

**ID Context storage** defaults to 255 bytes per context. EDHOC derives no ID Context,
so EDHOC-only applications can set the last `Edhoc` parameter to zero and save that RAM.
Standalone `oscore::Context` keeps the full default. `oscore::BoundedContext<N>` selects
a bound. Oversized IDs return `Error::Capacity`.

**Unprotected replies to protected requests.** A matched unprotected 4.xx or 5.xx
completes the operation as `Error::UnprotectedResponse(code)` instead of waiting through
retransmissions. Its content is never treated as authenticated.

## Forward proxy

Enable `proxy`. `proxy::ForwardProxy` wraps your local application on the same endpoint
([example](../examples/proxy.rs)):

```rust,ignore
let mut app = ForwardProxy::<_, _>::new(local_resources, routing, shared.handle())?;
endpoint.run(&mut socket, &clock, &mut app, &policy).await?;
```

- **Destinations are denied by default.** Implement `proxy::Routing`: `allow` decides
  access, and `resolve` maps a host to an address. The default `resolve` accepts IP
  literals only, because the library has no name resolver. `parameters` optionally sets
  a destination's transmission profile.
- **OSCORE stays end to end.** Protected traffic is forwarded without being decrypted.
- **Timeouts.** Forwarding has a processing budget from the destination's transmission
  profile, including time queued for congestion credit, and returns 5.04 on expiry.
- **Bridging network stacks.** `ForwardProxy::with_outbound` forwards through another
  endpoint's handle, with its own exchange capacity. Both drivers must run.
- **Observe** is not forwarded.

## Errors and diagnostics

Protocol and driver errors implement `Display` and `core::error::Error`. The main
`mai_coap::Error` variants are:

| Variant | Meaning |
|---|---|
| `Timeout`, `Reset` | No response after retransmissions; the peer sent RST |
| `LocalSendTimeout`, `LocalSendFailed` | The datagram never left: see [local sending](integration.md#local-send-policy) |
| `Response(code)` | A 4.xx or 5.xx where a helper required success |
| `UnprotectedResponse(code)` | An unauthenticated error reply to a protected request |
| `Protection`, `Replay`, `ContextNotFound`, `SequenceExhausted`, `Edhoc` | Security failures |
| `Capacity` | A bounded table or buffer is full, or the capability has zero capacity |
| `RepresentationChanged` | The ETag changed during a block-wise transfer |

`Endpoint::counters()` returns `Counters`. Enable `shared-counters` to read an owned
snapshot through `shared.counters()` or `handle.counters()` while `run()` owns the
endpoint. The snapshot updates at each driver pass, can lag in-progress work and stays
readable after the driver stops. Reads do not wake the driver. Useful counters:

| Counter | Counts |
|---|---|
| `requests`, `retransmissions`, `duplicates` | Normal traffic |
| `dropped_messages`, `send_failures`, `local_send_timeouts`, `oversized` | Local losses |
| `rate_limited` | Rate-limit rejections, separate from `dropped_messages` |
| `protection_failures`, `unprotected_responses`, `edhoc_runs`, `context_evictions` | Security |
| `dedup_record_evictions`, `dedup_reply_drops`, `dedup_reply_misses` | [Duplicate cache](integration.md#duplicate-detection-under-pressure) pressure |

Enable `log` or `defmt` (not both) for event logging. Keys, protected plaintext and
complete tokens are not logged.

## Lower layers

Each layer is usable without those above it.

| Layer | Types | Notes |
|---|---|---|
| Codec | `codec::MessageView`, `MessageBuilder` | Unknown methods, options and formats stay representable. `MessageBuilder` requires ascending options. `MessageView::processed` writes a filtered copy, `process_in_place` compacts without a second buffer; recognition callbacks must be deterministic |
| URI | `uri::Uri` | `Uri::options_with_scratch` decomposes with caller-owned storage |
| Block | `block::Block`, `Download`, `etag`; with `block1`: `BodyKey`, `StreamingUpload`, `BufferedUpload`, `Progress`, `UploadSink` | The caller owns transfer storage, expiry and sink cleanup |
| OSCORE | `oscore::Context`, `BoundedContext` | Standalone protect and unprotect |
| EDHOC | `edhoc::Initiator`, `Responder` | Standalone roles through Lakers |

Public configuration and output records are non-exhaustive. Use constructors such as
`Metadata::new`, `Settings::new`, `BodyChunk::new` and `SliceBody::new`, or defaults
with their `with_*` setters. Validate configuration before use.

The `_test-support` feature exposes unstable repository test hooks and is not an
application API.
