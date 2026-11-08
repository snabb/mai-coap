# Integration guide

How to fit mai-coap into firmware or a custom platform: features, network adapters,
storage sizing and extension points. For application APIs, see the [user
guide](guide.md).

## Feature flags

Default features are empty. Without any features you get the message codec, URI
handling, transport and clock traits, and the `CryptoProvider` trait.

| Feature | Provides | Enables |
|---|---|---|
| `server`, `client` | Endpoint roles, routing, request handles | |
| `block` | Block2 downloads, random-access response windows | |
| `block1` | Block1 uploads, Request-Tag, buffered and streaming bodies | `block` |
| `observe` | Observation streams and notifications | |
| `link-format` | Link-format parser and writer | |
| `discovery` | Generated `/.well-known/core` | `server`, `block`, `link-format` |
| `multicast` | Multicast discovery: unicast replies, bounded collection | |
| `proxy` | Forward proxy | `client`, `server` |
| `oscore` | OSCORE protection | |
| `edhoc` | EDHOC through Lakers (Git dependency) | `oscore` |
| `software-crypto` | `crypto::SoftwareCrypto`, the RustCrypto provider | `oscore` |
| `shared-counters` | Counter snapshots readable while the driver runs | |
| `std` | Linux UDP transport and host clock; a `critical-section` implementation | |
| `embassy-net-ipv4`, `embassy-net-ipv6` | Released `embassy-net` adapter | `embassy-net` |
| `xarxa-ipv4`, `xarxa-ipv6` | Native xarxa adapter (Git dependency) | `xarxa` |
| `embassy-net-xarxa-ipv4`, `embassy-net-xarxa-ipv6` | Xarxa-backed Embassy adapter (Git dependency) | `embassy-net-xarxa` |
| `embassy-time` | `time::EmbassyClock` | |
| `log` or `defmt` | Event logging. Mutually exclusive; `defmt` also formats public errors | |

Don't use `--all-features`, because `log` and `defmt` conflict. On a non-Linux host,
`std` compiles but provides no transport or clock.

## Bare-metal requirements

The application provides:

- a `critical-section` implementation, for example `cortex-m = { features =
  ["critical-section-single-core"] }`
- a cryptographically secure RNG (`rand_core` 0.10 `CryptoRng`)
- a running network stack and its buffers
- a timer driver when using `embassy-time`, or your own `time::Clock`
- for `software-crypto`, enough stack for P-256: see the [fixture
  peaks](sizes.md#driver-stack-checks)

[`embedded-example`](../embedded-example/src/lib.rs) is a board-independent task body
that accepts an application-created stack:

```sh
cargo build --locked --manifest-path embedded-example/Cargo.toml --target thumbv7em-none-eabihf
```

Its [`xarxa.rs`](../embedded-example/src/xarxa.rs) shows both owned-packet servers
(features `xarxa` and `embassy-xarxa`).

## Network adapters

| Adapter | Type | Features | Receive and send | Device busy handling |
|---|---|---|---|---|
| Linux | `transport::linux::StdTransport` | `std` | Copying, with packet info | Readiness |
| Released Embassy | `transport::embassy::EmbassyTransport` | `embassy-net-ipv4`, `embassy-net-ipv6` | Copying | Readiness |
| Native xarxa | `transport::xarxa::XarxaTransport` | `xarxa-ipv4`, `xarxa-ipv6` | Owned packets | Readiness |
| Xarxa-backed Embassy | `transport::embassy_xarxa::EmbassyXarxaTransport` | `embassy-net-xarxa-ipv4`, `embassy-net-xarxa-ipv6` | Owned packets | Timed retries |

Adapters coexist in one build.

**Embassy.** Select the address family on mai-coap: `embassy-net` alone is a compile
error, and enabling `proto-ipv4` on the Embassy dependency does not select the adapter's
family. Sending to a disabled family returns `UnsupportedAddressFamily`: the driver
counts and drops the datagram and continues. With `log` or `defmt`, the first such
failure warns about the feature selection. Configure the network medium in your
application, for example `embassy-net/medium-ip`.

**[Xarxa](https://github.com/embassy-rs/xarxa).** These adapters also need at least one mai-coap family feature. The pinned
revisions are:

| Dependency | Revision |
|---|---|
| xarxa, xarxa-driver | `8f6f33b131deb9ff3290e0e01079537e1ed7b2ad` |
| Embassy | `8a940dab0d56a910277b816987e45315ca7979aa` |

- Select the medium and bind each socket to one known interface, supplying its interface
  ID. Wildcard sockets spanning interfaces are not supported.
- mai-coap's `defmt` feature does not enable `defmt` on xarxa or Git Embassy. Enable it
  there directly.
- Network-stack borrows end before application or crypto callbacks run.
- Native xarxa users drive and wake their own stack.
- xarxa-backed Embassy applications must repeat this patch in their workspace root,
  because Cargo does not inherit dependency-level patches. Without it, the Git and
  registry time-driver packages conflict over their `links` identity.

  ```toml
  [patch."https://github.com/embassy-rs/embassy"]
  embassy-time = { version = "0.5.1" }
  ```

**Validation status.** Both xarxa adapters pass aiocoap interoperability over a loopback
test link, and native xarxa also runs exchanges and loss recovery in M4 and M33 QEMU.
Physical radio and board drivers need validation in your application.

### Network readiness

The endpoint does not wait for network configuration. Submit client requests only after
the interface has a source address and a route:

| Stack | Check |
|---|---|
| Released Embassy | `Stack::wait_config_up` |
| Xarxa-backed Embassy | Per-interface `wait_link_up` / `wait_config_up`, and `Stack::routes` |
| Native xarxa | `link_state`, `ip_addrs` and `routes` after polling the stack |

Link-local destinations need only link-local addressing. Off-link destinations also need
a default or matching route. Configuration can be lost after the check, so on
`LocalSendFailed`, wait for configuration again and resubmit.

### Local send policy

`SendPolicy` bounds how long a datagram can wait for the local transport. The default is
a 1-second budget from enqueue, with timed retries doubling from 1 ms to 64 ms; change
it with `Endpoint::set_send_policy`. The run drivers start the budget when handler and
crypto work finishes. Time spent queued behind other datagrams counts.

- Budget expiry drops the queued attempt and counts `local_send_timeouts`.
- An initial request or EDHOC step that was never accepted fails with
  `LocalSendTimeout`. A per-datagram rejection gives `LocalSendFailed`.
- CoAP ACK timers and retransmission counters start at local acceptance, not at enqueue.
- Established observations survive: unsent refreshes keep the old binding and retry, and
  servers schedule a fresh notification. Explicit client cancellation still releases the
  local subscription.

## Storage

Protocol tables have const-generic capacities. Choose a named profile or set the
parameters yourself; `Endpoint`'s rustdoc lists their positional order.

| Bound | `DefaultEndpoint` | `SmallEndpoint` | `ServerEndpoint` |
|---|---:|---:|---:|
| Datagram bytes (`DATAGRAM_BYTES`) | 1152 | 1152 | 1152, configurable |
| Outbound exchanges (`OUTBOUND`) | 8 | 4 | 0 |
| Duplicate records (`DEDUP_ENTRIES`) | 32 | 16 | 8 |
| Observers (`OBSERVERS`) | 8 | 4 | 0 |
| Full cached replies (`CACHED_REPLIES`) | 8 | 4 | 2 |
| Queued sends (`SEND_QUEUE`) | 16 | 4 | 2 |
| Command slots (`COMMANDS`) | 8 | 4 | 0 |
| Deferred responses (`DEFERRED`) | 8 | 4 | 0 |
| Application context leases (`BODY_CONTEXTS`) | 8 | 4 | 0 |
| Shared packet buffers (`PACKETS`) | 40 | 16 | 2 |

Pair each with `DefaultShared`, `SmallShared` or `ServerShared`. Security storage is
separate.

| Other storage | Default |
|---|---:|
| `Edhoc`: contexts / handshakes / trusted peers | 4 / 4 / 16 |
| OSCORE ID Context per context | 255 bytes |
| `Router`: routes / buffered upload bodies | 16 / 2 × 4096 bytes |
| `ForwardProxy`: forwards | 8 |
| Unread multicast replies per collection | 8 |

Rate limits default to 4 responses/s with a burst of 128 per source, and 32/s with a
burst of 512 overall. Change them with `Endpoint::set_rate_limits`.

**These are counts, not RAM figures.** See [resource measurements](sizes.md).

### Overload behavior

| Condition | Result |
|---|---|
| Command table full | `Error::Capacity` |
| Capability set to zero | Prompt failure. Zero outbound declines Observe registration and withholds deferred tickets for CON requests |
| Server overload | 5.03 or 4.29 with Max-Age |
| Send queue or packet slots full | Retries and commands wait; replies that can't be queued are dropped and counted, leaving peers to retry |
| Backing allocation failure (owned packets) | Commands, refreshes and notifications retry with delays doubling from 1 ms to 2 s |
| Unanswered NON requests | Paced by `PROBING_RATE` |
| 4.29 received | Delays later requests to that destination. If the table fills, the earliest-expiring destination is forgotten |
| Unread multicast replies full | Excess replies dropped |

Size your concurrency and datagrams to these bounds, and handle dropped notifications
and transfer restarts in the application.

### Duplicate detection under pressure

Duplicate records and full cached replies have separate bounds, and cached replies
replay their exact original bytes.

- **Record pressure** evicts the oldest record, and a later duplicate of that request
  can be processed again.
- **Reply pressure** reclaims a cached reply while keeping its record. It prefers the
  oldest reply from the same remote and local address, then the oldest overall.
- **A duplicate CON whose reply was reclaimed** receives an unprotected 5.03 with
  Max-Age 0, subject to send-queue space, a free packet slot and rate limits. The
  handler does not run again, and the original operation may already have succeeded. A
  protected client sees `Error::UnprotectedResponse(Code::UNAVAILABLE)`. Decide retries
  for non-idempotent work in the application.
- **Duplicate NON requests** stay silent.

`dedup_record_evictions`, `dedup_reply_drops` and `dedup_reply_misses` measure this. If
they increase, raise `CACHED_REPLIES`, `DEDUP_ENTRIES` or `PACKETS`.

### Owned packets and shared pools

With the xarxa adapters, `Endpoint::with_storage` selects packet storage from the
network pool, and `Endpoint::run_owned` hands sole-owner queued buffers directly to UDP
through `OwnedDatagramSender`.

- **Which packets transfer.** NON replies and notifications commonly qualify. Packets
  still referenced by an exchange or duplicate cache use a copying send path, so
  retained CON replies and retries keep their original bytes.
- **Receive scratch.** `Transport::receive_buffer` removes the endpoint's receive
  scratch. Retained EDHOC continuation processing may still use scratch, and this
  doesn't cover crypto scratch, network fragmentation or hardware drivers.
- **Budgeting a pool conservatively:**

  ```text
  sum(endpoint PACKETS) + RX depth + concurrent copying sends
    + buffers held by other sockets, drivers, fragmentation or neighbor queues
  ```

  A piggybacked ACK reply is owned by both the cache and the send queue, so sending it
  needs a second buffer, and its cached original can occupy a pool buffer for
  `EXCHANGE_LIFETIME`. The stack cannot reclaim endpoint-held buffers for RX.
- **Each buffer** must hold the full datagram after UDP/IP and driver headroom. Use the
  socket's allocator rather than guessing headroom.
- **Measure pool headroom on your board.** The repository's fixtures don't establish a
  production pool size.

## Crypto providers

`crypto::CryptoProvider` is available without features, and `software-crypto` adds
`crypto::SoftwareCrypto`. Providers implement `Sha256<'a>` and `sha256_start()` using
the public `crypto::Sha256State` contract. The state can borrow a hardware peripheral.
`update` and consuming `finalize` are fallible, and dropping the state releases its
resources and erases buffered input. All provider calls are synchronous.

**Keep crypto dependencies current.** Your application's lockfile selects the transitive
crypto versions, not this repository's. After updating mai-coap, run this and then
validate your firmware:

```sh
cargo update -p crypto-bigint@0.7 -p ctutils@0.4 -p inout@0.2
```

## Custom transports and wrappers

Traits are public and unsealed, including `Transport`, `Clock`, `Application`,
`Protection` and `CryptoProvider`.

**Transport.** `Transport` splits into independently borrowable `DatagramReceiver` and
`DatagramSender` handles. A send poll either accepts the entire datagram, registers a
readiness waker (`Pending`), or returns `SendOutcome::RetryLater`. Temporary busy states
keep the queue and don't count as failures. Classify per-datagram errors with
`discard_receive_error` and `discard_send_error`, where a recoverable error drops one
datagram and continues. Other errors stop the driver, leaving the front datagram queued
for a custom driver to retry or discard. Never fabricate unspecified local addresses.

**Wrappers must forward the complete trait contract:**

- Transport wrappers forward both halves, the receive-storage hook and both error hooks.
- `delegate_application!(field, D)` and `delegate_protection!(field, BindingType)`
  forward everything inside a trait implementation.
- Add `; except [handle]` or `; except [incoming, outgoing]` before the closing
  parenthesis to override specific methods. Unknown names are compile errors.
- `Protection::incoming` receives a caller-provided output buffer and returns the
  decoded length, security state and optional binding.

## Custom drivers

`Endpoint::run` and `run_owned` handle all of this, so use them unless you need direct
control. The supported manual methods are `receive`, `poll`, `poll_resources`,
`poll_observations` (with Observe), `front_outgoing`, `complete_outgoing`,
`discard_outgoing`, `poll_transmit`, `poll_transmit_owned` and `deadline`.

1. Wrap synchronous `receive`, `poll`, `poll_resources` and direct `poll_observations`
   calls in `Endpoint::with_send_window(&clock, |window| ...)`. Its restricted
   `SendWindow` view uses one entry timestamp, and new send budgets start when the
   window closes.
2. Transmit after the window closes, using current time. `front_outgoing` borrows the
   queued datagram: call `complete_outgoing(now)` with the actual time after the
   transport accepts it, or `discard_outgoing` after a recoverable failure.
3. Preserve transport metadata, and pass the driver's task context to `poll_resources`.
   It already includes notification polling, and it lets upstream completions wake a
   proxy's receiving driver.
4. Arrange command wakeups, and honor both endpoint and application deadlines, including
   immediate wakeups.

IPv6 peer matching ignores flow information and global-unicast scope hints, while
link-local and multicast zones still distinguish peers. Send routes and received
metadata keep their original addresses.
