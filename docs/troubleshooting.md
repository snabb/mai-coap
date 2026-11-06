# Troubleshooting

## Build errors

| Error | Fix |
|---|---|
| `log and defmt are mutually exclusive` | Enable one of them. Don't use `--all-features` |
| `embassy-net requires embassy-net-ipv4 or embassy-net-ipv6` | Select `embassy-net-ipv4` or `embassy-net-ipv6` on mai-coap. Enabling `proto-ipv4` on Embassy does not count |
| `xarxa requires xarxa-ipv4 or xarxa-ipv6`, and the `embassy-net-xarxa` equivalent | Select the matching family feature on mai-coap |
| Cargo `links` conflict on the Embassy time driver | [Repeat the `embassy-time` patch](integration.md#network-adapters) in your workspace root |
| `transport::linux` or `StdClock` not found | They need `std` on Linux. Other hosts supply `Transport` and `Clock` |
| Undefined `critical-section` symbols on bare metal | Link an [implementation](integration.md#bare-metal-requirements) |
| A closure handler doesn't match the expected signature | Callbacks take `&mut ResponseWriter<'_, D>`, with `D` equal to the endpoint's datagram size |

## Requests and responses

| Symptom | Cause and fix |
|---|---|
| Every request gets 4.01, even for paths that don't exist | The default policy refuses unprotected requests before routing. Add a `PublicPaths` entry or use protection: see [access policy](guide.md#access-policy) |
| Discovery returns 4.01 | Add `(Code::GET, "/.well-known/core")` to the policy, and check the `discovery` feature is enabled |
| `Error::Response(Code(129))` | Code values print as raw numbers: 129 is `0x81`, which is 4.01. The class is `code >> 5` and the detail is `code & 0x1f` |
| `get` returned but the operation failed | `get` returns all delivered responses, so check `reply.message()?.code()` |
| Requests to a link-local IPv6 peer fail | Include the scope ID: `[fe80::1%7]:5683` |
| Requests hang with no driver activity | The driver future must be polled concurrently with the caller, including when awaiting `respond`: see [program structure](guide.md#program-structure) |
| Everything stalls while a handler runs | Handlers and crypto run on the driver. Move slow I/O to a [deferred worker](guide.md#slow-handlers-deferred-responses) |
| A large unprotected response arrives in 64-byte blocks | This is the amplification default. Raise it with [`Router::set_block_caps`](guide.md#block-wise-transfers) |
| Setting a payload returns `ResponseError` | The token, options and payload share one datagram. Check `remaining_payload()`, or use a block-wise representation |
| Observe registration returns a plain response | The endpoint has zero outbound capacity, because notifications need an exchange slot |
| `Error::Capacity` from a request | The command table is full, or that capability is configured with zero capacity. See [overload behavior](integration.md#overload-behavior) |

## Network

| Symptom | Cause and fix |
|---|---|
| `LocalSendFailed` on the first request after boot | The interface has no address or route yet. [Wait for configuration](integration.md#network-readiness) and resubmit |
| `LocalSendTimeout` or a rising `local_send_timeouts` | The device stayed busy past the [send budget](integration.md#local-send-policy). Check the driver, or raise the budget |
| `UnsupportedAddressFamily`, or a warning about a family feature | The destination's family isn't compiled in. Enable the mai-coap family feature |
| Intermittent unanswered requests on Thread or radio links | Check link counters first: MAC retry expiries and IPv6 transmit failures can account for this rather than endpoint processing. See [measuring your own firmware](sizes.md#measuring-your-own-firmware). A successful rerun does not explain a failure |
| Large requests silently disappear | The socket's receive buffer is smaller than the datagram, so the stack drops them before the endpoint sees them |
| Requests vanish during bursts while `requests` and `dropped_messages` stay flat | Check `rate_limited`. Rate-limited requests don't count as `requests` or `dropped_messages` |
| Owned-packet sends stall or allocations are refused | The pool is too small: see the [pool budget](integration.md#owned-packets-and-shared-pools) |

## Security

| Symptom | Cause and fix |
|---|---|
| `Identity::new` returns an error | The private key doesn't match the CCS public key, or the key isn't 32 raw bytes |
| Handshake fails with `Error::Edhoc` | Check that each side trusts the other's exact CCS bytes, that the key ID is unambiguous, and that the peer uses method 3 and cipher suite 2 |
| Handshakes receive 4.29 with Max-Age 1 | The source IP has reached its [responder limit](guide.md#handshake-limits). Clients behind a proxy share it |
| 5.03 with Max-Age 1 at handshake completion | No context slot is free because live contexts are pinned. Raise `CONTEXTS` or wait |
| `Error::UnprotectedResponse(code)` | The peer or an intermediary sent an unauthenticated error. Treat the code as a diagnostic only |
| `Error::UnprotectedResponse(Code::UNAVAILABLE)` on a retry | The reply was evicted from the [duplicate cache](integration.md#duplicate-detection-under-pressure). The original operation may have succeeded |
| Requests fail after a reboot | Contexts live in RAM. Clients recover through a fresh handshake unless `recovery(false)` is set |
| A removed peer can still communicate | Store changes don't revoke established contexts. Live revocation is [planned](todo.md#6-improve-credential-lifecycle-apis) |

## Resources

| Symptom | Cause and fix |
|---|---|
| Stack overflow during EDHOC | P-256 needs deep stack. See the [fixture peaks](sizes.md#driver-stack-checks) and paint the stack on your board. Measure a repainted handshake phase, because the boot peak can hide it |
| RAM use higher than expected | Lower the capacities, select zero ID Context capacity for EDHOC-only use, and reduce socket metadata. Make the CoAP task a plain function returning the server future, because another async wrapper can enlarge its poll frame |
| `Error::InvalidStorage` | The packet storage's buffers are smaller than the datagram bound |

Still stuck? Enable `log` or `defmt`, read the [counters](guide.md#errors-and-diagnostics),
and check [conformance](conformance.md) for the exact behavior and its interpretation.
