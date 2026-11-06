# mai-coap

CoAP and OSCORE for Rust, on microcontrollers and Linux hosts. All protocol storage has
a fixed bound. The library needs no heap and no particular executor, HAL or network
stack, and it never spawns tasks.

## What it does

| Capability | Cargo features |
|---|---|
| CoAP over UDP (IPv4/IPv6): client and server on one endpoint, retries, duplicate detection, congestion control, rate limits | `server`, `client` |
| Message codec and URI handling, usable alone | none |
| Block-wise downloads; uploads, including streaming to storage | `block`; `block1` |
| Observe, including protected observations | `observe` |
| `/.well-known/core` discovery and link format; multicast discovery | `discovery`, `link-format`; `multicast` |
| End-to-end security: OSCORE keyed by EDHOC (method 3, cipher suite 2, raw public keys) | `oscore`, `edhoc`, `software-crypto` |
| Forward proxy with opaque OSCORE forwarding and default-deny destinations | `proxy` |

Default features are empty. See the [full feature
list](docs/integration.md#feature-flags).

## Supported platforms

Rust 1.97 or newer, on stable. The library is `no_std` and runs on targets without
atomic compare-and-swap. Bare-metal applications supply a
[critical-section](https://crates.io/crates/critical-section) implementation.

| Platform | Network integration | Validation |
|---|---|---|
| Linux | Included UDP transport (`std`) | Tests and interop with libcoap and aiocoap on every CI run |
| Other `std` hosts | Supply your own `Transport` and `Clock` | Windows compile check in CI |
| Cortex-M0, Cortex-M33 | [Embassy or xarxa adapters](docs/integration.md#network-adapters), or your own `Transport` | Lints and QEMU tests on every CI run |
| Cortex-M4, RV32IMAC | As above | Lints and QEMU tests weekly |
| ESP32-S3, ESP32-C6, nRF52840, nRF54LM20A, RP2040, RP2350 | Embassy | Known to work on hardware in the server role; not tested in CI |

The repository contains no board support: see the [board-independent Embassy
example](embedded-example/src/lib.rs).

## Quick start

You need Rust 1.97 or newer. The included UDP transport requires Linux.

Run the example server, then query it from a second terminal:

```sh
git clone https://github.com/snabb/mai-coap
cd mai-coap
cargo run --example minimal-server --features std,server
```

```sh
cargo run --example minimal-client --features std,client   # prints: hello
```

The server also works with any CoAP client, for example libcoap:

```sh
coap-client-notls -m get coap://127.0.0.1/hello
```

### Command-line client

`mai-coap` is a curl-like client built on the library, including EDHOC and OSCORE. It uses
libcoap's and aiocoap's flag names where they make sense. See the [guide](docs/cli.md):

```sh
cargo install --locked --git https://github.com/snabb/mai-coap mai-coap-cli
mai-coap coap://127.0.0.1/hello
mai-coap -m put -t json -e '{"on":true}' coap://127.0.0.1/config
```

### Use it in your project

mai-coap is not on crates.io yet, because some dependencies are pinned to Git revisions.
Depend on the repository:

```toml
[dependencies]
mai-coap = { git = "https://github.com/snabb/mai-coap", features = ["server", "std"] }
futures-lite = "2"
rand = "0.10"
```

A complete server. `futures-lite` and `rand` are the choices of this example; any
executor and any cryptographically secure RNG work.

```rust
use mai_coap::{
    codec::Code,
    endpoint::{DefaultEndpoint, DefaultShared, Disposition, Request, ResponseWriter, Unsecured},
    security::PublicPaths,
    server::DefaultRouter,
    time::StdClock,
    transport::linux::StdTransport,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    futures_lite::future::block_on(async {
        let mut socket = StdTransport::bind("127.0.0.1:5683".parse()?)?;
        // Access is denied by default: unprotected requests need a policy entry.
        let policy = PublicPaths(&[(Code::GET, "/hello")]);
        let mut hello = |_: Request<'_>, response: &mut ResponseWriter<'_>| {
            response.set_payload(b"hello")?;
            Ok(Disposition::Complete)
        };
        let mut router = DefaultRouter::new(&policy);
        router.route("/hello", &[Code::GET], &mut hello)?;
        let shared = DefaultShared::new();
        let mut endpoint = DefaultEndpoint::new(&shared, Unsecured(rand::rng()))?;
        router.run(&mut endpoint, &mut socket, &StdClock::default()).await?;
        Ok(())
    })
}
```

To add security, follow the [EDHOC and OSCORE walkthrough](docs/guide.md#security). For
firmware, start with [bare-metal
integration](docs/integration.md#bare-metal-requirements).

## Examples

| Example | What it shows | Run with `cargo run --example <name> --features ...` |
|---|---|---|
| [`minimal-server`](examples/minimal-server.rs) | `/hello` and `/echo`. Optional argument: bind address | `std,server` |
| [`minimal-client`](examples/minimal-client.rs) | GET. Optional arguments: server address, path | `std,client` |
| [`observe`](examples/observe.rs) | Server and client in one process | `std,server,client,observe` |
| [`streaming-upload`](examples/streaming-upload.rs) | Transactional upload through a worker | `std,server,client,block1` |
| [`secured-server`](examples/secured-server.rs), [`secured-client`](examples/secured-client.rs) | EDHOC and OSCORE, [walkthrough](docs/guide.md#security) | `std,server,client,edhoc,software-crypto,observe,block` |
| [`proxy`](examples/proxy.rs) | Forward proxy. Arguments: bind address, `coap://HOST:PORT` of the one allowed origin | `std,proxy` |
| [`embedded-example`](embedded-example/src/lib.rs) | Embassy task body for firmware | [Separate workspace](docs/development.md#repository-layout) |

## Documentation

| Document | Use it to |
|---|---|
| [User guide](docs/guide.md) | Write clients and servers, and use security, block-wise transfers, Observe, discovery and the proxy |
| [Command-line client](docs/cli.md) | Make CoAP requests from a shell, secured or not |
| [Integration guide](docs/integration.md) | Choose features and network adapters, size storage, write custom transports and drivers |
| [Troubleshooting](docs/troubleshooting.md) | Look up build errors and runtime symptoms |
| [Development](docs/development.md) | Build, test and contribute to the project |
| [Conformance](docs/conformance.md) | Check RFC coverage, interpretations and validation limits |
| [Requirements](docs/requirements.md) | Read the normative scope, with requirement IDs |
| [Resource measurements](docs/sizes.md) | See flash, RAM and stack figures |
| [Roadmap](docs/todo.md) | See proposed future work |

API reference: `cargo doc --open --features
std,server,client,block1,observe,proxy,edhoc,software-crypto,discovery,multicast`.

## Limitations

- **Deferred:** static or persistent OSCORE contexts (contexts live in RAM, and EDHOC
  runs again after a reboot), Observe forwarding through the proxy, and Echo return-path
  challenges.
- **Known gap:** a retransmitted Observe notification keeps its original Observe value. See
  [known conformance gaps](docs/conformance.md#known-conformance-gaps).
- **Not supported:**
  - DTLS and `coaps://`; CoAP over TCP or WebSockets
  - other EDHOC methods or cipher suites; X.509 credentials
  - Group OSCORE, protected multicast and multicast application commands
  - ACE and AIF authorization
  - caching or reverse proxies, CoAP-to-HTTP translation
  - OSCORE outer block-wise fragmentation and Appendix B.2 context re-derivation
  - BERT, Q-Block, No-Response and extended tokens
  - Resource Directory, DNS resolution and DNS-SD/mDNS
- **Your application supplies:** payload formats, credentials and access policy, name
  resolution, multicast group membership, and any device management or firmware-update
  logic. The library provides the protocol machinery for these, not the complete
  service.
- **Validate on your own hardware:** stack headroom and live-network behavior depend on
  your board and capacities. See the [validation
  boundaries](docs/conformance.md#validation-boundaries).

## Contributing

Implemented from the RFCs and published test vectors; contributors don't consult other
stacks' source. Developed with LLM assistance. Read
[Development](docs/development.md#contribution-rules) before submitting changes.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual
licensed as described under [License](#license), without any additional terms or
conditions.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your
option. Redistributed binaries must carry the applicable dependency notices from
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

Copyright (c) 2026 mai-coap contributors.
