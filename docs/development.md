# Development

How to build, test and change mai-coap. Coding-agent conventions, which also apply to
anyone changing protocol code, are in [AGENTS.md](../AGENTS.md).

## Contribution rules

- **Sources.** Implement protocols from RFCs, verified errata and published test
  vectors. Don't read other CoAP, OSCORE or EDHOC-over-CoAP stacks' source, or model
  APIs on theirs. Independent stacks are black-box interoperability peers only. Lakers
  is the exception, used through its public API and a pinned revision.
- **Scope.** [Requirements](requirements.md) define it, and RFC text takes precedence.
  Record behavior changes and interpretations in [conformance](conformance.md).
- **Licensing.** Project code is MIT OR Apache-2.0, with notices held by **mai-coap
  contributors**. Unless you explicitly state otherwise, any contribution intentionally
  submitted for inclusion in this project by you, as defined in the Apache-2.0 license,
  shall be dual licensed the same way, without any additional terms or conditions.

## Repository layout

The root package is not an umbrella workspace. Format and check each workspace through
its own manifest.

| Path | Contents |
|---|---|
| `src/`, `tests/`, `examples/` | The library, integration tests and host examples |
| `embedded-example/` | Separate workspace: board-independent Embassy and xarxa servers |
| `target-tests/` | Separate workspace: no_std fixtures run under QEMU |
| `fuzz/` | Separate workspace: cargo-fuzz targets (nightly) |
| `tools/` | Python check, measurement and notice scripts |
| `tests/fixtures/` | [Published RFC credential vectors](../tests/fixtures/README.md) |
| `docs/` | Documentation and generated resource reports |

## Prerequisites

| For | You need |
|---|---|
| Host tests | Rust 1.97+ (CI also tests current stable), Python 3, Linux with IPv4 and IPv6 loopback |
| libcoap interop in `tests/interop.rs` | `coap-client-notls` and `coap-server-notls` (libcoap 4.3.4 or 4.3.5; on Ubuntu, `libcoap3-bin`) |
| aiocoap interop | [uv](https://docs.astral.sh/uv/) |
| Cross checks and QEMU | Rust targets below, `qemu-system-arm`, `qemu-system-riscv32`, binutils |
| Fuzzing | Nightly Rust, `cargo-fuzz` 0.13.2 |
| Proofs | `kani-verifier` 0.68.0 (`cargo kani setup` installs its pinned nightly) |
| Python tool linting | `uv tool run ruff==0.17.3` |

The library builds on stable. Nightly is confined to fuzzing and Kani.

## Checks

Before submitting, run the comprehensive host check and format every workspace you
changed:

```sh
python3 tools/checks.py --docs --test
cargo fmt --check
cargo fmt --manifest-path embedded-example/Cargo.toml --check   # likewise fuzz/ and target-tests/
```

Then add the checks for the affected area:

| Affected area | Command |
|---|---|
| Feature gates, embedded compatibility | `python3 tools/checks.py --target thumbv6m-none-eabi` (also `thumbv7em-none-eabihf`, `thumbv8m.main-none-eabihf`, `riscv32imac-unknown-none-elf`) |
| MSRV | `RUSTUP_TOOLCHAIN=1.97 python3 tools/checks.py --msrv` |
| Target runtime behavior | `python3 tools/target-runtime.py` (or `--target <target>`) |
| Parser or protocol state machine | `python3 tools/fuzz-smoke.py --seconds 30` |
| Codec, block option, URI, OSCORE core arithmetic, writer sizes, messaging timers | `python3 tools/kani.py` (or `--harness <filter>`) |
| Wire behavior | Build the examples (below), then `uv run --with 'aiocoap[oscore]==0.4.17' tools/interop-aiocoap.py` |
| Flash, static RAM, stack | [Resource checks](sizes.md#checking-a-change) |
| Dependencies or lockfiles | `python3 tools/notices.py --check` |
| Examples | `cargo build --locked --examples --features std,server,client,block,block1,observe,proxy,edhoc,software-crypto,multicast,discovery`, then `python3 tools/example-smoke.py` |

Use the feature matrix in `tools/checks.py`, not `--all-features`. Documentation-only
changes need document checks, not a protocol validation campaign.

**More aiocoap profiles:**

```sh
uv run --with 'aiocoap[oscore]==0.4.17' tools/interop-aiocoap.py --profile minimal-ccs

# Xarxa adapters over the loopback test link. Build the example with the adapters first.
cargo build --locked --example secured-server --features std,server,client,block,block1,observe,proxy,edhoc,software-crypto,multicast,discovery,xarxa-ipv4,xarxa/medium-ip,embassy-net-xarxa-ipv4,embassy-net-xarxa/medium-ip
uv run --with 'aiocoap[oscore]==0.4.17' tools/interop-aiocoap.py --xarxa native
uv run --with 'aiocoap[oscore]==0.4.17' tools/interop-aiocoap.py --xarxa embassy
```

**Fuzzing.** Each [target](../fuzz/fuzz_targets) needs an oracle beyond panic freedom.
Generate reproducible seeds with `tools/fuzz-seeds.py`, and turn every crash into a
regression test and a seed.

**Tool self-tests** are `tools/test-*.py`. CI runs them on every change.

## Continuous integration

[`ci.yml`](../.github/workflows/ci.yml) runs on Ubuntu 26.04.

| Run | Trigger | Jobs |
|---|---|---|
| Routine | Pull requests, merge queue, `master` pushes | Embedded (Cortex-M0, Cortex-M33), then `CI passed`: formatting, Python lint, Actions lint, host feature matrix and tests, Windows compile check, notices, examples, libcoap and aiocoap interop, xarxa interop, MSRV |
| Full | Mondays 04:23 UTC, manual | Also Cortex-M4 and RISC-V, fuzzing each target for 30 s, and Kani |

- `CI passed` requires the embedded jobs. It also requires fuzzing and Kani on full
  runs, and allows their skips on routine runs.
- Cortex-M33 stack and owned-xarxa budgets are enforced on every run, and Cortex-M4
  budgets on full runs. Each run's summary page shows [resource
  tables](sizes.md#ci-summaries).
- Documentation-only pushes to `master` are skipped. Pull requests always run.
- Pushes to other branches rely on pull-request checks.
- Newer routine runs cancel superseded ones for the same branch or pull request.
- Dependabot checks GitHub Actions releases weekly.

## Dependencies and notices

Redistributed binaries must carry [THIRD_PARTY_NOTICES.txt](../THIRD_PARTY_NOTICES.txt).
After changing a lockfile, regenerate it instead of editing it by hand:

```sh
python3 tools/notices.py            # --refresh also caches missing upstream licenses for review
```

Lakers, xarxa and xarxa-backed Embassy are pinned Git dependencies, which blocks
crates.io publication. Compatible published releases plus regression validation are
[release prerequisites](todo.md#release).

Manage Python dependencies with `uv`. Keep the shared crypto-provider and RNG
abstractions, and don't introduce another `rand_core` major into the protocol graph.

## Documentation map

| Document | Audience | Keep it current when |
|---|---|---|
| [README](../README.md) | New users | Capabilities, platforms or the quick start change |
| [guide.md](guide.md) | Application developers | Public APIs change |
| [integration.md](integration.md) | Firmware and platform integrators | Features, adapters, capacities or extension points change |
| [troubleshooting.md](troubleshooting.md) | All users | A real problem has a known cause |
| [requirements.md](requirements.md) | Maintainers | Scope changes |
| [conformance.md](conformance.md) | Maintainers, reviewers | Behavior, interpretations or validation change |
| [sizes.md](sizes.md) | Maintainers | Measurement methods change. Figures live in the JSON reports |
| [todo.md](todo.md) | Maintainers | Work is agreed or finished |
| [AGENTS.md](../AGENTS.md) | Coding agents | Conventions change |

Describe the current design. Git history records how it got there.
