# Coding agent conventions

Copyright (c) 2026 mai-coap contributors.

Build, check and CI commands are in [docs/development.md](docs/development.md). This file
holds the constraints a change must preserve.

## Scope

- [docs/requirements.md](docs/requirements.md) defines scope.
  [docs/conformance.md](docs/conformance.md) records interpretations, coverage, deferred
  requirements and validation limits. Update them and the
  [documented user guides](docs/development.md#documentation-map) when behavior changes; a
  module compiling does not establish conformance.
- Implement protocols from RFCs, verified errata and published test vectors. RFC text
  overrides conflicting requirement wording; record the decision in the conformance document.
- Do not read other CoAP/OSCORE/EDHOC-over-CoAP stacks' source or model APIs on theirs.
  Independent stacks are black-box interoperability peers. Lakers is the exception: use its
  public API and pinned dependency without vendoring or modifying it.
- Static OSCORE contexts, proxy Observe forwarding and Echo challenges are deferred. Do not
  expand scope incidentally. Ask before implementing an ambiguous request or choosing between
  materially different designs.

## Architecture and resource bounds

- Keep the protocol crate `no_std`, allocator-independent and free of unsafe code. Preserve
  Cortex-M0 support without atomic compare-and-swap, using the existing critical-section
  abstraction for shared state.
- Keep default features empty and optional layers isolated. Keep public, unsealed extension
  points for transport, clock, crypto and applications, with no required executor, HAL or
  network stack.
- Client, server and proxy work share one endpoint/socket driver by default; cross-stack
  forwarding may use a separately driven outbound endpoint. The library spawns no tasks. Use
  bounded deferred-work APIs for slow application I/O. Do not block the driver or hold critical
  sections across `.await`.
- Every queue, table and buffer has an explicit bound and defined capacity, eviction or drop
  behavior. Keep contexts pinned while exchanges, observations or uploads reference them.
- Wrappers must forward the complete trait contract, including default lifecycle, policy,
  deadline and counter methods, and be tested through the wrapper when behavior depends on
  forwarding. Update the delegation macros when changing `Application` or `Protection`; preserve
  driver wakers and transport error classification.

## Protocol invariants

- Preserve cancellation safety. Release resources on completion, cancellation, timeout and error;
  preserve transport datagrams and endpoint metadata.
- Retransmit stored serialized bytes, including cached duplicate replies. Do not re-encrypt
  retries. Reserve sender sequence numbers before use and never roll them back after failure.
- Preserve byte-exact credentials and cryptographic transcript inputs. Forward protected proxy
  traffic opaquely, without decrypting or reassembling it.
- Keep resource and proxy policies default-deny. Public paths and proxy destinations require
  explicit policy; never silently fall back to unprotected communication.
- Validate network input with checked operations and explicit errors. Avoid network-reachable
  panics, assertions and unchecked indexing.
- Keep compatibility guards and workarounds until the replacement has regression coverage and
  validation against the pinned dependency.
- Keep keys, protected plaintext and complete tokens out of logs. Test-vector credentials belong
  in tests, not runnable secured examples.

## Tests and checks

- Run `python3 tools/checks.py --docs --test`, plus the
  [checks for the affected area](docs/development.md#checks). Use the feature matrix in
  `tools/checks.py`, not `--all-features`: `log` and `defmt` are mutually exclusive.
- `fuzz/`, `target-tests/` and `embedded-example/` are independent workspaces with their own
  lockfiles. Format and validate each affected one through its manifest.
- Use deterministic clocks and transports for state-machine tests. Cover relevant loss,
  duplication, reordering, expiry, cancellation, capacity and error-cleanup cases. Use published
  vectors and independent interoperability checks for wire changes.
- For refactors and changes to buffers, generics, features or dependencies, compare resource use
  even when behavior is unchanged, as described in [docs/sizes.md](docs/sizes.md). Investigate and
  report growth; do not raise budgets merely to pass. Moving storage between stack and statics is
  not a total-RAM reduction. Change baselines only with linked workloads and section or symbol
  reports, and state which allocations a measurement excludes.
- Do not weaken assertions or hide failures. Report compile checks, host networking, emulation,
  interoperability and hardware validation separately.

## Proofs and fuzz oracles

- Kani suits pure parsing/encoding, size or offset arithmetic and security state (sequence
  numbers, replay windows, nonces); fuzzing suits large inputs and multi-message sequences. Update
  harnesses in the module's `proofs.rs` when changing such code.
- For a new network-input surface, extend a fuzz target, add boundary seeds through
  `tools/fuzz-seeds.py`, and keep `tools/fuzz-smoke.py` covering it.
- Derive properties and oracles from the RFC, not the implementation, and cite the requirement ID.
  Fuzz targets need an oracle beyond panic freedom. Invariants over sequences need an inductive
  harness.
- Reach code behind authentication by fuzzing the plaintext side rather than relying on random
  ciphertext.
- Show each new harness or oracle fails on a plausible defect (temporary mutation, not committed).
  Give harnesses with assumptions or early returns a `kani::cover!`.
- Have a separate agent or person derive expected properties from the RFC without reading the
  implementation or harnesses, then record gaps as findings.
- Turn every crash or oracle failure into a unit regression test and a seed.

## Dependencies and licensing

- Use edition 2024. When changing dependencies, verify current stable releases while respecting
  documented pins. Keep the shared crypto-provider and RNG abstractions; do not add another
  `rand_core` major to the protocol graph. Manage Python dependencies with `uv`.
- Licensing is MIT OR Apache-2.0, held by **mai-coap contributors**. Preserve upstream attribution
  verbatim. After lockfile changes run `python3 tools/notices.py`, never hand-edit its output, and
  review cached license text and metadata.
- Keep generated binaries, fuzz artifacts, temporary credentials and environment directories out of
  Git.

## Style

- Write comments for experienced Rust developers: non-obvious constraints and invariants, not
  individual steps or language features. Document public APIs, errors, panics and safety contracts.
- Documentation describes the current design. Keep commit messages and PR text concise and factual.
