# Resource measurements

Copyright (c) 2026 mai-coap contributors.

How this repository measures flash, RAM and stack, and how to check a change. Measured
byte counts live in generated reports, not here:

| Report | Contents |
|---|---|
| [size-resources.json](size-resources.json) | Linked Cortex-M4 flash and static RAM per feature workload, secured endpoint layouts per profile, toolchain, date |
| [stack-resources.json](stack-resources.json) | QEMU driver stack peaks, budgets, driver-future sizes |
| [xarxa-resources.json](xarxa-resources.json) | Owned-packet workload stack, futures, static RAM and component breakdown |
| [proxy-resources.json](proxy-resources.json) | Matched two-endpoint role experiment at D=1152 and two 1,024-byte replies |

These cover reference fixtures, ABI layouts and exercised QEMU peaks, not complete
firmware on real boards.

## Checking a change

For production refactors and changes to buffers, generics, features or dependencies,
compare before and after, even if behavior is unchanged:

```sh
python3 tools/firmware-size.py --output target/resources-after
python3 tools/target-runtime.py --stack-check --output target/resources-after
python3 tools/target-runtime.py --xarxa-check --output target/resources-after
python3 tools/resource-summary.py --target thumbv7em-none-eabihf --reports target/resources-after --baseline target/resources-before > target/resource-summary.md
```

Build the `target/resources-before` reports the same way from the base revision. Use
`--fetch-baseline --repository snabb/mai-coap` instead of `--baseline` to download a
`master` baseline with an authenticated GitHub CLI.

Compare matched build settings and record compiler changes. Investigate growth before
completing a change, and don't raise budgets merely to pass. Moving storage between
stack and statics is not a total-RAM reduction, and task pools are already in static
RAM.

## Regenerating the reports

```sh
python3 tools/target-runtime.py --target thumbv7em-none-eabihf --features memory-layout | tee target/memory-layout.txt
python3 tools/storage-layout.py target-tests/target/thumbv7em-none-eabihf/release/mai-coap-target-tests --runtime-log target/memory-layout.txt --profile "release opt-level=s, LTO, codegen-units=1" --output target/storage-unicast.json
python3 tools/target-runtime.py --target thumbv7em-none-eabihf --features memory-layout,multicast | tee target/memory-layout-multicast.txt
python3 tools/storage-layout.py target-tests/target/thumbv7em-none-eabihf/release/mai-coap-target-tests --runtime-log target/memory-layout-multicast.txt --profile "release opt-level=s, LTO, codegen-units=1" --output target/storage-multicast.json
python3 tools/firmware-size.py --layout-report target/storage-unicast.json --layout-report target/storage-multicast.json
```

Pass both layout reports to generate the layout summaries and counter-size metadata
together. Review `target/size-report/sizes.json` before copying it to
`docs/size-resources.json`. ELFs, section totals and symbol reports stay under
`target/size-report`.

`storage-layout.py` records the ELF's compiler identity. Pass the actual settings
through `--profile`, and pass `--build-host <compiler-host-triple>` for an ELF built on
another host. Linked sizes depend on the build host, so compare same-host builds.

## CI summaries

Each CI run's Summary page shows resource tables and byte deltas against the latest
successful `master` push, scheduled or manual run with unexpired measurements.

| Measurement | Routine runs | Weekly and manual runs |
|---|---|---|
| M33 stack, futures, owned-xarxa ceilings | Enforced | Enforced |
| M4 stack, futures, owned-xarxa ceilings | | Enforced |
| M4 linked flash, static RAM, layouts | | Informational |

Each section names the baseline and current compiler, build host and profile. Compiler,
build-host and ID Context capacity changes are highlighted and still count in deltas.
Incompatible profiles, features or capacities show no delta. Missing history shows as
unavailable, not zero.

Each job writes to a directory specific to its run and attempt, so cached reports can't
stand in for current measurements. `resource-metrics-<target>` JSON artifacts are kept
for 90 days, and ELF, section and symbol artifacts for 14 days.

## Linked Cortex-M4 workloads

`tools/firmware-size.py` builds `target-tests` for `thumbv7em-none-eabihf` (release,
size optimization, LTO, one codegen unit). Workloads exercise reachable protocol paths.
They don't give whole-feature upper bounds, and static RAM excludes stack. Two-role
EDHOC and protocol tables use stack storage, so section totals don't estimate peak RAM.

| Workload | Exercises |
|---|---|
| Base features | Small datagram and packet budget, shared with the Cortex-M0 QEMU image, plus the client and test-support layers |
| `get-server`, `get-server-shared-counters` | `ServerEndpoint` and an immediate router: a GET, a duplicate reply and the async driver through a scripted transport. No real network adapter or executor |
| `block`; `block1`, `full-block1` | Block2 without uploads; with uploads |
| Proxy, discovery, full | Their own bounded tables; full also includes multicast collection |

Capacities are in [the fixture](../target-tests/src/main.rs), and they are not library
defaults. Linked deltas include fixture changes, so use the saved symbol reports to
attribute cost.

## Two-endpoint proxy workload

`tools/proxy-resources.py --output target/proxy-profile` measures two overlapping
opaque forwards with 1,024-byte origin payloads at a 1,152-byte datagram limit,
followed by a public local GET. Add `--roles` to select a server-only receiving
endpoint and client-only outbound endpoint; all capacities remain identical.
The ELF contains both plain and secure-capable receiving endpoints. Origin replies
are scripted, so this does not validate protected local interoperability or hardware.

The report records flash, static RAM, both driver futures and exercised stack paint,
with compiler/build host, source revision/digest and ELF/fixture hashes. Endpoints and Shared storage are
static; the proxy, link and futures occupy the stack. Stack paint records exercised
writes rather than a worst-case bound; endpoint construction happens before painting,
and its peak is unmeasured. Preserve both ELFs and symbol reports when
comparing revisions. [proxy-resources.json](proxy-resources.json) records the matched
role experiment.

## Endpoint layouts

The `memory-layout` fixture keeps secured `DefaultEndpoint`, `SmallEndpoint` and
`ServerEndpoint` in one ELF. `tools/storage-layout.py` checks runtime `size_of` results
against DWARF and rejects changed capacities, missing or conflicting layouts, unexpected
members and disagreements. It reports packet-pool storage separately from other inline
state.

- Layouts aid budgeting but don't measure a complete application.
- Nested rows in detailed layout artifacts are included in parent totals.
- Command and result storage occupy mutually exclusive variants.
- Multicast adds a bounded reply queue per command slot.
- `shared-counters` adds one `Counters` snapshot per `Shared`, whatever the command
  capacity (`measurement.counter_snapshot_bytes`).

Unsecured operation futures in the report are reachability probes, not estimates of
production storage.

## Driver stack checks

`python3 tools/target-runtime.py --stack-check` runs on Cortex-M4 and M33. Each mode
establishes EDHOC using real endpoint driver futures at `D=1152`, then exchanges an
OSCORE request and response on the same context. Combined and sequential EDHOC have
separate handshake and traffic measurements.

**Configuration.** One outbound exchange, four duplicate records, one observer, two
cached replies, two send descriptors, one command, one deferred request, one body
context, three packet slots, one security context, one handshake and one trusted peer.
The fixture has a 128 KiB RAM region and is not a board budget.

**Method.** Before each phase, the fixture paints unused stack below the active stack
pointer, then a volatile scan finds the deepest changed word. A 256-byte intact lower
guard is required. Paint can miss reserved but unwritten space and excludes interrupts,
executors and network adapters, so this is not a worst-case bound. Both drivers, the
operation future and the transport mailboxes live on the fixture stack, so peaks include
that storage.

**Budgets.** [tools/stack-budgets.json](../tools/stack-budgets.json) uses the maximum of
three runs plus 512 bytes, rounded up to 256 bytes. Update budgets only after reviewing
measurements and disassembly.

CI enforces budgets on current stable Rust, so compiler-induced growth also fails. If a
failure coincides with a compiler update, compare the same source on both compilers. A
version change never disables enforcement or raises a budget automatically.

`--target` selects one machine, and `--measure-only` records without enforcing.
`--stack-check` fixes the feature set. Missing, malformed or duplicated scenarios,
exhausted guards and exceeded budgets fail the check.

`peak_bytes` in the reports is the budgeted value and currently equals `painted_bytes`.

## Owned xarxa workloads

`python3 tools/target-runtime.py --xarxa-check --output target/xarxa-report` runs native
xarxa on M4 and M33. Each mode runs three 1,024-byte-body exchanges at `D=1152`:
establishment, a lost CON reply with retry, and NON traffic. Modes cover plain CoAP and
combined and sequential EDHOC with OSCORE. The loss check compares exact reply bytes,
and every mode must return all 16 network buffers.

- `endpoint_bytes`, `shared_bytes` and `network_state_bytes` cover both peers, and
  `network_pool_bytes` covers the entire shared pool. These are components of static
  RAM, not extra allocations.
- Driver futures are on the measured stack, so don't add them to its peak.
- The raw-IP link excludes board and radio drivers and the Embassy runner.
- This workload is separate from the slice-transport fixture, so its peaks are not a
  before/after comparison.

[tools/xarxa-budgets.json](../tools/xarxa-budgets.json) sets per-target ceilings for
each phase, driver futures and static RAM. They stay fixed as later changes consume
headroom, so update them deliberately, not from each new peak.

## Measuring your own firmware

- **Boot can hide handshake stack.** A cumulative paint never shows anything below the
  boot peak. Repaint free stack before each phase.
- **Don't add nested figures.** Task pools are already in static RAM, futures sit inside
  task pools, and security variants overlap. Moving storage between stack and statics is
  not a saving, so compare static RAM plus peak stack.
- **Control the build.** Longer source paths in panic locations change `.rodata`. Compare
  the same host, path, compiler and settings.
- **Small stack differences aren't repeatable.** Repeat runs before attributing one to a
  change.
- **Check the link before blaming the build.** MAC retry expiries and IPv6 transmit
  failures can account for unanswered datagrams. Link counters still don't attribute
  individual datagrams.
- **Counters have boundaries.** `requests` increments after rate limiting and other
  admission checks, so flat counters don't prove a packet missed the node. Use
  `rate_limited` and a socket-level witness. Burst experiments can also exhaust the
  default rate limit (128 per source).
- **A rerun is not an explanation.** Record traces and per-case counter deltas for
  intermittent failures.

## Design trade-offs

Current choices that shape the reports:

- **ID Context storage.** The default keeps 255 bytes per OSCORE context. EDHOC derives
  no ID Context, so zero capacity removes that reservation without changing counts. The
  slice fixture keeps the default and native xarxa uses zero, so compact-only
  measurements can't hide growth in the default.
- **Response construction.** Synchronous callbacks use `ResponseWriter` in one D-byte
  arena, and deferred submission uses owned `Response` values. The writer lowers stack
  peaks at a flash cost. Each fresh arena is initialized; keeping one would trade CPU
  for persistent RAM.
- **Retained replies.** Proxy forwards and Block1 duplicates keep one tokenless
  serialized packet. Deferred entries keep only the token and message type. Observer
  entries keep their request, because notification callbacks read it.
- **Packet handles.** A handle is a one-based `u16` slot holding one counted reference,
  so a slot can't be reused while a handle exists.
- **Credentials.** Identity and trusted peers keep validated CCS bytes and reparse
  during lookup and handshakes. The scanning store can parse up to N candidates plus the
  selected one, and node-side execution time is unmeasured.
- **Frame boundaries.** `#[inline(never)]` on receive, command and crypto paths keeps
  mutually exclusive datagram buffers in separate frames. Removing one can raise a peak
  without changing any layout, so check the stack reports. Proxy normalization declares
  `2 * DATAGRAM_BYTES + 255` bytes of scratch in its own frames.
- **Receive waiting.** The driver pins the transport receive future once and polls it
  before the command and timer wake future, and drops them before processing.
  `tests/driver_wait.rs` covers simultaneous readiness, cancellation and arrivals
  preserved across a restart.
- **Rejected experiments.** Splitting incoming crypto, refusal and dispatch into staged
  frames left peaks unchanged. Borrowed request input saved responder stack but cost
  public API, flash and protected-traffic stack.
