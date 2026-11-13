#!/usr/bin/env python3
"""Measure a two-forward, two-endpoint proxy with fixed packet/table bounds."""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import subprocess

from resource_metadata import rustc_metadata

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = {
    "thumbv7em-none-eabihf": "netduinoplus2",
    "thumbv8m.main-none-eabihf": "mps2-an505",
}
LINE = re.compile(
    r"proxy: security=(plain|secure) D=1152 forwards=2 payload=1024 "
    r"incoming_future=(\d+) outgoing_future=(\d+) painted=(\d+) capacity=(\d+)"
)


def measurements(log):
    result = {}
    for line in log.splitlines():
        if not line.startswith("proxy:"):
            continue
        match = LINE.fullmatch(line)
        if not match or match[1] in result:
            raise ValueError(f"invalid or duplicate proxy measurement: {line}")
        values = dict(
            zip(
                ("incoming_future", "outgoing_future", "painted", "capacity"),
                map(int, match.groups()[1:]),
                strict=True,
            )
        )
        if any(value <= 0 for value in values.values()):
            raise ValueError(f"invalid proxy sizes: {line}")
        if values["painted"] > values["capacity"] - 256:
            raise ValueError("proxy stack guard exhausted")
        result[match[1]] = values
    if set(result) != {"plain", "secure"}:
        raise ValueError("missing plain or secure proxy scenario")
    if log.splitlines().count("mai-coap proxy runtime: PASS") != 1:
        raise ValueError("proxy runtime did not complete")
    return result


def section_sizes(output):
    result = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[0].startswith("."):
            continue
        if parts[0] in result:
            raise ValueError(f"duplicate ELF section: {parts[0]}")
        result[parts[0]] = int(parts[1])
        if result[parts[0]] < 0:
            raise ValueError(f"negative ELF section size: {parts[0]}")
    if any(result.get(name, 0) <= 0 for name in (".vector_table", ".text")):
        raise ValueError("missing or empty executable ELF sections")
    return result


def source_metadata():
    paths = set((ROOT / "src").rglob("*.rs"))
    paths.update((ROOT / "target-tests/src").rglob("*.rs"))
    paths.update(
        ROOT / name
        for name in (
            "Cargo.toml",
            "Cargo.lock",
            "target-tests/Cargo.toml",
            "target-tests/Cargo.lock",
            "target-tests/build.rs",
            "rust-toolchain.toml",
            "tests/fixtures/i.ccs",
            "tests/fixtures/r.ccs",
        )
    )
    digest = hashlib.sha256()
    for path in sorted(paths):
        if path.is_file():
            digest.update(str(path.relative_to(ROOT)).encode() + b"\0")
            digest.update(path.read_bytes() + b"\0")
    return {
        "source_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "git_dirty": bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"], cwd=ROOT, text=True
            )
        ),
        "source_sha256": digest.hexdigest(),
        "source_digest_boundary": (
            "Sorted relative path, NUL, file bytes, NUL for src/**/*.rs, "
            "target-tests/src/**/*.rs, both Cargo manifests/lockfiles, "
            "target-tests/build.rs, rust-toolchain.toml and tests/fixtures/{i,r}.ccs "
            "when present."
        ),
        "fixture_sha256": {
            name: hashlib.sha256(
                (ROOT / "target-tests/src" / name).read_bytes()
            ).hexdigest()
            for name in ("proxy_main.rs", "stack.rs", "rng.rs")
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, default="thumbv7em-none-eabihf")
    parser.add_argument("--roles", action="store_true")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    features = "proxy-roles" if args.roles else "proxy-profile"
    subprocess.run(
        [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(ROOT / "target-tests/Cargo.toml"),
            "--target",
            args.target,
            "--no-default-features",
            "--features",
            features,
            "--bin",
            "mai-coap-proxy-profile",
        ],
        cwd=ROOT,
        check=True,
    )
    image = (
        ROOT / "target-tests/target" / args.target / "release/mai-coap-proxy-profile"
    )
    saved = args.output / "proxy.elf"
    shutil.copyfile(image, saved)
    runtime = subprocess.run(
        [
            "qemu-system-arm",
            "-M",
            TARGETS[args.target],
            "-nographic",
            "-semihosting-config",
            "enable=on,target=native",
            "-kernel",
            str(saved),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    log = runtime.stdout + runtime.stderr
    (args.output / "runtime.txt").write_text(log)
    print(log, flush=True)
    runtime.check_returncode()
    scenarios = measurements(log)
    sections = subprocess.check_output(["size", "-A", str(saved)], text=True)
    symbols = subprocess.check_output(
        ["nm", "-S", "--size-sort", "--radix=d", "-C", str(saved)], text=True
    )
    (args.output / "sections.txt").write_text(sections)
    (args.output / "symbols.txt").write_text(symbols)
    sizes = section_sizes(sections)
    report = {
        **rustc_metadata(cwd=ROOT),
        **source_metadata(),
        "target": args.target,
        "profile": "release opt-level=s, LTO, codegen-units=1",
        "features": features,
        "datagram_bytes": 1152,
        "forwards": 2,
        "payload_bytes": 1024,
        "elf_sha256": hashlib.sha256(saved.read_bytes()).hexdigest(),
        "roles": args.roles,
        "flash_bytes": sum(
            sizes.get(s, 0) for s in (".vector_table", ".text", ".rodata", ".data")
        ),
        "static_ram_bytes": sum(sizes.get(s, 0) for s in (".data", ".bss", ".uninit")),
        "scenarios": scenarios,
        "boundary": (
            "Two simultaneous opaque forwards with 1024-byte origin payloads and a "
            "public local GET, with plain and "
            "secure-capable receiving endpoints and an unsecured outbound endpoint. "
            "Origin replies are scripted; this does not establish protected local "
            "interoperability or hardware behavior. Endpoints/Shared are static; "
            "driver futures, proxy and simulated link are on the measured stack. "
            "Endpoint construction precedes painting and its peak is unmeasured. "
            "Stack paint is an exercised-write measurement, not a worst-case bound. "
            "CPU and physical hardware are not measured."
        ),
    }
    (args.output / "proxy.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
