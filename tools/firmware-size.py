#!/usr/bin/env python3
"""Record linked Cortex-M4 reference workloads, sections and largest symbols."""

import argparse
import datetime
import json
import pathlib
import shutil
import subprocess

from resource_metadata import rustc_metadata

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMON = "client,test-support"
PROFILES = {
    "base": COMMON,
    "block": f"{COMMON},block",
    "block1": f"{COMMON},block1",
    "observe": f"{COMMON},observe",
    "oscore": f"{COMMON},oscore",
    "edhoc": f"{COMMON},edhoc",
    "proxy": f"{COMMON},proxy",
    "discovery": f"{COMMON},discovery",
    "full-block1": f"{COMMON},edhoc,block1,observe,proxy,discovery,multicast",
    "get-server": "get-server",
    "get-server-shared-counters": "get-server,shared-counters",
    "get-server-block1": "get-server-block1",
}

BASELINE_PROFILES = {
    "base": "base",
    "block1": "block",
    "observe": "observe",
    "oscore": "oscore",
    "edhoc": "edhoc",
    "proxy": "proxy",
    "discovery": "discovery",
    "full-block1": "full",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=pathlib.Path, default=ROOT / "target/size-report"
    )
    parser.add_argument(
        "--layout-report",
        type=pathlib.Path,
        action="append",
        default=[],
        help="include summary of a storage-layout.py JSON report (repeat for both modes)",
    )
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {}
    for name, features in PROFILES.items():
        command = [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            str(ROOT / "target-tests/Cargo.toml"),
            "--target",
            "thumbv7em-none-eabihf",
            "--no-default-features",
            "--target-dir",
            str(ROOT / "target/size-build"),
        ]
        if features:
            command += ["--features", features]
        subprocess.run(command, cwd=ROOT, check=True)
        image = (
            ROOT
            / "target/size-build/thumbv7em-none-eabihf/release/mai-coap-target-tests"
        )
        saved = args.output / (name + ".elf")
        shutil.copyfile(image, saved)
        sections = subprocess.check_output(["size", "-A", str(saved)], text=True)
        symbols = subprocess.check_output(
            ["nm", "-S", "--size-sort", "--radix=d", "-C", str(saved)], text=True
        )
        (args.output / (name + "-sections.txt")).write_text(sections)
        (args.output / (name + "-symbols.txt")).write_text(symbols)
        sizes = {
            parts[0]: int(parts[1])
            for line in sections.splitlines()
            if len(parts := line.split()) >= 3 and parts[0].startswith(".")
        }
        report[name] = {
            "features": features,
            "flash_bytes": sum(
                sizes.get(s, 0) for s in [".vector_table", ".text", ".rodata", ".data"]
            ),
            "static_ram_bytes": sum(
                sizes.get(s, 0) for s in [".data", ".bss", ".uninit"]
            ),
        }
    report["measurement"] = {
        "date": datetime.date.today().isoformat(),
        **rustc_metadata(cwd=ROOT),
        "target": "thumbv7em-none-eabihf",
        "profile": "release opt-level=s, LTO, codegen-units=1",
        "boundary": "Reachable test workloads, not whole-feature upper bounds. Static RAM excludes stack. Two-role EDHOC and protocol tables use stack storage; this is not a peak RAM measurement.",
    }
    if args.layout_report:
        report["layouts"] = {}
        counter_sizes = set()
        for path in args.layout_report:
            layout = json.loads(path.read_text())
            counter_sizes.update(
                profile["endpoint"]["fields"]["counters"]["size_bytes"]
                for profile in layout["profiles"].values()
            )
            mode = "multicast" if layout["multicast"] else "unicast"
            if mode in report["layouts"]:
                raise ValueError(f"duplicate {mode} layout report")
            report["layouts"][mode] = {
                "build_host": layout.get("build_host"),
                "shared_counters": layout["shared_counters"],
                "target": layout["target"],
                "boundary": layout["boundary"],
                "profiles": {
                    name: {
                        "capacities": profile["capacities"],
                        "endpoint_bytes": profile["endpoint"]["total_bytes"],
                        "shared_bytes": profile["shared"]["total_bytes"],
                        "packet_pool_bytes": profile["endpoint"]["fields"]["pool"][
                            "size_bytes"
                        ],
                    }
                    for name, profile in layout["profiles"].items()
                },
            }
        if len(counter_sizes) != 1:
            raise ValueError("counter snapshot layouts disagree")
        report["measurement"]["counter_snapshot_bytes"] = counter_sizes.pop()
    baseline_path = ROOT / "target/resource-before/sizes.json"
    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text())
        report["comparison"] = {
            "baseline": "target/resource-before/sizes.json",
            "same_toolchain": baseline.get("measurement", {}).get("toolchain")
            == report["measurement"]["toolchain"],
            "same_build_host": baseline.get("measurement", {}).get("build_host")
            == report["measurement"]["build_host"],
            "matched_profiles": {
                name: {
                    "baseline_profile": old_name,
                    "flash_delta_bytes": report[name]["flash_bytes"]
                    - baseline[old_name]["flash_bytes"],
                    "static_ram_delta_bytes": report[name]["static_ram_bytes"]
                    - baseline[old_name]["static_ram_bytes"],
                }
                for name, old_name in BASELINE_PROFILES.items()
            },
            "block_semantics": (
                "The saved block/full fixtures included Block1 uploads. Their "
                "feature-equivalent current profiles are block1/full-block1; "
                "the current block profile measures Block2 without uploads."
            ),
        }
    (args.output / "sizes.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
