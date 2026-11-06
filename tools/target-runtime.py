#!/usr/bin/env python3
"""Build and execute bounded no_std tests on each specified QEMU machine."""

import argparse
import datetime
import json
import pathlib
import re
import shutil
import subprocess
import tomllib

from resource_metadata import rustc_metadata

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGETS = {
    "thumbv6m-none-eabi": ("qemu-system-arm", "microbit"),
    "thumbv7em-none-eabihf": ("qemu-system-arm", "netduinoplus2"),
    "thumbv8m.main-none-eabihf": ("qemu-system-arm", "mps2-an505"),
    "riscv32imac-unknown-none-elf": ("qemu-system-riscv32", "virt"),
}
STACK_TARGETS = ("thumbv7em-none-eabihf", "thumbv8m.main-none-eabihf")
SCENARIOS = {
    f"{mode}/{phase}"
    for mode in ("combined", "sequential")
    for phase in ("handshake", "traffic")
}
STACK_LINE = re.compile(
    r"stack: mode=(combined|sequential) phase=(handshake|traffic) D=(\d+) "
    r"painted=(\d+) capacity=(\d+) client_future=(\d+) server_future=(\d+)"
)

XARXA_SCENARIOS = {
    f"{mode}/{phase}"
    for mode in ("plain", "combined", "sequential")
    for phase in ("handshake", "traffic", "non")
}
XARXA_LINE = re.compile(
    r"xarxa: mode=(plain|combined|sequential) phase=(handshake|traffic|non) D=(\d+) "
    r"painted=(\d+) capacity=(\d+) client_future=(\d+) server_future=(\d+) "
    r"endpoint=(\d+) shared=(\d+) network_pool=(\d+) network_state=(\d+) owned=(-?\d+) copied=(-?\d+)"
)


def xarxa_measurements(log):
    measurements = {}
    fields = (
        "datagram_bytes",
        "painted_bytes",
        "capacity_bytes",
        "client_future_bytes",
        "server_future_bytes",
        "endpoint_bytes",
        "shared_bytes",
        "network_pool_bytes",
        "network_state_bytes",
        "owned_sends",
        "copied_sends",
    )
    for line in log.splitlines():
        if not line.startswith("xarxa:"):
            continue
        match = XARXA_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid xarxa measurement: {line}")
        mode, phase, *values = match.groups()
        key = f"{mode}/{phase}"
        if key in measurements:
            raise ValueError(f"duplicate xarxa scenario: {key}")
        value = dict(zip(fields, map(int, values), strict=True))
        if value["datagram_bytes"] != 1152 or any(
            value[field] <= 0 for field in fields[:-2]
        ):
            raise ValueError(f"invalid xarxa sizes: {key}")
        if any(value[field] < 0 for field in fields[-2:]):
            raise ValueError(f"invalid xarxa send counters: {key}")
        if value["painted_bytes"] > value["capacity_bytes"] - 256:
            raise ValueError(f"xarxa stack guard exhausted: {key}")
        value["peak_bytes"] = value["painted_bytes"]
        measurements[key] = value
    if measurements.keys() != XARXA_SCENARIOS:
        raise ValueError(
            f"missing xarxa scenarios: {sorted(XARXA_SCENARIOS - measurements.keys())}"
        )
    for mode in ("plain", "combined", "sequential"):
        if not any(
            measurements[f"{mode}/{phase}"]["owned_sends"] > 0
            for phase in ("handshake", "traffic", "non")
        ):
            raise ValueError(f"missing xarxa owned sends: {mode}")
    if log.splitlines().count("xarxa pool: free=16 buffers=16") != 3:
        raise ValueError("missing xarxa pool reclamation checks")
    return measurements


def stack_measurements(log):
    measurements = {}
    for line in log.splitlines():
        if not line.startswith("stack:"):
            continue
        match = STACK_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"invalid stack measurement: {line}")
        mode, phase, *values = match.groups()
        datagram, painted, capacity, client, server = map(int, values)
        key = f"{mode}/{phase}"
        if key in measurements:
            raise ValueError(f"duplicate stack scenario: {key}")
        if datagram != 1152 or min(painted, client, server) <= 0:
            raise ValueError(f"invalid stack sizes: {key}")
        if painted > capacity - 256:
            raise ValueError(f"stack guard exhausted: {key}")
        measurements[key] = {
            "datagram_bytes": datagram,
            "painted_bytes": painted,
            "peak_bytes": painted,
            "capacity_bytes": capacity,
            "client_future_bytes": client,
            "server_future_bytes": server,
        }
    if measurements.keys() != SCENARIOS:
        raise ValueError(
            f"missing stack scenarios: {sorted(SCENARIOS - measurements.keys())}"
        )
    return measurements


def check_budgets(target, measurements, budgets, scenarios=SCENARIOS):
    limits = budgets.get(target, {})
    if limits.keys() != scenarios:
        raise ValueError(f"missing or unexpected stack budgets: {target}")
    for name, measurement in measurements.items():
        budget = limits[name]
        if type(budget) is not int or budget <= 0:
            raise ValueError(f"invalid stack budget: {target} {name}")
        if measurement["peak_bytes"] > budget:
            raise ValueError(
                f"stack budget exceeded: {target} {name}: "
                f"{measurement['peak_bytes']} > {budget} bytes"
            )


def record_stack(target, log, image, output, enforce, budgets, *, kind="stack"):
    output.mkdir(parents=True, exist_ok=True)
    stem = output / f"{kind}-{target}"
    stem.with_name(stem.name + ".txt").write_text(log)
    saved = stem.with_name(stem.name + ".elf")
    shutil.copyfile(image, saved)
    outputs = {}
    for label, command in (
        ("sections", ["size", "-A", str(saved)]),
        ("symbols", ["nm", "-S", "--size-sort", "--radix=d", "-C", str(saved)]),
    ):
        outputs[label] = subprocess.check_output(command, text=True)
        stem.with_name(stem.name + f"-{label}.txt").write_text(outputs[label])
    sections = {
        parts[0]: int(parts[1])
        for line in outputs["sections"].splitlines()
        if len(parts := line.split()) >= 3 and parts[0].startswith(".")
    }
    if ".text" not in sections:
        raise ValueError("missing linked text section")
    measurements = (
        stack_measurements(log) if kind == "stack" else xarxa_measurements(log)
    )
    target_budgets = budgets.get(target, {})
    stack_budgets = (
        target_budgets.get("stack", {}) if kind == "xarxa" else target_budgets
    )
    context_capacity = re.findall(
        rf"^{kind} config: id_context_bytes=(\d+)$", log, re.MULTILINE
    )
    if len(context_capacity) != 1:
        raise ValueError("missing or invalid fixture ID Context capacity")
    report = {
        "target": target,
        "date": datetime.date.today().isoformat(),
        "flash_bytes": sum(
            sections.get(name, 0)
            for name in (".vector_table", ".text", ".rodata", ".data")
        ),
        "static_ram_bytes": sum(
            sections.get(name, 0) for name in (".data", ".bss", ".uninit")
        ),
        "machine": TARGETS[target][1],
        **rustc_metadata(cwd=ROOT),
        "features": "stack-profile (EDHOC, Block1, Observe, proxy, discovery, multicast)",
        "profile": "release opt-level=s, LTO, codegen-units=1",
        "id_context_bytes": int(context_capacity[0]),
        "boundary": (
            "Two endpoint drivers and operation futures on the fixture stack; endpoints "
            "and Shared storage are static. Phases exclude credential setup and reporting. "
            "Paint observes writes; reserved but unwritten space may be missed. "
            "These exercised peaks do not establish worst-case bounds or physical-board headroom."
        ),
        "budget_enforced": enforce,
        "budgets": stack_budgets if enforce else None,
        "scenarios": measurements,
    }
    if kind == "xarxa":
        report["features"] = (
            "xarxa-profile (native xarxa, EDHOC/OSCORE, 1024-byte bodies)"
        )
        report["boundary"] = (
            "Two endpoint drivers and operation futures on stack; both endpoints, Shared, "
            "network stacks, raw-IP drivers and all 16 network buffers are static. "
            "Storage component sizes are totals for both peers and already included in static RAM. "
            "Mode send counts repeat across phases. Phases exclude setup/reporting; "
            "paint observes writes and is an exercised QEMU peak, not a hardware bound."
        )
        packages = tomllib.loads((ROOT / "target-tests/Cargo.lock").read_text())[
            "package"
        ]
        dependencies = [package for package in packages if package["name"] == "xarxa"]
        if len(dependencies) != 1:
            raise ValueError("expected one xarxa dependency in the fixture lockfile")
        dependency = dependencies[0]
        report["dependencies"] = {
            "xarxa": dependency.get("source", dependency["version"]).split("#")[-1]
        }
        fields = (
            "endpoint_bytes",
            "shared_bytes",
            "network_pool_bytes",
            "network_state_bytes",
        )
        components = {
            tuple(value[key] for key in fields) for value in measurements.values()
        }
        if len(components) != 1:
            raise ValueError("xarxa static components differ between scenarios")
        accounted = sum(components.pop())
        residual = report["static_ram_bytes"] - accounted
        report["static_accounting"] = {
            "accounted_bytes": accounted,
            "residual_bytes": residual,
        }
        if residual != 0:
            raise ValueError(
                f"xarxa static accounting mismatch: {target}: "
                f"static_ram={report['static_ram_bytes']} accounted={accounted} residual={residual} bytes"
            )
        report["resource_budgets"] = (
            {
                name: target_budgets[name]
                for name in ("driver_future_bytes", "static_ram_bytes")
            }
            if enforce
            else None
        )
    stem.with_name(stem.name + ".json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{kind} toolchain: {report['toolchain']}", flush=True)
    if enforce:
        check_budgets(
            target,
            measurements,
            {target: stack_budgets},
            SCENARIOS if kind == "stack" else XARXA_SCENARIOS,
        )
        if kind == "xarxa":
            for name, value in measurements.items():
                if (
                    max(value["client_future_bytes"], value["server_future_bytes"])
                    > target_budgets["driver_future_bytes"]
                ):
                    raise ValueError(f"xarxa future budget exceeded: {name}")
            if report["static_ram_bytes"] > target_budgets["static_ram_bytes"]:
                raise ValueError("xarxa static RAM budget exceeded")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--features")
    parser.add_argument("--no-default-features", action="store_true")
    measurement = parser.add_mutually_exclusive_group()
    measurement.add_argument(
        "--stack-check",
        action="store_true",
        help="measure and enforce M4/M33 driver stack budgets",
    )
    measurement.add_argument(
        "--xarxa-check",
        action="store_true",
        help="measure owned xarxa workloads and enforce resource budgets",
    )
    parser.add_argument(
        "--xarxa-budgets", type=pathlib.Path, default=ROOT / "tools/xarxa-budgets.json"
    )
    parser.add_argument(
        "--measure-only",
        action="store_true",
        help="record stack data without enforcing budgets",
    )
    parser.add_argument(
        "--output", type=pathlib.Path, default=ROOT / "target/size-report"
    )
    parser.add_argument(
        "--stack-budgets", type=pathlib.Path, default=ROOT / "tools/stack-budgets.json"
    )
    args = parser.parse_args(argv)
    managed = args.stack_check or args.xarxa_check
    if args.measure_only and not managed:
        parser.error("--measure-only requires --stack-check or --xarxa-check")
    if managed and (args.features is not None or args.no_default_features):
        parser.error(
            "--stack-check/--xarxa-check cannot be combined with --features or --no-default-features"
        )
    if managed and args.target and args.target not in STACK_TARGETS:
        parser.error(
            "--stack-check/--xarxa-check supports Cortex-M4 and Cortex-M33 only"
        )
    if args.features is None:
        args.features = "edhoc"
    return args


def main():
    args = parse_args()
    managed = args.stack_check or args.xarxa_check
    targets = [args.target] if args.target else (STACK_TARGETS if managed else TARGETS)
    budgets = (
        json.loads(
            (args.xarxa_budgets if args.xarxa_check else args.stack_budgets).read_text()
        )
        if managed and not args.measure_only
        else {}
    )
    for target in targets:
        binary = "mai-coap-target-tests"
        features = args.features
        if managed:
            binary = (
                "mai-coap-xarxa-profile"
                if args.xarxa_check
                else "mai-coap-stack-profile"
            )
            features = "xarxa-profile" if args.xarxa_check else "stack-profile"
        command = [
            "cargo",
            "build",
            "--locked",
            "--manifest-path",
            str(ROOT / "target-tests/Cargo.toml"),
            "--release",
            "--target",
            target,
            "--bin",
            binary,
            "--features",
            features,
        ]
        if args.no_default_features or managed:
            command.append("--no-default-features")
        subprocess.run(command, cwd=ROOT, check=True)
        image = ROOT / "target-tests/target" / target / "release" / binary
        qemu, machine = TARGETS[target]
        command = [
            qemu,
            "-M",
            machine,
            "-nographic",
            "-semihosting-config",
            "enable=on,target=native",
        ]
        if machine == "virt":
            command += ["-bios", "none"]
        command += ["-kernel", str(image)]
        result = subprocess.run(
            command, timeout=60, check=False, capture_output=True, text=True
        )
        log = result.stdout + result.stderr
        print(f"{target}:\n{log}", flush=True)
        result.check_returncode()
        completion = (
            "mai-coap xarxa runtime: PASS"
            if args.xarxa_check
            else "mai-coap target runtime: PASS"
        )
        if completion not in log:
            raise RuntimeError(f"{target}: missing test completion marker")
        if managed:
            record_stack(
                target,
                log,
                image,
                args.output,
                not args.measure_only,
                budgets,
                kind="xarxa" if args.xarxa_check else "stack",
            )


if __name__ == "__main__":
    main()
