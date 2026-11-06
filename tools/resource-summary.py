#!/usr/bin/env python3
"""Render resource reports and optional master-run comparisons as Markdown."""

import argparse
import json
import os
import pathlib
import subprocess
import tempfile

TARGETS = ("thumbv7em-none-eabihf", "thumbv8m.main-none-eabihf")
LAYOUTS = (
    "storage-unicast.json",
    "storage-multicast.json",
    "storage-shared-counters.json",
)


def load(directory, name):
    path = directory / name if directory else None
    return json.loads(path.read_text()) if path and path.exists() else None


def table(headers, rows):
    def line(cells):
        return "| " + " | ".join(str(c).replace("|", "\\|") for c in cells) + " |"

    return "\n".join([line(headers), line(["---"] * len(headers)), *map(line, rows)])


def amount(value):
    return f"{value:,}" if value is not None else "—"


def metrics(current, previous, *fields):
    cells = []
    for field in fields:
        value = current[field]
        old = previous.get(field) if previous else None
        cells.extend((amount(value), f"{value - old:+,}" if old is not None else "—"))
    return cells


def comparable(current, previous, *fields):
    return previous and all(current.get(k) == previous.get(k) for k in fields)


def compiler(report, previous):
    rows = []
    for label, field in (
        ("Compiler", "toolchain"),
        ("Build host", "build_host"),
        ("Profile", "profile"),
    ):
        old = previous.get(field) if previous else None
        current = report.get(field)
        rows.append(
            [label, f"`{old}`" if old else "—", f"`{current}`" if current else "—"]
        )
    for name, revision in report.get("dependencies", {}).items():
        old = previous.get("dependencies", {}).get(name) if previous else None
        rows.append([f"{name} revision", f"`{old}`" if old else "—", f"`{revision}`"])
    if "id_context_bytes" in report or (previous and "id_context_bytes" in previous):
        values = [
            (previous or {}).get("id_context_bytes"),
            report.get("id_context_bytes"),
        ]
        rows.append(
            [
                "ID Context capacity (bytes)",
                *(f"`{value}`" if value is not None else "—" for value in values),
            ]
        )
    text = table(["Build setting", "Baseline (A)", "Current (B)"], rows)
    if (
        previous
        and previous.get("toolchain")
        and report.get("toolchain")
        and report["toolchain"] != previous["toolchain"]
    ):
        text += "\n\n**Compiler changed**; deltas include compiler effects."
    if (
        previous
        and previous.get("build_host")
        and report.get("build_host")
        and report["build_host"] != previous["build_host"]
    ):
        text += "\n\n**Build host changed**; deltas include build-host effects."
    if (
        previous
        and "id_context_bytes" in previous
        and "id_context_bytes" in report
        and report["id_context_bytes"] != previous["id_context_bytes"]
    ):
        text += (
            "\n\n**ID Context capacity changed**; deltas include configuration effects."
        )
    return text


def stack_section(report, previous):
    owned = report.get("features", "").startswith("xarxa-profile")
    parts = [
        "### Owned xarxa workload" if owned else "### Driver stack",
        compiler(report, previous),
    ]
    if previous and not comparable(report, previous, "target", "features", "profile"):
        parts.append("Configuration changed; stack deltas are unavailable.")
        previous = None
    rows, futures = [], []
    for name, current in report["scenarios"].items():
        old = previous.get("scenarios", {}).get(name) if previous else None
        if not comparable(current, old, "datagram_bytes"):
            old = None
        budget = (report.get("budgets") or {}).get(name)
        enforced = report["budget_enforced"] and budget is not None
        status = (
            ("EXCEEDED" if current["peak_bytes"] > budget else "PASS")
            if enforced
            else "Not enforced"
        )
        rows.append(
            [
                name,
                *metrics(current, old, "peak_bytes"),
                amount(budget),
                amount(budget - current["peak_bytes"] if budget is not None else None),
                status,
            ]
        )
        futures.append(
            [name, *metrics(current, old, "client_future_bytes", "server_future_bytes")]
        )
    parts.extend(
        [
            table(["Scenario", "Peak", "Δ peak", "Budget", "Headroom", "Gate"], rows),
            table(["Scenario", "Client future", "Δ", "Server future", "Δ"], futures),
            table(
                ["Stack fixture flash", "Δ", "Fixture static RAM", "Δ"],
                [metrics(report, previous, "flash_bytes", "static_ram_bytes")],
            ),
            (
                "QEMU exercised peaks, not hardware worst-case bounds. Driver and operation "
                "futures are included in the painted stack; do not add future sizes again. "
                "Endpoint and Shared storage are included in the separate static RAM total."
            ),
        ]
    )
    if owned:
        current = next(iter(report["scenarios"].values()))
        old = next(iter(previous["scenarios"].values())) if previous else None
        fields = (
            "endpoint_bytes",
            "shared_bytes",
            "network_pool_bytes",
            "network_state_bytes",
        )
        parts.extend(
            [
                table(
                    ["Included static component", "Bytes", "Δ"],
                    [
                        [label, *metrics(current, old, field)]
                        for label, field in zip(
                            (
                                "Endpoints (both)",
                                "Shared (both)",
                                "All 16 network buffers",
                                "Network stacks and fixture link",
                            ),
                            fields,
                            strict=True,
                        )
                    ],
                ),
                "These components are already included in fixture static RAM. The shared pool also holds retained protocol packets; its 16 buffers are not additional endpoint wire buffers. Native xarxa is exercised on a simulated raw-IP link; board drivers and Embassy runner storage are excluded.",
            ]
        )
        limits = report.get("resource_budgets") or {}
        gates = []
        for label, field, value in (
            (
                "Largest driver future",
                "driver_future_bytes",
                max(
                    max(v["client_future_bytes"], v["server_future_bytes"])
                    for v in report["scenarios"].values()
                ),
            ),
            ("Fixture static RAM", "static_ram_bytes", report["static_ram_bytes"]),
        ):
            ceiling = limits.get(field)
            status = (
                ("PASS" if value <= ceiling else "EXCEEDED")
                if ceiling is not None and report["budget_enforced"]
                else "Not enforced"
            )
            gates.append([label, amount(value), amount(ceiling), status])
        parts.append(table(["Resource gate", "Bytes", "Budget", "Gate"], gates))
    return "\n\n".join(parts)


def sizes_section(report, previous):
    metadata = report["measurement"]
    parts = [
        "### Linked workloads",
        compiler(metadata, previous["measurement"] if previous else None),
    ]
    if previous and not comparable(
        metadata, previous["measurement"], "target", "profile"
    ):
        parts.append("Build configuration changed; linked-size deltas are unavailable.")
        previous = None
    rows = []
    for name, current in report.items():
        if "flash_bytes" not in current:
            continue
        old = previous.get(name) if previous else None
        if not comparable(current, old, "features"):
            old = None
        rows.append([name, *metrics(current, old, "flash_bytes", "static_ram_bytes")])
    parts.extend(
        [
            table(["Workload", "Flash", "Δ flash", "Static RAM", "Δ RAM"], rows),
            (
                "Linked-workload sizes are informational; they have no CI byte ceilings. "
                "Static RAM excludes stack and does not measure complete firmware RAM."
            ),
        ]
    )
    return "\n\n".join(parts)


def layout_section(report, previous):
    mode = "multicast" if report["multicast"] else "unicast"
    counters = "on" if report["shared_counters"] else "off"
    parts = [
        f"### Retained storage: {mode}, shared counters {counters}",
        compiler(report, previous),
    ]
    if previous and not all(
        isinstance(build.get(field), str) and build[field].strip()
        for build in (report, previous)
        for field in ("toolchain", "profile")
    ):
        parts.append(
            "Compiler/profile metadata missing; layout deltas are unavailable."
        )
        previous = None
    elif previous and not comparable(
        report, previous, "target", "multicast", "shared_counters", "profile"
    ):
        parts.append("Build configuration changed; layout deltas are unavailable.")
        previous = None
    rows = []
    for name, current in report["profiles"].items():
        old = previous.get("profiles", {}).get(name) if previous else None
        if not comparable(current, old, "capacities"):
            old = None
        row = [name]
        for field in ("endpoint", "shared"):
            row.extend(
                metrics(current[field], old[field] if old else None, "total_bytes")
            )
        row.extend(
            metrics(
                current["endpoint_breakdown"],
                old["endpoint_breakdown"] if old else None,
                "packet_pool_bytes",
            )
        )
        rows.append(row)
    parts.extend(
        [
            table(
                [
                    "Profile",
                    "Endpoint",
                    "Δ",
                    "Shared",
                    "Δ",
                    "Included packet pool",
                    "Δ",
                ],
                rows,
            ),
            (
                "Packet-pool bytes are included in endpoint totals. Layout "
                "deltas require matching build profiles and capacities; these sizes are "
                "informational, without byte ceilings."
            ),
        ]
    )
    return "\n\n".join(parts)


def render(reports, target, baseline=None, comparison="No baseline supplied."):
    parts = [
        f"## Resource measurements: {target}",
        comparison,
        (
            "All sizes and deltas are in bytes; Δ = B − A. Positive Δ means growth; negative Δ means "
            "a reduction. — means no comparable baseline measurement."
        ),
    ]
    sections = [
        (f"stack-{target}.json", stack_section),
        (f"xarxa-{target}.json", stack_section),
    ]
    if target == TARGETS[0]:
        sections += [("sizes.json", sizes_section)]
        sections += [(name, layout_section) for name in LAYOUTS]
    found = False
    for name, section in sections:
        current = load(reports, name)
        if current is not None:
            found = True
            parts.append(section(current, load(baseline, name)))
        else:
            parts.append(
                f"Report `{name}` was not produced; check the measurement steps."
            )
    if not found:
        parts.append("No resource measurements were produced in this job.")
    return "\n\n".join(parts) + "\n"


def gh_json(endpoint):
    result = subprocess.run(
        ["gh", "api", endpoint], check=True, capture_output=True, text=True, timeout=30
    )
    return json.loads(result.stdout)


def fetch_baseline(repository, target, destination, current_run):
    runs = gh_json(
        f"repos/{repository}/actions/workflows/ci.yml/runs"
        "?branch=master&status=success&per_page=100"
    )["workflow_runs"]
    artifact = f"resource-metrics-{target}"
    for run in runs:
        if (
            str(run["id"]) == str(current_run)
            or run["event"] not in ("push", "workflow_dispatch", "schedule")
            or run["head_branch"] != "master"
            or run["head_repository"]["full_name"].lower() != repository.lower()
        ):
            continue
        artifacts = gh_json(
            f"repos/{repository}/actions/runs/{run['id']}/artifacts?per_page=100"
        )["artifacts"]
        available = {a["name"] for a in artifacts if not a["expired"]}
        if artifact not in available:
            continue
        subprocess.run(
            [
                "gh",
                "run",
                "download",
                str(run["id"]),
                "--repo",
                repository,
                "--name",
                artifact,
                "--dir",
                str(destination),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return (
            f"Baseline: successful master [run #{run['run_number']}]({run['html_url']}), "
            f"commit `{run['head_sha']}`, artifact `{artifact}`."
        )
    return (
        "No unexpired metrics found among the 100 most recent successful master runs."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reports", type=pathlib.Path, default=pathlib.Path("target/size-report")
    )
    parser.add_argument("--target", choices=TARGETS, required=True)
    comparison = parser.add_mutually_exclusive_group()
    comparison.add_argument("--baseline", type=pathlib.Path)
    comparison.add_argument("--fetch-baseline", action="store_true")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    args = parser.parse_args()
    if args.fetch_baseline and not args.repository:
        parser.error("--fetch-baseline requires --repository or GITHUB_REPOSITORY")
    if args.fetch_baseline:
        args.reports.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="resource-baseline-", dir=args.reports.parent
        ) as tmp:
            baseline = pathlib.Path(tmp)
            try:
                note = fetch_baseline(
                    args.repository,
                    args.target,
                    baseline,
                    os.environ.get("GITHUB_RUN_ID"),
                )
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                # Historical artifacts are optional; measurement gates run independently.
                note = "Baseline download unavailable; current measurements are shown without deltas."
                baseline = None
            print(render(args.reports, args.target, baseline, note), end="")
    else:
        note = (
            f"Baseline: local reports in `{args.baseline}`."
            if args.baseline
            else "No baseline supplied."
        )
        print(render(args.reports, args.target, args.baseline, note), end="")


if __name__ == "__main__":
    main()
