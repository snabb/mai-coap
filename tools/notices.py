#!/usr/bin/env python3
"""Generate or check notices for the union of supported runtime dependency graphs."""

import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / "tools/licenses"
TARGETS = [
    "thumbv6m-none-eabi",
    "thumbv7em-none-eabihf",
    "thumbv8m.main-none-eabihf",
    "riscv32imac-unknown-none-elf",
]
MANIFESTS = [
    ROOT / "Cargo.toml",
    ROOT / "target-tests/Cargo.toml",
    ROOT / "embedded-example/Cargo.toml",
    ROOT / "cli/Cargo.toml",
]
# These dev dependencies are linked by runnable host examples, unlike proptest.
EXAMPLE_DEV_DEPENDENCIES = {"embassy-time", "futures-lite", "rand"}


def cargo(manifest, *args):
    return subprocess.check_output(
        [
            "cargo",
            *args,
            "--manifest-path",
            str(manifest),
            "--locked",
            "--all-features",
        ],
        cwd=ROOT,
        text=True,
    )


def runtime_packages():
    packages = {}
    for manifest in MANIFESTS:
        metadata = json.loads(cargo(manifest, "metadata", "--format-version=1"))
        examples = manifest.resolve() == (ROOT / "Cargo.toml").resolve()
        if examples:
            package = next(
                package
                for package in metadata["packages"]
                if pathlib.Path(package["manifest_path"]).resolve()
                == manifest.resolve()
            )
            roots = {
                dependency["name"]
                for dependency in package["dependencies"]
                if dependency["kind"] is None
                or dependency["kind"] == "dev"
                and dependency["name"] in EXAMPLE_DEV_DEPENDENCIES
            }
        graph = {}
        targets = (
            TARGETS
            if manifest.parent.name == "target-tests"
            else ["x86_64-unknown-linux-gnu"]
        )
        for target in targets:
            tree = cargo(
                manifest,
                "tree",
                "--target",
                target,
                "-e",
                "normal,dev,no-proc-macro" if examples else "normal,no-proc-macro",
                "--prefix",
                "depth" if examples else "none",
                "--no-dedupe",
                "-f",
                "{p}",
            )
            include = not examples
            for line in tree.splitlines():
                if not line.strip():
                    continue
                if examples:
                    match = re.match(r"(\d+)([A-Za-z_][\w-]*) v(\S+)", line)
                    if match is None:
                        raise ValueError(f"unexpected cargo tree line: {line!r}")
                    depth, name, version = match.groups()
                    if int(depth) <= 1:
                        include = int(depth) == 1 and name in roots
                    if include:
                        graph[name, version] = True
                    continue
                match = re.match(r"(\S+) v(\S+)", line)
                if match is None:
                    raise ValueError(f"unexpected cargo tree line: {line!r}")
                graph[match.groups()] = True
        for package in metadata["packages"]:
            key = package["name"], package["version"]
            if key in graph and package["source"] is not None:
                # Git and registry builds may share a name/version but carry
                # different notices (the two Embassy adapters do).
                packages[(*key, package["source"])] = package
    return [packages[key] for key in sorted(packages)]


def license_text(package, refresh):
    directory = pathlib.Path(package["manifest_path"]).parent
    declared = package["license"] or ""
    choice = next(
        (
            s
            for s in ["MIT", "BSD-3-Clause", "0BSD", "ISC", "Apache-2.0"]
            if s in re.split(r"\s+(?:OR|AND)\s+|/", declared)
        ),
        None,
    )
    if choice is None:
        raise RuntimeError(
            f"Review license expression for {package['name']}: {declared}"
        )
    markers = {
        "MIT": "Permission is hereby granted, free of charge",
        "BSD-3-Clause": "Redistribution and use in source and binary forms",
        "0BSD": "Permission to use, copy, modify",
        "ISC": "Permission to use, copy, modify",
        "Apache-2.0": "Apache License",
    }
    candidates = sorted(directory.glob("LICENSE*")) + sorted(directory.glob("COPYING*"))
    if (package.get("source") or "").startswith("git+"):
        candidates += sorted(directory.parent.glob("LICENSE*"))
    if package["name"] in ("lakers", "lakers-shared"):
        candidates = [directory.parent / "LICENSE.md"]
    for path in candidates:
        if path.is_file() and "THIRD-PARTY" not in path.name:
            content = path.read_text()
            if markers[choice] in content and (
                choice not in ("MIT", "0BSD")
                or ("Permission is hereby" in content) == (choice == "MIT")
            ):
                return choice, content.strip(), None
    cached = CACHE / f"{package['name']}-{package['version']}.txt"
    if cached.exists() and not refresh:
        return choice, cached.read_text().strip(), None
    if not refresh:
        raise RuntimeError(
            f"Missing cached license: {cached}; regenerate with --refresh"
        )
    repository = package.get("repository", "").removesuffix(".git").rstrip("/")
    if repository.startswith("https://github.com/"):
        repository = "/".join(repository.split("/")[:5])
        for branch in ["main", "master", "HEAD"]:
            for name in [
                f"LICENSE-{choice}",
                f"LICENSE-{choice}.txt",
                f"LICENSE-{choice}.md",
                "LICENSE",
                "LICENSE.md",
                "LICENSE.txt",
                "COPYING",
            ]:
                url = (
                    repository.replace("github.com", "raw.githubusercontent.com")
                    + f"/{branch}/{name}"
                )
                try:
                    with urllib.request.urlopen(url, timeout=15) as response:
                        content = response.read().decode()
                except urllib.error.HTTPError as error:
                    if error.code == 404:
                        continue
                    raise
                if markers[choice] in content:
                    CACHE.mkdir(parents=True, exist_ok=True)
                    cached.write_text(content)
                    return choice, content.strip(), (cached.name, url)
    raise RuntimeError(
        f"No {choice} text found for {package['name']}; manual notice review required"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--refresh", action="store_true", help="Cache missing upstream license texts"
    )
    args = parser.parse_args()
    groups = {}
    provenance_path = CACHE / "sources.json"
    provenance = (
        json.loads(provenance_path.read_text()) if provenance_path.exists() else {}
    )
    packages = runtime_packages()
    identities = {}
    for package in packages:
        key = package["name"], package["version"]
        identities[key] = identities.get(key, 0) + 1
    for package in packages:
        choice, content, source = license_text(package, args.refresh)
        if source:
            provenance[source[0]] = source[1]
        label = f"{package['name']} {package['version']}"
        if identities[package["name"], package["version"]] > 1:
            label += f" ({package['source']})"
        groups.setdefault((choice, content), []).append(label)
        directory = pathlib.Path(package["manifest_path"]).parent
        for name in ["NOTICE", "NOTICE.txt", "LICENSE-THIRD-PARTY"]:
            path = directory / name
            if path.is_file():
                groups.setdefault(
                    ("Additional notice", path.read_text().strip()), []
                ).append(label)
    fingerprint = hashlib.sha256(
        b"".join(m.with_name("Cargo.lock").read_bytes() for m in MANIFESTS)
    ).hexdigest()
    lines = [
        "Third-party runtime notices",
        "===========================",
        "",
        f"Lockfiles SHA-256: {fingerprint}",
        "",
        "This file covers the union of supported runtime graphs, including host examples",
        "and emulated firmware. Build-only dependencies and proc macros are excluded.",
        "Where a dependency offers MIT OR Apache-2.0, its MIT license is selected.",
        "Redistributors must include the notices applicable to their linked dependencies.",
        "Project copyright: Copyright (c) 2026 mai-coap contributors.",
        "Third-party copyright holders below are preserved verbatim.",
        "",
    ]
    for (choice, content), packages in sorted(groups.items(), key=lambda item: item[1]):
        lines += [
            ", ".join(packages),
            f"Selected license: {choice}",
            "",
            content,
            "",
            "=" * 78,
            "",
        ]
    expected = "\n".join(lines)
    path = ROOT / "THIRD_PARTY_NOTICES.txt"
    if args.check:
        if not path.exists() or path.read_text() != expected:
            raise SystemExit("Third-party notices are stale; run tools/notices.py")
        print("Third-party notices: current")
    else:
        path.write_text(expected)
        if provenance:
            CACHE.mkdir(parents=True, exist_ok=True)
            provenance_path.write_text(
                json.dumps(provenance, indent=2, sort_keys=True) + "\n"
            )
        print(
            f"Wrote {path.name}: {sum(len(p) for p in groups.values())} package notices"
        )


if __name__ == "__main__":
    main()
