#!/usr/bin/env python3
"""Run the Kani harnesses and fail unless every harness reports its covers.

Kani reports an unsatisfiable `kani::cover!` without failing verification, so a
harness whose assumptions exclude every interesting path would otherwise pass.
Every harness must contain at least one cover, and every harness found in the
sources must be reported, so a change in Kani's output format fails closed.
"""

import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FEATURES = "server,block,oscore"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
PROOF = re.compile(
    r"#\[kani::proof\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?fn\s+(\w+)"
)
HARNESS = re.compile(r"^Checking harness (\S+)\.\.\.$")
COVER = re.compile(r"^ \*\* (\d+) of (\d+) cover properties satisfied")


def source_harnesses(name_filter):
    names = set()
    for path in (ROOT / "src").rglob("proofs.rs"):
        module = "::".join(path.relative_to(ROOT / "src").with_suffix("").parts)
        for name in PROOF.findall(path.read_text()):
            full = f"{module}::{name}"
            if not name_filter or name_filter in full:
                names.add(full)
    return names


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--harness", help="Run only harnesses matching this filter")
    args = parser.parse_args()
    expected = source_harnesses(args.harness)
    if not expected:
        print("No Kani harnesses found in the sources", file=sys.stderr)
        return 1
    command = [
        "cargo",
        "kani",
        "--no-default-features",
        "--features",
        FEATURES,
        "--output-format",
        "terse",
    ]
    if args.harness:
        command += ["--harness", args.harness]
    print("+", " ".join(command), flush=True)
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    harness = None
    covers = {}
    for line in process.stdout:
        print(line, end="", flush=True)
        line = ANSI.sub("", line)
        if match := HARNESS.match(line):
            harness = match[1]
            covers.setdefault(harness, None)
        elif (match := COVER.match(line)) and harness:
            covers[harness] = (int(match[1]), int(match[2]))
    status = process.wait()
    problems = []
    if missing := expected - covers.keys():
        problems.append(f"not reported by Kani: {', '.join(sorted(missing))}")
    for name, result in sorted(covers.items()):
        if result is None:
            problems.append(f"{name}: no cover properties")
        elif result[0] != result[1]:
            problems.append(f"{name}: {result[0]} of {result[1]} covers satisfied")
    if problems:
        print("Kani cover check failed:", *problems, sep="\n  ", file=sys.stderr)
        return 1
    return status


if __name__ == "__main__":
    sys.exit(main())
