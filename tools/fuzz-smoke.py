#!/usr/bin/env python3
"""Run a bounded smoke test of every network-input fuzz target."""

import argparse
import os
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=15)
    parser.add_argument("--cargo-fuzz", default="cargo-fuzz")
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    subprocess.run(["python3", str(root / "tools/fuzz-seeds.py")], check=True)
    for target in [
        "codec",
        "link_format",
        "oscore",
        "edhoc",
        "block1",
        "proxy_uri",
        "endpoint",
        "response_writer",
        "client_transfer",
    ]:
        subprocess.run(
            [
                args.cargo_fuzz,
                "fuzz",
                "run",
                target,
                "--",
                "-max_total_time=" + str(args.seconds),
                "-timeout=2",
                "-max_len=4096",
            ],
            cwd=root,
            env=dict(os.environ, RUSTUP_TOOLCHAIN="nightly"),
            check=True,
        )


if __name__ == "__main__":
    main()
