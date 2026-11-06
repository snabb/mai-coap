#!/usr/bin/env python3
"""Run the minimal host client/server examples on an ephemeral loopback port."""

import pathlib
import select
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    examples = ROOT / "target/debug/examples"
    child = subprocess.Popen(
        [str(examples / "minimal-server"), "127.0.0.1:0"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not select.select([child.stdout], [], [], 5)[0]:
            raise RuntimeError("Minimal server readiness timeout")
        line = child.stdout.readline().strip()
        if not line.startswith("listening on "):
            raise RuntimeError("Minimal server did not announce its socket")
        remote = line.removeprefix("listening on ")
        result = subprocess.run(
            [str(examples / "minimal-client"), remote],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        if result.stdout.strip() != "hello":
            raise RuntimeError("Minimal client returned an unexpected body")
        print("Minimal host examples: PASS")
    finally:
        if child.poll() is None:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


if __name__ == "__main__":
    main()
