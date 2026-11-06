"""Compiler identity for resource measurements."""

import os
import subprocess


def rustc_metadata(*, cwd=None):
    compiler = os.environ.get("RUSTC", "rustc")
    lines = subprocess.check_output([compiler, "-vV"], text=True, cwd=cwd).splitlines()
    hosts = [
        line.removeprefix("host: ").strip()
        for line in lines
        if line.startswith("host: ")
    ]
    if (
        not lines
        or not lines[0].startswith("rustc ")
        or len(hosts) != 1
        or not hosts[0]
    ):
        raise ValueError("rustc -vV must identify the compiler and its build host")
    return {"toolchain": lines[0], "build_host": hosts[0]}
