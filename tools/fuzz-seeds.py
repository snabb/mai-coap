#!/usr/bin/env python3
"""Create reproducible vector and boundary seeds for network fuzz targets."""

import pathlib
import re
import struct

ROOT = pathlib.Path(__file__).resolve().parents[1]


def seed(target, name, data):
    directory = ROOT / "fuzz/corpus" / target
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def main():
    message = bytes.fromhex("40017d34bb") + b"temperature"
    for target in ["codec", "endpoint", "proxy_uri", "oscore"]:
        seed(target, "get", message)
    seed(
        "endpoint",
        "send-budget-boundaries",
        bytes([0, 0, 124, 0, 1, 0, 125, 0, 1, 1, 255, 1]),
    )
    for flags in range(8):
        seed("endpoint", f"response-handoff-{flags}", bytes([flags, 0, 1, 3, 125]))
    # API-1: sorted/repeated options, atomic refusals and shared wire capacity.
    seed("response_writer", "empty", bytes([0]))
    seed(
        "response_writer",
        "repeat-replace",
        bytes([8, 0, 7, 1, 255, 0, 1, 0, 0, 7, 1, 2, 1, 7, 1, 3]),
    )
    seed(
        "response_writer",
        "full-table",
        bytes([0]) + bytes([0, 1, 0]) * 17 + bytes([1, 1, 0]),
    )
    seed("response_writer", "dot-refusal", bytes([0, 0, 3, 1, 46, 0, 2, 2, 46, 46]))
    seed(
        "response_writer",
        "shared-capacity",
        bytes([8, 2, 0, 114]) + b"p" * 114 + bytes([0, 4, 1, 255]),
    )
    seed(
        "response_writer",
        "payload-refusal",
        bytes([8, 2, 0, 3]) + b"old" + bytes([2, 0, 116]) + b"x" * 116,
    )
    seed("response_writer", "delta-overflow", bytes([0, 0, 9, 0]))
    # OSC-6 regression: all-zero flags must be sent as an empty value.
    seed("oscore", "zero-flags", b"\x00")
    # RFC 8613 appendix C.4 request, with an unprotected Uri-Host option.
    seed(
        "oscore",
        "c4-request",
        bytes.fromhex("44015d1f00003974396c6f63616c686f737483747631"),
    )
    seed("proxy_uri", "uri", b"coap://[2001:db8::1]:5683/a%2fb?q=x%20y")
    # RFC 7252 section 5.10.1 regression: encoded dot segments are removed.
    seed("proxy_uri", "dot-segments", b"coap://h/a/%2E%2E/b/.%2e/%2E?q")
    seed(
        "link_format",
        "core",
        b'</sensor>;rt="temperature outdoor";ct="0 60";obs,</other>;title="a, b"',
    )
    # DSC-1 regression: bare values are ptokens, which allow "<" but not "\".
    seed("link_format", "ptoken", b"</x>;rt=<a>,</y>;rt=\\")
    source = (ROOT / "src/edhoc.rs").read_text()
    for name, value in re.findall(r'const (M[123]): &str = "([0-9a-f]+)";', source):
        seed("edhoc", name.lower(), bytes.fromhex(value))
    for role in ["i", "r"]:
        seed(
            "edhoc",
            f"credential-{role}",
            (ROOT / f"tests/fixtures/{role}.ccs").read_bytes(),
        )
    for name, value in {
        "m3-truncated-short": b"\x41",
        "m3-truncated-length": b"\x58",
        "m3-truncated-long": b"\x58\x18",
        "m3-trailing": b"\x40\x00",
        "m3-wide-length": b"\x59\x00\x18" + bytes(24),
    }.items():
        seed("edhoc", name, value)
    body = struct.pack("!IH", 8, 16) + b"a" * 16 + struct.pack("!IH", 16, 3) + b"end"
    seed("block1", "two-blocks", body)


if __name__ == "__main__":
    main()
